use crate::db::Database;

use super::*;

fn monitored(block_height: u64) -> MonitoredUtxo {
    MonitoredUtxo {
        txid: [1; 32],
        output_index: 2,
        asset_kind: "tick".into(),
        amount: 1_700_000_000,
        script_pubkey: vec![0x51],
        auth_method: "signature-auth".into(),
        auth_data: vec![2; 32],
        account_owner_pubkey: [4; 32],
        internal_key: None,
        burning_fee_txid: [1; 32],
        burning_fee_output_index: 3,
        block_height,
        status: "active".into(),
        status_block_height: block_height,
        burn_txid: None,
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and TEST_POSTGRES_URL"]
async fn postgres_batched_burning_reservations() {
    sqlx::any::install_default_drivers();
    let url = std::env::var("TEST_POSTGRES_URL").expect("TEST_POSTGRES_URL must be set");
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TEMPORARY TABLE monitored_utxos \
             (burning_fee_txid BYTEA, burning_fee_output_index BIGINT, status TEXT)",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (txid, index, status) in [
        ([1; 32], 3, "active"),
        ([9; 32], 7, "expired"),
        ([8; 32], 5, "burning"),
        ([7; 32], 6, "unburnable"),
    ] {
        sqlx::query(
            "INSERT INTO monitored_utxos \
                 (burning_fee_txid, burning_fee_output_index, status) VALUES ($1, $2, $3)",
        )
        .bind(txid.to_vec())
        .bind(i64::from(index))
        .bind(status)
        .execute(&pool)
        .await
        .unwrap();
    }
    let store = MonitoredUtxoStore::new(pool);
    let mut outpoints = vec![
        ([1; 32], 7),
        ([9; 32], 3),
        ([1; 32], 3),
        ([9; 32], 7),
        ([1; 32], 3),
        ([8; 32], 5),
        ([7; 32], 6),
    ];
    outpoints.extend((10..103).map(|index| ([index; 32], u32::MAX)));
    let mut expected = vec![false; outpoints.len()];
    for index in [2, 3, 4, 5] {
        expected[index] = true;
    }

    assert_eq!(
        store.burning_reservations(&outpoints).await.unwrap(),
        expected
    );
    assert_eq!(
        store.burning_reservations(&outpoints[2..3]).await.unwrap(),
        vec![true]
    );
    store.pool.close().await;
    assert!(store.burning_reservations(&[]).await.unwrap().is_empty());
}

#[tokio::test]
async fn reports_statuses_the_oldest_unburned_utxo_and_reverted_burns() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let mut second = monitored(10);
    second.output_index = 4;
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(10),
            &[monitored(10), second],
            &[],
            60,
        )
        .await
        .unwrap();
    assert_eq!(
        store.count_by_status().await.unwrap(),
        vec![("active".to_string(), 2)]
    );
    assert_eq!(store.oldest_unburned_block_height().await.unwrap(), None);

    store
        .apply_block("burning-v1", &IndexedBlock::at(70), &[], &[], 60)
        .await
        .unwrap();
    store
        .mark_burning(&[([1; 32], 2)], [8; 32], 70)
        .await
        .unwrap();
    let mut statuses = store.count_by_status().await.unwrap();
    statuses.sort();
    assert_eq!(
        statuses,
        vec![("burning".to_string(), 1), ("expired".to_string(), 1)]
    );
    assert_eq!(
        store.oldest_unburned_block_height().await.unwrap(),
        Some(10)
    );

    // Unconfirmed after five blocks, the burn goes back to the queue.
    let mut transaction = store.pool.begin().await.unwrap();
    let reverted =
        MonitoredUtxoStore::apply_block_in(&mut transaction, &IndexedBlock::at(75), &[], &[], 60)
            .await
            .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(reverted, 1);
    assert_eq!(
        store.count_by_status().await.unwrap(),
        vec![("expired".to_string(), 2)]
    );
}

#[tokio::test]
async fn batched_burning_reservations_preserve_pairs_order_and_statuses() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let first = monitored(10);
    let mut second = monitored(10);
    second.output_index = 4;
    second.burning_fee_txid = [9; 32];
    second.burning_fee_output_index = 7;
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(10),
            &[first.clone(), second.clone()],
            &[],
            60,
        )
        .await
        .unwrap();
    let mut outpoints = vec![
        ([1; 32], 7),
        ([9; 32], 3),
        ([1; 32], 3),
        ([9; 32], 7),
        ([1; 32], 3),
    ];
    outpoints.extend((5..100).map(|index| ([index; 32], u32::MAX)));
    let mut expected = vec![false; 100];
    expected[2] = true;
    expected[3] = true;
    expected[4] = true;
    assert_eq!(
        store.burning_reservations(&outpoints).await.unwrap(),
        expected
    );

    store
        .apply_block("burning-v1", &IndexedBlock::at(70), &[], &[], 60)
        .await
        .unwrap();
    store
        .mark_burning(&[(first.txid, first.output_index)], [8; 32], 70)
        .await
        .unwrap();
    assert_eq!(
        store.burning_reservations(&outpoints).await.unwrap(),
        expected
    );
    store
        .quarantine_unburnable(&[(second.txid, second.output_index)], 70)
        .await
        .unwrap();
    expected[3] = false;
    assert_eq!(
        store.burning_reservations(&outpoints).await.unwrap(),
        expected
    );

    store.pool.close().await;
    assert!(store.burning_reservations(&[]).await.unwrap().is_empty());
}

#[tokio::test]
async fn advances_issued_utxo_lifecycle_from_confirmed_blocks() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let issued = monitored(10);

    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(10),
            std::slice::from_ref(&issued),
            &[],
            60,
        )
        .await
        .unwrap();
    assert!(store.list_expired(10).await.unwrap().is_empty());
    assert!(
        store
            .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
            .await
            .unwrap()
    );
    assert!(
        !store
            .is_reserved_for_burning([9; 32], issued.burning_fee_output_index)
            .await
            .unwrap()
    );

    store
        .apply_block("burning-v1", &IndexedBlock::at(70), &[], &[], 60)
        .await
        .unwrap();
    let expired = store.list_expired(10).await.unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].txid, issued.txid);
    assert_eq!(expired[0].status, "expired");
    assert_eq!(expired[0].status_block_height, 70);
    assert!(
        store
            .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
            .await
            .unwrap()
    );

    assert_eq!(
        store
            .mark_burning(&[([1; 32], 2)], [3; 32], 70)
            .await
            .unwrap(),
        1
    );
    store
        .apply_block("burning-v1", &IndexedBlock::at(75), &[], &[], 60)
        .await
        .unwrap();
    assert_eq!(store.list_expired(10).await.unwrap()[0].status, "expired");
}

#[tokio::test]
async fn expiry_remains_anchored_to_issuance_height() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let issued = monitored(100);

    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(100),
            std::slice::from_ref(&issued),
            &[],
            60,
        )
        .await
        .unwrap();

    for _ in 0..3 {
        store
            .apply_block("burning-v1", &IndexedBlock::at(159), &[], &[], 60)
            .await
            .unwrap();
        assert!(store.list_expired(10).await.unwrap().is_empty());
    }

    for height in [160, 161] {
        store
            .apply_block("burning-v1", &IndexedBlock::at(height), &[], &[], 60)
            .await
            .unwrap();
        let expired = store.list_expired(10).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].block_height, 100);
        assert_eq!(expired[0].status_block_height, 160);
    }
}

#[tokio::test]
async fn burn_retry_waits_for_five_confirmed_heights() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let issued = monitored(100);

    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(160),
            std::slice::from_ref(&issued),
            &[],
            60,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .mark_burning(&[(issued.txid, issued.output_index)], [9; 32], 160)
            .await
            .unwrap(),
        1
    );

    for height in [160, 164, 164, 165] {
        store
            .apply_block("burning-v1", &IndexedBlock::at(height), &[], &[], 60)
            .await
            .unwrap();
        assert!(
            store
                .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
                .await
                .unwrap()
        );
        let expired = store.list_expired(10).await.unwrap();
        if height < 165 {
            assert!(expired.is_empty());
        } else {
            assert_eq!(expired.len(), 1);
            assert_eq!(expired[0].block_height, 100);
            assert_eq!(expired[0].status_block_height, 165);
            assert_eq!(expired[0].burn_txid, None);
        }
    }
}

#[tokio::test]
async fn marking_a_burn_batch_is_all_or_nothing() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let first = monitored(1);
    let mut second = monitored(1);
    second.output_index = 3;
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock {
                height: 61,
                hash: [6; 32],
            },
            &[first, second],
            &[],
            60,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .mark_burning(&[([1; 32], 3)], [7; 32], 61)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .mark_burning(&[([1; 32], 3)], [7; 32], 61)
            .await
            .unwrap(),
        1
    );

    assert_eq!(
        store
            .mark_burning(&[([1; 32], 2), ([1; 32], 3)], [8; 32], 61)
            .await
            .unwrap(),
        0
    );
    assert_eq!(store.list_expired(10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn quarantines_an_unburnable_group() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let issued = monitored(1);
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock {
                height: 61,
                hash: [6; 32],
            },
            std::slice::from_ref(&issued),
            &[],
            60,
        )
        .await
        .unwrap();

    assert_eq!(
        store
            .quarantine_unburnable(&[(issued.txid, issued.output_index)], 61)
            .await
            .unwrap(),
        1
    );
    assert!(store.list_expired(10).await.unwrap().is_empty());
    assert!(
        !store
            .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn confirmed_spends_delete_ticks_and_release_the_shared_reserve() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let first = monitored(1);
    let mut second = monitored(1);
    second.output_index = 4;
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(1),
            &[first.clone(), second.clone()],
            &[],
            60,
        )
        .await
        .unwrap();

    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(2),
            &[],
            &[(first.txid, first.output_index, [8; 32])],
            60,
        )
        .await
        .unwrap();
    assert!(
        store
            .is_reserved_for_burning(first.burning_fee_txid, first.burning_fee_output_index,)
            .await
            .unwrap()
    );

    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(3),
            &[],
            &[(second.txid, second.output_index, [9; 32])],
            60,
        )
        .await
        .unwrap();
    assert!(
        !store
            .is_reserved_for_burning(first.burning_fee_txid, first.burning_fee_output_index,)
            .await
            .unwrap()
    );
    let remaining: i64 = sqlx::query("SELECT COUNT(*) AS count FROM monitored_utxos")
        .fetch_one(&store.pool)
        .await
        .unwrap()
        .try_get("count")
        .unwrap();
    assert_eq!(remaining, 0);
}
