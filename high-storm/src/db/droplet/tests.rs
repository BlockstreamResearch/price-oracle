use crate::db::Database;

use super::*;

#[tokio::test]
async fn credits_and_locks_droplet_balances_atomically() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let member = [7; 32];

    store.credit(member, 1_000, 10).await.unwrap();
    store.credit(member, 500, 11).await.unwrap();
    assert!(
        !store
            .lock_exchange(member, 2_000, 12, &[1, 2])
            .await
            .unwrap()
    );
    assert!(store.lock_exchange(member, 900, 12, &[1, 2]).await.unwrap());
    assert!(store.lock_exchange(member, 900, 12, &[1, 2]).await.unwrap());
    assert!(!store.lock_exchange(member, 1, 12, &[3]).await.unwrap());

    let balance = store.balance(member).await.unwrap().unwrap();
    assert_eq!(balance.amount, 1_500);
    assert_eq!(balance.block_height, 12);
    assert!(balance.exchange_locked);
    assert_eq!(balance.last_tx, Some(vec![1, 2]));
    assert_eq!(store.locked().await.unwrap(), vec![balance]);
    assert!(
        !store
            .update_locked_transaction(member, &[9], &[4, 5])
            .await
            .unwrap()
    );
    assert!(
        store
            .update_locked_transaction(member, &[1, 2], &[4, 5])
            .await
            .unwrap()
    );

    store.unlock_exchange(member, 13).await.unwrap();
    let balance = store.balance(member).await.unwrap().unwrap();
    assert!(!balance.exchange_locked);
    assert_eq!(balance.last_tx, None);
}

#[tokio::test]
async fn queues_and_finishes_only_the_matching_exchange_request() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let member = [3; 32];
    store
        .queue_exchange(member, &[1, 2], [4; 32], 10)
        .await
        .unwrap();
    let first = store.exchange_request(member).await.unwrap().unwrap();

    store
        .queue_exchange(member, &[5, 6], [7; 32], 11)
        .await
        .unwrap();

    assert!(
        !store
            .complete_exchange_request(&first, [8; 32])
            .await
            .unwrap()
    );
    let second = store.exchange_request(member).await.unwrap().unwrap();
    assert_eq!(second.status, "pending");
    assert_eq!(second.transaction, [5, 6]);
    assert_eq!(store.exchange_history(member).await.unwrap(), vec![first]);
    assert!(
        store
            .complete_exchange_request(&second, [9; 32])
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .exchange_request(member)
            .await
            .unwrap()
            .unwrap()
            .completed_txid,
        Some([9; 32])
    );

    store
        .queue_exchange(member, &[10, 11], [12; 32], 12)
        .await
        .unwrap();
    let history = store.exchange_history(member).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].transaction, [5, 6]);
    assert_eq!(history[0].status, "completed");
    assert_eq!(history[1].transaction, [1, 2]);
}

#[tokio::test]
async fn applies_deposits_and_confirmed_exchanges_once() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let members = [[1; 32], [2; 32], [3; 32]];

    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(10),
            &[TreasuryTransaction {
                txid: [4; 32],
                inputs: vec![],
                outputs: vec![(0, 1_001)],
                deposit_member: None,
                exchange_member: None,
            }],
            &members,
        )
        .await
        .unwrap();
    assert_eq!(
        store.balance(members[0]).await.unwrap().unwrap().amount,
        334
    );
    assert_eq!(
        store.balance(members[1]).await.unwrap().unwrap().amount,
        334
    );
    assert_eq!(
        store.balance(members[2]).await.unwrap().unwrap().amount,
        333
    );
    assert_eq!(
        store.treasury_utxos().await.unwrap(),
        vec![TreasuryUtxo {
            txid: [4; 32],
            output_index: 0,
            amount: 1_001,
        }]
    );

    store.credit(members[1], 1_000, 11).await.unwrap();
    assert!(
        store
            .lock_exchange(members[1], 600, 11, &[8, 9])
            .await
            .unwrap()
    );
    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(12),
            &[TreasuryTransaction {
                txid: [5; 32],
                inputs: vec![([4; 32], 0)],
                outputs: vec![(1, 401)],
                deposit_member: None,
                exchange_member: Some(members[1]),
            }],
            &members,
        )
        .await
        .unwrap();
    assert_eq!(
        store.balance(members[1]).await.unwrap().unwrap().amount,
        734
    );
    let balance = store.balance(members[1]).await.unwrap().unwrap();
    assert!(!balance.exchange_locked);
    assert_eq!(balance.last_tx, None);
    assert_eq!(
        store.cursor("droplets-v1").await.unwrap().unwrap().height,
        12
    );
    assert_eq!(
        store.treasury_utxos().await.unwrap(),
        vec![TreasuryUtxo {
            txid: [5; 32],
            output_index: 1,
            amount: 401,
        }]
    );
}

#[tokio::test]
async fn an_overdrawn_spend_records_a_deficit_that_credits_repay() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let member = [1; 32];
    let deficit = async || -> i64 {
        sqlx::query_scalar("SELECT deficit FROM droplets WHERE xonly_pubkey = $1")
            .bind(member.to_vec())
            .fetch_one(&store.pool)
            .await
            .unwrap()
    };
    let block = |height: u64| IndexedBlock {
        height,
        hash: [height as u8; 32],
    };
    let deposit = TreasuryTransaction {
        txid: [4; 32],
        inputs: vec![],
        outputs: vec![(0, 1_000), (1, 1_000)],
        deposit_member: Some(member),
        exchange_member: None,
    };
    let spend = |txid: u8, vout: u32| TreasuryTransaction {
        txid: [txid; 32],
        inputs: vec![([4; 32], vout)],
        outputs: vec![],
        deposit_member: None,
        exchange_member: Some(member),
    };
    store
        .apply_block("droplets-v1", &block(10), &[deposit], &[member])
        .await
        .unwrap();
    store.lock_exchange(member, 1_000, 10, &[1]).await.unwrap();

    // The second confirmed spend overdraws a balance already reduced to 500.
    store
        .apply_block("droplets-v1", &block(11), &[spend(5, 0)], &[member])
        .await
        .unwrap();
    sqlx::query("UPDATE droplets SET amount = 500 WHERE xonly_pubkey = $1")
        .bind(member.to_vec())
        .execute(&store.pool)
        .await
        .unwrap();
    store
        .apply_block("droplets-v1", &block(12), &[spend(6, 1)], &[member])
        .await
        .unwrap();
    let balance = store.balance(member).await.unwrap().unwrap();
    assert_eq!(balance.amount, 0);
    assert!(!balance.exchange_locked);
    assert_eq!(deficit().await, 500);
    assert_eq!(
        store.cursor("droplets-v1").await.unwrap().unwrap().height,
        12
    );

    store.credit(member, 300, 13).await.unwrap();
    assert_eq!(store.balance(member).await.unwrap().unwrap().amount, 0);
    assert_eq!(deficit().await, 200);
    store.credit(member, 450, 14).await.unwrap();
    assert_eq!(store.balance(member).await.unwrap().unwrap().amount, 250);
    assert_eq!(deficit().await, 0);
}

#[tokio::test]
async fn a_failed_droplets_block_rolls_back_only_its_savepoint() {
    use crate::db::monitored_utxo::MonitoredUtxo;

    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let members = [[1; 32]];
    let block = IndexedBlock::at(61);
    let tick = MonitoredUtxo {
        txid: [9; 32],
        output_index: 0,
        asset_kind: "tick".into(),
        amount: 1,
        script_pubkey: vec![0x51],
        auth_method: "signature-auth".into(),
        auth_data: vec![2; 32],
        account_owner_pubkey: [3; 32],
        internal_key: None,
        burning_fee_txid: [4; 32],
        burning_fee_output_index: 5,
        block_height: 1,
        status: "active".into(),
        status_block_height: 1,
        burn_txid: None,
    };
    let deposit = TreasuryTransaction {
        txid: [6; 32],
        inputs: vec![],
        outputs: vec![(0, 900)],
        deposit_member: None,
        exchange_member: None,
    };
    store
        .apply_block("droplets-v1", &IndexedBlock::at(60), &[deposit], &members)
        .await
        .unwrap();
    let unmarked_spend = TreasuryTransaction {
        txid: [7; 32],
        inputs: vec![([6; 32], 0)],
        outputs: vec![],
        deposit_member: None,
        exchange_member: None,
    };

    let mut transaction = store.pool.begin().await.unwrap();
    MonitoredUtxoStore::apply_block_in(&mut transaction, &block, &[tick], &[], 60)
        .await
        .unwrap();
    let mut savepoint = sqlx::Acquire::begin(&mut transaction).await.unwrap();
    let error = DropletStore::apply_block_in(&mut savepoint, &block, &[unmarked_spend], &members)
        .await
        .unwrap_err();
    let DropletError::Invalid(reason) = error else {
        panic!("expected an invalid Treasury spend");
    };
    savepoint.rollback().await.unwrap();
    DropletStore::halt_ledger_in(&mut transaction, block.height, &reason)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    assert_eq!(
        database
            .monitored_utxos()
            .list_expired(10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.balance(members[0]).await.unwrap().unwrap().amount,
        900
    );
    assert_eq!(store.treasury_utxos().await.unwrap().len(), 1);
    assert_eq!(
        store.ledger_halt().await.unwrap(),
        Some((61, "Treasury spend has no member marker".into()))
    );
    database.chain().reset_projections().await.unwrap();
    assert_eq!(store.ledger_halt().await.unwrap(), None);
}

#[tokio::test]
async fn accounts_treasury_activity_to_members_active_in_each_epoch() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let removed = [1; 32];
    let retained = [2; 32];
    let added = [3; 32];
    let previous_members = [removed, retained];
    let next_members = [retained, added];

    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(10),
            &[
                TreasuryTransaction {
                    txid: [10; 32],
                    inputs: vec![],
                    outputs: vec![(0, 100)],
                    deposit_member: Some(removed),
                    exchange_member: None,
                },
                TreasuryTransaction {
                    txid: [11; 32],
                    inputs: vec![],
                    outputs: vec![(0, 10)],
                    deposit_member: None,
                    exchange_member: None,
                },
            ],
            &previous_members,
        )
        .await
        .unwrap();
    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(11),
            &[TreasuryTransaction {
                txid: [12; 32],
                inputs: vec![([10; 32], 0)],
                outputs: vec![(0, 50)],
                deposit_member: None,
                exchange_member: Some(removed),
            }],
            &previous_members,
        )
        .await
        .unwrap();

    assert_eq!(store.balance(removed).await.unwrap().unwrap().amount, 55);
    assert_eq!(store.balance(retained).await.unwrap().unwrap().amount, 5);

    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(13),
            &[
                TreasuryTransaction {
                    txid: [13; 32],
                    inputs: vec![],
                    outputs: vec![(0, 100)],
                    deposit_member: Some(added),
                    exchange_member: None,
                },
                TreasuryTransaction {
                    txid: [14; 32],
                    inputs: vec![],
                    outputs: vec![(0, 10)],
                    deposit_member: None,
                    exchange_member: None,
                },
            ],
            &next_members,
        )
        .await
        .unwrap();
    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(14),
            &[TreasuryTransaction {
                txid: [15; 32],
                inputs: vec![([13; 32], 0)],
                outputs: vec![(0, 60)],
                deposit_member: None,
                exchange_member: Some(added),
            }],
            &next_members,
        )
        .await
        .unwrap();

    assert_eq!(store.balance(removed).await.unwrap().unwrap().amount, 55);
    assert_eq!(store.balance(retained).await.unwrap().unwrap().amount, 10);
    assert_eq!(store.balance(added).await.unwrap().unwrap().amount, 65);

    let removed_member_exchange = TreasuryTransaction {
        txid: [16; 32],
        inputs: vec![([12; 32], 0)],
        outputs: vec![(0, 25)],
        deposit_member: None,
        exchange_member: Some(removed),
    };
    assert!(matches!(
        store
            .apply_block(
                "droplets-v1",
                &IndexedBlock::at(15),
                &[removed_member_exchange],
                &next_members,
            )
            .await,
        Err(DropletError::Invalid(_))
    ));
    assert_eq!(store.balance(removed).await.unwrap().unwrap().amount, 55);
}

#[tokio::test]
async fn allocates_unknown_tags_over_sorted_unique_members() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let first = [1; 32];
    let second = [2; 32];

    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(10),
            &[TreasuryTransaction {
                txid: [4; 32],
                inputs: vec![],
                outputs: vec![(0, 5)],
                deposit_member: Some([9; 32]),
                exchange_member: None,
            }],
            &[second, first, second],
        )
        .await
        .unwrap();

    assert_eq!(store.balance(first).await.unwrap().unwrap().amount, 3);
    assert_eq!(store.balance(second).await.unwrap().unwrap().amount, 2);
    assert!(store.balance([9; 32]).await.unwrap().is_none());
}

#[tokio::test]
async fn rolls_back_treasury_ledger_and_cursor_on_invalid_spend() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.droplets();
    let member = [1; 32];
    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(10),
            &[TreasuryTransaction {
                txid: [4; 32],
                inputs: vec![],
                outputs: vec![(0, 100)],
                deposit_member: Some(member),
                exchange_member: None,
            }],
            &[member],
        )
        .await
        .unwrap();
    let invalid_spend = TreasuryTransaction {
        txid: [5; 32],
        inputs: vec![([4; 32], 0)],
        outputs: vec![(0, 20)],
        deposit_member: None,
        exchange_member: Some([9; 32]),
    };

    assert!(matches!(
        store
            .apply_block(
                "droplets-v1",
                &IndexedBlock::at(11),
                std::slice::from_ref(&invalid_spend),
                &[member],
            )
            .await,
        Err(DropletError::Invalid(_))
    ));
    assert_eq!(store.balance(member).await.unwrap().unwrap().amount, 100);
    assert_eq!(
        store.cursor("droplets-v1").await.unwrap().unwrap().height,
        10
    );

    store
        .apply_block(
            "droplets-v1",
            &IndexedBlock::at(11),
            &[TreasuryTransaction {
                exchange_member: Some(member),
                ..invalid_spend
            }],
            &[member],
        )
        .await
        .unwrap();

    assert_eq!(store.balance(member).await.unwrap().unwrap().amount, 20);
    assert_eq!(
        store.cursor("droplets-v1").await.unwrap().unwrap().height,
        11
    );
}
