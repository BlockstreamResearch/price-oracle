use crate::db::{Database, user_request::InsertPendingResult};

use super::FeeUtxo;

/// A round reads the queue in pages, so the pages have to cover it exactly
/// once: no row read twice, none stepped over, and issuance order kept
/// across the page boundary even where one height holds several requests.
#[tokio::test]
async fn pages_through_every_pending_request_in_issuance_order() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.user_requests();
    // Two at one height, so paging has to break the tie by request hash.
    let queued = [(1u64, [1u8; 32]), (1, [2; 32]), (2, [3; 32]), (3, [4; 32])];
    for (height, hash) in queued {
        let fee_utxo = FeeUtxo {
            txid: hash,
            output_index: 0,
        };
        store
            .insert_pending(hash, b"request", height, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap();
    }

    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let page = store.list_pending_after(2, cursor).await.unwrap();
        if page.is_empty() {
            break;
        }
        for stored in page {
            cursor = Some((stored.block_height, stored.request_hash));
            seen.push((stored.block_height, stored.request_hash));
        }
    }

    assert_eq!(seen, queued, "pages must cover the queue in order, once");
    // The first page alone is what a round used to be limited to.
    assert_eq!(
        store.list_pending_after(2, None).await.unwrap().len(),
        2,
        "a page is bounded by its limit"
    );
}

#[tokio::test]
async fn reports_statuses_and_the_oldest_open_request() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.user_requests();
    assert_eq!(store.oldest_open_block_height().await.unwrap(), None);
    for (height, hash) in [(5u64, [1u8; 32]), (9, [2; 32])] {
        let fee_utxo = FeeUtxo {
            txid: hash,
            output_index: 0,
        };
        store
            .insert_pending(hash, b"request", height, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap();
    }
    store
        .mark_failed([1; 32], b"input unavailable")
        .await
        .unwrap();

    let mut statuses = store.count_by_status().await.unwrap();
    statuses.sort();
    assert_eq!(
        statuses,
        vec![("failed".to_string(), 1), ("pending".to_string(), 1)]
    );
    // The failed request no longer holds up the queue.
    assert_eq!(store.oldest_open_block_height().await.unwrap(), Some(9));
}

#[tokio::test]
async fn inserts_pending_request_once() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.user_requests();
    let hash = [7; 32];
    let fee_utxo = FeeUtxo {
        txid: [8; 32],
        output_index: 3,
    };

    assert_eq!(
        store
            .insert_pending(hash, b"request", 42, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::Inserted
    );
    assert_eq!(
        store
            .insert_pending(hash, b"changed", 43, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::RequestExists
    );

    let stored = store.get(hash).await.unwrap().unwrap();
    assert_eq!(stored.request_hash, hash);
    assert_eq!(stored.request, b"request");
    assert_eq!(stored.block_height, 42);
    assert_eq!(stored.status, "pending");
    assert_eq!(stored.payload, None);
}

#[tokio::test]
async fn reserves_fee_utxos_through_processing_and_releases_after_execution() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.user_requests();
    let fee_utxo = FeeUtxo {
        txid: [8; 32],
        output_index: 3,
    };

    assert_eq!(
        store
            .insert_pending([1; 32], b"first", 42, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::Inserted
    );
    assert_eq!(store.list_pending(10).await.unwrap().len(), 1);
    assert!(
        store
            .mark_processing([1; 32], b"result", b"transaction")
            .await
            .unwrap()
    );
    assert!(store.list_pending(10).await.unwrap().is_empty());
    assert_eq!(
        store
            .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::FeeUtxoReserved(fee_utxo.clone())
    );

    assert!(store.mark_included([1; 32], 44, [9; 32]).await.unwrap());
    assert!(store.mark_executed([1; 32]).await.unwrap());
    assert_eq!(
        store
            .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::Inserted
    );
}

#[tokio::test]
async fn status_changes_that_match_no_row_keep_fee_utxos_reserved() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.user_requests();
    let fee_utxo = FeeUtxo {
        txid: [8; 32],
        output_index: 3,
    };
    store
        .insert_pending([1; 32], b"first", 42, std::slice::from_ref(&fee_utxo))
        .await
        .unwrap();
    assert!(
        store
            .mark_processing([1; 32], b"result", b"transaction")
            .await
            .unwrap()
    );

    // Neither applies to a request that is still processing.
    assert!(!store.mark_executed([1; 32]).await.unwrap());
    assert!(!store.mark_failed([1; 32], b"reason").await.unwrap());
    assert_eq!(
        store
            .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::FeeUtxoReserved(fee_utxo.clone())
    );
}

#[tokio::test]
async fn failing_pending_request_releases_fee_utxos() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.user_requests();
    let fee_utxo = FeeUtxo {
        txid: [8; 32],
        output_index: 3,
    };

    assert_eq!(
        store
            .insert_pending([1; 32], b"first", 42, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::Inserted
    );
    assert!(
        store
            .mark_failed([1; 32], b"input unavailable")
            .await
            .unwrap()
    );
    let failed = store.get([1; 32]).await.unwrap().unwrap();
    assert_eq!(failed.status, "failed");
    assert_eq!(failed.payload.as_deref(), Some(&b"input unavailable"[..]));
    assert!(store.list_pending(10).await.unwrap().is_empty());
    assert_eq!(
        store
            .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
            .await
            .unwrap(),
        InsertPendingResult::Inserted
    );
}
