use crate::db::Database;

#[tokio::test]
async fn counts_active_votings_separately_for_each_proposer() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.voting();
    let first = [1; 32];
    let second = [2; 32];
    store
        .insert_request([3; 32], &[4], first, 100)
        .await
        .unwrap();
    store
        .insert_request([5; 32], &[6], second, 100)
        .await
        .unwrap();
    store
        .insert_synchronized_request([7; 32], &[8], None, 100)
        .await
        .unwrap();

    assert_eq!(
        store
            .active_request_count_for_proposer(Some(first))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .active_request_count_for_proposer(Some(second))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.active_request_count_for_proposer(None).await.unwrap(),
        1
    );
    assert_eq!(
        store
            .active_request_count_for_proposer(Some([9; 32]))
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn expiry_preserves_in_flight_executions_and_removes_completed_records() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.voting();
    let timeout = crate::VOTING_TIMEOUT_BLOCKS;
    let pending = [1; 32];
    let executing = [2; 32];
    let proposer = [3; 32];
    let txid = [4; 32];
    for hash in [pending, executing] {
        store
            .insert_request(hash, &[5], proposer, 100)
            .await
            .unwrap();
        store
            .insert_approval(hash, proposer, &[6], 100, 1)
            .await
            .unwrap();
    }
    store.start_execution(executing, &[7]).await.unwrap();

    assert_eq!(
        store
            .delete_expired(100 + timeout - 1, timeout)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store.delete_expired(100 + timeout, timeout).await.unwrap(),
        1
    );
    assert!(store.get(pending).await.unwrap().is_none());
    assert_eq!(store.approval_count(pending).await.unwrap(), 0);
    assert!(store.get(executing).await.unwrap().is_some());
    assert_eq!(store.active_request_count().await.unwrap(), 1);

    store
        .record_broadcast(executing, proposer, &[7], &[8], txid)
        .await
        .unwrap();
    assert_eq!(
        store.delete_expired(100 + timeout, timeout).await.unwrap(),
        0
    );
    store
        .mark_execution_included(executing, txid, 101, [9; 32])
        .await
        .unwrap();
    store.confirm_execution(executing, txid).await.unwrap();
    assert_eq!(store.active_request_count().await.unwrap(), 0);
    assert_eq!(
        store.delete_expired(100 + timeout, timeout).await.unwrap(),
        1
    );
    assert_eq!(store.approval_count(executing).await.unwrap(), 0);
}

#[tokio::test]
async fn persists_voting_execution_lifecycle() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.voting();
    let request_hash = [1; 32];
    let proposer = [2; 32];
    let transaction = [3, 4, 5];
    let txid = [6; 32];
    let execution_request = [10, 11, 12];

    assert!(
        store
            .insert_request(request_hash, &[7], proposer, 10)
            .await
            .unwrap()
    );
    assert!(
        store
            .insert_approval(request_hash, [8; 32], &[9], 11, 1)
            .await
            .unwrap()
    );
    assert!(
        store
            .start_execution(request_hash, &transaction)
            .await
            .unwrap()
    );
    assert!(
        !store
            .start_execution(request_hash, &transaction)
            .await
            .unwrap()
    );

    let executing = store.get(request_hash).await.unwrap().unwrap();
    assert!(executing.execution_started);
    assert_eq!(executing.execution_transaction, Some(transaction.to_vec()));

    assert!(
        store
            .record_broadcast(
                request_hash,
                [9; 32],
                &transaction,
                &execution_request,
                txid,
            )
            .await
            .is_err()
    );
    store
        .record_broadcast(
            request_hash,
            proposer,
            &transaction,
            &execution_request,
            txid,
        )
        .await
        .unwrap();
    store
        .record_broadcast(
            request_hash,
            proposer,
            &transaction,
            &execution_request,
            txid,
        )
        .await
        .unwrap();
    let broadcast = store.get(request_hash).await.unwrap().unwrap();
    assert!(broadcast.execution_started);
    assert_eq!(broadcast.execution_transaction, Some(transaction.to_vec()));
    assert_eq!(
        broadcast.execution_request,
        Some(execution_request.to_vec())
    );
    assert_eq!(broadcast.execution_txid, Some(txid));
    assert!(!broadcast.execution_confirmed);

    store
        .mark_execution_included(request_hash, txid, 43, [8; 32])
        .await
        .unwrap();
    store.confirm_execution(request_hash, txid).await.unwrap();
    let executed = store.get(request_hash).await.unwrap().unwrap();
    assert!(!executed.execution_started);
    assert_eq!(executed.execution_transaction, Some(transaction.to_vec()));
    assert_eq!(executed.execution_request, Some(execution_request.to_vec()));
    assert_eq!(executed.execution_txid, Some(txid));
    assert!(executed.execution_confirmed);
    assert!(store.confirm_execution(request_hash, txid).await.is_err());
    assert!(store.confirm_execution([0; 32], txid).await.is_err());
}

#[tokio::test]
async fn completion_populates_an_unknown_synchronized_proposer() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.voting();
    let request_hash = [10; 32];
    let proposer = [12; 32];
    let txid = [13; 32];
    let transaction = [14];
    let execution_request = [15];

    assert!(
        store
            .insert_synchronized_request(request_hash, &[11], None, 12)
            .await
            .unwrap()
    );
    assert!(
        store
            .insert_approval(request_hash, [14; 32], &[15], 13, 1)
            .await
            .unwrap()
    );
    store
        .record_broadcast(
            request_hash,
            proposer,
            &transaction,
            &execution_request,
            txid,
        )
        .await
        .unwrap();
    let completed = store.get(request_hash).await.unwrap().unwrap();
    assert_eq!(completed.proposer_public_key, Some(proposer));
    assert_eq!(completed.execution_txid, Some(txid));
    assert!(!completed.execution_confirmed);
}
