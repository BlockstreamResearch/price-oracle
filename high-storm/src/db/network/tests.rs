use secp256k1_zkp::{Secp256k1, SecretKey};

use crate::{
    NetworkAsset,
    db::{Database, network_asset::STORM_EYE_KIND},
};

use super::*;

#[tokio::test]
async fn member_migration_persists_peers_and_contract_atomically() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.network();
    let old_peer = Peer::new([2; 33]);
    let new_peer = Peer::new(
        SecretKey::from_slice(&[3; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
            .serialize(),
    );
    let request_hash = [7; 32];
    let proposer = [8; 32];
    let transaction = [9];
    let execution_request = [10];
    let execution_txid = [11; 32];
    let stale_request_hash = [12; 32];
    let removed_member = [13; 32];
    store
        .save(std::slice::from_ref(&old_peer), [2; 33])
        .await
        .unwrap();
    let votes = database.voting();
    votes
        .insert_request(request_hash, &[12], proposer, 1)
        .await
        .unwrap();
    votes
        .insert_approval(request_hash, proposer, &[13], 2, 1)
        .await
        .unwrap();
    votes
        .record_broadcast(
            request_hash,
            proposer,
            &transaction,
            &execution_request,
            execution_txid,
        )
        .await
        .unwrap();
    votes
        .insert_request(stale_request_hash, &[14], removed_member, 2)
        .await
        .unwrap();
    votes
        .insert_approval(stale_request_hash, removed_member, &[15], 3, 1)
        .await
        .unwrap();

    assert!(matches!(
        store
            .apply_member_migration(
                std::slice::from_ref(&new_peer),
                [2; 33],
                STORM_EYE_KIND,
                &[0x52],
                &[9; 32],
                ConfirmedVotingExecution {
                    request_hash,
                    txid: execution_txid,
                    block_height: 43,
                    block_hash: [16; 32],
                },
            )
            .await
            .unwrap_err(),
        Error::MigrationAssetNotUpdated
    ));
    assert_eq!(store.load().await.unwrap(), vec![old_peer.clone()]);
    assert!(
        !votes
            .get(request_hash)
            .await
            .unwrap()
            .unwrap()
            .execution_confirmed
    );
    assert!(votes.get(stale_request_hash).await.unwrap().is_some());
    assert_eq!(votes.approval_count(stale_request_hash).await.unwrap(), 1);
    let migration_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network_member_migrations WHERE request_hash = $1",
    )
    .bind(request_hash.to_vec())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(migration_count, 0);

    database
        .network_assets()
        .insert_active(&NetworkAsset {
            kind: STORM_EYE_KIND.to_string(),
            name: "Storm Eye".to_string(),
            asset_id: [4; 32],
            reissuance_token_id: None,
            entropy: None,
            issuance_txid: [5; 32],
            contract_script: vec![0x51],
            contract_data: Some(vec![6; 32]),
            supply: 10_000,
            created_at_block: 1,
        })
        .await
        .unwrap();

    assert!(matches!(
        store
            .apply_member_migration(
                std::slice::from_ref(&new_peer),
                [2; 33],
                STORM_EYE_KIND,
                &[0x52],
                &[9; 32],
                ConfirmedVotingExecution {
                    request_hash,
                    txid: [12; 32],
                    block_height: 43,
                    block_hash: [16; 32],
                },
            )
            .await
            .unwrap_err(),
        Error::MigrationExecutionNotUpdated
    ));
    assert_eq!(store.load().await.unwrap(), vec![old_peer]);
    let unchanged_asset = database
        .network_assets()
        .get(STORM_EYE_KIND)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged_asset.contract_script, vec![0x51]);
    assert_eq!(unchanged_asset.contract_data, Some(vec![6; 32]));
    assert!(votes.get(stale_request_hash).await.unwrap().is_some());
    assert_eq!(votes.approval_count(stale_request_hash).await.unwrap(), 1);
    let migration_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM network_member_migrations WHERE request_hash = $1",
    )
    .bind(request_hash.to_vec())
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(migration_count, 0);

    database.chain().set_migration_paused(true).await.unwrap();
    store
        .apply_member_migration(
            std::slice::from_ref(&new_peer),
            [2; 33],
            STORM_EYE_KIND,
            &[0x52],
            &[9; 32],
            ConfirmedVotingExecution {
                request_hash,
                txid: execution_txid,
                block_height: 43,
                block_hash: [16; 32],
            },
        )
        .await
        .unwrap();
    assert_eq!(store.load().await.unwrap(), vec![new_peer]);
    assert!(
        votes
            .get(request_hash)
            .await
            .unwrap()
            .unwrap()
            .execution_confirmed
    );
    assert!(votes.get(stale_request_hash).await.unwrap().is_none());
    assert_eq!(votes.approval_count(stale_request_hash).await.unwrap(), 0);
    let asset = database
        .network_assets()
        .get(STORM_EYE_KIND)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(asset.contract_script, vec![0x52]);
    assert_eq!(asset.contract_data, Some(vec![9; 32]));
    let migrations = database
        .chain()
        .finalized_member_migrations()
        .await
        .unwrap();
    assert_eq!(migrations.len(), 1);
    assert_eq!(migrations[0].request_hash, request_hash);
    assert_eq!(migrations[0].block_height, 43);
    assert_eq!(migrations[0].block_hash, [16; 32]);
    assert_eq!(migrations[0].previous_script, vec![0x51]);
    assert_eq!(migrations[0].next_script, vec![0x52]);
    assert_eq!(migrations[0].previous_members.len(), 1);
    assert_eq!(migrations[0].next_members.len(), 1);
    assert!(
        !database
            .chain()
            .recovery_state()
            .await
            .unwrap()
            .migration_paused
    );

    database.chain().reset_projections().await.unwrap();
    let restored_asset = database
        .network_assets()
        .get(STORM_EYE_KIND)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored_asset.contract_script, vec![0x51]);
    assert_eq!(
        database
            .chain()
            .finalized_member_migrations()
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn member_migration_rejects_duplicate_x_only_identities_before_persistence() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.network();
    let secp = Secp256k1::new();
    let old_public_key = SecretKey::from_slice(&[2; 32])
        .unwrap()
        .public_key(&secp)
        .serialize();
    let old_peer = Peer::new(old_public_key);
    store
        .save(std::slice::from_ref(&old_peer), old_public_key)
        .await
        .unwrap();

    let member_public_key = SecretKey::from_slice(&[3; 32])
        .unwrap()
        .public_key(&secp)
        .serialize();
    let mut opposite_parity = member_public_key;
    opposite_parity[0] = if opposite_parity[0] == 2 { 3 } else { 2 };
    let error = store
        .apply_member_migration(
            &[Peer::new(member_public_key), Peer::new(opposite_parity)],
            old_public_key,
            STORM_EYE_KIND,
            &[0x52],
            &[9; 32],
            ConfirmedVotingExecution {
                request_hash: [7; 32],
                txid: [11; 32],
                block_height: 43,
                block_hash: [16; 32],
            },
        )
        .await
        .unwrap_err();

    assert!(matches!(error, Error::DuplicateMemberIdentity(_)));
    assert_eq!(store.load().await.unwrap(), vec![old_peer]);
}
