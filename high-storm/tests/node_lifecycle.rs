mod common;

use std::time::Duration;

use high_storm::{
    NetworkAsset,
    db::network_asset::{PendingNetworkAsset, STORM_EYE_KIND},
    initialize_host, initialize_join, start_initialized,
};
use storm::{PeerStatus, Storm};
use tokio::time::timeout;

use common::TestNode;

async fn wait_until_connected(nodes: &[&Storm]) {
    timeout(Duration::from_secs(5), async {
        loop {
            let mut connected = true;
            for node in nodes {
                connected &= node
                    .peers()
                    .await
                    .iter()
                    .all(|peer| peer.status != PeerStatus::Inactive);
            }
            if connected {
                return;
            }
            for node in nodes {
                node.peers().await;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("restored nodes did not connect");
}

#[tokio::test]
async fn initializes_persists_and_restores_a_network() {
    let host_node = TestNode::new(1).await;
    let join_node = TestNode::new(2).await;

    println!(
        "host node: {} ({})",
        host_node.public_key,
        host_node.address()
    );

    let host_config = host_node.config.clone();
    let host_store = host_node.store.clone();
    let members = vec![join_node.public_key.clone()];
    let host_task =
        tokio::spawn(async move { initialize_host(&host_config, &host_store, &members).await });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut join = timeout(
        Duration::from_secs(5),
        initialize_join(
            &join_node.config,
            &join_node.store,
            &host_node.public_key,
            &host_node.address(),
        ),
    )
    .await
    .expect("join initialization timed out")
    .unwrap();

    let mut host = timeout(Duration::from_secs(5), host_task)
        .await
        .expect("host initialization timed out")
        .unwrap()
        .unwrap();

    assert!(host.is_coordinator().await);
    assert!(!join.is_coordinator().await);
    assert_eq!(
        hex::encode(host.coordinator_public_key()),
        host_node.public_key
    );
    assert_eq!(host.coordinator_public_key(), join.coordinator_public_key());

    let pending_asset = PendingNetworkAsset {
        asset: NetworkAsset {
            kind: STORM_EYE_KIND.to_string(),
            name: "Storm Eye".to_string(),
            asset_id: [3; 32],
            reissuance_token_id: None,
            entropy: None,
            issuance_txid: [4; 32],
            contract_script: vec![0x51],
            contract_data: None,
            supply: 10_000,
            created_at_block: 1,
        },
        issuance_tx: vec![5; 64],
    };
    host_node
        .assets
        .insert_pending(&pending_asset)
        .await
        .unwrap();
    host_node.assets.activate(STORM_EYE_KIND).await.unwrap();
    host.announce_network_assets().await.unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            if join_node
                .assets
                .get(STORM_EYE_KIND)
                .await
                .unwrap()
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("joiner did not persist announced network assets");
    assert_eq!(
        join_node.assets.get(STORM_EYE_KIND).await.unwrap(),
        Some(pending_asset.asset)
    );
    let join_public_key = hex::decode(&join_node.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        host_node
            .assets
            .pending_for_peer(&join_public_key)
            .await
            .unwrap()
            .is_empty()
    );
    host.announce_network_assets().await.unwrap();

    for store in [&host_node.store, &join_node.store] {
        let peers = store.load().await.unwrap();
        assert_eq!(peers.len(), 2);
        assert!(
            peers
                .iter()
                .any(|peer| { hex::encode(peer.compressed_public_key) == host_node.public_key })
        );
        assert!(peers.iter().all(|peer| !peer.discovery));
        assert!(peers.iter().all(|peer| peer.socket_address.is_some()));
    }

    host.shutdown().await;
    join.shutdown().await;

    let mut restored_host = start_initialized(&host_node.config, &host_node.store)
        .await
        .unwrap();
    let mut restored_join = start_initialized(&join_node.config, &join_node.store)
        .await
        .unwrap();

    restored_host.start(None).await.unwrap();
    restored_join.start(None).await.unwrap();
    wait_until_connected(&[&restored_host, &restored_join]).await;

    assert!(restored_host.is_coordinator().await);
    assert!(!restored_join.is_coordinator().await);
    assert_eq!(
        restored_host.coordinator_public_key(),
        restored_join.coordinator_public_key()
    );

    restored_host.shutdown().await;
    restored_join.shutdown().await;
}
