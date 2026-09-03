mod common;

use std::time::Duration;

use high_storm::{ExternalRequests, HighStorm, initialize_host, initialize_join};
use storm::PeerStatus;
use tokio::time::timeout;

use common::TestNode;

struct TestNetwork {
    nodes: [HighStorm; 3],
}

impl TestNetwork {
    async fn start() -> Self {
        let first = TestNode::new(11).await;
        let second = TestNode::new(12).await;
        let third = TestNode::new(13).await;

        let host_config = first.config.clone();
        let host_store = first.store.clone();
        let members = vec![second.public_key.clone(), third.public_key.clone()];
        let host =
            tokio::spawn(async move { initialize_host(&host_config, &host_store, &members).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let host_address = first.address();
        let (second_node, third_node) = tokio::join!(
            initialize_join(
                &second.config,
                &second.store,
                &first.public_key,
                &host_address,
            ),
            initialize_join(
                &third.config,
                &third.store,
                &first.public_key,
                &host_address,
            ),
        );

        let first_node = timeout(Duration::from_secs(5), host)
            .await
            .expect("host initialization timed out")
            .expect("host task failed")
            .expect("host initialization failed");
        let nodes = [
            first_node,
            second_node.expect("second node initialization failed"),
            third_node.expect("third node initialization failed"),
        ];

        wait_for_all_connections(&nodes).await;

        Self { nodes }
    }

    async fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown().await;
        }
    }
}

#[tokio::test]
async fn rejects_malformed_execute_user_requests_transaction() {
    let mut network = TestNetwork::start().await;
    let signing_hash = [24; 32];
    let external_requests = vec![ExternalRequests {
        request_hash: [25; 32],
        network_user_requests: b"signed user request".to_vec(),
        additional_payload: None,
    }];

    let result = timeout(
        Duration::from_millis(500),
        network.nodes[0].sign_execute_user_requests(
            b"unsigned issuance transaction".to_vec(),
            signing_hash,
            external_requests,
        ),
    )
    .await;

    assert!(
        result.is_err(),
        "peers signed a malformed issuance transaction"
    );
    network.shutdown().await;
}

async fn wait_for_all_connections(nodes: &[HighStorm; 3]) {
    timeout(Duration::from_secs(5), async {
        loop {
            if futures_connected(nodes).await {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("nodes did not establish all connections");
}

async fn futures_connected(nodes: &[HighStorm; 3]) -> bool {
    for node in nodes {
        if node
            .peers()
            .await
            .iter()
            .any(|peer| peer.status == PeerStatus::Inactive)
        {
            return false;
        }
    }
    true
}
