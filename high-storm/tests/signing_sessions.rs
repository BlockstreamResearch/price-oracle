mod common;

use std::time::Duration;

use high_storm::{ExternalRequests, HighStorm};
use tokio::time::timeout;

struct TestNetwork {
    nodes: [HighStorm; 3],
}

impl TestNetwork {
    async fn start() -> Self {
        let (_, nodes) = common::start_network([11, 12, 13]).await;
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
            None,
            external_requests,
        ),
    )
    .await;

    assert!(
        !matches!(result, Ok(Ok(_))),
        "peers signed a malformed issuance transaction"
    );
    network.shutdown().await;
}
