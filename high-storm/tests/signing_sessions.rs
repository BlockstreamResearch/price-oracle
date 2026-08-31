mod common;

use std::time::Duration;

use high_storm::{HighStorm, initialize_host, initialize_join};
use secp256k1::{PublicKey, XOnlyPublicKey, schnorr};
use storm::PeerStatus;
use storm_tree::NodePublicKey;
use tokio::time::timeout;

use common::TestNode;

struct TestNetwork {
    definitions: [TestNode; 3],
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

        Self {
            definitions: [first, second, third],
            nodes,
        }
    }

    async fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown().await;
        }
    }
}

#[tokio::test]
async fn signs_dummy_messages_with_all_three_nodes_online() {
    let mut network = TestNetwork::start().await;
    let message_hashes = vec![[21; 32], [22; 32]];

    let result = timeout(
        Duration::from_secs(5),
        network.nodes[0].sign_test(message_hashes.clone()),
    )
    .await
    .expect("signing timed out")
    .expect("signing failed");

    assert_eq!(result.signatures.len(), message_hashes.len());
    verify_signatures(
        &result.signing_storm_tree_branch,
        &message_hashes,
        &result.signatures,
    );
    network.shutdown().await;
}

#[tokio::test]
async fn signs_with_only_two_of_three_nodes_online() {
    let mut network = TestNetwork::start().await;
    let offline_node = xonly_key(&network.definitions[2].public_key);
    network.nodes[2].shutdown().await;
    wait_for_peer_status(&network.nodes[0], offline_node, PeerStatus::Inactive).await;
    let message_hashes = vec![[31; 32]];

    let result = timeout(
        Duration::from_secs(5),
        network.nodes[0].sign_test(message_hashes.clone()),
    )
    .await
    .expect("signing timed out")
    .expect("signing failed");

    let selected = branch_nodes(&network, &result.signing_storm_tree_branch);
    assert!(!selected.contains(&offline_node));
    verify_signatures(
        &result.signing_storm_tree_branch,
        &message_hashes,
        &result.signatures,
    );
    network.shutdown().await;
}

#[tokio::test]
async fn retries_with_another_branch_when_a_chosen_signer_disconnects() {
    let mut network = TestNetwork::start().await;
    let selected = network.nodes[0]
        .selected_signers()
        .await
        .expect("a branch should be available");
    let requestor = xonly_key(&network.definitions[0].public_key);
    let delayed_signer = selected
        .into_iter()
        .find(|signer| *signer != requestor)
        .expect("the selected branch should include a remote signer");
    let delayed_index = network
        .definitions
        .iter()
        .position(|node| xonly_key(&node.public_key) == delayed_signer)
        .expect("selected signer should be in the test network");
    let message_hashes = vec![[41; 32]];

    let result = {
        let (requestor_node, other_nodes) = network.nodes.split_first_mut().unwrap();
        let delayed_node = &mut other_nodes[delayed_index - 1];
        let signing = requestor_node.sign_test_with_delay(
            message_hashes.clone(),
            Duration::from_millis(250),
            delayed_signer,
            Duration::from_secs(2),
        );
        let disconnect = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            delayed_node.shutdown().await;
        };
        let (result, ()) = tokio::join!(signing, disconnect);
        result
    };
    let result = result.expect("signing should retry with another branch");

    let retry_signers = branch_nodes(&network, &result.signing_storm_tree_branch);
    assert!(!retry_signers.contains(&delayed_signer));
    verify_signatures(
        &result.signing_storm_tree_branch,
        &message_hashes,
        &result.signatures,
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

async fn wait_for_peer_status(node: &HighStorm, peer: NodePublicKey, status: PeerStatus) {
    timeout(Duration::from_secs(5), async {
        loop {
            let matches = node.peers().await.iter().any(|candidate| {
                xonly_bytes(candidate.compressed_public_key) == peer && candidate.status == status
            });
            if matches {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer status did not change");
}

fn branch_nodes(network: &TestNetwork, branch: &[u8; 32]) -> Vec<NodePublicKey> {
    let tree = storm_tree::StormTree::new(
        network
            .definitions
            .iter()
            .map(|node| xonly_key(&node.public_key))
            .collect(),
    )
    .unwrap();
    tree.nodes_for_branch(branch).unwrap().to_vec()
}

fn verify_signatures(branch: &[u8; 32], messages: &[[u8; 32]], signatures: &[[u8; 64]]) {
    let aggregate_key = XOnlyPublicKey::from_byte_array(*branch).unwrap();
    for (message, signature) in messages.iter().zip(signatures) {
        let signature = schnorr::Signature::from_byte_array(*signature);
        schnorr::verify(&signature, message, &aggregate_key).unwrap();
    }
}

fn xonly_key(encoded: &str) -> NodePublicKey {
    let bytes = hex::decode(encoded).unwrap();
    xonly_bytes(bytes.try_into().unwrap())
}

fn xonly_bytes(compressed: [u8; 33]) -> NodePublicKey {
    PublicKey::from_slice(&compressed)
        .unwrap()
        .x_only_public_key()
        .0
        .serialize()
}
