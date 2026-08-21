mod common;

use std::time::Duration;

use secp256k1::{XOnlyPublicKey, schnorr};
use storm::PeerStatus;
use storm_tree::NodePublicKey;
use tokio::time::timeout;

use common::{TestNetwork, xonly_key};

#[tokio::test]
async fn signs_dummy_messages_with_all_three_nodes_online() {
    let mut network = TestNetwork::start(3).await;
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
    let mut network = TestNetwork::start(3).await;
    let offline_node = network.node_key(2);
    network.nodes[2].shutdown().await;
    network
        .wait_for_peer_status(0, offline_node, PeerStatus::Inactive)
        .await;
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
    let mut network = TestNetwork::start(3).await;
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

fn branch_nodes(network: &TestNetwork, branch: &[u8; 32]) -> Vec<NodePublicKey> {
    let tree = storm_tree::StormTree::new(network.node_keys()).unwrap();
    tree.nodes_for_branch(branch).unwrap().to_vec()
}

fn verify_signatures(branch: &[u8; 32], messages: &[[u8; 32]], signatures: &[[u8; 64]]) {
    let aggregate_key = XOnlyPublicKey::from_byte_array(*branch).unwrap();
    for (message, signature) in messages.iter().zip(signatures) {
        let signature = schnorr::Signature::from_byte_array(*signature);
        schnorr::verify(&signature, message, &aggregate_key).unwrap();
    }
}
