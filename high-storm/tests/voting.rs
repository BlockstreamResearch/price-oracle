mod common;

use std::time::Duration;

use high_storm::{
    ApproveVotingRequest, HighStorm, MergeStormEyes, NetworkVoteKind, NetworkVoteRequest,
    NodeMessage, NodeMessageKind, SplitStormEye, StormEyeUtxo, UpdateNetworkMembers,
    VOTING_TIMEOUT_BLOCKS, VotingError, VotingStatus, initialize_host, initialize_join,
    start_initialized,
};
use secp256k1::{Keypair, PublicKey, SecretKey, schnorr};
use secp256k1_zkp::PublicKey as TransportPublicKey;
use storm::PeerStatus;
use tokio::time::timeout;

use common::TestNode;

const START_HEIGHT: u64 = 50_000;

struct TestNetwork {
    definitions: [TestNode; 3],
    nodes: [HighStorm; 3],
}

impl TestNetwork {
    async fn start() -> Self {
        let first = TestNode::new(21).await;
        let second = TestNode::new(22).await;
        let third = TestNode::new(23).await;

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

        let nodes = [
            timeout(Duration::from_secs(5), host)
                .await
                .expect("host initialization timed out")
                .expect("host task failed")
                .expect("host initialization failed"),
            second_node.expect("second node initialization failed"),
            third_node.expect("third node initialization failed"),
        ];

        wait_for_all_connections(&nodes).await;

        for node in &nodes {
            node.set_block_height(START_HEIGHT);
        }

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
async fn creates_and_propagates_every_voting_request_kind() {
    let mut network = TestNetwork::start().await;
    let requests = [
        NetworkVoteRequest::new(
            NetworkVoteKind::UpdateNetworkMembers,
            &UpdateNetworkMembers {
                to_accept: vec![xonly_key(24)],
                to_remove: Vec::new(),
            },
        )
        .unwrap(),
        NetworkVoteRequest::new(
            NetworkVoteKind::MergeStormEyes,
            &MergeStormEyes {
                utxos_to_merge: vec![utxo(1, 0), utxo(2, 1)],
            },
        )
        .unwrap(),
        NetworkVoteRequest::new(
            NetworkVoteKind::SplitStormEye,
            &SplitStormEye {
                utxo_to_split: utxo(3, 2),
                number_of_splits: 3,
            },
        )
        .unwrap(),
    ];

    for request in requests {
        let hash = network.nodes[0]
            .create_voting_request(request.clone(), START_HEIGHT)
            .await
            .unwrap();
        wait_for_request_on_all(&network.nodes, hash).await;
        for node in &network.nodes {
            let stored = node.voting_request(hash).await.unwrap().unwrap();
            assert_eq!(stored.request, request);
            assert_eq!(stored.block_height, START_HEIGHT);
            assert_eq!(stored.status, VotingStatus::Pending);
            assert!(stored.approvals.is_empty());
        }
    }

    network.shutdown().await;
}

#[tokio::test]
async fn rejects_every_structurally_invalid_voting_request() {
    let mut network = TestNetwork::start().await;
    let member = xonly_key(21);
    let other_member = xonly_key(22);
    let outsider = xonly_key(24);
    let invalid_requests = vec![
        NetworkVoteRequest {
            kind: 99,
            payload: Vec::new(),
        },
        NetworkVoteRequest {
            kind: NetworkVoteKind::SplitStormEye as u16,
            payload: vec![0xff],
        },
        members_request(Vec::new(), Vec::new()),
        members_request(vec![outsider, outsider], Vec::new()),
        members_request(Vec::new(), vec![member, member]),
        members_request(vec![member], Vec::new()),
        members_request(Vec::new(), vec![outsider]),
        members_request(Vec::new(), vec![member, other_member]),
        members_request(vec![[0xff; 32]], Vec::new()),
        merge_request(Vec::new()),
        merge_request(vec![utxo(1, 0)]),
        merge_request(vec![utxo(1, 0), utxo(1, 0)]),
        split_request(0),
        split_request(1),
    ];

    for request in invalid_requests {
        assert!(
            network.nodes[0]
                .create_voting_request(request, START_HEIGHT)
                .await
                .is_err()
        );
    }
    assert!(network.nodes[0].voting_requests().await.unwrap().is_empty());

    let valid = split_request(2);
    let hash = network.nodes[0]
        .create_voting_request(valid.clone(), START_HEIGHT)
        .await
        .unwrap();
    wait_for_request_on_all(&network.nodes, hash).await;
    assert!(matches!(
        network.nodes[0]
            .create_voting_request(valid, START_HEIGHT + 1)
            .await,
        Err(VotingError::DuplicateRequest(_))
    ));

    network.shutdown().await;
}

#[tokio::test]
async fn accepts_member_votes_and_reaches_two_thirds_approval() {
    let mut network = TestNetwork::start().await;
    let hash = network.nodes[0]
        .create_voting_request(split_request(2), START_HEIGHT)
        .await
        .unwrap();
    wait_for_request_on_all(&network.nodes, hash).await;

    network.nodes[0]
        .approve_voting_request(hash, START_HEIGHT + 10)
        .await
        .unwrap();
    wait_for_approval_count_on_all(&network.nodes, hash, 1).await;
    for node in &network.nodes {
        assert_eq!(
            node.voting_request(hash).await.unwrap().unwrap().status,
            VotingStatus::Pending
        );
    }

    network.nodes[1]
        .approve_voting_request(hash, START_HEIGHT + 20)
        .await
        .unwrap();
    wait_for_approval_count_on_all(&network.nodes, hash, 2).await;
    for node in &network.nodes {
        assert_eq!(
            node.voting_request(hash).await.unwrap().unwrap().status,
            VotingStatus::Approved
        );
    }

    assert!(matches!(
        network.nodes[1]
            .approve_voting_request(hash, START_HEIGHT + 21)
            .await,
        Err(VotingError::DuplicateApproval(_))
    ));
    network.nodes[2]
        .approve_voting_request(hash, START_HEIGHT + 30)
        .await
        .unwrap();
    wait_for_approval_count_on_all(&network.nodes, hash, 3).await;
    assert!(matches!(
        network.nodes[0]
            .approve_voting_request([9; 32], START_HEIGHT + 40)
            .await,
        Err(VotingError::UnknownRequest(_))
    ));

    network.shutdown().await;
}

#[tokio::test]
async fn rejects_malformed_or_unauthorized_approval_messages() {
    let mut network = TestNetwork::start().await;
    let hash = network.nodes[0]
        .create_voting_request(split_request(2), START_HEIGHT)
        .await
        .unwrap();
    wait_for_request_on_all(&network.nodes, hash).await;
    let receiver_key = transport_key(&network.definitions[1].public_key);

    let malformed = [
        NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            None,
            &signed_approval(21, hash),
        )
        .unwrap(),
        NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            Some([8; 32]),
            &signed_approval(21, [8; 32]),
        )
        .unwrap(),
        NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            Some(hash),
            &ApproveVotingRequest {
                public_key: xonly_key(21),
                signature: vec![0; 63],
            },
        )
        .unwrap(),
        NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            Some(hash),
            &signed_approval(21, [7; 32]),
        )
        .unwrap(),
        NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            Some(hash),
            &signed_approval(24, hash),
        )
        .unwrap(),
        NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            Some(hash),
            &ApproveVotingRequest {
                public_key: [0xff; 32],
                signature: vec![0; 64],
            },
        )
        .unwrap(),
    ];
    for message in malformed {
        send_direct(&network.nodes[0], receiver_key, message).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        network.nodes[1]
            .voting_request(hash)
            .await
            .unwrap()
            .unwrap()
            .approvals
            .is_empty()
    );

    let relayed = NodeMessage::new(
        NodeMessageKind::ApproveVotingRequest,
        Some(hash),
        &signed_approval(23, hash),
    )
    .unwrap();
    send_direct(&network.nodes[0], receiver_key, relayed).await;
    wait_for_approval_count(&network.nodes[1], hash, 1).await;
    assert_eq!(
        network.nodes[1]
            .voting_request(hash)
            .await
            .unwrap()
            .unwrap()
            .approvals[0]
            .public_key,
        xonly_key(23)
    );

    network.shutdown().await;
}

#[tokio::test]
async fn expires_pending_and_approved_requests_at_their_exact_boundaries() {
    let mut network = TestNetwork::start().await;
    let pending_hash = network.nodes[0]
        .create_voting_request(split_request(2), START_HEIGHT)
        .await
        .unwrap();
    let approved_hash = network.nodes[0]
        .create_voting_request(split_request(3), START_HEIGHT)
        .await
        .unwrap();
    wait_for_request_on_all(&network.nodes, approved_hash).await;
    network.nodes[0]
        .approve_voting_request(approved_hash, START_HEIGHT + 10)
        .await
        .unwrap();
    for node in &network.nodes {
        node.set_block_height(START_HEIGHT + 20);
    }
    network.nodes[1]
        .approve_voting_request(approved_hash, START_HEIGHT + 20)
        .await
        .unwrap();
    wait_for_approval_count(&network.nodes[0], approved_hash, 2).await;

    assert_eq!(
        network.nodes[0]
            .remove_expired_voting_requests(START_HEIGHT + VOTING_TIMEOUT_BLOCKS - 1)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        network.nodes[0]
            .remove_expired_voting_requests(START_HEIGHT + VOTING_TIMEOUT_BLOCKS)
            .await
            .unwrap(),
        1
    );
    assert!(
        network.nodes[0]
            .voting_request(pending_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        network.nodes[0]
            .voting_request(approved_hash)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        network.nodes[0]
            .remove_expired_voting_requests(START_HEIGHT + 20 + VOTING_TIMEOUT_BLOCKS - 1,)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        network.nodes[0]
            .remove_expired_voting_requests(START_HEIGHT + 20 + VOTING_TIMEOUT_BLOCKS)
            .await
            .unwrap(),
        1
    );
    assert!(
        network.nodes[0]
            .voting_request(approved_hash)
            .await
            .unwrap()
            .is_none()
    );

    network.shutdown().await;
}

#[tokio::test]
async fn persists_votes_and_synchronizes_requests_missed_while_offline() {
    let mut network = TestNetwork::start().await;
    network.nodes[2].shutdown().await;
    wait_for_peer_status(&network.nodes[0], xonly_key(23), PeerStatus::Inactive).await;

    let hash = network.nodes[0]
        .create_voting_request(split_request(2), START_HEIGHT)
        .await
        .unwrap();
    network.nodes[0]
        .approve_voting_request(hash, START_HEIGHT + 1)
        .await
        .unwrap();
    network.nodes[1]
        .approve_voting_request(hash, START_HEIGHT + 2)
        .await
        .unwrap();
    wait_for_approval_count(&network.nodes[1], hash, 2).await;

    network.nodes[2] = start_initialized(
        &network.definitions[2].config,
        &network.definitions[2].store,
    )
    .await
    .unwrap();
    network.nodes[2].start(None).await.unwrap();
    wait_for_all_connections(&network.nodes).await;
    network.nodes[2].set_block_height(START_HEIGHT + 5);
    assert!(
        network.nodes[2]
            .voting_request(hash)
            .await
            .unwrap()
            .is_none()
    );
    network.nodes[2]
        .synchronize_voting_requests()
        .await
        .unwrap();
    wait_for_approval_count(&network.nodes[2], hash, 2).await;
    let synchronized = network.nodes[2]
        .voting_request(hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(synchronized.block_height, START_HEIGHT);
    assert_eq!(synchronized.status, VotingStatus::Approved);

    network.nodes[2].shutdown().await;
    network.nodes[2] = start_initialized(
        &network.definitions[2].config,
        &network.definitions[2].store,
    )
    .await
    .unwrap();
    let restored = network.nodes[2]
        .voting_request(hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(restored, synchronized);

    network.shutdown().await;
}

fn members_request(to_accept: Vec<[u8; 32]>, to_remove: Vec<[u8; 32]>) -> NetworkVoteRequest {
    NetworkVoteRequest::new(
        NetworkVoteKind::UpdateNetworkMembers,
        &UpdateNetworkMembers {
            to_accept,
            to_remove,
        },
    )
    .unwrap()
}

fn merge_request(utxos_to_merge: Vec<StormEyeUtxo>) -> NetworkVoteRequest {
    NetworkVoteRequest::new(
        NetworkVoteKind::MergeStormEyes,
        &MergeStormEyes { utxos_to_merge },
    )
    .unwrap()
}

fn split_request(number_of_splits: u64) -> NetworkVoteRequest {
    NetworkVoteRequest::new(
        NetworkVoteKind::SplitStormEye,
        &SplitStormEye {
            utxo_to_split: utxo(5, 0),
            number_of_splits,
        },
    )
    .unwrap()
}

fn utxo(txid_byte: u8, output_index: u32) -> StormEyeUtxo {
    StormEyeUtxo {
        txid: [txid_byte; 32],
        output_index,
    }
}

fn xonly_key(key_byte: u8) -> [u8; 32] {
    let secret = SecretKey::from_secret_bytes([key_byte; 32]).unwrap();
    PublicKey::from_secret_key(&secret)
        .x_only_public_key()
        .0
        .serialize()
}

fn signed_approval(key_byte: u8, hash: [u8; 32]) -> ApproveVotingRequest {
    let secret = SecretKey::from_secret_bytes([key_byte; 32]).unwrap();
    let keypair = Keypair::from_secret_key(&secret);
    ApproveVotingRequest {
        public_key: keypair.x_only_public_key().0.serialize(),
        signature: schnorr::sign(&hash, &keypair).to_byte_array().to_vec(),
    }
}

fn transport_key(encoded: &str) -> TransportPublicKey {
    TransportPublicKey::from_slice(&hex::decode(encoded).unwrap()).unwrap()
}

async fn send_direct(sender: &HighStorm, receiver: TransportPublicKey, message: NodeMessage) {
    sender
        .send_message(message.into_storm_message().unwrap(), &[receiver])
        .await
        .unwrap();
}

async fn wait_for_request_on_all(nodes: &[HighStorm; 3], hash: [u8; 32]) {
    timeout(Duration::from_secs(5), async {
        loop {
            let mut all_present = true;
            for node in nodes {
                all_present &= node.voting_request(hash).await.unwrap().is_some();
            }
            if all_present {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("voting request did not propagate");
}

async fn wait_for_approval_count_on_all(nodes: &[HighStorm; 3], hash: [u8; 32], count: usize) {
    timeout(Duration::from_secs(5), async {
        loop {
            let mut all_match = true;
            for node in nodes {
                all_match &= node
                    .voting_request(hash)
                    .await
                    .unwrap()
                    .is_some_and(|request| request.approvals.len() == count);
            }
            if all_match {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approval count did not propagate");
}

async fn wait_for_approval_count(node: &HighStorm, hash: [u8; 32], count: usize) {
    timeout(Duration::from_secs(5), async {
        loop {
            if node
                .voting_request(hash)
                .await
                .unwrap()
                .is_some_and(|request| request.approvals.len() == count)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approval count did not change");
}

async fn wait_for_all_connections(nodes: &[HighStorm; 3]) {
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
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("nodes did not establish all connections");
}

async fn wait_for_peer_status(node: &HighStorm, peer: [u8; 32], status: PeerStatus) {
    timeout(Duration::from_secs(5), async {
        loop {
            let matches = node.peers().await.iter().any(|candidate| {
                PublicKey::from_slice(&candidate.compressed_public_key)
                    .unwrap()
                    .x_only_public_key()
                    .0
                    .serialize()
                    == peer
                    && candidate.status == status
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
