use super::*;
use crate::StormEyeUtxo;
use crate::db::Database;
use secp256k1_zkp::{Secp256k1, SecretKey};
use storm::{MessageContext, Storm};

async fn voting_node() -> (Voting, Storm) {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let secret = SecretKey::from_slice(&[21; 32]).unwrap();
    let public = secret.public_key(&Secp256k1::new()).serialize();
    let storm = Storm::from_peers(secret, vec![Peer::new(public)]);
    let voting = Voting::new(secret.secret_bytes(), public, database.voting());
    (voting, storm)
}

fn distinct_request(index: u8) -> NetworkVoteRequest {
    NetworkVoteRequest::new(
        NetworkVoteKind::SplitStormEye,
        &SplitStormEye {
            utxo_to_split: storm_eye(index),
            number_of_splits: 2,
        },
    )
    .unwrap()
}

fn signed_request(index: u8, height: u64, signer: u8) -> NodeMessage {
    let request = distinct_request(index);
    let unsigned = NodeMessage::new_voting_request(request.clone(), height).unwrap();
    let keypair =
        Keypair::from_secret_key(&secp256k1::SecretKey::from_secret_bytes([signer; 32]).unwrap());
    NodeMessage::new(
        NodeMessageKind::NetworkVoteRequest,
        None,
        &super::super::message::SignedVotingProposal {
            request,
            created_at_block_height: height,
            proposer_public_key: keypair.x_only_public_key().0.serialize(),
            signature: schnorr::sign(&unsigned.hash().unwrap(), &keypair)
                .to_byte_array()
                .to_vec(),
        },
    )
    .unwrap()
}

#[tokio::test]
async fn isolates_requester_limits_for_direct_and_relayed_votes() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let secret = SecretKey::from_slice(&[21; 32]).unwrap();
    let public_keys: Vec<_> = (21..=23)
        .map(|signer| {
            SecretKey::from_slice(&[signer; 32])
                .unwrap()
                .public_key(&Secp256k1::new())
                .serialize()
        })
        .collect();
    let storm = Storm::from_peers(secret, public_keys.iter().copied().map(Peer::new).collect());
    let handle = storm.handle();
    let voting = Voting::new(secret.secret_bytes(), public_keys[0], database.voting());
    let height = 100;

    for index in 0..50 {
        voting
            .create(&handle, distinct_request(index), height)
            .await
            .unwrap();
    }
    let first = node_key(public_keys[0]).unwrap();
    let second = node_key(public_keys[1]).unwrap();
    let third = node_key(public_keys[2]).unwrap();
    for index in 50..100 {
        let message = signed_request(index, height + 1, 22);
        let context = StormContext {
            storm_handle: handle.clone(),
            storm_message: message.clone().into_storm_message().unwrap(),
            message_context: MessageContext {
                peer_public_key: public_keys[1],
            },
        };
        voting
            .handle_request(message, &context, height + 1)
            .await
            .unwrap();
    }
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(Some(first))
            .await
            .unwrap(),
        50
    );
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(Some(second))
            .await
            .unwrap(),
        50
    );

    let overflow = signed_request(100, height + 1, 22);
    let context = StormContext {
        storm_handle: handle.clone(),
        storm_message: overflow.clone().into_storm_message().unwrap(),
        message_context: MessageContext {
            peer_public_key: public_keys[1],
        },
    };
    assert!(
        matches!(voting.handle_request(overflow, &context, height + 1).await,
        Err(VotingError::InvalidRequest(reason)) if reason.contains("50 active"))
    );

    let overflowing = signed_request(101, height + 1, 21);
    let fresh = signed_request(102, height + 1, 23);
    let overflow_hash = overflowing.hash().unwrap();
    let fresh_hash = fresh.hash().unwrap();
    let records = [overflowing, fresh]
        .into_iter()
        .map(|message| VotingSyncRequest {
            message_hash: message.hash().unwrap(),
            message: postcard::to_stdvec(&message).unwrap(),
            approvals: Vec::new(),
        })
        .collect();
    voting
        .accept_synchronized(records, &handle, public_keys[0], height + 1)
        .await
        .unwrap();
    assert!(voting.get(overflow_hash).await.unwrap().is_none());
    assert_eq!(
        voting
            .get(fresh_hash)
            .await
            .unwrap()
            .unwrap()
            .proposer_public_key,
        Some(third)
    );
    assert_eq!(voting.store.active_request_count().await.unwrap(), 101);

    assert_eq!(
        voting
            .remove_expired(height + VOTING_TIMEOUT_BLOCKS)
            .await
            .unwrap(),
        50
    );
    voting
        .create(
            &handle,
            distinct_request(103),
            height + VOTING_TIMEOUT_BLOCKS,
        )
        .await
        .unwrap();
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(Some(first))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(Some(second))
            .await
            .unwrap(),
        50
    );
}

#[tokio::test]
async fn counts_each_vote_once_however_it_arrives() {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let secret = SecretKey::from_slice(&[21; 32]).unwrap();
    let public_keys: Vec<_> = (21..=23)
        .map(|signer| {
            SecretKey::from_slice(&[signer; 32])
                .unwrap()
                .public_key(&Secp256k1::new())
                .serialize()
        })
        .collect();
    let storm = Storm::from_peers(secret, public_keys.iter().copied().map(Peer::new).collect());
    let handle = storm.handle();
    let voting = Voting::new(secret.secret_bytes(), public_keys[0], database.voting());
    let height = 100;
    let direct = signed_request(1, height, 22);
    let relayed = signed_request(2, height, 23);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();

    {
        let _local = metrics::set_default_local_recorder(&recorder);
        let context = StormContext {
            storm_handle: handle.clone(),
            storm_message: direct.clone().into_storm_message().unwrap(),
            message_context: MessageContext {
                peer_public_key: public_keys[1],
            },
        };
        voting
            .handle_request(direct.clone(), &context, height)
            .await
            .unwrap();
        let records = [direct.clone(), relayed]
            .into_iter()
            .map(|message| VotingSyncRequest {
                message_hash: message.hash().unwrap(),
                message: postcard::to_stdvec(&message).unwrap(),
                approvals: Vec::new(),
            })
            .collect();
        voting
            .accept_synchronized(records, &handle, public_keys[1], height)
            .await
            .unwrap();
        let hash = direct.hash().unwrap();
        voting.approve(&handle, hash, height).await.unwrap();
        assert!(matches!(
            voting.approve(&handle, hash, height).await,
            Err(VotingError::DuplicateApproval(_))
        ));
    }

    let rendered = recorder.handle().render();
    for (proposer, count) in [(public_keys[1], 1), (public_keys[2], 1)] {
        let line = format!(
            "high_storm_voting_requests_created_total{{kind=\"split_storm_eye\",proposer=\"{}\"}} {count}",
            hex::encode(proposer)
        );
        assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
    }
    assert!(rendered.contains(r#"high_storm_voting_approvals_total{kind="split_storm_eye"} 1"#));
    assert_eq!(
        voting.unconfirmed_kinds().await.unwrap(),
        ["split_storm_eye", "split_storm_eye"]
    );
}

#[tokio::test]
async fn rejects_forged_proposer_attribution() {
    let (voting, storm) = voting_node().await;
    let handle = storm.handle();
    let public = handle.peers().await[0].compressed_public_key;
    let other = signed_request(1, 100, 22);
    let context = StormContext {
        storm_handle: handle.clone(),
        storm_message: other.clone().into_storm_message().unwrap(),
        message_context: MessageContext {
            peer_public_key: public,
        },
    };
    assert!(matches!(voting.handle_request(other, &context, 100).await,
        Err(VotingError::InvalidRequest(reason)) if reason.contains("does not match its sender")));

    let mut proposal: super::super::message::SignedVotingProposal =
        signed_request(2, 100, 22).decode_payload().unwrap();
    proposal.proposer_public_key = node_key(public).unwrap();
    let forged = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &proposal).unwrap();
    assert!(verified_proposer(&forged).is_err());
    assert!(
        voting
            .accept_synchronized(
                vec![VotingSyncRequest {
                    message_hash: forged.hash().unwrap(),
                    message: postcard::to_stdvec(&forged).unwrap(),
                    approvals: Vec::new(),
                }],
                &handle,
                public,
                100
            )
            .await
            .is_err()
    );

    let mut tampered: super::super::message::SignedVotingProposal =
        signed_request(3, 100, 21).decode_payload().unwrap();
    tampered.created_at_block_height += 1;
    let tampered = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &tampered).unwrap();
    assert!(verified_proposer(&tampered).is_err());
    assert!(voting.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn bounds_legacy_sync_without_consuming_member_quota() {
    let (voting, storm) = voting_node().await;
    let handle = storm.handle();
    let public = handle.peers().await[0].compressed_public_key;
    let mut messages: Vec<_> = (0..51)
        .map(|index| NodeMessage::new_voting_request(distinct_request(index), 100).unwrap())
        .collect();
    messages[0] = NodeMessage::new(
        NodeMessageKind::NetworkVoteRequest,
        None,
        &distinct_request(0),
    )
    .unwrap();
    messages.push(signed_request(51, 100, 21));
    let records = messages
        .into_iter()
        .map(|message| VotingSyncRequest {
            message_hash: message.hash().unwrap(),
            message: postcard::to_stdvec(&message).unwrap(),
            approvals: Vec::new(),
        })
        .collect();

    voting
        .accept_synchronized(records, &handle, public, 100)
        .await
        .unwrap();
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(None)
            .await
            .unwrap(),
        50
    );
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(Some(node_key(public).unwrap()))
            .await
            .unwrap(),
        1
    );
    assert_eq!(voting.store.active_request_count().await.unwrap(), 51);
}

#[tokio::test]
async fn limits_active_votings_across_creation_peers_and_synchronization() {
    let (voting, storm) = voting_node().await;
    let handle = storm.handle();
    let block_height = 100;
    let mut first_hash = None;
    for index in 0..49 {
        let hash = voting
            .create(&handle, distinct_request(index), block_height)
            .await
            .unwrap();
        first_hash.get_or_insert(hash);
    }

    let (last_slot, overflow) = tokio::join!(
        voting.create(&handle, distinct_request(49), block_height),
        voting.create(&handle, distinct_request(50), block_height),
    );
    assert_eq!(
        usize::from(last_slot.is_ok()) + usize::from(overflow.is_ok()),
        1
    );
    assert!(matches!(
        last_slot.err().or_else(|| overflow.err()),
        Some(VotingError::InvalidRequest(reason)) if reason.contains("50 active")
    ));
    assert_eq!(voting.store.active_request_count().await.unwrap(), 50);

    let message = NodeMessage::new_voting_request(distinct_request(51), block_height).unwrap();
    let public = handle.peers().await[0].compressed_public_key;
    let context = StormContext {
        storm_handle: handle.clone(),
        storm_message: message.clone().into_storm_message().unwrap(),
        message_context: MessageContext {
            peer_public_key: public,
        },
    };
    assert!(matches!(
        voting.handle_request(message.clone(), &context, block_height).await,
        Err(VotingError::InvalidRequest(reason)) if reason.contains("50 active")
    ));
    let legacy_hash = message.hash().unwrap();
    voting
        .accept_synchronized(
            vec![VotingSyncRequest {
                message_hash: legacy_hash,
                message: postcard::to_stdvec(&message).unwrap(),
                approvals: Vec::new(),
            }],
            &handle,
            public,
            block_height,
        )
        .await
        .unwrap();
    assert_eq!(
        voting
            .store
            .active_request_count_for_proposer(None)
            .await
            .unwrap(),
        1
    );

    let first_hash = first_hash.unwrap();
    voting
        .approve(&handle, first_hash, block_height + 1)
        .await
        .unwrap();
    let known = voting.store.get(first_hash).await.unwrap().unwrap();
    voting
        .accept_synchronized(
            vec![VotingSyncRequest {
                message_hash: first_hash,
                message: known.message,
                approvals: known
                    .approvals
                    .into_iter()
                    .map(|approval| VotingSyncApproval {
                        message: approval.message,
                    })
                    .collect(),
            }],
            &handle,
            public,
            block_height + 1,
        )
        .await
        .unwrap();
    assert_eq!(voting.store.active_request_count().await.unwrap(), 51);

    let new_hash = voting
        .create(
            &handle,
            distinct_request(52),
            block_height + VOTING_TIMEOUT_BLOCKS,
        )
        .await
        .unwrap();
    assert_eq!(voting.store.active_request_count().await.unwrap(), 2);
    assert!(voting.get(first_hash).await.unwrap().is_some());
    assert!(voting.get(new_hash).await.unwrap().is_some());
}

#[tokio::test]
async fn a_bad_synchronized_record_does_not_block_later_records() {
    let (voting, storm) = voting_node().await;
    let handle = storm.handle();
    let height = 100;
    let fresh = NodeMessage::new_voting_request(distinct_request(2), height).unwrap();
    let fresh_hash = fresh.hash().unwrap();
    let records = vec![
        VotingSyncRequest {
            message_hash: [9; 32],
            message: postcard::to_stdvec(&signed_request(1, height, 21)).unwrap(),
            approvals: Vec::new(),
        },
        VotingSyncRequest {
            message_hash: fresh_hash,
            message: postcard::to_stdvec(&fresh).unwrap(),
            approvals: Vec::new(),
        },
    ];

    let result = voting
        .accept_synchronized(
            records,
            &handle,
            handle.peers().await[0].compressed_public_key,
            height,
        )
        .await;

    assert!(matches!(result, Err(VotingError::InvalidRequest(_))));
    assert!(voting.get(fresh_hash).await.unwrap().is_some());
}

#[tokio::test]
async fn skips_expired_synchronized_votes_without_blocking_fresh_ones() {
    let (voting, storm) = voting_node().await;
    let handle = storm.handle();
    let expired = NodeMessage::new_voting_request(distinct_request(1), 100).unwrap();
    let height = 100 + VOTING_TIMEOUT_BLOCKS;
    let fresh = NodeMessage::new_voting_request(distinct_request(2), height).unwrap();
    let expired_hash = expired.hash().unwrap();
    let fresh_hash = fresh.hash().unwrap();
    let requests = [expired, fresh]
        .into_iter()
        .map(|message| VotingSyncRequest {
            message_hash: message.hash().unwrap(),
            message: postcard::to_stdvec(&message).unwrap(),
            approvals: Vec::new(),
        })
        .collect();

    voting
        .accept_synchronized(
            requests,
            &handle,
            handle.peers().await[0].compressed_public_key,
            height,
        )
        .await
        .unwrap();

    assert!(voting.get(expired_hash).await.unwrap().is_none());
    assert!(voting.get(fresh_hash).await.unwrap().is_some());
    assert_eq!(voting.store.active_request_count().await.unwrap(), 1);
    assert_eq!(
        voting
            .remove_expired(height + VOTING_TIMEOUT_BLOCKS)
            .await
            .unwrap(),
        1
    );
    assert!(voting.list().await.unwrap().is_empty());
}

#[test]
fn proposal_heights_are_bounded_by_the_voting_window() {
    assert!(validate_proposal_height(Some(100), 100).is_ok());
    assert!(validate_proposal_height(Some(101), 100).is_ok());
    assert!(validate_proposal_height(Some(102), 100).is_err());
    assert!(validate_proposal_height(Some(100), 100 + VOTING_TIMEOUT_BLOCKS - 1).is_ok());
    assert!(validate_proposal_height(Some(100), 100 + VOTING_TIMEOUT_BLOCKS).is_err());
}

#[test]
fn replays_only_requested_finalized_execution_notices() {
    let message = NodeMessage::new(
        NodeMessageKind::NetworkVoteRequest,
        None,
        &distinct_request(1),
    )
    .unwrap();
    let notice = ExecuteVotingRequest {
        tx: vec![1],
        final_tx: Some(vec![2]),
        signing_hashes: vec![[3; 32]],
        signing_storm_tree_branch: [4; 32],
        proposer_public_key: [5; 32],
        chain_tip: Some(super::super::message::ChainTip {
            height: 6,
            hash: [7; 32],
        }),
    };
    let executed = StoredVotingRequest {
        message_hash: [1; 32],
        message: postcard::to_allocvec(&message).unwrap(),
        proposer_public_key: Some([5; 32]),
        block_height: 3,
        approved_at_block_height: Some(4),
        execution_started: false,
        execution_transaction: Some(vec![1]),
        execution_request: Some(postcard::to_allocvec(&notice).unwrap()),
        execution_txid: Some([8; 32]),
        execution_confirmed: true,
        approvals: Vec::new(),
    };
    let pending = StoredVotingRequest {
        message_hash: [2; 32],
        execution_request: None,
        execution_txid: None,
        execution_confirmed: false,
        ..executed.clone()
    };

    let notices =
        execution_notices(&[executed.clone(), pending.clone()], &[[1; 32], [2; 32]]).unwrap();
    assert!(
        execution_notices(&[executed, pending], &[[2; 32]])
            .unwrap()
            .is_empty()
    );

    assert_eq!(notices.len(), 1);
    assert_eq!(
        notices[0].decoded_kind(),
        Some(NodeMessageKind::ExecuteVotingRequest)
    );
    assert_eq!(notices[0].linked_to, Some([1; 32]));
    assert_eq!(
        notices[0].decode_payload::<ExecuteVotingRequest>().unwrap(),
        notice
    );
}

#[test]
fn broadcast_vote_remains_executing_until_confirmed() {
    let request = NetworkVoteRequest::new(
        NetworkVoteKind::SplitStormEye,
        &SplitStormEye {
            utxo_to_split: StormEyeUtxo {
                txid: [9; 32],
                output_index: 0,
            },
            number_of_splits: 2,
        },
    )
    .unwrap();
    let message = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request).unwrap();
    let mut stored = StoredVotingRequest {
        message_hash: [1; 32],
        message: postcard::to_allocvec(&message).unwrap(),
        proposer_public_key: Some([2; 32]),
        block_height: 3,
        approved_at_block_height: Some(4),
        execution_started: true,
        execution_transaction: Some(vec![5]),
        execution_request: Some(vec![6]),
        execution_txid: Some([7; 32]),
        execution_confirmed: false,
        approvals: Vec::new(),
    };

    assert_eq!(
        decode_stored(stored.clone()).unwrap().status,
        VotingStatus::Executing
    );

    stored.execution_confirmed = true;
    assert_eq!(
        decode_stored(stored).unwrap().status,
        VotingStatus::Executed
    );
}

#[test]
fn accepts_two_or_three_reshape_outputs_only() {
    for count in 2..=3 {
        let merge = NetworkVoteRequest::new(
            NetworkVoteKind::MergeStormEyes,
            &MergeStormEyes {
                utxos_to_merge: (0..count).map(storm_eye).collect(),
            },
        )
        .unwrap();
        assert!(validate_request(&merge, &[], [0; 32]).is_ok());

        let split = NetworkVoteRequest::new(
            NetworkVoteKind::SplitStormEye,
            &SplitStormEye {
                utxo_to_split: storm_eye(0),
                number_of_splits: count.into(),
            },
        )
        .unwrap();
        assert!(validate_request(&split, &[], [0; 32]).is_ok());
    }

    let merge = NetworkVoteRequest::new(
        NetworkVoteKind::MergeStormEyes,
        &MergeStormEyes {
            utxos_to_merge: (0..4).map(storm_eye).collect(),
        },
    )
    .unwrap();
    assert!(matches!(
        validate_request(&merge, &[], [0; 32]),
        Err(VotingError::InvalidRequest(_))
    ));

    let split = NetworkVoteRequest::new(
        NetworkVoteKind::SplitStormEye,
        &SplitStormEye {
            utxo_to_split: storm_eye(0),
            number_of_splits: 4,
        },
    )
    .unwrap();
    assert!(matches!(
        validate_request(&split, &[], [0; 32]),
        Err(VotingError::InvalidRequest(_))
    ));
}

#[test]
fn member_update_cannot_remove_the_fixed_coordinator() {
    let secp = Secp256k1::new();
    let peers = (1..=3)
        .map(|byte| {
            Peer::new(
                SecretKey::from_slice(&[byte; 32])
                    .unwrap()
                    .public_key(&secp)
                    .serialize(),
            )
        })
        .collect::<Vec<_>>();
    let coordinator = member_keys(&peers).unwrap().into_iter().next().unwrap();
    let accepted = SecretKey::from_slice(&[4; 32])
        .unwrap()
        .public_key(&secp)
        .x_only_public_key()
        .0
        .serialize();
    let update = NetworkVoteRequest::new(
        NetworkVoteKind::UpdateNetworkMembers,
        &UpdateNetworkMembers {
            to_accept: vec![accepted],
            to_remove: vec![coordinator],
        },
    )
    .unwrap();

    assert!(matches!(
        validate_request(&update, &peers, coordinator),
        Err(VotingError::InvalidRequest(message))
            if message.contains("cannot remove the coordinator")
    ));
}

#[test]
fn historical_member_updates_synchronize_after_membership_changes() {
    let secp = Secp256k1::new();
    let peers = (1..=4)
        .map(|byte| {
            Peer::new(
                SecretKey::from_slice(&[byte; 32])
                    .unwrap()
                    .public_key(&secp)
                    .serialize(),
            )
        })
        .collect::<Vec<_>>();
    let changed_member = PublicKey::from_slice(&peers[3].compressed_public_key)
        .unwrap()
        .x_only_public_key()
        .0
        .serialize();
    let update = NetworkVoteRequest::new(
        NetworkVoteKind::UpdateNetworkMembers,
        &UpdateNetworkMembers {
            to_accept: vec![changed_member],
            to_remove: Vec::new(),
        },
    )
    .unwrap();

    assert!(validate_synchronized_request(&update, &peers, [0; 32]).is_ok());
    assert!(matches!(
        validate_request(&update, &peers, [0; 32]),
        Err(VotingError::InvalidRequest(message)) if message.contains("already a member")
    ));

    let remaining_peers = peers[..3].to_vec();
    let update = NetworkVoteRequest::new(
        NetworkVoteKind::UpdateNetworkMembers,
        &UpdateNetworkMembers {
            to_accept: Vec::new(),
            to_remove: vec![changed_member],
        },
    )
    .unwrap();

    assert!(validate_synchronized_request(&update, &remaining_peers, [0; 32]).is_ok());
    assert!(matches!(
        validate_request(&update, &remaining_peers, [0; 32]),
        Err(VotingError::InvalidRequest(message)) if message.contains("is not a member")
    ));
}

fn storm_eye(byte: u8) -> StormEyeUtxo {
    StormEyeUtxo {
        txid: [byte; 32],
        output_index: byte.into(),
    }
}
