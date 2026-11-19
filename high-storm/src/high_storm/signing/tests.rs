use super::*;

#[tokio::test]
async fn leader_requests_start_a_session_over_their_own_hashes() {
    let secrets = [[11; 32], [12; 32], [13; 32]];
    let keys = secrets.map(|secret| {
        TransportPublicKey::from_secret_key(
            &secp256k1_zkp::Secp256k1::new(),
            &secp256k1_zkp::SecretKey::from_slice(&secret).unwrap(),
        )
        .serialize()
    });
    let peers = keys
        .iter()
        .map(|key| {
            let mut peer = Peer::new(*key);
            peer.status = PeerStatus::Active;
            peer
        })
        .collect::<Vec<_>>();
    let storm = Storm::from_peers(
        secp256k1_zkp::SecretKey::from_slice(&secrets[0]).unwrap(),
        peers,
    );
    let signing = Signing::new(&storm, secrets[0], keys[0]).await;
    let branch = signing
        .state
        .lock()
        .await
        .tree
        .as_ref()
        .unwrap()
        .branches()
        .next()
        .unwrap();
    let leader = keys[1];
    let messages = [
        NodeMessage::new(
            NodeMessageKind::BurnExpiredUtxos,
            None,
            &BurnExpiredUtxos {
                tx: vec![1],
                signing_hash: [21; 32],
                signing_storm_tree_branch: branch,
                block_height: 1,
                chain_tip: None,
            },
        ),
        NodeMessage::new(
            NodeMessageKind::ExchangeRewards,
            None,
            &ExchangeRewards {
                tx: vec![2],
                final_tx: None,
                signing_hash: [22; 32],
                signing_storm_tree_branch: branch,
                block_height: 1,
                chain_tip: None,
            },
        ),
        NodeMessage::new(
            NodeMessageKind::ExecuteVotingRequest,
            None,
            &ExecuteVotingRequest {
                tx: vec![3],
                final_tx: None,
                signing_hashes: vec![[23; 32], [24; 32]],
                signing_storm_tree_branch: branch,
                proposer_public_key: [0; 32],
                chain_tip: None,
            },
        ),
        NodeMessage::new(
            NodeMessageKind::RenewStormUtxos,
            None,
            &RenewStormUtxos {
                tx: vec![4],
                final_tx: None,
                signing_hashes: vec![[25; 32], [26; 32]],
                signing_storm_tree_branch: branch,
                block_height: 1,
                chain_tip: None,
                new_rescue_height: 2,
            },
        ),
    ];
    let expected = [
        vec![[21; 32]],
        vec![[22; 32]],
        vec![[23; 32], [24; 32]],
        vec![[25; 32], [26; 32]],
    ];

    for (message, hashes) in messages.into_iter().zip(expected) {
        let message = message.unwrap();
        let kind = message.decoded_kind().unwrap();
        let request_hash = message.hash().unwrap();
        let context = StormContext {
            storm_handle: storm.handle(),
            storm_message: message.clone().into_storm_message().unwrap(),
            message_context: storm::MessageContext {
                peer_public_key: leader,
            },
        };
        // Nothing is connected, so the first round may fail to send; the
        // session is started before that.
        let _ = match kind {
            NodeMessageKind::BurnExpiredUtxos => {
                signing
                    .handle_burn_expired_utxos(message, &context, leader)
                    .await
            }
            NodeMessageKind::ExchangeRewards => {
                signing
                    .handle_exchange_rewards(message, &context, leader)
                    .await
            }
            NodeMessageKind::ExecuteVotingRequest => {
                signing
                    .handle_execute_voting_request(message, &context)
                    .await
            }
            _ => signing.handle_renew_storm_utxos(message, &context).await,
        };

        let state = signing.state.lock().await;
        let session = &state.sessions[&request_hash];
        assert_eq!(session.request.kind, kind);
        assert_eq!(session.request.message_hashes, hashes);
        assert_eq!(session.request.signing_storm_tree_branch, branch);
    }
}

const COORDINATOR: [u8; 33] = [1; 33];
const MEMBER: [u8; 33] = [2; 33];

#[test]
fn coordinator_can_initiate_user_request_signing() {
    require_coordinator(COORDINATOR, COORDINATOR).unwrap();
}

#[test]
fn member_cannot_initiate_user_request_signing() {
    let error = require_coordinator(COORDINATOR, MEMBER).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
}

#[test]
fn a_round_signs_its_rate_after_its_transaction() {
    assert_eq!(execute_message_hashes([7; 32], None), vec![[7; 32]]);
    assert_eq!(
        execute_message_hashes([7; 32], Some([8; 32])),
        vec![[7; 32], [8; 32]]
    );
}

#[test]
fn blames_only_the_signers_that_held_up_a_requested_signing() {
    let secrets = [[11; 32], [12; 32], [13; 32]];
    let peers = secrets
        .iter()
        .map(|secret| {
            let key = secp256k1_zkp::SecretKey::from_slice(secret).unwrap();
            Peer::new(
                TransportPublicKey::from_secret_key(&secp256k1_zkp::Secp256k1::new(), &key)
                    .serialize(),
            )
        })
        .collect::<Vec<_>>();
    let mut state = SigningState::new(secrets[0], &peers);
    let local = state.local_node;
    let (branch, other) = {
        let tree = state.tree.as_ref().unwrap();
        let branch = tree
            .branches()
            .find(|branch| tree.nodes_for_branch(branch).unwrap().contains(&local))
            .unwrap();
        let other = *tree
            .nodes_for_branch(&branch)
            .unwrap()
            .iter()
            .find(|signer| **signer != local)
            .unwrap();
        (branch, other)
    };
    let request = || SigningRequest {
        kind: NodeMessageKind::BurnExpiredUtxos,
        signing_storm_tree_branch: branch,
        message_hashes: vec![[24; 32]],
    };
    for (request_hash, requestor) in [([1; 32], local), ([2; 32], local), ([3; 32], other)] {
        state
            .start_session(request_hash, requestor, request(), None)
            .unwrap();
    }
    let no_nonce = state.sessions.remove(&[1; 32]).unwrap();
    let mut no_partial = state.sessions.remove(&[2; 32]).unwrap();
    no_partial.contributions.get_mut(&other).unwrap().nonces = Some(Vec::new());
    let someone_elses = state.sessions.remove(&[3; 32]).unwrap();
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();

    metrics::with_local_recorder(&recorder, || {
        state.count_missing_contributions(&no_nonce);
        state.count_missing_contributions(&no_partial);
        state.count_missing_contributions(&someone_elses);
    });

    let rendered = recorder.handle().render();
    let peer = hex::encode(state.member_transport_keys[&other]);
    for stage in ["nonce", "partial"] {
        let line = format!(
            r#"high_storm_signing_missing_contributions_total{{peer="{peer}",kind="burn_expired_utxos",stage="{stage}"}} 1"#
        );
        assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
    }
    assert!(
        !rendered.contains(&hex::encode(state.member_transport_keys[&local])),
        "this node never blames itself"
    );
}

fn signing_round() -> (
    Vec<SigningState>,
    Vec<PartialSignaturesMessage>,
    oneshot::Receiver<Result<SigningResult, SessionExpired>>,
) {
    let secrets = [[11; 32], [12; 32], [13; 32]];
    let peers = secrets
        .iter()
        .map(|secret| {
            let key = secp256k1_zkp::SecretKey::from_slice(secret).unwrap();
            Peer::new(
                TransportPublicKey::from_secret_key(&secp256k1_zkp::Secp256k1::new(), &key)
                    .serialize(),
            )
        })
        .collect::<Vec<_>>();
    let mut states = secrets
        .into_iter()
        .map(|secret| SigningState::new(secret, &peers))
        .collect::<Vec<_>>();
    let tree = states[0].tree.as_ref().unwrap();
    let branch = tree.branches().next().unwrap();
    let signers = tree.nodes_for_branch(&branch).unwrap().to_vec();
    states.retain(|state| signers.contains(&state.local_node));
    let requestor = states[0].local_node;
    let (completion, receiver) = oneshot::channel();
    let mut completion = Some(completion);
    let mut nonces = Vec::<SigningNoncesMessage>::new();

    for (index, state) in states.iter_mut().enumerate() {
        let message = state
            .start_session(
                [42; 32],
                requestor,
                SigningRequest {
                    kind: NodeMessageKind::BurnExpiredUtxos,
                    signing_storm_tree_branch: branch,
                    message_hashes: vec![[24; 32], [25; 32]],
                },
                if index == 0 { completion.take() } else { None },
            )
            .unwrap()
            .unwrap();
        nonces.push(message.decode_payload().unwrap());
    }

    let mut partials = Vec::new();
    for state in &mut states {
        for nonce in &nonces {
            if nonce.signer == state.local_node {
                continue;
            }
            if let Some((message, _)) = state
                .accept_nonces(
                    [42; 32],
                    nonce.signer,
                    SigningNoncesMessage {
                        signer: nonce.signer,
                        nonces: nonce.nonces.clone(),
                    },
                )
                .unwrap()
            {
                partials.push(message.decode_payload().unwrap());
            }
        }
    }

    (states, partials, receiver)
}

#[test]
fn rejects_a_bad_batch_atomically_and_accepts_a_valid_retry() {
    let (mut states, messages, mut completion) = signing_round();
    let state = &mut states[0];
    let valid = messages
        .into_iter()
        .find(|message| message.signer != state.local_node)
        .unwrap();
    let mut bad = PartialSignaturesMessage {
        signer: valid.signer,
        partial_signatures: valid.partial_signatures.clone(),
    };
    bad.partial_signatures[1] = bad.partial_signatures[0];

    let error = state
        .accept_partial_signatures([42; 32], bad.signer, bad)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&hex::encode(valid.signer)));
    assert!(error.contains("message 1"));
    assert!(
        state.sessions[&[42; 32]].contributions[&valid.signer]
            .partial_signatures
            .is_none()
    );
    assert!(completion.try_recv().is_err());

    state
        .accept_partial_signatures([42; 32], valid.signer, valid)
        .unwrap();
    assert_eq!(completion.try_recv().unwrap().unwrap().signatures.len(), 2);
    assert!(!state.sessions.contains_key(&[42; 32]));
}

#[test]
fn tells_the_waiting_attempt_its_session_expired() {
    let (mut states, _, mut completion) = signing_round();
    let state = &mut states[0];
    state.sessions.get_mut(&[42; 32]).unwrap().created_at =
        Instant::now() - SIGNING_SESSION_TIMEOUT;

    state.remove_expired_sessions();

    assert!(matches!(completion.try_recv(), Ok(Err(SessionExpired))));
    assert!(!state.sessions.contains_key(&[42; 32]));
}

#[test]
fn rejects_shares_from_another_nonce_round() {
    let (mut states, _, mut completion) = signing_round();
    let (_, replayed, _) = signing_round();
    let state = &mut states[0];
    let replayed = replayed
        .into_iter()
        .find(|message| message.signer != state.local_node)
        .unwrap();
    let signer = replayed.signer;

    let error = state
        .accept_partial_signatures([42; 32], signer, replayed)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&hex::encode(signer)));
    assert!(error.contains("message 0"));
    assert!(
        state.sessions[&[42; 32]].contributions[&signer]
            .partial_signatures
            .is_none()
    );
    assert!(completion.try_recv().is_err());
}

#[test]
fn verifies_pending_shares_when_the_last_nonce_arrives() {
    for invalid in [false, true] {
        let (mut states, messages, mut completion) = signing_round();
        let state = &mut states[0];
        let valid = messages
            .into_iter()
            .find(|message| message.signer != state.local_node)
            .unwrap();
        let signer = valid.signer;
        let nonces = state
            .sessions
            .get_mut(&[42; 32])
            .unwrap()
            .contributions
            .get_mut(&signer)
            .unwrap()
            .nonces
            .take()
            .unwrap();
        let mut pending = PartialSignaturesMessage {
            signer,
            partial_signatures: valid.partial_signatures.clone(),
        };
        if invalid {
            pending.partial_signatures[1] = pending.partial_signatures[0];
        }

        state
            .accept_partial_signatures([42; 32], signer, pending)
            .unwrap();
        assert!(completion.try_recv().is_err());

        let result = state.accept_nonces(
            [42; 32],
            signer,
            SigningNoncesMessage {
                signer,
                nonces: nonces
                    .iter()
                    .map(|nonce| nonce.serialize().to_vec())
                    .collect(),
            },
        );
        if invalid {
            let error = result.unwrap_err().to_string();
            assert!(error.contains(&hex::encode(signer)));
            assert!(error.contains("message 1"));
            assert!(
                state.sessions[&[42; 32]].contributions[&signer]
                    .partial_signatures
                    .is_none()
            );
            assert!(completion.try_recv().is_err());
            state
                .accept_partial_signatures([42; 32], signer, valid)
                .unwrap();
        } else {
            assert!(result.is_ok());
        }

        assert_eq!(completion.try_recv().unwrap().unwrap().signatures.len(), 2);
        assert!(!state.sessions.contains_key(&[42; 32]));
    }
}

#[tokio::test]
async fn responsive_threshold_does_not_wait_for_an_unresponsive_branch() {
    let reservations = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let addresses = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().to_string())
        .collect::<Vec<_>>();
    let secrets = [[11; 32], [12; 32], [13; 32]];
    let public_keys = secrets
        .iter()
        .map(|secret| {
            let secret = secp256k1_zkp::SecretKey::from_slice(secret).unwrap();
            TransportPublicKey::from_secret_key(&secp256k1_zkp::Secp256k1::new(), &secret)
        })
        .collect::<Vec<_>>();
    let peers = public_keys
        .iter()
        .zip(&addresses)
        .map(|(key, address)| {
            let mut peer = Peer::new(key.serialize());
            peer.status = PeerStatus::Active;
            peer.socket_address = Some(address.clone());
            peer
        })
        .collect::<Vec<_>>();
    let mut nodes = Vec::new();
    for (index, reservation) in reservations.into_iter().enumerate() {
        drop(reservation);
        let mut node = Storm::from_peers(
            secp256k1_zkp::SecretKey::from_slice(&secrets[index]).unwrap(),
            peers.clone(),
        );
        node.start(Some(addresses[index].clone())).await.unwrap();
        nodes.push(node);
    }
    for node in &mut nodes {
        node.start(None).await.unwrap();
    }
    timeout(Duration::from_secs(5), async {
        loop {
            let mut ready = true;
            for node in &nodes {
                ready &= node.handle().connected_peer_keys().await.len() == 2;
            }
            if ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("transport connections did not become ready");

    let mut signings = Vec::new();
    for (index, node) in nodes.iter().enumerate() {
        signings.push(Signing::new(node, secrets[index], public_keys[0].serialize()).await);
    }
    let unresponsive = {
        let state = signings[0].state.lock().await;
        let branch = state
            .select_branch(
                &nodes[0].peers().await,
                &nodes[0].handle().connected_peer_keys().await,
                &BTreeSet::new(),
            )
            .unwrap();
        *state
            .tree
            .as_ref()
            .unwrap()
            .nodes_for_branch(&branch)
            .unwrap()
            .iter()
            .find(|key| **key != state.local_node)
            .unwrap()
    };
    for (index, node) in nodes.iter().enumerate() {
        if node_key(&public_keys[index].serialize()).unwrap() == unresponsive {
            continue;
        }
        let signing = signings[index].clone();
        node.register_custom_handler(move |custom, context| {
            let signing = signing.clone();
            async move {
                let Some(message) = NodeMessage::from_custom(&custom).unwrap() else {
                    return;
                };
                let result = match message.decoded_kind() {
                    Some(NodeMessageKind::ExecuteUserRequests) => {
                        signing
                            .handle_execute_user_requests(message, &context, None)
                            .await
                    }
                    Some(NodeMessageKind::SigningNonces) => {
                        signing.handle_signing_nonces(message, &context).await
                    }
                    Some(NodeMessageKind::PartialSignatures) => {
                        signing.handle_partial_signatures(message, &context).await
                    }
                    _ => Ok(()),
                };
                assert!(result.is_ok(), "signing message failed: {result:?}");
            }
        })
        .await;
    }
    let result = timeout(
        Duration::from_secs(5),
        signings[0].sign_per_branch(
            &nodes[0].handle(),
            NodeMessageKind::BurnExpiredUtxos,
            SIGNING_SESSION_TIMEOUT,
            |branch| {
                Ok((
                    NodeMessage::new(
                        NodeMessageKind::ExecuteUserRequests,
                        None,
                        &ExecuteUserRequests {
                            tx: vec![1],
                            signing_hash: [24; 32],
                            signing_storm_tree_branch: branch,
                            external_requests: vec![ExternalRequests {
                                request_hash: [25; 32],
                                network_user_requests: vec![1],
                                additional_payload: None,
                            }],
                            chain_tip: None,
                        },
                    )?,
                    vec![[24; 32]],
                ))
            },
        ),
    )
    .await;
    let unresponsive_index = public_keys
        .iter()
        .position(|key| node_key(&key.serialize()).unwrap() == unresponsive)
        .unwrap();
    nodes[unresponsive_index].shutdown().await;
    timeout(Duration::from_secs(5), async {
        while nodes[0]
            .handle()
            .connected_peer_keys()
            .await
            .contains(&public_keys[unresponsive_index].serialize())
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("disconnected peer remained available");
    let offline_result = timeout(
        Duration::from_secs(5),
        signings[0].sign_per_branch(
            &nodes[0].handle(),
            NodeMessageKind::BurnExpiredUtxos,
            SIGNING_SESSION_TIMEOUT,
            |branch| {
                Ok((
                    NodeMessage::new(
                        NodeMessageKind::ExecuteUserRequests,
                        None,
                        &ExecuteUserRequests {
                            tx: vec![1],
                            signing_hash: [26; 32],
                            signing_storm_tree_branch: branch,
                            external_requests: vec![ExternalRequests {
                                request_hash: [27; 32],
                                network_user_requests: vec![1],
                                additional_payload: None,
                            }],
                            chain_tip: None,
                        },
                    )?,
                    vec![[26; 32]],
                ))
            },
        ),
    )
    .await;
    for node in &mut nodes {
        node.shutdown().await;
    }
    let result = result
        .expect("responsive two-of-three branch waited for the unresponsive peer")
        .unwrap();
    let offline_result = offline_result
        .expect("two connected signers did not complete with the third offline")
        .unwrap();
    assert_eq!(
        offline_result.signing_storm_tree_branch,
        result.signing_storm_tree_branch
    );
    assert_eq!(offline_result.signatures.len(), 1);
    let state = signings[0].state.lock().await;
    let signers = state
        .tree
        .as_ref()
        .unwrap()
        .nodes_for_branch(&result.signing_storm_tree_branch)
        .unwrap();
    assert!(!signers.contains(&unresponsive));
    assert_eq!(result.signatures.len(), 1);
    assert!(state.sessions.is_empty());
}
