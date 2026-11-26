use super::*;

const COORDINATOR: [u8; 33] = [1; 33];
const MEMBER: [u8; 33] = [2; 33];

#[test]
fn current_member_can_execute_another_members_voting_request() {
    let proposer = secp256k1::PublicKey::from_secret_key(
        &secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap(),
    );
    let executor = secp256k1::PublicKey::from_secret_key(
        &secp256k1::SecretKey::from_secret_bytes([2; 32]).unwrap(),
    );
    let current_members = [
        proposer.x_only_public_key().0.serialize(),
        executor.x_only_public_key().0.serialize(),
    ]
    .into_iter()
    .collect();

    authorize_voting_executor(&current_members, proposer.serialize()).unwrap();
    authorize_voting_executor(&current_members, executor.serialize()).unwrap();
}

#[test]
fn non_member_cannot_execute_a_voting_request() {
    let outsider = secp256k1::PublicKey::from_secret_key(
        &secp256k1::SecretKey::from_secret_bytes([3; 32]).unwrap(),
    );
    let error = authorize_voting_executor(&Default::default(), outsider.serialize()).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    assert!(authorize_voting_executor(&Default::default(), [0; 33]).is_err());
}

#[test]
fn coordinator_can_send_user_request_messages() {
    authorize_sender(
        NodeMessageKind::ExecuteUserRequests,
        COORDINATOR,
        COORDINATOR,
    )
    .unwrap();
}

#[test]
fn member_cannot_send_user_request_messages() {
    let error =
        authorize_sender(NodeMessageKind::ExecuteUserRequests, COORDINATOR, MEMBER).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
}

#[test]
fn member_can_send_messages_without_coordinator_restriction() {
    authorize_sender(NodeMessageKind::AttestPrice, COORDINATOR, MEMBER).unwrap();
}

#[test]
fn only_coordinator_can_announce_network_assets() {
    let error = authorize_sender(NodeMessageKind::NetworkAssets, COORDINATOR, MEMBER).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
}

#[test]
fn only_coordinator_can_renew_storm_eyes() {
    let error =
        authorize_sender(NodeMessageKind::RenewStormUtxos, COORDINATOR, MEMBER).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    authorize_sender(NodeMessageKind::RenewStormUtxos, COORDINATOR, COORDINATOR).unwrap();
}

#[test]
fn current_leader_can_send_burn_messages() {
    authorize_leader_sender(COORDINATOR, COORDINATOR).unwrap();
}

#[test]
fn non_leader_cannot_send_burn_messages() {
    let error = authorize_leader_sender(COORDINATOR, MEMBER).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
}

#[test]
fn non_leader_cannot_send_exchange_messages() {
    let error = authorize_leader_sender(COORDINATOR, MEMBER).unwrap_err();

    assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
}

#[test]
fn leader_messages_must_target_the_current_tip() {
    require_current_tip(42, 42).unwrap();

    let error = require_current_tip(43, 42).unwrap_err();
    assert!(matches!(error, SigningError::ChainAnchorMismatch(_)));
}

#[test]
fn finalized_executions_accept_any_seen_canonical_anchor() {
    let anchor = ChainTip {
        height: 40,
        hash: [4; 32],
    };

    canonical_anchor(anchor, Some([4; 32])).unwrap();

    let fork = canonical_anchor(anchor, Some([5; 32])).unwrap_err();
    assert!(
        matches!(fork, SigningError::ChainAnchorMismatch(reason) if reason.contains("outside"))
    );

    let unseen = canonical_anchor(anchor, None).unwrap_err();
    assert!(
        matches!(unseen, SigningError::ChainAnchorMismatch(reason) if reason.contains("not seen"))
    );
}

#[test]
fn signing_messages_require_a_chain_anchor() {
    let error = required_chain_tip(None).unwrap_err();

    assert!(matches!(error, SigningError::ChainAnchorMismatch(_)));
}

#[test]
fn signing_messages_must_target_the_current_block_hash() {
    require_current_hash([4; 32], [4; 32]).unwrap();

    let error = require_current_hash([4; 32], [5; 32]).unwrap_err();
    assert!(matches!(error, SigningError::ChainAnchorMismatch(_)));
}

#[test]
fn only_sender_authorization_counts_as_unauthorized() {
    let unauthorized = HandlerError::from(
        authorize_sender(NodeMessageKind::RenewStormUtxos, COORDINATOR, MEMBER).unwrap_err(),
    );
    let behind = HandlerError::from(require_current_tip(43, 42).unwrap_err());

    assert!(unauthorized.is_unauthorized());
    assert_eq!(unauthorized.metric_reason(), "unauthorized");
    assert!(!behind.is_unauthorized());
    assert_eq!(behind.metric_reason(), "chain_anchor_mismatch");
}

#[test]
fn labels_why_a_signing_request_was_refused() {
    use super::super::{
        burning::BurningError, user_requests::UserRequestError,
        voting_execution::VotingExecutionError,
    };

    let off_price = HandlerError::UserRequest(UserRequestError::InstructedPrice(
        price_feed::ValidationError::DeviationExceeded,
    ));
    let bad_burn = HandlerError::Burning(BurningError::ReserveShortfall);
    let local = HandlerError::VotingExecution(VotingExecutionError::MemberMigrationNotReady);

    assert_eq!(off_price.refusal_reason(), Some("price_deviation_exceeded"));
    assert_eq!(bad_burn.refusal_reason(), Some("invalid"));
    assert_eq!(local.refusal_reason(), Some("other"));
}

#[tokio::test]
async fn spend_messages_wait_for_recovery_and_migration_finality() {
    use secp256k1_zkp::{Secp256k1, SecretKey};
    use storm::{MessageContext, Peer, Storm};

    let database = crate::db::Database::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    let secp = Secp256k1::new();
    let secrets =
        [[31; 32], [32; 32], [33; 32]].map(|secret| SecretKey::from_slice(&secret).unwrap());
    let keys = secrets.map(|secret| secret.public_key(&secp).serialize());
    let storm = Storm::from_peers(secrets[0], keys.into_iter().map(Peer::new).collect());
    let state =
        NetworkState::for_tests(&storm, secrets[0].secret_bytes(), keys[0], &database).await;
    let gated = [
        NodeMessageKind::ExecuteUserRequests,
        NodeMessageKind::ExchangeRewards,
        NodeMessageKind::SigningNonces,
        NodeMessageKind::PartialSignatures,
        NodeMessageKind::BurnExpiredUtxos,
        NodeMessageKind::ExpiredUtxosBurned,
        NodeMessageKind::ExecuteVotingRequest,
        NodeMessageKind::RenewStormUtxos,
    ];
    // The gate runs before the payload is decoded, so an empty one will do.
    let run = |kind| {
        let state = state.clone();
        let storm = storm.handle();
        async move {
            let message = NodeMessage::new(kind, None, &()).unwrap();
            let context = StormContext {
                storm_handle: storm,
                storm_message: message.clone().into_storm_message().unwrap(),
                message_context: MessageContext {
                    peer_public_key: keys[0],
                },
            };
            dispatch(state, message, kind, context, &mut false).await
        }
    };

    for kind in gated {
        assert!(matches!(run(kind).await, Err(HandlerError::Recovering)));
    }
    let settings = run(NodeMessageKind::ProtocolSettings).await;
    assert!(!matches!(
        settings,
        Err(HandlerError::Recovering | HandlerError::MigrationFinalizing)
    ));

    state.indexer().mark_synced();
    state.set_spending_paused(true).await.unwrap();
    for kind in gated {
        assert!(matches!(
            run(kind).await,
            Err(HandlerError::MigrationFinalizing)
        ));
    }
    let settings = run(NodeMessageKind::ProtocolSettings).await;
    assert!(!matches!(
        settings,
        Err(HandlerError::Recovering | HandlerError::MigrationFinalizing)
    ));
}

#[tokio::test]
async fn a_rejected_notice_of_a_broadcast_is_no_refusal_to_sign() {
    use secp256k1_zkp::{Secp256k1, SecretKey};
    use storm::{MessageContext, Peer, Storm};

    let database = crate::db::Database::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    let secp = Secp256k1::new();
    let secrets =
        [[21; 32], [22; 32], [23; 32]].map(|secret| SecretKey::from_slice(&secret).unwrap());
    let keys = secrets.map(|secret| secret.public_key(&secp).serialize());
    let storm = Storm::from_peers(secrets[0], keys.into_iter().map(Peer::new).collect());
    let state =
        NetworkState::for_tests(&storm, secrets[0].secret_bytes(), keys[0], &database).await;
    state.indexer().mark_synced();
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();

    {
        let _local = metrics::set_default_local_recorder(&recorder);
        // Neither links to the vote it executes; only the first asks to sign.
        for final_tx in [None, Some(vec![1])] {
            let message = NodeMessage::new(
                NodeMessageKind::ExecuteVotingRequest,
                None,
                &ExecuteVotingRequest {
                    tx: Vec::new(),
                    final_tx,
                    signing_hashes: Vec::new(),
                    signing_storm_tree_branch: [0; 32],
                    proposer_public_key: [0; 32],
                    chain_tip: None,
                },
            )
            .unwrap();
            let storm_message = message.into_storm_message().unwrap();
            let custom = postcard::from_bytes(&storm_message.payload).unwrap();
            let context = StormContext {
                storm_handle: storm.handle(),
                storm_message,
                message_context: MessageContext {
                    peer_public_key: keys[1],
                },
            };
            handle(state.clone(), custom, context).await.unwrap_err();
        }
    }

    let rendered = recorder.handle().render();
    let peer = hex::encode(keys[1]);
    for line in [
        format!(
            r#"high_storm_node_messages_rejected_total{{peer="{peer}",kind="execute_voting_request",reason="voting_execution"}} 2"#
        ),
        format!(
            r#"high_storm_signing_refused_total{{peer="{peer}",kind="execute_voting_request",reason="invalid"}} 1"#
        ),
    ] {
        assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
    }
}

#[test]
fn shared_helper_failures_in_user_requests_still_count_as_invalid_proposals() {
    use crate::high_storm::{TransactionHelperError, UserRequestError};

    for helper in [
        TransactionHelperError::Invalid("required UTXO is unavailable".into()),
        TransactionHelperError::Pset("missing input".into()),
    ] {
        let error = HandlerError::UserRequest(UserRequestError::TransactionHelper(helper));
        assert_eq!(error.refusal_reason(), Some("invalid"));
    }
}
