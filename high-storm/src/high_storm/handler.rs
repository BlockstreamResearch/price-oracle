use storm::{CustomMsg, StormContext};

use super::{
    assets::AssetError,
    burning::BurningError,
    droplets::DropletsError,
    leader,
    message::{
        BurnExpiredUtxos, ExecuteVotingRequest, ExpiredUtxosBurned, NodeMessage, NodeMessageKind,
    },
    signing::SigningError,
    state::NetworkState,
    voting::VotingError,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandlerError {
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error(transparent)]
    Voting(#[from] VotingError),
    #[error(transparent)]
    VotingExecution(#[from] super::voting_execution::VotingExecutionError),
    #[error(transparent)]
    Asset(#[from] AssetError),
    #[error(transparent)]
    UserRequest(#[from] super::user_requests::UserRequestError),
    #[error(transparent)]
    Burning(#[from] BurningError),
    #[error(transparent)]
    Droplets(#[from] DropletsError),
    #[error(transparent)]
    Indexer(#[from] super::indexer::IndexerError),
    #[error(transparent)]
    Encoding(#[from] postcard::Error),
}

pub(crate) async fn handle(
    state: NetworkState,
    custom: CustomMsg,
    context: StormContext,
) -> Result<(), HandlerError> {
    let Some(message) = NodeMessage::from_custom(&custom)? else {
        return Ok(());
    };
    let Some(kind) = message.decoded_kind() else {
        return Err(SigningError::InvalidMessage(format!(
            "unknown NodeMessage kind {}",
            message.kind
        ))
        .into());
    };
    authorize_sender(
        kind,
        state.coordinator_public_key(),
        context.message_context.peer_public_key,
    )?;

    match kind {
        NodeMessageKind::ExecuteUserRequests => {
            let request: crate::ExecuteUserRequests = message.decode_payload()?;
            state.user_requests().validate_execute(&request).await?;
            state
                .signing()
                .handle_execute_user_requests(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::BurnExpiredUtxos => {
            let request: BurnExpiredUtxos = message.decode_payload()?;
            let expected_leader =
                require_current_leader(&state, &context, request.block_height).await?;
            state.burning().validate_request(&request).await?;
            state
                .signing()
                .handle_burn_expired_utxos(message, &context, expected_leader)
                .await?;
            Ok(())
        }
        NodeMessageKind::ExchangeRewards => {
            let request: crate::ExchangeRewards = message.decode_payload()?;
            let expected_leader =
                require_current_leader(&state, &context, request.block_height).await?;
            if request.final_tx.is_some() {
                state
                    .droplets()
                    .observe_broadcast(&request, expected_leader)
                    .await?;
                return Ok(());
            }
            let exchange = state
                .droplets()
                .validate_request(&request, expected_leader)
                .await?;
            state
                .droplets()
                .lock_exchange(&exchange, request.block_height, &request.tx)
                .await?;
            if let Err(error) = state
                .signing()
                .handle_exchange_rewards(message, &context, expected_leader)
                .await
            {
                state
                    .droplets()
                    .unlock_exchange(exchange.member, request.block_height)
                    .await?;
                return Err(error.into());
            }
            Ok(())
        }
        NodeMessageKind::ExpiredUtxosBurned => {
            let notification: ExpiredUtxosBurned = message.decode_payload()?;
            require_current_leader(&state, &context, notification.block_height).await?;
            state.burning().observe_broadcast(&notification).await?;
            Ok(())
        }
        NodeMessageKind::NetworkAssets => {
            state
                .assets()
                .handle_announcement(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::NetworkVoteRequest => {
            state
                .voting()
                .handle_request(message, &context, state.block_height())
                .await?;
            Ok(())
        }
        NodeMessageKind::ApproveVotingRequest => {
            state
                .voting()
                .handle_approval(message, &context, state.block_height())
                .await?;
            Ok(())
        }
        NodeMessageKind::AskAboutVotings => {
            state
                .voting()
                .handle_synchronization(message, &context, state.block_height())
                .await?;
            Ok(())
        }
        NodeMessageKind::ExecuteVotingRequest => {
            let request_hash = message.linked_to.ok_or_else(|| {
                super::voting_execution::VotingExecutionError::Invalid(
                    "voting execution does not link to a voting request".into(),
                )
            })?;
            let request: ExecuteVotingRequest = message.decode_payload()?;
            authorize_voting_proposer(
                request.proposer_public_key,
                context.message_context.peer_public_key,
            )?;
            let peers = context.storm_handle.peers().await;
            let current_members = super::voting_member_keys(&peers)?;
            let vote = state.voting().get(request_hash).await?.ok_or_else(|| {
                super::voting_execution::VotingExecutionError::UnknownRequest(hex::encode(
                    request_hash,
                ))
            })?;
            if let Some(target_members) =
                super::member_migration_target(&vote.request, &current_members)?
            {
                state
                    .ensure_member_migration(&context.storm_handle, request_hash, target_members)
                    .await
                    .map_err(|error| {
                        super::voting_execution::VotingExecutionError::Invalid(error.to_string())
                    })?;
                if !context.storm_handle.local_member_migration_ready().await {
                    return Err(
                        super::voting_execution::VotingExecutionError::MemberMigrationNotReady
                            .into(),
                    );
                }
            }
            if request.final_tx.is_some() {
                state
                    .voting_execution()
                    .observe_broadcast(
                        request_hash,
                        &request,
                        &current_members,
                        state.block_height(),
                    )
                    .await?;
                return Ok(());
            }
            state
                .voting_execution()
                .begin(
                    request_hash,
                    &request,
                    state.block_height(),
                    &current_members,
                )
                .await?;
            state
                .signing()
                .handle_execute_voting_request(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::SigningNonces => {
            state
                .signing()
                .handle_signing_nonces(message, &context)
                .await?;
            Ok(())
        }
        NodeMessageKind::PartialSignatures => {
            state
                .signing()
                .handle_partial_signatures(message, &context)
                .await?;
            Ok(())
        }
        _ => {
            tracing::debug!(?kind, "NodeMessage kind has no high-storm handler yet");
            Ok(())
        }
    }
}

fn authorize_voting_proposer(proposer: [u8; 32], sender: [u8; 33]) -> Result<(), SigningError> {
    let sender = secp256k1::PublicKey::from_slice(&sender)
        .map_err(|error| SigningError::UnauthorizedMessage(error.to_string()))?
        .x_only_public_key()
        .0
        .serialize();
    if sender != proposer {
        return Err(SigningError::UnauthorizedMessage(
            "only the node that proposed a voting request may execute it".into(),
        ));
    }
    Ok(())
}

async fn require_current_leader(
    state: &NetworkState,
    context: &StormContext,
    block_height: u64,
) -> Result<[u8; 33], HandlerError> {
    let expected = leader::leader_for_height(&context.storm_handle.peers().await, block_height)
        .ok_or_else(|| SigningError::UnauthorizedMessage("network has no leader".into()))?;
    authorize_leader_sender(expected, context.message_context.peer_public_key)?;
    require_current_tip(block_height, state.indexer().tip()?)?;

    state.indexer().sync().await?;
    if let Some(cursor) = state.indexer().cursor().await? {
        state.set_block_height(cursor.height);
    }
    require_current_tip(block_height, state.block_height())?;

    Ok(expected)
}

fn require_current_tip(block_height: u64, tip: u64) -> Result<(), SigningError> {
    if block_height != tip {
        return Err(SigningError::UnauthorizedMessage(
            "leader message does not target the current block".into(),
        ));
    }

    Ok(())
}

fn authorize_leader_sender(expected: [u8; 33], sender: [u8; 33]) -> Result<(), SigningError> {
    if sender != expected {
        return Err(SigningError::UnauthorizedMessage(format!(
            "only network leader {} may send leader-only messages",
            hex::encode(expected)
        )));
    }
    Ok(())
}

fn authorize_sender(
    kind: NodeMessageKind,
    coordinator_public_key: [u8; 33],
    sender_public_key: [u8; 33],
) -> Result<(), SigningError> {
    if kind.requires_coordinator() && sender_public_key != coordinator_public_key {
        return Err(SigningError::UnauthorizedMessage(format!(
            "only coordinator {} may send {kind:?}",
            hex::encode(coordinator_public_key)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COORDINATOR: [u8; 33] = [1; 33];
    const MEMBER: [u8; 33] = [2; 33];

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
        let error = authorize_sender(NodeMessageKind::ExecuteUserRequests, COORDINATOR, MEMBER)
            .unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }

    #[test]
    fn member_can_send_messages_without_coordinator_restriction() {
        authorize_sender(NodeMessageKind::AttestPrice, COORDINATOR, MEMBER).unwrap();
    }

    #[test]
    fn only_coordinator_can_announce_network_assets() {
        let error =
            authorize_sender(NodeMessageKind::NetworkAssets, COORDINATOR, MEMBER).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
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
        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }
}
