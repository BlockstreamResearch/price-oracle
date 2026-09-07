use storm::{CustomMsg, StormContext};

use super::{
    assets::AssetError,
    burning::BurningError,
    leader,
    message::{BurnExpiredUtxos, ExpiredUtxosBurned, NodeMessage, NodeMessageKind},
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
    Asset(#[from] AssetError),
    #[error(transparent)]
    UserRequest(#[from] super::user_requests::UserRequestError),
    #[error(transparent)]
    Burning(#[from] BurningError),
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
            let request = message.decode_payload()?;
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
                .handle_synchronization(message, &context)
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

async fn require_current_leader(
    state: &NetworkState,
    context: &StormContext,
    block_height: u64,
) -> Result<[u8; 33], SigningError> {
    if block_height != state.block_height() {
        return Err(SigningError::UnauthorizedMessage(
            "burn message does not target the currently indexed block".into(),
        ));
    }
    let expected = leader::leader_for_height(&context.storm_handle.peers().await, block_height)
        .ok_or_else(|| SigningError::UnauthorizedMessage("network has no leader".into()))?;
    authorize_burn_sender(expected, context.message_context.peer_public_key)?;
    Ok(expected)
}

fn authorize_burn_sender(expected: [u8; 33], sender: [u8; 33]) -> Result<(), SigningError> {
    if sender != expected {
        return Err(SigningError::UnauthorizedMessage(format!(
            "only network leader {} may send burn messages",
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
        authorize_burn_sender(COORDINATOR, COORDINATOR).unwrap();
    }

    #[test]
    fn non_leader_cannot_send_burn_messages() {
        let error = authorize_burn_sender(COORDINATOR, MEMBER).unwrap_err();

        assert!(matches!(error, SigningError::UnauthorizedMessage(_)));
    }
}
