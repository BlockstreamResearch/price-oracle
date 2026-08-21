use storm::{CustomMsg, StormContext};

use super::{
    message::{NodeMessage, NodeMessageKind},
    signing::SigningError,
    state::NetworkState,
};

pub(crate) async fn handle(
    state: NetworkState,
    custom: CustomMsg,
    context: StormContext,
) -> Result<(), SigningError> {
    let Some(message) = NodeMessage::from_custom(&custom)? else {
        return Ok(());
    };
    let Some(kind) = message.decoded_kind() else {
        return Err(SigningError::InvalidMessage(format!(
            "unknown NodeMessage kind {}",
            message.kind
        )));
    };
    authorize_sender(
        kind,
        state.coordinator_public_key(),
        context.message_context.peer_public_key,
    )?;

    match kind {
        NodeMessageKind::Test => state.signing().handle_test(message, &context).await,
        NodeMessageKind::SigningNonces => {
            state
                .signing()
                .handle_signing_nonces(message, &context)
                .await
        }
        NodeMessageKind::PartialSignatures => {
            state
                .signing()
                .handle_partial_signatures(message, &context)
                .await
        }
        _ => {
            tracing::debug!(?kind, "NodeMessage kind has no high-storm handler yet");
            Ok(())
        }
    }
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
}
