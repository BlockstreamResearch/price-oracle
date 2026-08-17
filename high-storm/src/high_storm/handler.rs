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
