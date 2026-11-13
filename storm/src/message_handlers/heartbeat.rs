use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    MessageContext, StormMessage, StormState, message::StormErrorCode,
    message_handlers::StormMessagePayloadType,
};

pub(crate) fn message() -> StormMessage {
    StormMessage::new(StormMessagePayloadType::Heartbeat, Vec::new())
}

pub(super) async fn handle(
    _state: &Arc<RwLock<StormState>>,
    context: MessageContext,
    _message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    tracing::trace!(
        target: "storm::heartbeat",
        peer_public_key = %hex::encode(context.peer_public_key),
        "heartbeat received"
    );
    Ok(())
}
