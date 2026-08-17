use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;

use crate::{
    MessageContext, StormMessage, StormMessageHeader, StormState, constants,
    message::StormErrorCode, message_handlers::StormMessagePayloadType,
};

pub(crate) fn message() -> StormMessage {
    StormMessage {
        header: StormMessageHeader {
            payload_id: StormMessagePayloadType::Heartbeat as u32,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    }
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
