use crate::{
    Error, MessageContext, StormHandle, StormMessage, StormMessageHeader, constants,
    message::StormErrorCode,
    message_handlers::{StormMessagePayloadType, peers_socket_info},
};

pub(crate) fn message() -> StormMessage {
    StormMessage {
        header: StormMessageHeader {
            payload_id: StormMessagePayloadType::AskPeersSocketInfo as u32,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    }
}

pub(super) async fn handle(
    storm: &StormHandle,
    context: MessageContext,
    _message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    let response = {
        let state = storm.inner.read().await;
        if state.migration_contains(&context.peer_public_key) {
            if !state.migration_ready() {
                return Err((
                    StormErrorCode::Busy,
                    "Member migration is waiting for target peers".to_string(),
                ));
            }
            peers_socket_info::message(&state.migration_peers)?
        } else {
            peers_socket_info::message(&state.peers)?
        }
    };

    storm
        .send_message_by_public_keys(response, &[context.peer_public_key])
        .await
        .map_err(operation_error)
}

fn operation_error(error: Error) -> (StormErrorCode, String) {
    (StormErrorCode::Busy, error.to_string())
}
