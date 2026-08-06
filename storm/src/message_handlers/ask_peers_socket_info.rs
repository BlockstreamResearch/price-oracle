use crate::{
    Error, MessageContext, StormHandle, StormMessage, message::StormErrorCode,
    message_handlers::peers_socket_info,
};

pub(super) async fn handle(
    storm: &StormHandle,
    context: MessageContext,
    _message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    let response = {
        let state = storm.inner.read().await;
        peers_socket_info::message(&state.peers)?
    };

    storm
        .send_message_by_public_keys(response, &[context.peer_public_key])
        .await
        .map_err(operation_error)
}

fn operation_error(error: Error) -> (StormErrorCode, String) {
    (StormErrorCode::Busy, error.to_string())
}
