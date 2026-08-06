use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    MessageContext, MessageError, StormMessage, StormMessageHeader, constants,
    message::StormErrorCode, message_handlers::StormMessagePayloadType,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ErrorPayload {
    pub(crate) code: StormErrorCode,
    pub(crate) message: String,
    pub(crate) request_payload_id: u32,
}

pub(crate) fn message(
    code: StormErrorCode,
    error_message: String,
    request_payload_id: u32,
) -> Result<StormMessage, MessageError> {
    let payload = ErrorPayload {
        code,
        message: error_message,
        request_payload_id,
    };

    Ok(StormMessage {
        header: StormMessageHeader {
            payload_id: StormMessagePayloadType::Error as u32,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: postcard::to_stdvec(&payload)?,
    })
}

pub(super) fn handle(
    context: MessageContext,
    message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    let error = decode(&message).map_err(|_| {
        (
            StormErrorCode::InvalidPayload,
            "Failed to deserialize Error payload".to_string(),
        )
    })?;

    log::error!(
        "Peer {} reported {:?}: {}; failed request payload_id={}",
        hex::encode(context.peer_public_key),
        error.code,
        error.message,
        error.request_payload_id,
    );

    Ok(())
}

pub(crate) fn decode(message: &StormMessage) -> Result<ErrorPayload, postcard::Error> {
    postcard::from_bytes(&message.payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_message_contains_code_message_and_request_payload_id() {
        let message = message(
            StormErrorCode::InvalidPayload,
            "invalid request".to_string(),
            42,
        )
        .unwrap();
        let payload = postcard::from_bytes::<ErrorPayload>(&message.payload).unwrap();

        assert_eq!(
            message.header.payload_id,
            StormMessagePayloadType::Error as u32
        );
        assert_eq!(message.header.protocol_version, constants::PROTOCOL_VERSION);
        assert_eq!(payload.code, StormErrorCode::InvalidPayload);
        assert_eq!(payload.message, "invalid request");
        assert_eq!(payload.request_payload_id, 42);
    }
}
