use serde::{Deserialize, Serialize};

use crate::{
    MessageContext, MessageError, StormContext, StormHandle, StormMessage, message::StormErrorCode,
};

/// An application-defined payload namespaced by a domain string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomMsg {
    /// Application namespace used to interpret the payload.
    pub domain: String,
    /// Opaque application bytes.
    pub payload: Vec<u8>,
}

impl CustomMsg {
    /// Encodes this custom payload as a versioned [`StormMessage`].
    pub fn into_storm_message(self) -> Result<StormMessage, MessageError> {
        let payload = postcard::to_stdvec(&self)?;

        Ok(StormMessage::new(
            super::StormMessagePayloadType::Custom,
            payload,
        ))
    }
}

pub(super) async fn handle(
    storm: &StormHandle,
    message_context: MessageContext,
    message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    let custom_message = postcard::from_bytes(&message.payload).map_err(|_| {
        (
            StormErrorCode::InvalidPayload,
            "Failed to deserialize Custom payload".to_string(),
        )
    })?;
    let handler = storm.inner.read().await.custom_handler.clone();

    if let Some(handler) = handler {
        let context = StormContext {
            storm_handle: storm.clone(),
            storm_message: message,
            message_context,
        };
        handler(custom_message, context).await;
    }

    Ok(())
}
