pub(crate) mod ask_peers_socket_info;
pub(crate) mod custom;
pub(crate) mod error;
pub(crate) mod heartbeat;
pub(crate) mod peers_socket_info;

use crate::{MessageContext, StormHandle, StormMessage, constants, message::StormErrorCode};

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StormMessagePayloadType {
    Heartbeat = 0,
    AskPeersSocketInfo,
    PeersSocketInfo,
    Error,
    Custom,
}

impl TryFrom<u32> for StormMessagePayloadType {
    type Error = StormErrorCode;

    fn try_from(value: u32) -> Result<Self, StormErrorCode> {
        match value {
            0 => Ok(StormMessagePayloadType::Heartbeat),
            1 => Ok(StormMessagePayloadType::AskPeersSocketInfo),
            2 => Ok(StormMessagePayloadType::PeersSocketInfo),
            3 => Ok(StormMessagePayloadType::Error),
            4 => Ok(StormMessagePayloadType::Custom),
            _ => Err(StormErrorCode::InvalidPayload),
        }
    }
}

pub(super) fn is_error(message: &StormMessage) -> bool {
    message.header.payload_id == StormMessagePayloadType::Error as u32
}

pub(super) async fn storm_message(
    storm: &StormHandle,
    context: MessageContext,
    message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    if message.header.protocol_version != constants::PROTOCOL_VERSION {
        return Err((
            StormErrorCode::UnsupportedVersion,
            format!(
                "Unsupported protocol version {}; expected {}",
                message.header.protocol_version,
                constants::PROTOCOL_VERSION
            ),
        ));
    }

    let payload_type = StormMessagePayloadType::try_from(message.header.payload_id)
        .map_err(|error| (error, "Unsupported payload ID".to_string()))?;

    match payload_type {
        StormMessagePayloadType::Heartbeat => {
            heartbeat::handle(&storm.inner, context, message).await
        }
        StormMessagePayloadType::AskPeersSocketInfo => {
            ask_peers_socket_info::handle(storm, context, message).await
        }
        StormMessagePayloadType::PeersSocketInfo => {
            peers_socket_info::handle(storm, context, message).await
        }
        StormMessagePayloadType::Error => error::handle(context, message),
        StormMessagePayloadType::Custom => custom::handle(storm, context, message).await,
    }
}
