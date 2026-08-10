use serde::{Deserialize, Serialize};

/// Maximum encoded application message size, in bytes.
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;
const MESSAGE_LENGTH_SIZE: usize = size_of::<u32>();

/// Metadata attached to a [`StormMessage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StormMessageHeader {
    /// Numeric identifier used to select the payload handler.
    pub payload_id: u32,
    /// Message creation time as seconds since the Unix epoch.
    ///
    /// Receivers reject messages outside the protocol's clock-skew window and
    /// recently received messages with the same authenticated contents.
    pub timestamp: u64,
    /// Storm protocol version used to construct the message.
    pub protocol_version: u32,
}

/// A protocol header and its encoded application payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StormMessage {
    /// Routing and protocol metadata.
    pub header: StormMessageHeader,
    /// Handler-specific encoded payload.
    pub payload: Vec<u8>,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum StormErrorCode {
    InvalidPayload = 0,
    UnsupportedVersion,
    Busy,
    Unauthorized,
    InternalError,
}

impl StormMessage {
    /// Serializes this message with postcard.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let bytes = postcard::to_stdvec(self)?;
        validate_message_size(bytes.len())?;
        Ok(bytes)
    }

    /// Deserializes a postcard-encoded message after checking its size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        validate_message_size(bytes.len())?;
        Ok(postcard::from_bytes(bytes)?)
    }

    /// Serializes this message with a four-byte, big-endian length prefix.
    pub fn to_framed_bytes(&self) -> Result<Vec<u8>, MessageError> {
        let bytes = self.to_bytes()?;
        let length = u32::try_from(bytes.len()).map_err(|_| MessageError::TooLarge {
            size: bytes.len(),
            max: MAX_MESSAGE_SIZE,
        })?;
        let mut framed = Vec::with_capacity(MESSAGE_LENGTH_SIZE + bytes.len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&bytes);
        Ok(framed)
    }
}

/// Errors produced while encoding or decoding application messages.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// The encoded message exceeds [`MAX_MESSAGE_SIZE`].
    #[error("message is {size} bytes; maximum is {max} bytes")]
    TooLarge {
        /// Actual encoded size in bytes.
        size: usize,
        /// Maximum accepted size in bytes.
        max: usize,
    },
    /// Postcard could not encode or decode the message.
    #[error("postcard codec error: {0}")]
    Postcard(#[from] postcard::Error),
}

#[derive(Default)]
pub(super) struct MessageDecoder {
    length_bytes: [u8; MESSAGE_LENGTH_SIZE],
    length_bytes_read: usize,
    expected_length: Option<usize>,
    message_bytes: Vec<u8>,
}

impl MessageDecoder {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn push(&mut self, mut bytes: &[u8]) -> Result<Vec<StormMessage>, MessageError> {
        let mut messages = Vec::new();

        while !bytes.is_empty() {
            if self.expected_length.is_none() {
                let needed = MESSAGE_LENGTH_SIZE - self.length_bytes_read;
                let copied = needed.min(bytes.len());
                self.length_bytes[self.length_bytes_read..self.length_bytes_read + copied]
                    .copy_from_slice(&bytes[..copied]);
                self.length_bytes_read += copied;
                bytes = &bytes[copied..];

                if self.length_bytes_read < MESSAGE_LENGTH_SIZE {
                    continue;
                }

                let expected_length = u32::from_be_bytes(self.length_bytes) as usize;
                validate_message_size(expected_length)?;
                self.expected_length = Some(expected_length);
                self.message_bytes = Vec::with_capacity(expected_length);
            }

            let expected_length = self.expected_length.expect("length was decoded");
            let needed = expected_length - self.message_bytes.len();
            let copied = needed.min(bytes.len());
            self.message_bytes.extend_from_slice(&bytes[..copied]);
            bytes = &bytes[copied..];

            if self.message_bytes.len() == expected_length {
                messages.push(StormMessage::from_bytes(&self.message_bytes)?);
                self.reset();
            }
        }

        Ok(messages)
    }

    fn reset(&mut self) {
        self.length_bytes = [0; MESSAGE_LENGTH_SIZE];
        self.length_bytes_read = 0;
        self.expected_length = None;
        self.message_bytes = Vec::new();
    }
}

fn validate_message_size(size: usize) -> Result<(), MessageError> {
    if size > MAX_MESSAGE_SIZE {
        return Err(MessageError::TooLarge {
            size,
            max: MAX_MESSAGE_SIZE,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(payload: Vec<u8>) -> StormMessage {
        StormMessage {
            header: StormMessageHeader {
                payload_id: 7,
                timestamp: 1_754_326_800,
                protocol_version: crate::constants::PROTOCOL_VERSION,
            },
            payload,
        }
    }

    #[test]
    fn postcard_round_trip() {
        let message = message(vec![1, 2, 3, 4]);
        let encoded = message.to_bytes().unwrap();

        assert_eq!(StormMessage::from_bytes(&encoded).unwrap(), message);
    }

    #[test]
    fn decoder_reassembles_a_message_from_multiple_records() {
        let message = message(vec![42; 128 * 1024]);
        let framed = message.to_framed_bytes().unwrap();
        let mut decoder = MessageDecoder::new();
        let mut decoded = Vec::new();

        for chunk in framed.chunks(60_000) {
            decoded.extend(decoder.push(chunk).unwrap());
        }

        assert_eq!(decoded, vec![message]);
    }

    #[test]
    fn decoder_rejects_an_oversized_length_before_receiving_payload() {
        let mut decoder = MessageDecoder::new();
        let oversized = u32::try_from(MAX_MESSAGE_SIZE + 1).unwrap().to_be_bytes();

        assert!(matches!(
            decoder.push(&oversized),
            Err(MessageError::TooLarge { .. })
        ));
    }
}
