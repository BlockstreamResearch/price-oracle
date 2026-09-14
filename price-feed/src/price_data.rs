use serde::{Deserialize, Serialize};

use crate::registry::FeedId;

pub const PRICE_FEED_DATA_LEN: usize = 32;

/// Payload signed under the `OracleNetworkV1/Price` tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceFeedData {
    pub feed_id: FeedId,
    pub price: u64,
    pub decimals: u32,
    pub received_at: u64,
    pub valid_until: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("price feed data must be {PRICE_FEED_DATA_LEN} bytes, got {0}")]
    InvalidLength(usize),
}

impl PriceFeedData {
    /// Canonical: two nodes signing the same value produce identical bytes.
    pub fn to_bytes(&self) -> [u8; PRICE_FEED_DATA_LEN] {
        let mut bytes = [0; PRICE_FEED_DATA_LEN];
        bytes[0..4].copy_from_slice(&self.feed_id.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.price.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.decimals.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.received_at.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.valid_until.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let bytes: [u8; PRICE_FEED_DATA_LEN] = bytes
            .try_into()
            .map_err(|_| DecodeError::InvalidLength(bytes.len()))?;
        Ok(Self {
            feed_id: u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")),
            price: u64::from_le_bytes(bytes[4..12].try_into().expect("8 bytes")),
            decimals: u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes")),
            received_at: u64::from_le_bytes(bytes[16..24].try_into().expect("8 bytes")),
            valid_until: u64::from_le_bytes(bytes[24..32].try_into().expect("8 bytes")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: PriceFeedData = PriceFeedData {
        feed_id: 4,
        price: 9_876_543_210,
        decimals: 8,
        received_at: 1_700_000_000,
        valid_until: 1_700_000_060,
    };

    #[test]
    fn lays_out_every_field_little_endian_at_its_offset() {
        let bytes = SAMPLE.to_bytes();

        assert_eq!(&bytes[0..4], &4u32.to_le_bytes());
        assert_eq!(&bytes[4..12], &9_876_543_210u64.to_le_bytes());
        assert_eq!(&bytes[12..16], &8u32.to_le_bytes());
        assert_eq!(&bytes[16..24], &1_700_000_000u64.to_le_bytes());
        assert_eq!(&bytes[24..32], &1_700_000_060u64.to_le_bytes());
    }

    #[test]
    fn round_trips_through_the_canonical_encoding() {
        assert_eq!(
            PriceFeedData::from_bytes(&SAMPLE.to_bytes()).unwrap(),
            SAMPLE
        );
    }

    #[test]
    fn rejects_any_length_other_than_the_canonical_one() {
        let bytes = SAMPLE.to_bytes();

        for length in [0, PRICE_FEED_DATA_LEN - 1, PRICE_FEED_DATA_LEN + 1] {
            let mut resized = bytes.to_vec();
            resized.resize(length, 0);

            assert_eq!(
                PriceFeedData::from_bytes(&resized),
                Err(DecodeError::InvalidLength(length))
            );
        }
    }
}
