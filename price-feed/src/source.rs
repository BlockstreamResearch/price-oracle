use std::future::Future;

use serde::{Deserialize, Serialize};

use crate::{
    constants::{MAX_CLOCK_SKEW, SOURCE_DATA_VALIDITY_DURATION, VALIDITY_WINDOW},
    registry::FeedId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceObservation {
    pub price: u64,
    pub decimals: u32,
    pub observed_at: u64,
    pub received_at: u64,
    pub valid_until: u64,
}

impl SourceObservation {
    pub fn new(price: u64, decimals: u32, observed_at: u64, received_at: u64) -> Self {
        Self {
            price,
            decimals,
            observed_at,
            received_at,
            valid_until: received_at.saturating_add(VALIDITY_WINDOW),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    #[error("the source could not be reached")]
    // refused, timeout, TLS failure, non-2xx HTTP
    RequestFailure,

    #[error("the source answer is unparseable or missing fields")]
    // answered, but unparseable or missing fields
    MalformedResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RejectionReason {
    #[error("the observed price is not a usable value")]
    // zero, negative, non-numeric, or u64 overflow
    InvalidPrice,

    #[error("the source data is older than the source data validity duration")]
    // now - observed_at > SOURCE_DATA_VALIDITY_DURATION
    Expired,

    #[error("the source clock runs ahead by more than the tolerated skew")]
    // observed_at > received_at + MAX_CLOCK_SKEW
    ClockSkewExceeded,

    #[error("the source has published nothing new")]
    // observed_at not greater than the last for this source
    StaleObservation,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceState {
    #[default]
    Active, // polled on every cycle
    Dropped, // MAX_POLLING_ERROR_NUM failures in a row
    Frozen,  // disabled by the operator; not polled and not retried
}

pub trait PriceSource {
    fn poll(
        &self,
        feed: FeedId,
    ) -> impl Future<Output = Result<SourceObservation, ConnectionError>> + Send;

    /// `last_observed_at` is the `observed_at` last recorded for this source.
    fn validate(
        obs: &SourceObservation,
        last_observed_at: Option<u64>,
    ) -> Result<(), RejectionReason> {
        let behind = obs.received_at.saturating_sub(obs.observed_at);
        let ahead = obs.observed_at.saturating_sub(obs.received_at);

        if obs.price == 0 {
            return Err(RejectionReason::InvalidPrice);
        }
        if behind > SOURCE_DATA_VALIDITY_DURATION {
            return Err(RejectionReason::Expired);
        }
        if ahead > MAX_CLOCK_SKEW {
            return Err(RejectionReason::ClockSkewExceeded);
        }
        if last_observed_at.is_some_and(|last| obs.observed_at <= last) {
            return Err(RejectionReason::StaleObservation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    struct Source;

    impl PriceSource for Source {
        async fn poll(&self, _feed: FeedId) -> Result<SourceObservation, ConnectionError> {
            unreachable!("validation never polls")
        }
    }

    fn observation() -> SourceObservation {
        SourceObservation::new(100, 8, NOW, NOW)
    }

    #[test]
    fn closes_the_validity_window_one_window_after_receipt() {
        assert_eq!(observation().valid_until, NOW + VALIDITY_WINDOW);
        assert_eq!(
            SourceObservation::new(100, 8, NOW, u64::MAX).valid_until,
            u64::MAX
        );
    }

    #[test]
    fn accepts_a_fresh_observation() {
        assert_eq!(Source::validate(&observation(), None), Ok(()));
    }

    #[test]
    fn rejects_a_zero_price() {
        let observation = SourceObservation::new(0, 8, NOW, NOW);

        assert_eq!(
            Source::validate(&observation, None),
            Err(RejectionReason::InvalidPrice)
        );
    }

    #[test]
    fn rejects_source_data_older_than_the_validity_duration() {
        let stamped = NOW - SOURCE_DATA_VALIDITY_DURATION - 1;

        assert_eq!(
            Source::validate(&SourceObservation::new(100, 8, stamped, NOW), None),
            Err(RejectionReason::Expired)
        );
        assert_eq!(
            Source::validate(&SourceObservation::new(100, 8, stamped + 1, NOW), None),
            Ok(())
        );
    }

    #[test]
    fn rejects_an_observation_the_source_already_published() {
        let obs = observation();

        // Equal and older both mean the source published nothing new.
        assert_eq!(
            Source::validate(&obs, Some(obs.observed_at)),
            Err(RejectionReason::StaleObservation)
        );
        assert_eq!(
            Source::validate(&obs, Some(obs.observed_at + 1)),
            Err(RejectionReason::StaleObservation)
        );
        assert_eq!(Source::validate(&obs, Some(obs.observed_at - 1)), Ok(()));
    }

    #[test]
    fn rejects_a_source_clock_beyond_the_tolerated_skew() {
        let ahead = NOW + MAX_CLOCK_SKEW;

        assert_eq!(
            Source::validate(&SourceObservation::new(100, 8, ahead + 1, NOW), None),
            Err(RejectionReason::ClockSkewExceeded)
        );
        assert_eq!(
            Source::validate(&SourceObservation::new(100, 8, ahead, NOW), None),
            Ok(())
        );
    }
}
