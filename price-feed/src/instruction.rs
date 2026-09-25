use crate::{
    constants::{MAX_ACCEPT_DEVIATION_FEED_BPS, MAX_CLOCK_SKEW, VALIDITY_WINDOW},
    price_data::PriceFeedData,
    registry::FeedRegistry,
};

const BASIS_POINTS: u128 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("the instructed feed is not in the registry")]
    UnknownFeed,
    #[error("the signer holds no valid price of its own for the feed")]
    NoLocalPrice,
    #[error("the instructed price is past its validity")]
    Stale,
    #[error("the instructed price is stamped further ahead than a clock explains")]
    ImplausibleTimestamp,
    #[error("the instructed price is valid for longer than the validity window")]
    StretchedValidity,
    #[error("the instructed price is not quoted at the decimals of its feed")]
    WrongDecimals,
    #[error("the instructed price deviates from the signer's own by more than the bound")]
    DeviationExceeded,
}

/// Whether a signer accepts an instructed rate. `own` is its own value for the
/// same feed, `None` while that feed is unavailable.
pub fn validate(
    instructed: &PriceFeedData,
    registry: &FeedRegistry,
    own: Option<PriceFeedData>,
    now: u64,
) -> Result<(), ValidationError> {
    let Some(definition) = registry.get(instructed.feed_id) else {
        return Err(ValidationError::UnknownFeed);
    };
    let own = own.ok_or(ValidationError::NoLocalPrice)?;
    // The covenant spends a price only while `now` is strictly before
    // `valid_until`, so a rate accepted here at that second signs unusably.
    if now >= instructed.valid_until {
        return Err(ValidationError::Stale);
    }
    // The coordinator's clock may run ahead of this one by the skew.
    if instructed.received_at > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(ValidationError::ImplausibleTimestamp);
    }
    // Or an old price beside a fresh validity signs as a current rate.
    if instructed.valid_until > instructed.received_at.saturating_add(VALIDITY_WINDOW) {
        return Err(ValidationError::StretchedValidity);
    }
    if instructed.decimals != definition.decimals {
        return Err(ValidationError::WrongDecimals);
    }
    if !within_deviation(instructed.price, own.price) {
        return Err(ValidationError::DeviationExceeded);
    }
    Ok(())
}

/// `instructed·(1 − d) < own < instructed·(1 + d)`, multiplied out so the bound
/// keeps its precision on a small price, in u128 so no product overflows.
fn within_deviation(instructed: u64, own: u64) -> bool {
    let (instructed, own) = (u128::from(instructed), u128::from(own));

    instructed.abs_diff(own) * BASIS_POINTS < instructed * u128::from(MAX_ACCEPT_DEVIATION_FEED_BPS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::FeedId;

    const NOW: u64 = 1_700_000_000;
    const LBTC_USD: FeedId = 0;

    fn price(feed: FeedId, price: u64) -> PriceFeedData {
        PriceFeedData {
            feed_id: feed,
            price,
            decimals: 8,
            received_at: NOW - 10,
            valid_until: NOW + 60,
        }
    }

    fn validate_against(
        instructed: PriceFeedData,
        own: Option<PriceFeedData>,
    ) -> Result<(), ValidationError> {
        validate(&instructed, &FeedRegistry::default(), own, NOW)
    }

    #[test]
    fn accepts_a_rate_the_signer_holds_within_the_bound() {
        let instructed = price(LBTC_USD, 10_000_000_000);
        let own = price(LBTC_USD, 10_099_000_000);

        assert_eq!(validate_against(instructed, Some(own)), Ok(()));
    }

    #[test]
    fn rejects_a_rate_for_a_feed_outside_the_registry() {
        let instructed = price(99, 10_000_000_000);

        assert_eq!(
            validate_against(instructed, Some(price(99, 10_000_000_000))),
            Err(ValidationError::UnknownFeed)
        );
    }

    #[test]
    fn rejects_a_rate_while_the_signer_has_no_price_of_its_own() {
        let instructed = price(LBTC_USD, 10_000_000_000);

        assert_eq!(
            validate_against(instructed, None),
            Err(ValidationError::NoLocalPrice)
        );
    }

    #[test]
    fn rejects_a_rate_the_node_clock_has_passed() {
        let own = price(LBTC_USD, 10_000_000_000);
        let expired = PriceFeedData {
            valid_until: NOW - 1,
            ..own
        };
        // The covenant reads the second it expires in as expired, so this side
        // does too, and the last second it signs for is the one before.
        let expiring = PriceFeedData {
            valid_until: NOW,
            ..own
        };
        let last = PriceFeedData {
            valid_until: NOW + 1,
            ..own
        };

        assert_eq!(
            validate_against(expired, Some(own)),
            Err(ValidationError::Stale)
        );
        assert_eq!(
            validate_against(expiring, Some(own)),
            Err(ValidationError::Stale)
        );
        assert_eq!(validate_against(last, Some(own)), Ok(()));
    }

    #[test]
    fn rejects_a_rate_stamped_further_ahead_than_a_clock_explains() {
        let own = price(LBTC_USD, 10_000_000_000);
        let ahead = PriceFeedData {
            received_at: NOW + MAX_CLOCK_SKEW + 1,
            ..own
        };

        assert_eq!(
            validate_against(ahead, Some(own)),
            Err(ValidationError::ImplausibleTimestamp)
        );
        // A coordinator whose clock leads by the skew still signs.
        assert_eq!(
            validate_against(
                PriceFeedData {
                    received_at: NOW + MAX_CLOCK_SKEW,
                    valid_until: NOW + MAX_CLOCK_SKEW + VALIDITY_WINDOW,
                    ..own
                },
                Some(own)
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_a_rate_valid_for_longer_than_the_window() {
        let own = price(LBTC_USD, 10_000_000_000);
        let forever = PriceFeedData {
            valid_until: u64::MAX,
            ..own
        };
        // An old price cannot be given a fresh validity.
        let stretched = PriceFeedData {
            received_at: NOW - VALIDITY_WINDOW - 1,
            valid_until: NOW + VALIDITY_WINDOW,
            ..own
        };
        // A Direct feed of one source is valid for exactly the window.
        let whole_window = PriceFeedData {
            received_at: NOW - 10,
            valid_until: NOW - 10 + VALIDITY_WINDOW,
            ..own
        };

        assert_eq!(
            validate_against(forever, Some(own)),
            Err(ValidationError::StretchedValidity)
        );
        assert_eq!(
            validate_against(stretched, Some(own)),
            Err(ValidationError::StretchedValidity)
        );
        assert_eq!(validate_against(whole_window, Some(own)), Ok(()));
    }

    #[test]
    fn rejects_a_rate_further_than_the_bound_from_its_own_either_way() {
        let instructed = price(LBTC_USD, 10_000_000_000);
        let above = price(LBTC_USD, 10_100_000_000);
        let below = price(LBTC_USD, 9_900_000_000);

        // The bound itself is not within it.
        assert_eq!(
            validate_against(instructed, Some(above)),
            Err(ValidationError::DeviationExceeded)
        );
        assert_eq!(
            validate_against(instructed, Some(below)),
            Err(ValidationError::DeviationExceeded)
        );
    }

    #[test]
    fn rejects_a_rate_quoted_at_other_decimals_than_its_feed() {
        let own = price(LBTC_USD, 100_000_000);
        let instructed = PriceFeedData { decimals: 6, ..own };

        assert_eq!(
            validate_against(instructed, Some(own)),
            Err(ValidationError::WrongDecimals)
        );
    }

    #[test]
    fn keeps_the_bound_on_a_price_of_a_few_units() {
        let instructed = price(LBTC_USD, 50);
        let same = price(LBTC_USD, 50);
        let off_by_one = price(LBTC_USD, 51);

        // A percent of 50 rounds to nothing, which is not a bound of nothing.
        assert_eq!(validate_against(instructed, Some(same)), Ok(()));
        assert_eq!(
            validate_against(instructed, Some(off_by_one)),
            Err(ValidationError::DeviationExceeded)
        );
    }

    #[test]
    fn reports_the_first_failure_of_an_instruction_that_fails_several() {
        let expired_unknown = PriceFeedData {
            valid_until: NOW,
            ..price(99, 1)
        };

        assert_eq!(
            validate_against(expired_unknown, None),
            Err(ValidationError::UnknownFeed)
        );
    }
}
