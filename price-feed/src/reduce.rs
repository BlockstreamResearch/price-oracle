use crate::{
    price_data::PriceFeedData,
    registry::{FeedId, FeedRegistry},
    source::SourceObservation,
};

/// Reduces a feed's valid observations to one price, alike on every node.
pub trait Reducer {
    fn reduce(&self, feed: FeedId, valid_obs: &[SourceObservation]) -> Option<PriceFeedData>;
}

#[derive(Clone, Debug)]
pub struct MedianReducer {
    registry: FeedRegistry,
}

impl MedianReducer {
    pub fn new(registry: FeedRegistry) -> Self {
        Self { registry }
    }
}

impl Reducer for MedianReducer {
    fn reduce(&self, feed: FeedId, valid_obs: &[SourceObservation]) -> Option<PriceFeedData> {
        let decimals = self.registry.get(feed)?.decimals;
        if valid_obs.is_empty()
            || valid_obs
                .iter()
                .any(|observation| observation.decimals != decimals)
        {
            return None;
        }

        Some(PriceFeedData {
            feed_id: feed,
            price: median(valid_obs)?,
            decimals,
            received_at: valid_obs
                .iter()
                .map(|observation| observation.received_at)
                .min()?,
            valid_until: valid_obs
                .iter()
                .map(|observation| observation.valid_until)
                .min()?,
        })
    }
}

fn median(observations: &[SourceObservation]) -> Option<u64> {
    let mut prices: Vec<u64> = observations
        .iter()
        .map(|observation| observation.price)
        .collect();
    prices.sort_unstable();

    let middle = prices.len() / 2;
    if prices.len() % 2 == 1 {
        return Some(prices[middle]);
    }

    let sum = u128::from(prices[middle - 1]) + u128::from(prices[middle]);
    let half = sum / 2;
    let rounded = if sum % 2 == 1 && half % 2 == 1 {
        half + 1
    } else {
        half
    };
    u64::try_from(rounded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::VALIDITY_WINDOW;

    const NOW: u64 = 1_700_000_000;

    fn reducer() -> MedianReducer {
        MedianReducer::new(FeedRegistry::default())
    }

    fn observations(prices: &[u64]) -> Vec<SourceObservation> {
        prices
            .iter()
            .enumerate()
            .map(|(index, price)| SourceObservation::new(*price, 8, NOW - 1, NOW - index as u64))
            .collect()
    }

    #[test]
    fn reduces_a_single_source_to_its_own_price() {
        let reduced = reducer().reduce(0, &observations(&[500])).unwrap();

        assert_eq!(reduced.price, 500);
        assert_eq!(reduced.decimals, 8);
        assert_eq!(reduced.feed_id, 0);
    }

    #[test]
    fn takes_the_middle_value_of_an_odd_count() {
        let reduced = reducer()
            .reduce(0, &observations(&[300, 100, 200]))
            .unwrap();

        assert_eq!(reduced.price, 200);
    }

    #[test]
    fn ignores_outliers_beyond_the_two_middle_values() {
        let reduced = reducer()
            .reduce(0, &observations(&[100, 200, 400, 500]))
            .unwrap();

        assert_eq!(reduced.price, 300);
    }

    #[test]
    fn resolves_an_exact_half_to_the_even_neighbour() {
        let down = reducer().reduce(0, &observations(&[100, 101])).unwrap();
        let up = reducer().reduce(0, &observations(&[101, 102])).unwrap();

        assert_eq!(down.price, 100);
        assert_eq!(up.price, 102);
    }

    #[test]
    fn holds_the_median_of_the_largest_prices_a_feed_can_carry() {
        let reduced = reducer()
            .reduce(0, &observations(&[u64::MAX, u64::MAX - 2]))
            .unwrap();

        assert_eq!(reduced.price, u64::MAX - 1);
    }

    #[test]
    fn stamps_the_stalest_leg() {
        let reduced = reducer().reduce(0, &observations(&[100, 200])).unwrap();

        assert_eq!(reduced.received_at, NOW - 1);
        assert_eq!(reduced.valid_until, reduced.received_at + VALIDITY_WINDOW);
    }

    #[test]
    fn reduces_nothing_without_observations_or_a_registered_feed() {
        assert_eq!(reducer().reduce(0, &[]), None);
        assert_eq!(reducer().reduce(99, &observations(&[100])), None);
    }

    #[test]
    fn reduces_nothing_when_a_source_reports_another_scale() {
        let mut mismatched = observations(&[100, 200]);
        mismatched[1].decimals = 6;

        assert_eq!(reducer().reduce(0, &mismatched), None);
    }
}
