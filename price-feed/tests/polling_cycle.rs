use price_feed::{
    Clock, ConnectionError, FeedAvailability, FeedId, FeedRegistry, FeedState, FeedStates,
    PriceFeedData, PriceSource, RejectionReason, SourceObservation, SourceState,
    constants::{MAX_POLLING_ERROR_NUM, VALIDITY_WINDOW},
};

const NOW: u64 = 1_700_000_000;
const LBTC_USD: FeedId = 0;

enum Exchange {
    /// Answers every poll with the same observation.
    Quotes(u64),
    Unreachable,
}

impl PriceSource for Exchange {
    async fn poll(&self, _feed: FeedId) -> Result<SourceObservation, ConnectionError> {
        match self {
            Self::Quotes(price) => Ok(SourceObservation::new(*price, 8, NOW, NOW)),
            Self::Unreachable => Err(ConnectionError::RequestFailure),
        }
    }
}

/// One polling cycle over `sources`, the way a node runs it: poll what is
/// pollable, validate the answer, and record either outcome. An answer the
/// source already published is neither recorded nor a failure.
async fn poll_once(state: &mut FeedState, sources: &[Exchange]) {
    for (index, source) in sources.iter().enumerate() {
        if !state.is_pollable(index) {
            continue;
        }
        match source.poll(LBTC_USD).await {
            Ok(observation) => {
                match Exchange::validate(&observation, state.last_observed_at(index)) {
                    Ok(()) => state.record_poll_success(index, observation),
                    Err(RejectionReason::StaleObservation) => {}
                    Err(_) => state.record_poll_failure(index),
                }
            }
            Err(_) => state.record_poll_failure(index),
        }
    }
}

#[tokio::test]
async fn reduces_a_polling_cycle_to_a_signable_price() {
    let registry = FeedRegistry::default();
    let mut states = FeedStates::new(&registry, Clock::Fixed(NOW)).unwrap();
    let sources = [Exchange::Quotes(100), Exchange::Quotes(300)];

    poll_once(states.get_mut(LBTC_USD).unwrap(), &sources).await;

    let value = states.get(LBTC_USD).unwrap().value().unwrap();

    assert_eq!(value.feed_id, LBTC_USD);
    assert_eq!(value.price, 200);
    assert_eq!(value.decimals, 8);
    assert_eq!(value.received_at, NOW);
    // What one node signs is what its peers decode.
    assert_eq!(PriceFeedData::from_bytes(&value.to_bytes()).unwrap(), value);
}

#[tokio::test]
async fn serves_the_surviving_source_once_the_unreachable_one_is_dropped() {
    let registry = FeedRegistry::default();
    let mut states = FeedStates::new(&registry, Clock::Fixed(NOW)).unwrap();
    let sources = [Exchange::Quotes(100), Exchange::Unreachable];
    let state = states.get_mut(LBTC_USD).unwrap();

    for _ in 0..MAX_POLLING_ERROR_NUM {
        poll_once(state, &sources).await;
    }

    assert_eq!(state.state(1), SourceState::Dropped);
    assert_eq!(state.state(0), SourceState::Active);
    assert_eq!(state.value().unwrap().price, 100);
}

#[tokio::test]
async fn stays_unavailable_while_no_source_answers() {
    let registry = FeedRegistry::default();
    let mut states = FeedStates::new(&registry, Clock::Fixed(NOW)).unwrap();
    let sources = [Exchange::Unreachable, Exchange::Unreachable];
    let state = states.get_mut(LBTC_USD).unwrap();

    for _ in 0..MAX_POLLING_ERROR_NUM {
        poll_once(state, &sources).await;
    }

    assert!(!state.is_available());
    assert_eq!(state.value(), None);
}

#[tokio::test]
async fn keeps_polling_a_source_that_republishes_while_its_observation_expires() {
    let registry = FeedRegistry::default();
    // A window after the source's only observation was received.
    let mut states = FeedStates::new(&registry, Clock::Fixed(NOW + VALIDITY_WINDOW + 1)).unwrap();
    let sources = [Exchange::Quotes(100)];
    let state = states.get_mut(LBTC_USD).unwrap();

    // Publishing nothing new is not a failed poll, so a stuck source is never
    // dropped: it stays in the cycle and costs a request on every one.
    for _ in 0..=MAX_POLLING_ERROR_NUM {
        poll_once(state, &sources).await;
    }
    assert_eq!(state.state(0), SourceState::Active);
    assert!(state.is_pollable(0));

    // Its observation expires regardless, and the feed goes unavailable.
    assert!(!state.is_available());
}
