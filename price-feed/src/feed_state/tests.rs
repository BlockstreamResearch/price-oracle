use super::*;
use crate::{constants::VALIDITY_WINDOW, registry::Asset};

impl FeedState {
    /// `Clock::Fixed` is a frozen instant, so a test that needs time to pass
    /// swaps the clock rather than waiting.
    fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }
}

impl FeedStates {
    fn set_clock(&mut self, clock: Clock) {
        for state in self.states.values_mut() {
            state.set_clock(clock);
        }
    }
}

const NOW: u64 = 1_700_000_000;
const LBTC_USD: FeedId = 0;
const USDT_USD: FeedId = 1;
const LBTC_USDT: FeedId = 4;

fn feed_state(clock: Clock) -> FeedState {
    let registry = FeedRegistry::default();
    let definition = *registry.get(0).unwrap();
    let reducer = MedianReducer::new(registry);
    FeedState::new(definition, reducer, clock)
}

fn observation(price: u64, received_at: u64) -> SourceObservation {
    SourceObservation::new(price, 8, received_at, received_at)
}

#[test]
fn is_unavailable_until_a_source_reports() {
    let state = feed_state(Clock::Fixed(NOW));

    assert!(!state.is_available());
    assert_eq!(state.value(), None);
}

#[test]
fn reduces_the_observations_of_every_reporting_source() {
    let mut state = feed_state(Clock::Fixed(NOW));

    state.record_poll_success(0, observation(100, NOW));
    state.record_poll_success(1, observation(300, NOW));

    assert!(state.is_available());
    assert_eq!(state.value().unwrap().price, 200);
}

#[test]
fn keeps_only_the_latest_observation_of_a_source() {
    let mut state = feed_state(Clock::Fixed(NOW));

    state.record_poll_success(0, observation(100, NOW - 1));
    state.record_poll_success(0, observation(400, NOW));

    assert_eq!(state.value().unwrap().price, 400);
}

#[test]
fn stays_available_until_its_observation_expires() {
    let mut fresh = feed_state(Clock::Fixed(NOW + VALIDITY_WINDOW));
    fresh.record_poll_success(0, observation(100, NOW));

    assert!(fresh.is_available());

    let mut expired = feed_state(Clock::Fixed(NOW + VALIDITY_WINDOW + 1));
    expired.record_poll_success(0, observation(100, NOW));

    assert!(!expired.is_available());
    assert_eq!(expired.value(), None);
}

#[test]
fn reduces_only_the_sources_that_have_not_expired() {
    let mut state = feed_state(Clock::Fixed(NOW + VALIDITY_WINDOW + 1));
    state.record_poll_success(0, observation(100, NOW));
    state.record_poll_success(1, observation(400, NOW + 1));

    assert_eq!(state.value().unwrap().price, 400);
}

#[test]
fn drops_a_source_after_the_maximum_consecutive_failures() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_success(0, observation(100, NOW));
    state.record_poll_success(1, observation(300, NOW));

    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(1);
    }
    assert_eq!(state.value().unwrap().price, 200);

    state.record_poll_failure(1);

    assert_eq!(state.value().unwrap().price, 100);
}

#[test]
fn a_successful_poll_resets_the_failure_count() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_success(1, observation(300, NOW));

    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(0);
    }
    state.record_poll_success(0, observation(100, NOW));
    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(0);
    }

    // Without the reset, the source would already have been dropped.
    assert_eq!(state.value().unwrap().price, 200);
}

#[test]
fn retries_a_dropped_source_only_after_the_polling_retry_time() {
    let mut state = feed_state(Clock::Fixed(NOW));
    for _ in 0..MAX_POLLING_ERROR_NUM {
        state.record_poll_failure(0);
    }

    assert_eq!(state.state(0), SourceState::Dropped);
    assert!(!state.is_pollable(0));

    state.set_clock(Clock::Fixed(NOW + POLLING_RETRY_TIME - 1));
    assert!(!state.is_pollable(0));

    state.set_clock(Clock::Fixed(NOW + POLLING_RETRY_TIME));
    assert!(state.is_pollable(0));
}

#[test]
fn a_dropped_source_rejoins_on_its_first_successful_retry() {
    let mut state = feed_state(Clock::Fixed(NOW));
    for _ in 0..MAX_POLLING_ERROR_NUM {
        state.record_poll_failure(0);
    }
    state.record_poll_success(0, observation(100, NOW));

    assert_eq!(state.state(0), SourceState::Active);
    assert!(state.is_available());

    // The count reset on rejoining, so a full run is needed to drop again.
    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(0);
    }
    assert_eq!(state.state(0), SourceState::Active);
}

#[test]
fn is_unavailable_when_every_source_is_dropped_or_frozen() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_success(0, observation(100, NOW));
    state.record_poll_success(1, observation(300, NOW));

    state.freeze(1);
    for _ in 0..MAX_POLLING_ERROR_NUM {
        state.record_poll_failure(0);
    }

    assert_eq!(state.state(0), SourceState::Dropped);
    assert_eq!(state.state(1), SourceState::Frozen);
    assert!(!state.is_available());
    assert_eq!(state.value(), None);
}

#[test]
fn a_frozen_source_is_never_polled_or_retried() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.freeze(0);

    assert!(!state.is_pollable(0));

    // Freezing does not drop, so failures reported anyway change nothing.
    for _ in 0..MAX_POLLING_ERROR_NUM {
        state.record_poll_failure(0);
    }
    assert_eq!(state.state(0), SourceState::Frozen);

    state.set_clock(Clock::Fixed(NOW + POLLING_RETRY_TIME));
    assert!(!state.is_pollable(0));
}

#[test]
fn unfreezing_restores_an_active_source_with_its_observation() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_success(0, observation(100, NOW));
    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(0);
    }
    state.freeze(0);

    assert!(!state.is_available());

    state.unfreeze(0);

    assert!(state.is_available());
    assert_eq!(state.value().unwrap().price, 100);

    // The failure count started over with the unfreeze.
    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(0);
    }
    assert_eq!(state.state(0), SourceState::Active);
}

#[test]
fn a_frozen_source_does_not_price_the_feed() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_success(0, observation(100, NOW));
    state.record_poll_success(1, observation(1_000_000, NOW));

    state.freeze(1);

    // Priced by source 0 alone, not the median of the two.
    assert!(state.is_available());
    assert_eq!(state.value().unwrap().price, 100);

    // The observation is kept, so unfreezing brings it back.
    state.unfreeze(1);
    assert_eq!(state.value().unwrap().price, 500_050);
}

#[test]
fn a_feed_whose_only_reporting_source_is_frozen_is_unavailable() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.register(0);
    state.record_poll_success(1, observation(1_000_000, NOW));

    state.freeze(1);

    assert!(!state.is_available());
    assert_eq!(state.value(), None);
}

#[test]
fn unfreezing_a_source_that_is_not_frozen_keeps_its_drop_back_off() {
    let mut state = feed_state(Clock::Fixed(NOW));
    for _ in 0..MAX_POLLING_ERROR_NUM {
        state.record_poll_failure(0);
    }
    assert_eq!(state.state(0), SourceState::Dropped);

    state.unfreeze(0);

    // Still dropped, and still waiting out POLLING_RETRY_TIME.
    assert_eq!(state.state(0), SourceState::Dropped);
    assert!(!state.is_pollable(0));

    // An active source keeps the failures it has run up, too.
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_failure(0);
    state.unfreeze(0);
    for _ in 0..MAX_POLLING_ERROR_NUM - 1 {
        state.record_poll_failure(0);
    }
    assert_eq!(state.state(0), SourceState::Dropped);
}

#[test]
fn lists_a_registered_source_as_active_before_it_reports() {
    let mut state = feed_state(Clock::Fixed(NOW));
    assert!(!state.is_registered(0));

    state.register(0);

    assert!(state.is_registered(0));
    assert_eq!(
        state.sources().collect::<Vec<_>>(),
        [(
            0,
            SourceStatus {
                state: SourceState::Active,
                failures: 0,
                observation: None,
                retry_at: None,
            }
        )]
    );
    assert!(!state.is_available());
}

#[test]
fn registering_a_known_source_again_keeps_its_state() {
    let mut state = feed_state(Clock::Fixed(NOW));
    state.record_poll_success(0, observation(100, NOW));
    state.freeze(0);

    state.register(0);

    let (_, status) = state.sources().next().unwrap();
    assert_eq!(status.state, SourceState::Frozen);
    assert_eq!(status.observation, Some(observation(100, NOW)));
}

#[test]
fn reports_the_failures_and_retry_of_a_dropped_source() {
    let mut state = feed_state(Clock::Fixed(NOW));
    for _ in 0..MAX_POLLING_ERROR_NUM {
        state.record_poll_failure(0);
    }

    let (_, status) = state.sources().next().unwrap();
    assert_eq!(status.state, SourceState::Dropped);
    assert_eq!(status.failures, MAX_POLLING_ERROR_NUM);
    assert_eq!(status.retry_at, Some(NOW + POLLING_RETRY_TIME));
}

fn feed_states(clock: Clock) -> FeedStates {
    FeedStates::new(&FeedRegistry::default(), clock).unwrap()
}

fn observe(states: &mut FeedStates, feed: FeedId, price: u64, received_at: u64) {
    states
        .get_mut(feed)
        .unwrap()
        .record_poll_success(0, observation(price, received_at));
}

#[test]
fn prices_a_cross_pair_from_its_legs() {
    let mut states = feed_states(Clock::Fixed(NOW));
    observe(&mut states, LBTC_USD, 6_000_000_000_000, NOW - 20);
    observe(&mut states, USDT_USD, 80_000_000, NOW - 10);

    let value = states.value(LBTC_USDT).unwrap();

    assert_eq!(value.feed_id, LBTC_USDT);
    assert_eq!(value.price, 7_500_000_000_000);
    assert_eq!(value.decimals, 8);
    assert_eq!(value.received_at, NOW - 10);
    assert_eq!(value.valid_until, NOW - 20 + VALIDITY_WINDOW);
}

#[test]
fn keeps_a_cross_pair_value_until_a_leg_changes() {
    let mut states = feed_states(Clock::Fixed(NOW));
    observe(&mut states, LBTC_USD, 6_000_000_000_000, NOW);
    observe(&mut states, USDT_USD, 80_000_000, NOW);
    let first = states.value(LBTC_USDT).unwrap();

    states.set_clock(Clock::Fixed(NOW + 10));
    assert_eq!(states.value(LBTC_USDT), Some(first));

    observe(&mut states, USDT_USD, 75_000_000, NOW + 10);
    let second = states.value(LBTC_USDT).unwrap();

    assert_eq!(second.price, 8_000_000_000_000);
    assert_eq!(second.received_at, NOW + 10);
}

#[test]
fn prices_a_rebuilt_cross_pair_as_it_was_before_a_restart() {
    let mut before = feed_states(Clock::Fixed(NOW));
    let mut after = feed_states(Clock::Fixed(NOW + 30));
    for states in [&mut before, &mut after] {
        observe(states, LBTC_USD, 6_000_000_000_000, NOW - 20);
        observe(states, USDT_USD, 80_000_000, NOW - 10);
    }

    // Only the legs may tell two values apart, or a restarted node attests
    // an unchanged pair again.
    assert_eq!(after.value(LBTC_USDT), before.value(LBTC_USDT));
}

#[test]
fn a_cross_pair_is_unavailable_while_a_leg_is() {
    let mut states = feed_states(Clock::Fixed(NOW));
    observe(&mut states, LBTC_USD, 6_000_000_000_000, NOW);

    assert_eq!(states.value(LBTC_USDT), None);

    observe(&mut states, USDT_USD, 80_000_000, NOW);
    assert!(states.value(LBTC_USDT).is_some());

    states.set_clock(Clock::Fixed(NOW + VALIDITY_WINDOW + 1));
    assert_eq!(states.value(LBTC_USDT), None);
}

#[test]
fn refuses_a_registry_with_a_cross_pair_it_cannot_price() {
    let registry = FeedRegistry::new([
        FeedDefinition::new(0, Asset::Lbtc, Asset::Usd, FeedKind::Direct),
        FeedDefinition::new(1, Asset::DePix, Asset::Usdt, FeedKind::Cross),
    ]);

    assert_eq!(
        FeedStates::new(&registry, Clock::Fixed(NOW)).err(),
        Some(CrossPairError::NoRoute(1))
    );
}

#[test]
fn holds_a_state_for_every_direct_feed_only() {
    let registry = FeedRegistry::default();
    let states = FeedStates::new(&registry, Clock::Fixed(NOW)).unwrap();

    for feed in registry.feeds() {
        assert_eq!(states.get(feed.id).is_some(), feed.kind == FeedKind::Direct);
    }
    assert!(states.get(8).is_none());
}
