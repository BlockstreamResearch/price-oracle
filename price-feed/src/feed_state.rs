use std::collections::BTreeMap;

use crate::{
    clock::Clock,
    constants::{MAX_POLLING_ERROR_NUM, POLLING_RETRY_TIME},
    price_data::PriceFeedData,
    reduce::{MedianReducer, Reducer},
    registry::{FeedDefinition, FeedId, FeedRegistry},
    source::{SourceObservation, SourceState},
};

pub trait FeedAvailability {
    /// At least one source up, its freshest observation not past `valid_until`.
    fn is_available(&self) -> bool;

    /// Drops the source after `MAX_POLLING_ERROR_NUM` failures in a row.
    fn record_poll_failure(&mut self, source: usize);

    /// Resets the source's failure count.
    fn record_poll_success(&mut self, source: usize, obs: SourceObservation);

    /// The reduced value, or `None` while unavailable.
    fn value(&self) -> Option<PriceFeedData>;
}

#[derive(Clone, Debug, Default)]
struct SourceRecord {
    state: SourceState,
    failures: u32,
    observation: Option<SourceObservation>,
    /// When a `Dropped` source rejoins the polling cycle.
    retry_at: Option<u64>,
}

/// A Cross pair holds no observations of its own, so it stays unavailable.
#[derive(Clone, Debug)]
pub struct FeedState {
    definition: FeedDefinition,
    reducer: MedianReducer,
    clock: Clock,
    sources: BTreeMap<usize, SourceRecord>,
}

impl FeedState {
    pub fn new(definition: FeedDefinition, reducer: MedianReducer, clock: Clock) -> Self {
        Self {
            definition,
            reducer,
            clock,
            sources: BTreeMap::new(),
        }
    }

    pub fn state(&self, source: usize) -> SourceState {
        self.sources
            .get(&source)
            .map_or(SourceState::Active, |record| record.state)
    }

    /// Whether this cycle polls the source: active ones always, dropped ones
    /// once `POLLING_RETRY_TIME` has elapsed, frozen ones never.
    pub fn is_pollable(&self, source: usize) -> bool {
        let now = self.clock.now();
        self.sources
            .get(&source)
            .is_none_or(|record| match record.state {
                SourceState::Active => true,
                SourceState::Dropped => record.retry_at.is_some_and(|at| now >= at),
                SourceState::Frozen => false,
            })
    }

    /// Freezing keeps the source's observations, which expire on their own.
    pub fn freeze(&mut self, source: usize) {
        let record = self.sources.entry(source).or_default();
        record.state = SourceState::Frozen;
        record.retry_at = None;
    }

    pub fn unfreeze(&mut self, source: usize) {
        let record = self.sources.entry(source).or_default();
        record.state = SourceState::Active;
        record.failures = 0;
        record.retry_at = None;
    }

    fn valid_observations(&self) -> Vec<SourceObservation> {
        let now = self.clock.now();
        self.sources
            .values()
            .filter_map(|record| record.observation)
            .filter(|observation| observation.valid_until >= now)
            .collect()
    }
}

impl FeedAvailability for FeedState {
    fn is_available(&self) -> bool {
        let polled = self
            .sources
            .values()
            .any(|record| record.state == SourceState::Active);

        polled && !self.valid_observations().is_empty()
    }

    fn record_poll_failure(&mut self, source: usize) {
        let now = self.clock.now();
        let record = self.sources.entry(source).or_default();
        if record.state == SourceState::Frozen {
            return;
        }
        record.failures = record.failures.saturating_add(1);

        if record.failures >= MAX_POLLING_ERROR_NUM {
            record.state = SourceState::Dropped;
            record.observation = None;
            record.retry_at = Some(now.saturating_add(POLLING_RETRY_TIME));
        }
    }

    fn record_poll_success(&mut self, source: usize, obs: SourceObservation) {
        let record = self.sources.entry(source).or_default();
        if record.state == SourceState::Frozen {
            return;
        }
        record.state = SourceState::Active;
        record.failures = 0;
        record.retry_at = None;
        record.observation = Some(obs);
    }

    fn value(&self) -> Option<PriceFeedData> {
        if !self.is_available() {
            return None;
        }
        self.reducer
            .reduce(self.definition.id, &self.valid_observations())
    }
}

#[derive(Clone, Debug)]
pub struct FeedStates {
    states: BTreeMap<FeedId, FeedState>,
}

impl FeedStates {
    pub fn new(registry: &FeedRegistry, clock: Clock) -> Self {
        let reducer = MedianReducer::new(registry.clone());
        Self {
            states: registry
                .feeds()
                .map(|definition| {
                    (
                        definition.id,
                        FeedState::new(*definition, reducer.clone(), clock),
                    )
                })
                .collect(),
        }
    }

    pub fn get(&self, feed: FeedId) -> Option<&FeedState> {
        self.states.get(&feed)
    }

    pub fn get_mut(&mut self, feed: FeedId) -> Option<&mut FeedState> {
        self.states.get_mut(&feed)
    }
}

#[cfg(test)]
impl FeedState {
    /// `Clock::Fixed` is a frozen instant, so a test that needs time to pass
    /// swaps the clock rather than waiting.
    fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::VALIDITY_WINDOW, registry::FeedKind};

    const NOW: u64 = 1_700_000_000;

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
    fn holds_a_state_for_every_registered_feed() {
        let registry = FeedRegistry::default();
        let states = FeedStates::new(&registry, Clock::Fixed(NOW));
        let cross = registry
            .feeds()
            .find(|feed| feed.kind == FeedKind::Cross)
            .unwrap();

        for feed in registry.feeds() {
            assert!(states.get(feed.id).is_some());
        }
        assert!(!states.get(cross.id).unwrap().is_available());
        assert!(states.get(7).is_none());
    }
}
