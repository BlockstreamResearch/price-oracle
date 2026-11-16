use std::collections::BTreeMap;

use crate::{
    clock::Clock,
    constants::{MAX_POLLING_ERROR_NUM, POLLING_RETRY_TIME},
    cross::{self, ComputationPath, CrossPairError},
    price_data::PriceFeedData,
    reduce::{MedianReducer, Reducer},
    registry::{FeedDefinition, FeedId, FeedKind, FeedRegistry},
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

/// What a node operator sees of one source of a feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceStatus {
    pub state: SourceState,
    /// Failed polls in a row.
    pub failures: u32,
    /// The latest one kept, expired or not.
    pub observation: Option<SourceObservation>,
    /// When a `Dropped` source is polled again.
    pub retry_at: Option<u64>,
}

impl From<&SourceRecord> for SourceStatus {
    fn from(record: &SourceRecord) -> Self {
        Self {
            state: record.state,
            failures: record.failures,
            observation: record.observation,
            retry_at: record.retry_at,
        }
    }
}

/// A Direct feed's sources and what they observed.
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

    /// Lists the source before it first reports, so an operator can see it,
    /// and freeze it, from the start. A known source is left as it is.
    pub fn register(&mut self, source: usize) {
        self.sources.entry(source).or_default();
    }

    pub fn is_registered(&self, source: usize) -> bool {
        self.sources.contains_key(&source)
    }

    /// Every source registered or heard from, by index.
    pub fn sources(&self) -> impl Iterator<Item = (usize, SourceStatus)> + '_ {
        self.sources
            .iter()
            .map(|(source, record)| (*source, SourceStatus::from(record)))
    }

    /// What `StaleObservation` compares the source's next observation against.
    pub fn last_observed_at(&self, source: usize) -> Option<u64> {
        self.last_observation(source)
            .map(|observation| observation.observed_at)
    }

    pub fn last_observation(&self, source: usize) -> Option<SourceObservation> {
        self.sources.get(&source)?.observation
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

    /// Freezing keeps the source's observation, so unfreezing restores it, but
    /// `valid_observations` leaves it out: an operator freezes a source to stop
    /// it pricing the feed, which a kept observation would otherwise go on
    /// doing until it expired.
    pub fn freeze(&mut self, source: usize) {
        let record = self.sources.entry(source).or_default();
        record.state = SourceState::Frozen;
        record.retry_at = None;
    }

    /// Only a frozen source is returned to active. Unfreezing anything else
    /// would clear a dropped source's `retry_at`, putting it back in the
    /// cycle before `POLLING_RETRY_TIME`, and reset a failing source's count.
    pub fn unfreeze(&mut self, source: usize) {
        let record = self.sources.entry(source).or_default();
        if record.state != SourceState::Frozen {
            return;
        }
        record.state = SourceState::Active;
        record.failures = 0;
        record.retry_at = None;
    }

    fn valid_observations(&self) -> Vec<SourceObservation> {
        let now = self.clock.now();
        self.sources
            .values()
            .filter(|record| record.state != SourceState::Frozen)
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
    cross_pairs: BTreeMap<FeedId, CrossPair>,
}

#[derive(Clone, Debug)]
struct CrossPair {
    definition: FeedDefinition,
    routes: Vec<Vec<ComputationPath>>,
}

impl FeedStates {
    /// Fails for a Cross pair no route of Direct feeds can price, so a node
    /// with such a registry does not start.
    pub fn new(registry: &FeedRegistry, clock: Clock) -> Result<Self, CrossPairError> {
        let reducer = MedianReducer::new(registry.clone());
        let cross_pairs = registry
            .feeds()
            .filter(|definition| definition.kind == FeedKind::Cross)
            .map(|definition| {
                cross::candidates(registry, definition).map(|routes| {
                    let pair = CrossPair {
                        definition: *definition,
                        routes,
                    };
                    (definition.id, pair)
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            states: registry
                .feeds()
                .filter(|definition| definition.kind == FeedKind::Direct)
                .map(|definition| {
                    (
                        definition.id,
                        FeedState::new(*definition, reducer.clone(), clock),
                    )
                })
                .collect(),
            cross_pairs,
        })
    }

    /// A Direct feed's state; a Cross pair has none.
    pub fn get(&self, feed: FeedId) -> Option<&FeedState> {
        self.states.get(&feed)
    }

    pub fn get_mut(&mut self, feed: FeedId) -> Option<&mut FeedState> {
        self.states.get_mut(&feed)
    }

    /// The feed's value, or `None` while it is unavailable. A Cross pair is
    /// priced from the first route whose every leg is available, and from
    /// nothing else, so a restarted node rebuilds it exactly.
    pub fn value(&self, feed: FeedId) -> Option<PriceFeedData> {
        let Some(pair) = self.cross_pairs.get(&feed) else {
            return self.states.get(&feed)?.value();
        };
        let legs = pair.routes.iter().find_map(|route| {
            route
                .iter()
                .map(|leg| Some((*leg, self.states.get(&leg.feed)?.value()?)))
                .collect::<Option<Vec<_>>>()
        })?;
        cross::compute(&pair.definition, &legs)
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
impl FeedStates {
    fn set_clock(&mut self, clock: Clock) {
        for state in self.states.values_mut() {
            state.set_clock(clock);
        }
    }
}

#[cfg(test)]
mod tests;
