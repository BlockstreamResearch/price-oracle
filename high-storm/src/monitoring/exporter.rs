use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
};

use metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SetRecorderError,
    SharedString, Unit,
};
use metrics_exporter_prometheus::{BuildError, PrometheusHandle, PrometheusRecorder};

const POISONED: &str = "held counters lock poisoned";

/// Renders the process-wide recorder for the metrics endpoint.
#[derive(Clone)]
pub struct Exporter {
    handle: PrometheusHandle,
    unseen: Arc<UnseenCounters>,
}

impl Exporter {
    pub(super) fn new(recorder: PrometheusRecorder) -> (Self, ZeroFirstRecorder) {
        let unseen = Arc::<UnseenCounters>::default();
        (
            Self {
                handle: recorder.handle(),
                unseen: unseen.clone(),
            },
            ZeroFirstRecorder {
                inner: recorder,
                unseen,
            },
        )
    }

    pub(super) fn install(recorder: PrometheusRecorder) -> Result<Self, BuildError> {
        let (exporter, recorder) = Self::new(recorder);
        metrics::set_global_recorder(recorder)
            .map_err(|SetRecorderError(recorder)| SetRecorderError(recorder.inner))?;
        Ok(exporter)
    }

    /// Lets the counters this render showed at zero count from then on.
    pub(super) fn render(&self) -> String {
        let shown = self.unseen.keys();
        let rendered = self.handle.render();
        self.unseen.release(shown);
        rendered
    }

    pub(super) fn run_upkeep(&self) {
        self.handle.run_upkeep();
    }
}

/// Prometheus takes a counter that first appears above zero to have always
/// had that value, so `increase()` misses the events that created it and a rule
/// for a single event never fires. Every new counter is therefore shown at zero,
/// and its increments are held back until a scrape has seen that zero. With
/// several Prometheus servers, the first to scrape releases them.
pub(super) struct ZeroFirstRecorder {
    inner: PrometheusRecorder,
    unseen: Arc<UnseenCounters>,
}

impl Recorder for ZeroFirstRecorder {
    fn describe_counter(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner.describe_counter(key, unit, description);
    }

    fn describe_gauge(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner.describe_gauge(key, unit, description);
    }

    fn describe_histogram(&self, key: KeyName, unit: Option<Unit>, description: SharedString) {
        self.inner.describe_histogram(key, unit, description);
    }

    fn register_counter(&self, key: &Key, metadata: &Metadata<'_>) -> Counter {
        self.unseen
            .hold(key, self.inner.register_counter(key, metadata))
    }

    fn register_gauge(&self, key: &Key, metadata: &Metadata<'_>) -> Gauge {
        self.inner.register_gauge(key, metadata)
    }

    fn register_histogram(&self, key: &Key, metadata: &Metadata<'_>) -> Histogram {
        self.inner.register_histogram(key, metadata)
    }
}

#[derive(Default)]
struct UnseenCounters(Mutex<Counters>);

#[derive(Default)]
struct Counters {
    unseen: HashMap<Key, Arc<HeldCounter>>,
    seen: HashSet<Key>,
}

impl UnseenCounters {
    fn lock(&self) -> MutexGuard<'_, Counters> {
        self.0.lock().expect(POISONED)
    }

    fn hold(&self, key: &Key, counter: Counter) -> Counter {
        let mut counters = self.lock();
        if counters.seen.contains(key) {
            return counter;
        }
        let held = counters
            .unseen
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(HeldCounter {
                    counter,
                    held: Mutex::new(Some(0)),
                })
            })
            .clone();
        Counter::from_arc(held)
    }

    /// Taken before a render, so a counter registered during it waits for the next.
    fn keys(&self) -> Vec<Key> {
        self.lock().unseen.keys().cloned().collect()
    }

    fn release(&self, shown: Vec<Key>) {
        let mut counters = self.lock();
        for key in shown {
            if let Some(held) = counters.unseen.remove(&key) {
                held.release();
            }
            counters.seen.insert(key);
        }
    }
}

struct HeldCounter {
    counter: Counter,
    /// `None` once a scrape has seen the counter at zero.
    held: Mutex<Option<u64>>,
}

impl HeldCounter {
    fn release(&self) {
        if let Some(held) = self.held.lock().expect(POISONED).take() {
            self.counter.increment(held);
        }
    }
}

impl CounterFn for HeldCounter {
    fn increment(&self, value: u64) {
        match self.held.lock().expect(POISONED).as_mut() {
            Some(held) => *held += value,
            None => self.counter.increment(value),
        }
    }

    /// Only the process metrics set a counter outright, and they mark no event.
    fn absolute(&self, value: u64) {
        self.release();
        self.counter.absolute(value);
    }
}

#[cfg(test)]
mod tests {
    use metrics::counter;

    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn shows_a_new_counter_at_zero_to_one_scrape_first() {
        let (exporter, recorder) = Exporter::new(builder().unwrap().build_recorder());
        let increment = |by| {
            metrics::with_local_recorder(&recorder, || {
                counter!("high_storm_votes_total", "kind" => "update").increment(by);
            });
        };

        increment(2);
        assert!(
            exporter
                .render()
                .contains(r#"high_storm_votes_total{kind="update"} 0"#)
        );
        assert!(
            exporter
                .render()
                .contains(r#"high_storm_votes_total{kind="update"} 2"#)
        );
        // Once seen, increments count straight away.
        increment(1);
        assert!(
            exporter
                .render()
                .contains(r#"high_storm_votes_total{kind="update"} 3"#)
        );
    }

    #[test]
    fn holds_each_label_set_on_its_own() {
        let (exporter, recorder) = Exporter::new(builder().unwrap().build_recorder());
        let increment = |kind| {
            metrics::with_local_recorder(&recorder, || {
                counter!("high_storm_votes_total", "kind" => kind).increment(1);
            });
        };

        increment("update");
        exporter.render();
        increment("update");
        increment("renew");

        let rendered = exporter.render();
        assert!(rendered.contains(r#"high_storm_votes_total{kind="update"} 2"#));
        assert!(rendered.contains(r#"high_storm_votes_total{kind="renew"} 0"#));
    }
}
