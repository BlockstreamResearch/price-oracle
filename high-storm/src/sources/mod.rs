pub mod coingecko;

use std::{future::Future, sync::Arc, time::Duration};

use price_feed::constants::{BACKOFF_CAP, POLLING_INTERVAL};
use tokio::{sync::Notify, time::MissedTickBehavior};

use crate::{HighStormHandle, config::PriceSourcesConfig, high_storm::PollOutcome};

use coingecko::CoinGecko;

/// The source's index in every feed's state.
const COINGECKO: usize = 0;

/// Polls every configured source, each feed on its own task. The returned
/// `Notify` fires on every new observation, which is when the node attests.
pub fn spawn(
    config: &PriceSourcesConfig,
    node: HighStormHandle,
) -> Result<Arc<Notify>, reqwest::Error> {
    let observed = Arc::new(Notify::new());
    let Some(coingecko) = &config.coingecko else {
        tracing::warn!("no price source is configured, so this node attests no prices");
        return Ok(observed);
    };
    let source = Arc::new(CoinGecko::new(coingecko)?);
    for feed in source.feeds() {
        let (node, source) = (node.clone(), source.clone());
        let poll = move || {
            let (node, source) = (node.clone(), source.clone());
            async move { node.poll_price_source(feed, COINGECKO, &*source).await }
        };
        tokio::spawn(run(poll, observed.clone()));
    }
    Ok(observed)
}

/// Polls once per `POLLING_INTERVAL`. A failed poll is retried after
/// `random(0, BACKOFF_CAP)` until one does not fail; any other outcome waits
/// for the next cycle.
async fn run<F>(mut poll: impl FnMut() -> F, observed: Arc<Notify>)
where
    F: Future<Output = PollOutcome>,
{
    let mut cycle = tokio::time::interval(Duration::from_secs(POLLING_INTERVAL));
    cycle.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        cycle.tick().await;
        loop {
            match poll().await {
                PollOutcome::Observed => {
                    observed.notify_one();
                    break;
                }
                PollOutcome::Unchanged | PollOutcome::Skipped => break,
                PollOutcome::Failed => tokio::time::sleep(backoff()).await,
            }
        }
    }
}

/// `random(0, BACKOFF_CAP)`.
fn backoff() -> Duration {
    let cap_millis = BACKOFF_CAP * 1_000;
    Duration::from_millis(getrandom::u64().unwrap_or_default() % cap_millis)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use tokio::time::Instant;

    use super::*;

    /// Runs the loop over `outcomes`, then returns when each of them was polled,
    /// counted from the first poll.
    async fn poll_times(outcomes: &[PollOutcome]) -> (Vec<Duration>, Arc<Notify>) {
        let script = Arc::new(Mutex::new(VecDeque::from(outcomes.to_vec())));
        let times = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::new(Notify::new());
        let start = Instant::now();

        let poll = {
            let (script, times) = (script.clone(), times.clone());
            move || {
                times.lock().unwrap().push(start.elapsed());
                let outcome = script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(PollOutcome::Unchanged);
                async move { outcome }
            }
        };
        let task = tokio::spawn(run(poll, observed.clone()));
        // The paused clock jumps to each timer as soon as every task waits on one.
        tokio::time::sleep(Duration::from_secs(10 * POLLING_INTERVAL)).await;
        task.abort();

        let times = times.lock().unwrap()[..outcomes.len()].to_vec();
        (times, observed)
    }

    #[tokio::test(start_paused = true)]
    async fn retries_a_failed_poll_before_the_next_cycle() {
        let outcomes = [
            PollOutcome::Failed,
            PollOutcome::Failed,
            PollOutcome::Observed,
        ];

        let (times, observed) = poll_times(&outcomes).await;

        let cap = Duration::from_secs(BACKOFF_CAP);
        assert!(times[1] - times[0] < cap);
        assert!(times[2] - times[1] < cap);
        // The observation is what the node attests on.
        let notified = tokio::time::timeout(Duration::from_secs(1), observed.notified());
        assert!(notified.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn waits_for_the_next_cycle_after_a_poll_that_did_not_fail() {
        let outcomes = [
            PollOutcome::Unchanged,
            PollOutcome::Skipped,
            PollOutcome::Observed,
            PollOutcome::Unchanged,
        ];

        let (times, _) = poll_times(&outcomes).await;

        let cycle = Duration::from_secs(POLLING_INTERVAL);
        assert_eq!(times, [Duration::ZERO, cycle, cycle * 2, cycle * 3]);
    }
}
