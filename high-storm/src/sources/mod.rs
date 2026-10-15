pub mod blockstream;
pub mod coingecko;
pub mod sideswap;

use std::{future::Future, sync::Arc, time::Duration};

use price_feed::{
    Asset, FeedId, PriceSource,
    constants::{BACKOFF_CAP, POLLING_INTERVAL},
};
use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use tokio::{sync::Notify, time::MissedTickBehavior};

use crate::{HighStormHandle, config::PriceSourcesConfig, high_storm::PollOutcome};

use blockstream::Blockstream;
use coingecko::CoinGecko;
use sideswap::SideSwap;

/// Each source's index in every feed's state, for this run only: a persisted
/// freeze names the source by its `NAME`, so an index may change.
const COINGECKO: usize = 0;
const BLOCKSTREAM: usize = 1;
const SIDESWAP: usize = 2;

/// CoinGecko's edge refuses a request that names no client.
const USER_AGENT: &str = concat!("high-storm/", env!("CARGO_PKG_VERSION"));

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Polls every configured source, each feed on its own task. The returned
/// `Notify` fires on every new observation, which is when the node attests.
pub fn spawn(
    config: &PriceSourcesConfig,
    node: HighStormHandle,
) -> Result<Arc<Notify>, reqwest::Error> {
    let observed = Arc::new(Notify::new());
    if config.coingecko.is_none() && config.blockstream.is_none() && config.sideswap.is_none() {
        tracing::warn!("no price source is configured, so this node attests no prices");
    }
    if let Some(coingecko) = &config.coingecko {
        let source = CoinGecko::new(coingecko)?;
        let feeds: Vec<_> = source.feeds().collect();
        spawn_source(source, COINGECKO, CoinGecko::NAME, feeds, &node, &observed);
    }
    if let Some(blockstream) = &config.blockstream {
        let source = Blockstream::new(blockstream)?;
        let feeds: Vec<_> = source.feeds().collect();
        spawn_source(
            source,
            BLOCKSTREAM,
            Blockstream::NAME,
            feeds,
            &node,
            &observed,
        );
    }
    if let Some(sideswap) = &config.sideswap {
        let source = SideSwap::new(sideswap, node.clone());
        let feeds: Vec<_> = source.feeds().collect();
        spawn_source(source, SIDESWAP, SideSwap::NAME, feeds, &node, &observed);
    }
    Ok(observed)
}

fn spawn_source<S>(
    source: S,
    index: usize,
    name: &'static str,
    feeds: Vec<FeedId>,
    node: &HighStormHandle,
    observed: &Arc<Notify>,
) where
    S: PriceSource + Send + Sync + 'static,
{
    let source = Arc::new(source);
    for feed in feeds {
        let (node, source, observed) = (node.clone(), source.clone(), observed.clone());
        tokio::spawn(async move {
            register(&node, feed, index, name).await;
            let poll = move || {
                let (node, source) = (node.clone(), source.clone());
                async move { node.poll_price_source(feed, index, &*source).await }
            };
            run(poll, observed).await
        });
    }
}

/// A source the operator froze must not be polled after a restart, so it is
/// not polled until the node has read whether it is frozen.
async fn register(node: &HighStormHandle, feed: FeedId, index: usize, name: &'static str) {
    while let Err(error) = node.register_price_source(feed, index, name).await {
        tracing::warn!(feed, source = name, %error, "failed to register a price source; retrying");
        tokio::time::sleep(backoff()).await;
    }
}

fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .use_preconfigured_tls(tls())
        .user_agent(USER_AGENT)
        .timeout(REQUEST_TIMEOUT)
        .build()
}

/// reqwest's rustls backend brings no crypto of its own, so the client carries
/// its TLS configuration instead of relying on a process-wide default.
fn tls() -> ClientConfig {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// The id an asset is issued under on Liquid, for the sources that name
/// assets by it. USD is no Liquid asset, and USDC is not issued there.
fn liquid_asset_id(asset: Asset) -> Option<&'static str> {
    match asset {
        Asset::Lbtc => Some("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"),
        Asset::Usdt => Some("ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2"),
        Asset::Eurx => Some("18729918ab4bca843656f08d4dd877bed6641fbd596a0a963abbf199cfeb3cec"),
        Asset::DePix => Some("02f22f8d9c76ab41661a2729e4752e2c5d1a263012141b86ea98af5472df5189"),
        Asset::Usd | Asset::Usdc => None,
    }
}

/// A price that is missing or not a usable number becomes zero, which
/// `validate` rejects as `InvalidPrice`.
fn base_units(price: Option<f64>, decimals: u32) -> u64 {
    let scaled = price.unwrap_or_default() * 10f64.powi(decimals as i32);
    if (0.0..u64::MAX as f64).contains(&scaled) {
        scaled.round() as u64
    } else {
        0
    }
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
