//! Prometheus metrics, served on the internal `service.metrics` listener.

mod chain;
mod elements;
mod names;
mod prices;
mod refresh;
mod server;

use std::time::Duration;

use metrics::{describe_counter, describe_gauge, describe_histogram, gauge};
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use metrics_util::MetricKindMask;

pub(crate) use chain::{
    RenewalOutcome, record_chain_reorg, record_storm_eye_renewal, set_chain_safety_halt,
};
pub use chain::{set_storm_eye_utxos, spawn_storm_eye_probe};
pub use elements::spawn_elements_probe;
pub use prices::register_price_source;
pub use refresh::{LoopTask, record_loop_tick, spawn_refresh};
pub use server::MetricsServer;

/// Covers fast database probes up to the 60s signing session timeout.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// Drops a gauge nothing has set for this long, such as one for a peer that
/// left the network. Gauges an alert relies on are republished by the refresh
/// task, so they never go idle.
const GAUGE_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Installs the process-wide recorder. Call once, before any metric is emitted.
pub fn install() -> Result<PrometheusHandle, BuildError> {
    let handle = builder()?.install_recorder()?;
    describe();
    record_build_info();
    Ok(handle)
}

/// Durations render as histograms rather than summaries so alerts can
/// aggregate quantiles across nodes.
fn builder() -> Result<PrometheusBuilder, BuildError> {
    Ok(PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix("_duration_seconds".into()),
            DURATION_BUCKETS,
        )?
        .idle_timeout(MetricKindMask::GAUGE, Some(GAUGE_IDLE_TIMEOUT)))
}

fn describe() {
    describe_gauge!(
        names::BUILD_INFO,
        "Always 1; the labels identify the running high-storm build."
    );
    describe_gauge!(
        names::LOOP_LAST_TICK,
        "Unix time at which each main loop task last started."
    );
    describe_gauge!(
        names::IS_MEMBER,
        "1 while this node is in the network's member table."
    );
    describe_gauge!(
        names::IS_COORDINATOR,
        "1 if this node coordinates user requests."
    );
    describe_gauge!(
        names::IS_LEADER,
        "1 if this node leads at the current block height."
    );
    describe_gauge!(
        names::BLOCK_HEIGHT,
        "Height of the last Liquid block this node indexed."
    );
    describe_gauge!(
        names::MEMBERS_TOTAL,
        "Members in the network, this node included."
    );
    describe_gauge!(
        names::SIGNING_THRESHOLD,
        "Signers a Storm Tree branch needs: two-thirds of the members, rounded up."
    );
    describe_gauge!(
        names::CONNECTED_MEMBERS,
        "Members signing can use now: this node plus the active members it is connected to."
    );
    describe_gauge!(
        names::COORDINATOR_CONNECTED,
        "1 if this node is the coordinator or is connected to it."
    );
    describe_gauge!(
        names::PEER_CONNECTED,
        "1 while the peer is active and its connection is open."
    );
    describe_gauge!(
        names::PEER_LAST_SEEN,
        "Unix time of the last message received from the peer."
    );
    describe_gauge!(
        names::DB_UP,
        "1 if a trivial query completed within 2s, which also needs a free pool connection."
    );
    describe_histogram!(
        names::DB_PING_DURATION,
        "Time taken by the database probe that succeeded."
    );
    describe_gauge!(
        names::DB_POOL_CONNECTIONS,
        "Database pool connections, by state."
    );
    describe_gauge!(
        names::ELEMENTS_RPC_UP,
        "1 if the last probe of this node's Elements RPC succeeded."
    );
    describe_gauge!(
        names::ELEMENTS_TIP_HEIGHT,
        "Height of Elements' best block, as last seen."
    );
    describe_gauge!(
        names::ELEMENTS_TIP_TIMESTAMP,
        "Unix time of Elements' best block, as last seen."
    );
    describe_gauge!(
        names::ELEMENTS_PEERS,
        "Peers Elements is connected to, as last seen."
    );
    describe_gauge!(
        names::ELEMENTS_INITIAL_BLOCK_DOWNLOAD,
        "1 while Elements is in initial block download."
    );
    describe_counter!(
        names::CHAIN_REORGS,
        "Chain reorganizations the indexer found under its journal or cursors."
    );
    describe_gauge!(
        names::CHAIN_RECOVERING,
        "1 while the indexer rebuilds chain-derived state."
    );
    describe_gauge!(
        names::CHAIN_SAFETY_HALT,
        "1 while indexing is halted for safety; an operator must act."
    );
    describe_gauge!(
        names::SPENDING_PAUSED,
        "1 while spending is paused for a member migration."
    );
    describe_gauge!(
        names::STORM_EYE_UTXOS,
        "Storm Eye UTXOs available to sign with, counted after each new block."
    );
    describe_gauge!(
        names::STORM_EYE_RESCUE_BLOCKS_REMAINING,
        "Blocks until anyone may take the Storm Eye UTXOs; negative once passed."
    );
    describe_counter!(
        names::STORM_EYE_RENEWALS,
        "Storm Eye timelock renewals, by outcome."
    );
    describe_gauge!(
        names::PRICE_FEED_AVAILABLE,
        "1 while the feed has a valid price; only feeds some source can price are reported."
    );
    describe_gauge!(
        names::PRICE_FEED_RECEIVED,
        "Unix time the feed's current price was received."
    );
    describe_gauge!(
        names::PRICE_FEED_VALID_UNTIL,
        "Unix time until which the feed's current price is valid."
    );
    describe_gauge!(
        names::PRICE_FEED_ACTIVE_SOURCES,
        "Sources of a Direct feed that are neither dropped nor frozen."
    );
    describe_gauge!(
        names::PRICE_SOURCE_STATE,
        "1 for the state a feed's source is in: active, dropped or frozen."
    );
    describe_gauge!(
        names::PRICE_SOURCE_LAST_OBSERVED,
        "Unix time the source itself stamped its latest kept observation."
    );
    metrics_process::Collector::default().describe();
}

fn flag(value: bool) -> f64 {
    f64::from(u8::from(value))
}

fn record_build_info() {
    let git_sha = option_env!("HIGH_STORM_GIT_SHA")
        .filter(|sha| !sha.is_empty())
        .unwrap_or("unknown");
    gauge!(
        names::BUILD_INFO,
        "version" => env!("CARGO_PKG_VERSION"),
        "git_sha" => git_sha,
    )
    .set(1.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_build_info() {
        let recorder = builder().unwrap().build_recorder();
        let handle = recorder.handle();

        metrics::with_local_recorder(&recorder, record_build_info);

        let rendered = handle.render();
        let line = rendered
            .lines()
            .find(|line| line.starts_with("high_storm_build_info{"))
            .expect("build info is rendered");
        assert!(line.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))));
        assert!(line.contains("git_sha=\""));
        assert!(line.ends_with(" 1"));
    }
}
