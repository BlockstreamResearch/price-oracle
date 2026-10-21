//! Prometheus metrics, served on the internal `service.metrics` listener.

mod names;
mod refresh;
mod server;

use std::time::Duration;

use metrics::{describe_gauge, describe_histogram, gauge};
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use metrics_util::MetricKindMask;

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
    metrics_process::Collector::default().describe();
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
