//! Prometheus metrics, served on the internal `service.metrics` listener.

mod api;
mod chain;
mod elements;
mod exporter;
mod governance;
mod health;
mod messages;
mod names;
mod prices;
mod refresh;
mod rounds;
mod rpc;
mod server;
mod signing;

use std::time::Duration;

use metrics::gauge;
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder};
use metrics_util::MetricKindMask;

pub(crate) use api::{
    ApiConnection, record_api_connection_rejected, record_api_request, record_api_request_rejected,
    record_ipc_rejected, record_operator_auth_failure, record_operator_change,
    record_user_request_rejected,
};
pub(crate) use chain::{
    RenewalOutcome, record_chain_reorg, record_storm_eye_renewal, set_chain_safety_halt,
};
pub use chain::{set_storm_eye_utxos, spawn_storm_eye_probe};
pub use elements::spawn_elements_probe;
pub use exporter::Exporter;
pub(crate) use governance::{
    record_droplets_exchange, record_voting_approval, record_voting_execution,
    record_voting_request_created,
};
pub(crate) use messages::{RejectedMessage, record_rejected_message};
pub use prices::register_price_source;
pub(crate) use prices::{
    record_price_attestation_rejected, record_price_change, record_price_poll,
    record_price_poll_duration, record_price_poll_error, record_price_poll_rejection,
};
pub use refresh::{LoopTask, record_loop_tick, spawn_refresh};
pub use rounds::spawn_db_gauges;
pub(crate) use rounds::{
    record_burn_round, record_burns_reverted, record_issuance_round, record_issuance_tx_weight,
    record_user_request_failed,
};
pub(crate) use rpc::elements_client;
pub use server::MetricsServer;
pub(crate) use signing::{
    record_aggregate_invalid, record_invalid_partial_signatures,
    record_missing_signing_contribution, record_signing_attempt, record_signing_branch_failure,
    set_signing_sessions_active,
};

/// Covers fast database probes up to the 60s signing session timeout.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// Up to Elements' standard limit of 400,000 weight units.
const WEIGHT_BUCKETS: &[f64] = &[
    10_000.0, 25_000.0, 50_000.0, 100_000.0, 200_000.0, 300_000.0, 400_000.0,
];

/// Drops a gauge nothing has set for this long, such as one for a peer that
/// left the network. Gauges an alert relies on are republished by the refresh
/// task, and task heartbeats on every scrape, so they never go idle.
const GAUGE_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Installs the process-wide recorder. Call once, before any metric is emitted.
pub fn install() -> Result<Exporter, BuildError> {
    let exporter = Exporter::install(builder()?.build_recorder())?;
    describe();
    record_build_info();
    Ok(exporter)
}

/// Durations render as histograms rather than summaries so alerts can
/// aggregate quantiles across nodes.
fn builder() -> Result<PrometheusBuilder, BuildError> {
    Ok(PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix("_duration_seconds".into()),
            DURATION_BUCKETS,
        )?
        .set_buckets_for_metric(
            Matcher::Full(names::ISSUANCE_TX_WEIGHT.into()),
            WEIGHT_BUCKETS,
        )?
        .idle_timeout(MetricKindMask::GAUGE, Some(GAUGE_IDLE_TIMEOUT)))
}

fn describe() {
    names::describe();
    metrics_process::Collector::default().describe();
    storm::telemetry::describe();
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
