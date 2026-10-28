//! Prometheus metrics, served on the internal `service.metrics` listener.

mod names;
mod server;

use metrics::{describe_gauge, gauge};
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};

pub use server::MetricsServer;

/// Covers fast database probes up to the 60s signing session timeout.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

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
    PrometheusBuilder::new().set_buckets_for_metric(
        Matcher::Suffix("_duration_seconds".into()),
        DURATION_BUCKETS,
    )
}

fn describe() {
    describe_gauge!(
        names::BUILD_INFO,
        "Always 1; the labels identify the running high-storm build."
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
