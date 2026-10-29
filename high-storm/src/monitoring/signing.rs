use std::time::Duration;

use metrics::{counter, histogram};

use super::{names, refresh::set_retained};

/// One signing this node requested, from the first branch to the outcome:
/// `ok`, or the reason it failed.
pub(crate) fn record_signing_attempt(kind: &'static str, outcome: &'static str, took: Duration) {
    counter!(names::SIGNING_ATTEMPTS, "kind" => kind, "outcome" => outcome).increment(1);
    if outcome == "ok" {
        histogram!(names::SIGNING_DURATION, "kind" => kind).record(took.as_secs_f64());
    }
}

pub(crate) fn record_signing_branch_failure(kind: &'static str, timed_out: bool) {
    let reason = if timed_out { "timeout" } else { "error" };
    counter!(names::SIGNING_BRANCH_FAILURES, "kind" => kind, "reason" => reason).increment(1);
}

/// `stage` is `nonce` or `partial`.
pub(crate) fn record_missing_signing_contribution(
    peer: String,
    kind: &'static str,
    stage: &'static str,
) {
    counter!(
        names::SIGNING_MISSING_CONTRIBUTIONS,
        "peer" => peer,
        "kind" => kind,
        "stage" => stage,
    )
    .increment(1);
}

pub(crate) fn record_invalid_partial_signatures(peer: String, kind: &'static str) {
    counter!(
        names::SIGNING_INVALID_PARTIAL_SIGNATURES,
        "peer" => peer,
        "kind" => kind,
    )
    .increment(1);
}

pub(crate) fn record_aggregate_invalid(kind: &'static str) {
    counter!(names::SIGNING_AGGREGATE_INVALID, "kind" => kind).increment(1);
}

pub(crate) fn set_signing_sessions_active(count: usize) {
    set_retained(names::SIGNING_SESSIONS_ACTIVE, count as f64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn times_only_signings_that_succeeded() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_signing_attempt("burn_expired_utxos", "ok", Duration::from_millis(1_500));
            record_signing_attempt(
                "burn_expired_utxos",
                "signing_failed",
                Duration::from_secs(60),
            );
            record_signing_branch_failure("burn_expired_utxos", true);
            record_missing_signing_contribution("02aa".into(), "burn_expired_utxos", "nonce");
            set_signing_sessions_active(3);
        });

        let rendered = recorder.handle().render();
        for line in [
            r#"high_storm_signing_attempts_total{kind="burn_expired_utxos",outcome="ok"} 1"#,
            r#"high_storm_signing_attempts_total{kind="burn_expired_utxos",outcome="signing_failed"} 1"#,
            r#"high_storm_signing_duration_seconds_count{kind="burn_expired_utxos"} 1"#,
            r#"high_storm_signing_duration_seconds_sum{kind="burn_expired_utxos"} 1.5"#,
            r#"high_storm_signing_branch_failures_total{kind="burn_expired_utxos",reason="timeout"} 1"#,
            r#"high_storm_signing_missing_contributions_total{peer="02aa",kind="burn_expired_utxos",stage="nonce"} 1"#,
            "high_storm_signing_sessions_active 3",
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
    }
}
