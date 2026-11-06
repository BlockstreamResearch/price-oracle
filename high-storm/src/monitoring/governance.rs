use metrics::{counter, gauge};

use super::names;
use crate::HighStormHandle;

const VOTE_KINDS: [&str; 3] = [
    "update_network_members",
    "merge_storm_eyes",
    "split_storm_eye",
];

/// `proposer` is the proposer's transport key, or `unknown` for a legacy
/// request that names none.
pub(crate) fn record_voting_request_created(kind: &'static str, proposer: String) {
    counter!(names::VOTING_REQUESTS_CREATED, "kind" => kind, "proposer" => proposer).increment(1);
}

pub(crate) fn record_voting_approval(kind: &'static str) {
    counter!(names::VOTING_APPROVALS, "kind" => kind).increment(1);
}

/// `outcome` is `broadcast`, `failed`, `migration_not_ready` or `confirmed`.
pub(crate) fn record_voting_execution(outcome: &'static str) {
    counter!(names::VOTING_EXECUTIONS, "outcome" => outcome).increment(1);
}

/// `outcome` is `broadcast`, `retry` when signing will be tried again, or
/// `failed`.
pub(crate) fn record_droplets_exchange(outcome: &'static str) {
    counter!(names::DROPLETS_EXCHANGES, "outcome" => outcome).increment(1);
}

pub(super) async fn record_open_votings(node: &HighStormHandle) {
    match node.open_voting_kinds().await {
        Ok(kinds) => record_open_kinds(&kinds),
        Err(error) => {
            super::health::record_task_error(super::health::MonitoringTask::DbGauges);
            tracing::debug!(%error, "could not count open voting requests");
        }
    }
}

/// Every kind is reported, a missing one as 0, so a vote that closes reads as 0
/// instead of going stale.
fn record_open_kinds(open: &[&'static str]) {
    for kind in VOTE_KINDS {
        let count = open.iter().filter(|open| **open == kind).count();
        gauge!(names::VOTING_REQUESTS_OPEN, "kind" => kind).set(count as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{high_storm::NetworkVoteKind, monitoring::builder};

    #[test]
    fn labels_every_vote_kind() {
        for (id, label) in VOTE_KINDS.into_iter().enumerate() {
            assert_eq!(
                NetworkVoteKind::from_id(id as u16).map(NetworkVoteKind::as_str),
                Some(label)
            );
        }
    }

    #[test]
    fn reports_every_vote_kind_even_when_none_is_open() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_open_kinds(&["update_network_members", "update_network_members"]);
            record_voting_request_created("update_network_members", "02ab".into());
            record_voting_approval("split_storm_eye");
            record_voting_execution("migration_not_ready");
            record_droplets_exchange("retry");
        });

        let rendered = recorder.handle().render();
        for line in [
            r#"high_storm_voting_requests_open{kind="update_network_members"} 2"#,
            r#"high_storm_voting_requests_open{kind="merge_storm_eyes"} 0"#,
            r#"high_storm_voting_requests_open{kind="split_storm_eye"} 0"#,
            r#"high_storm_voting_requests_created_total{kind="update_network_members",proposer="02ab"} 1"#,
            r#"high_storm_voting_approvals_total{kind="split_storm_eye"} 1"#,
            r#"high_storm_voting_executions_total{outcome="migration_not_ready"} 1"#,
            r#"high_storm_droplets_exchanges_total{outcome="retry"} 1"#,
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
    }
}
