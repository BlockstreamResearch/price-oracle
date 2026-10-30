use std::time::Duration;

use metrics::{counter, gauge, histogram};
use tokio::time::MissedTickBehavior;

use super::{elements, names, refresh::set_retained};
use crate::{HighStormHandle, db::Database};

/// These gauges need `GROUP BY` queries, too heavy for the 5s refresh.
const DB_GAUGES_INTERVAL: Duration = Duration::from_secs(30);

const UTXO_STATUSES: [&str; 4] = ["active", "expired", "burning", "unburnable"];
const USER_REQUEST_STATUSES: [&str; 5] =
    ["pending", "processing", "included", "executed", "failed"];

/// `outcome` is `broadcast` or `failed`.
pub(crate) fn record_burn_round(outcome: &'static str) {
    counter!(names::BURN_ROUNDS, "outcome" => outcome).increment(1);
}

/// `outcome` is `broadcast` or `failed`.
pub(crate) fn record_issuance_round(outcome: &'static str) {
    counter!(names::ISSUANCE_ROUNDS, "outcome" => outcome).increment(1);
}

pub(crate) fn record_issuance_tx_weight(weight: usize) {
    histogram!(names::ISSUANCE_TX_WEIGHT).record(weight as f64);
}

pub(crate) fn record_burns_reverted(count: u64) {
    counter!(names::BURNING_REVERTED).increment(count);
}

pub(crate) fn record_user_request_failed(reason: &'static str) {
    counter!(names::USER_REQUESTS_FAILED, "reason" => reason).increment(1);
}

/// Reports monitored UTXOs, user requests, open votes, peer price
/// attestations, operators and balances from the database until the process
/// exits.
pub fn spawn_db_gauges(node: HighStormHandle, database: Database, tick_lifetime_blocks: u64) {
    tokio::spawn(async move {
        let mut refresh = tokio::time::interval(DB_GAUGES_INTERVAL);
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            refresh.tick().await;
            // Ages keep growing when indexing stalls while blocks keep coming.
            let tip = elements::tip_height()
                .map_or(node.block_height(), |tip| tip.max(node.block_height()));
            let utxos = database.monitored_utxos();
            match utxos.count_by_status().await {
                Ok(counts) => {
                    record_counts(names::MONITORED_UTXOS, "state", &UTXO_STATUSES, &counts)
                }
                Err(error) => tracing::debug!(%error, "could not count monitored UTXOs"),
            }
            match utxos.oldest_unburned_block_height().await {
                Ok(oldest) => set_retained(
                    names::EXPIRED_UTXO_OLDEST_AGE,
                    expired_age_blocks(oldest, tick_lifetime_blocks, tip) as f64,
                ),
                Err(error) => tracing::debug!(%error, "could not read the oldest unburned UTXO"),
            }
            let requests = database.user_requests();
            match requests.count_by_status().await {
                Ok(counts) => record_counts(
                    names::USER_REQUESTS,
                    "status",
                    &USER_REQUEST_STATUSES,
                    &counts,
                ),
                Err(error) => tracing::debug!(%error, "could not count user requests"),
            }
            match requests.oldest_open_block_height().await {
                Ok(oldest) => set_retained(
                    names::USER_REQUEST_OLDEST_PENDING_AGE,
                    oldest.map_or(0, |height| tip.saturating_sub(height)) as f64,
                ),
                Err(error) => {
                    tracing::debug!(%error, "could not read the oldest open user request")
                }
            }
            super::governance::record_open_votings(&node).await;
            super::prices::record_peer_attestations(&node).await;
            match database.node_operators().count().await {
                Ok(count) => super::api::set_operators(count),
                Err(error) => tracing::debug!(%error, "could not count operators"),
            }
            match database.droplets().treasury_utxos().await {
                Ok(utxos) => set_retained(
                    names::TREASURY_BALANCE,
                    utxos.iter().map(|utxo| utxo.amount).sum::<u64>() as f64,
                ),
                Err(error) => tracing::debug!(%error, "could not read the Treasury UTXOs"),
            }
            match node.droplet_state().await {
                Ok((balance, _)) => set_retained(
                    names::DROPLETS_BALANCE,
                    balance.map_or(0, |balance| balance.amount) as f64,
                ),
                Err(error) => tracing::debug!(%error, "could not read this node's Droplets"),
            }
        }
    });
}

/// Every known status is reported, a missing one as 0, so a count that drops
/// to nothing reads as 0 instead of going stale.
fn record_counts(
    name: &'static str,
    label: &'static str,
    statuses: &[&'static str],
    counts: &[(String, u64)],
) {
    for status in statuses {
        let count = counts
            .iter()
            .find(|(counted, _)| counted == status)
            .map_or(0, |(_, count)| *count);
        gauge!(name, label => *status).set(count as f64);
    }
}

/// Blocks since the oldest unburned Tick or Verifier expired; 0 when none is waiting.
fn expired_age_blocks(oldest_issued: Option<u64>, tick_lifetime_blocks: u64, tip: u64) -> u64 {
    oldest_issued.map_or(0, |issued| {
        tip.saturating_sub(issued.saturating_add(tick_lifetime_blocks))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn ages_an_unburned_utxo_from_its_expiry() {
        assert_eq!(expired_age_blocks(None, 60, 500), 0);
        assert_eq!(expired_age_blocks(Some(100), 60, 160), 0);
        assert_eq!(expired_age_blocks(Some(100), 60, 185), 25);
    }

    #[test]
    fn reports_every_status_even_when_none_is_counted() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_counts(
                names::MONITORED_UTXOS,
                "state",
                &UTXO_STATUSES,
                &[("expired".into(), 3)],
            );
            record_burns_reverted(2);
            record_issuance_tx_weight(42_000);
            record_burn_round("failed");
            record_user_request_failed("unpriced_feed");
        });

        let rendered = recorder.handle().render();
        for line in [
            r#"high_storm_monitored_utxos{state="expired"} 3"#,
            r#"high_storm_monitored_utxos{state="active"} 0"#,
            r#"high_storm_monitored_utxos{state="unburnable"} 0"#,
            "high_storm_burning_reverted_total 2",
            r#"high_storm_issuance_tx_weight_bucket{le="50000"} 1"#,
            r#"high_storm_issuance_tx_weight_bucket{le="25000"} 0"#,
            r#"high_storm_burn_rounds_total{outcome="failed"} 1"#,
            r#"high_storm_user_requests_failed_total{reason="unpriced_feed"} 1"#,
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
    }
}
