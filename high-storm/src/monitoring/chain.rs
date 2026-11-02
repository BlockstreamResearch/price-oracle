use std::time::Duration;

use metrics::counter;
use tokio::time::MissedTickBehavior;

use super::{elements, flag, names, refresh::set_retained};
use crate::HighStormHandle;

const STORM_EYE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenewalOutcome {
    Broadcast,
    Failed,
    Confirmed,
}

impl RenewalOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Broadcast => "broadcast",
            Self::Failed => "failed",
            Self::Confirmed => "confirmed",
        }
    }
}

pub(crate) fn record_chain_reorg() {
    counter!(names::CHAIN_REORGS).increment(1);
}

pub(crate) fn set_chain_safety_halt(halted: bool) {
    set_retained(names::CHAIN_SAFETY_HALT, flag(halted));
}

pub(crate) fn record_storm_eye_renewal(outcome: RenewalOutcome) {
    counter!(names::STORM_EYE_RENEWALS, "outcome" => outcome.as_str()).increment(1);
}

pub fn set_storm_eye_utxos(count: usize) {
    set_retained(names::STORM_EYE_UTXOS, count as f64);
}

/// Counts down to the rescue height against Elements' own tip, so the countdown
/// keeps moving when this node's indexing stalls while blocks keep coming.
/// Runs until the process exits.
pub fn spawn_storm_eye_probe(node: HighStormHandle) {
    tokio::spawn(async move {
        let mut probe = tokio::time::interval(STORM_EYE_PROBE_INTERVAL);
        probe.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            probe.tick().await;
            let rescue_height = match node.storm_eye_rescue_height().await {
                Ok(rescue_height) => rescue_height,
                Err(error) => {
                    tracing::debug!(%error, "could not read the Storm Eye rescue height");
                    continue;
                }
            };
            if let (Some(rescue_height), Some(tip_height)) = (rescue_height, elements::tip_height())
            {
                set_storm_eye_rescue_blocks_remaining(rescue_height, tip_height);
            }
        }
    });
}

/// Negative once the rescue height has passed.
fn set_storm_eye_rescue_blocks_remaining(rescue_height: u32, tip_height: u64) {
    set_retained(
        names::STORM_EYE_RESCUE_BLOCKS_REMAINING,
        f64::from(rescue_height) - tip_height as f64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn counts_blocks_left_before_the_rescue_height() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            set_storm_eye_utxos(6);
            set_chain_safety_halt(true);
            set_storm_eye_rescue_blocks_remaining(1_000, 1_250);
            record_chain_reorg();
            record_storm_eye_renewal(RenewalOutcome::Broadcast);
        });

        let rendered = recorder.handle().render();
        for line in [
            "high_storm_storm_eye_utxos 6",
            "high_storm_chain_safety_halt 1",
            "high_storm_storm_eye_rescue_blocks_remaining -250",
            "high_storm_chain_reorgs_total 1",
            "high_storm_storm_eye_renewals_total{outcome=\"broadcast\"} 1",
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
    }
}
