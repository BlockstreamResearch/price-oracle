use metrics::counter;

use super::{flag, names, refresh::set_retained};

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

/// Negative once the rescue height has passed.
pub fn set_storm_eye_rescue_blocks_remaining(rescue_height: u32, block_height: u64) {
    set_retained(
        names::STORM_EYE_RESCUE_BLOCKS_REMAINING,
        f64::from(rescue_height) - block_height as f64,
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
