use simplex::provider::SimplicityNetwork;

use crate::artifacts::auth::derived_auth::AuthArguments;

/// Compilation parameters for the Storm Eye covenant.
pub struct AuthParameters {
    pub max_split_utxos_count: u8,
    pub max_merge_utxos_count: u8,
    pub rescue_output_script_hash: [u8; 32],
    pub network: SimplicityNetwork,
}

impl AuthParameters {
    /// `rescue_output_script_hash` defaults to zero, it is only ever read by the
    /// rescue path. You can set it via [`Self::with_rescue_output`].
    #[must_use]
    pub fn new(
        max_split_utxos_count: u8,
        max_merge_utxos_count: u8,
        network: SimplicityNetwork,
    ) -> Self {
        Self {
            max_split_utxos_count,
            max_merge_utxos_count,
            rescue_output_script_hash: [0u8; 32],
            network,
        }
    }

    #[must_use]
    pub fn with_rescue_output(mut self, rescue_output_script_hash: [u8; 32]) -> Self {
        self.rescue_output_script_hash = rescue_output_script_hash;
        self
    }

    #[must_use]
    pub fn build_arguments(&self) -> AuthArguments {
        AuthArguments {
            max_split_utxos_count: self.max_split_utxos_count,
            max_merge_utxos_count: self.max_merge_utxos_count,
            rescue_output_script_hash: self.rescue_output_script_hash,
        }
    }
}
