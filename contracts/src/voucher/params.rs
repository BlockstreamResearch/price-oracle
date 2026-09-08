use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::AssetId;

use crate::artifacts::voucher::derived_voucher::VoucherArguments;

/// Compilation parameters for the Voucher covenant.
pub struct VoucherParameters {
    pub storm_eye_asset_id: AssetId,
    pub auth_method: VoucherAuthMethod,
    pub network: SimplicityNetwork,
}

#[derive(Debug, Clone, Copy)]
pub enum VoucherAuthMethod {
    /// An input carrying this asset id authorizes the burn.
    Asset { auth_asset_id: AssetId },
    /// An input matching this script hash authorizes the burn.
    Script { auth_script_hash: [u8; 32] },
    /// A BIP-340 signature under this pubkey authorizes the burn.
    Signature { auth_pubkey: [u8; 32] },
}

impl VoucherParameters {
    #[must_use]
    pub fn build_arguments(&self) -> VoucherArguments {
        let mut arguments = VoucherArguments {
            storm_eye_asset_id: self.storm_eye_asset_id.into_inner().to_byte_array(),
            auth_method: 0,
            auth_asset_id: [0u8; 32],
            auth_script_hash: [0u8; 32],
            auth_pubkey: [0u8; 32],
        };

        match self.auth_method {
            VoucherAuthMethod::Asset { auth_asset_id } => {
                arguments.auth_method = 0;
                arguments.auth_asset_id = auth_asset_id.into_inner().to_byte_array();
            }
            VoucherAuthMethod::Script { auth_script_hash } => {
                arguments.auth_method = 1;
                arguments.auth_script_hash = auth_script_hash;
            }
            VoucherAuthMethod::Signature { auth_pubkey } => {
                arguments.auth_method = 2;
                arguments.auth_pubkey = auth_pubkey;
            }
        }

        arguments
    }
}
