use simplex::either::Either;
use simplex::transaction::RequiredSignature;

use crate::artifacts::voucher::derived_voucher::VoucherWitness;

#[derive(Debug, Clone, Copy)]
pub enum VoucherSpendPath {
    /// An input carrying `AUTH_ASSET_ID` authorizes the burn.
    AssetAuth {
        auth_input_index: u32,
        voucher_output_index: u32,
    },
    /// An input matching `AUTH_SCRIPT_HASH` authorizes the burn.
    ScriptAuth {
        auth_input_index: u32,
        voucher_output_index: u32,
    },
    /// A BIP-340 signature over `sig_all_hash` authorizes the burn.
    SignatureAuth { voucher_output_index: u32 },
    /// The Storm Eye asset at this input authorizes the burn.
    NetworkAuth { storm_eye_input_index: u32 },
}

impl VoucherSpendPath {
    #[must_use]
    pub fn required_signature(&self) -> RequiredSignature {
        match self {
            Self::SignatureAuth { .. } => {
                RequiredSignature::witness_with_path("PATH", ["Right", "Left", "0"])
            }
            _ => RequiredSignature::None,
        }
    }

    #[must_use]
    pub fn build_witness(self) -> VoucherWitness {
        let path = match self {
            Self::AssetAuth {
                auth_input_index,
                voucher_output_index,
            } => Either::Left(Either::Left((auth_input_index, voucher_output_index))),
            Self::ScriptAuth {
                auth_input_index,
                voucher_output_index,
            } => Either::Left(Either::Right((auth_input_index, voucher_output_index))),
            Self::SignatureAuth {
                voucher_output_index,
            } => Either::Right(Either::Left(([0u8; 64], voucher_output_index))),
            Self::NetworkAuth {
                storm_eye_input_index,
            } => Either::Right(Either::Right(storm_eye_input_index)),
        };

        VoucherWitness { path }
    }
}
