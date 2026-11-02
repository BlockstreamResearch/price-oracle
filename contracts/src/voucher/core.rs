use simplex::simplicityhl::elements::schnorr::XOnlyPublicKey;
use simplex::simplicityhl::elements::{AssetId, Script, Sequence};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, ProgramInput};

use crate::artifacts::voucher::VoucherProgram;
use crate::voucher::{PERMISSIONLESS_BURN_DELAY_INTERVALS, VoucherParameters, VoucherSpendPath};

/// The Voucher covenant: a burn-after-use, network-issued proof token.
pub struct Voucher {
    program: VoucherProgram,
    params: VoucherParameters,
}

impl Voucher {
    #[must_use]
    pub fn new(params: VoucherParameters) -> Self {
        Self {
            program: VoucherProgram::new(params.build_arguments()),
            params,
        }
    }

    #[must_use]
    pub fn new_with_taproot_pubkey(params: VoucherParameters, pub_key: XOnlyPublicKey) -> Self {
        Self {
            program: VoucherProgram::new(params.build_arguments()).with_taproot_pubkey(pub_key),
            params,
        }
    }

    #[must_use]
    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.params.network)
    }

    /// The leaf a consumer passes to `sdk::voucher::verify_price` to rebuild this script.
    #[must_use]
    pub fn get_tapleaf_hash(&self) -> [u8; 32] {
        self.program.get_tapleaf_hash()
    }

    #[must_use]
    pub fn get_parameters(&self) -> &VoucherParameters {
        &self.params
    }

    /// Attaches a spend of `voucher_utxo` along the given spending path.
    pub fn attach_spend(
        &self,
        ft: &mut FinalTransaction,
        voucher_utxo: &UTXO,
        path: VoucherSpendPath,
    ) {
        let required_signature = path.required_signature();
        let input = PartialInput::new(voucher_utxo.clone());
        let input = match path {
            VoucherSpendPath::PermissionlessBurn { .. } => input.with_sequence(
                Sequence::from_512_second_intervals(PERMISSIONLESS_BURN_DELAY_INTERVALS),
            ),
            _ => input,
        };

        ft.add_program_input(
            input,
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                path.build_witness(),
            ),
            required_signature,
        );
    }

    /// The script requester and permissionless burns must pay into.
    #[must_use]
    pub fn get_burn_script(voucher_input_index: u32) -> Script {
        Script::new_op_return(&voucher_input_index.to_be_bytes())
    }

    /// Adds the full-amount, input-tagged burn for requester and permissionless paths.
    pub fn attach_voucher_output(
        &self,
        ft: &mut FinalTransaction,
        voucher_utxo: &UTXO,
        voucher_input_index: u32,
    ) {
        ft.add_output(PartialOutput::new(
            Self::get_burn_script(voucher_input_index),
            voucher_utxo.explicit_amount(),
            voucher_utxo.explicit_asset(),
        ));
    }

    /// Adds an output that pays `amount` of `asset_id` to this Voucher.
    pub fn attach_voucher_creation(
        &self,
        ft: &mut FinalTransaction,
        amount: u64,
        asset_id: AssetId,
    ) {
        ft.add_output(PartialOutput::new(
            self.get_script_pubkey(),
            amount,
            asset_id,
        ));
    }
}
