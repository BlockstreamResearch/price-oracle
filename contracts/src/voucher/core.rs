use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, ProgramInput};

use crate::artifacts::voucher::VoucherProgram;
use crate::voucher::{VoucherParameters, VoucherSpendPath};

/// The Voucher covenant: a burn-after-use, network-issued proof token.
pub struct Voucher {
    program: VoucherProgram,
    params: VoucherParameters,
}

impl Voucher {
    #[must_use]
    pub fn new(params: VoucherParameters) -> Self {
        Self {
            program: VoucherProgram::new(&params.build_arguments()),
            params,
        }
    }

    #[must_use]
    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.params.network)
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

        ft.add_program_input(
            PartialInput::new(voucher_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(path.build_witness()),
            ),
            required_signature,
        );
    }

    /// Adds an output that pays `amount` of `asset_id` to this Voucher.
    pub fn attach_voucher_output(&self, ft: &mut FinalTransaction, amount: u64, asset_id: AssetId) {
        ft.add_output(PartialOutput::new(
            self.get_script_pubkey(),
            amount,
            asset_id,
        ));
    }
}
