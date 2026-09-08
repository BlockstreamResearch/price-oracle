use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature};

use crate::artifacts::treasury::TreasuryProgram;
use crate::artifacts::treasury::derived_treasury::{TreasuryArguments, TreasuryWitness};

/// The Treasury covenant: spendable alongside a Storm Eye input.
pub struct Treasury {
    program: TreasuryProgram,
}

impl Treasury {
    #[must_use]
    pub fn new(storm_eye_asset_id: AssetId) -> Self {
        let program = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye_asset_id.into_inner().to_byte_array(),
        });

        Self { program }
    }

    #[must_use]
    pub fn get_script_pubkey(&self, network: &SimplicityNetwork) -> Script {
        self.program.get_script_pubkey(network)
    }

    /// Attaches a spend of `treasury_utxo`, proving `storm_eye_input_index`
    /// carries the Storm Eye asset.
    pub fn attach_spend(
        &self,
        ft: &mut FinalTransaction,
        treasury_utxo: &UTXO,
        storm_eye_input_index: u32,
    ) {
        ft.add_program_input(
            PartialInput::new(treasury_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(TreasuryWitness {
                    storm_eye_input_index,
                }),
            ),
            RequiredSignature::None,
        );
    }
}
