use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use crate::artifacts::treasury::TreasuryProgram;
use crate::artifacts::treasury::derived_treasury::{TreasuryArguments, TreasuryWitness};

/// The Treasury covenant: spendable alongside a Storm Eye input.
pub struct Treasury {
    program: TreasuryProgram,
    params: TreasuryParameters,
}

pub struct TreasuryParameters {
    pub storm_eye_asset_id: AssetId,
}

impl Treasury {
    #[must_use]
    pub fn new(params: TreasuryParameters) -> Self {
        let program = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: params.storm_eye_asset_id.into_inner().to_byte_array(),
        });

        Self { program, params }
    }

    #[must_use]
    pub fn get_script_pubkey(&self, network: &SimplicityNetwork) -> Script {
        self.program.get_script_pubkey(network)
    }

    #[must_use]
    pub fn get_parameters(&self) -> &TreasuryParameters {
        &self.params
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

    /// Adds an output that pays `amount` of `asset_id` to this Treasury.
    pub fn attach_output(
        &self,
        ft: &mut FinalTransaction,
        network: &SimplicityNetwork,
        amount: u64,
        asset_id: AssetId,
    ) {
        ft.add_output(PartialOutput::new(
            self.get_script_pubkey(network),
            amount,
            asset_id,
        ));
    }
}
