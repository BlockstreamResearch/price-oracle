use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use crate::artifacts::account::AccountProgram;
use crate::artifacts::account::derived_account::{AccountArguments, AccountWitness};

/// The Account covenant: spendable alongside a Storm Eye input.
pub struct Account {
    program: AccountProgram,
    params: AccountParameters,
}

pub struct AccountParameters {
    pub storm_eye_asset_id: AssetId,
    pub account_owner_pubkey: [u8; 32],
    pub network: SimplicityNetwork,
}

impl Account {
    #[must_use]
    pub fn new(params: AccountParameters) -> Self {
        let program = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: params.storm_eye_asset_id.into_inner().to_byte_array(),
            account_owner_pubkey: params.account_owner_pubkey,
        });

        Self { program, params }
    }

    #[must_use]
    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.params.network)
    }

    #[must_use]
    pub fn get_parameters(&self) -> &AccountParameters {
        &self.params
    }

    pub fn attach_spend(
        &self,
        ft: &mut FinalTransaction,
        account_utxo: &UTXO,
        storm_eye_input_index: u32,
    ) {
        ft.add_program_input(
            PartialInput::new(account_utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(AccountWitness {
                    storm_eye_input_index,
                }),
            ),
            RequiredSignature::None,
        );
    }

    /// Adds an output that pays `amount` of `asset_id` to this Account.
    pub fn attach_account_output(&self, ft: &mut FinalTransaction, amount: u64, asset_id: AssetId) {
        ft.add_output(PartialOutput::new(
            self.get_script_pubkey(),
            amount,
            asset_id,
        ));
    }
}
