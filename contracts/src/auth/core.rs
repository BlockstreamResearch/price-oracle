use simplex::simplicityhl::elements::{AssetId, Script, Sequence};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, utxo::UTXO,
};

use crate::artifacts::auth::AuthProgram;
use crate::auth::params::AuthParameters;
use crate::auth::storage::StormEyeStorage;
use crate::auth::storm_tree::StormTreeBloom;
use crate::auth::witness::{AuthSpendPath, build_rescue_witness};

/// The Storm Eye covenant: the network's authorization anchor.
pub struct Auth {
    program: AuthProgram,
    params: AuthParameters,
    storage: StormEyeStorage,
}

impl Auth {
    #[must_use]
    pub fn new(params: AuthParameters, storage: StormEyeStorage) -> Self {
        let mut program = AuthProgram::new(&params.build_arguments()).with_storage_capacity(2);
        storage.apply(&mut program);

        Self {
            program,
            params,
            storage,
        }
    }

    #[must_use]
    pub fn get_script_pubkey(&self) -> Script {
        self.program.get_script_pubkey(&self.params.network)
    }

    #[must_use]
    pub fn get_parameters(&self) -> &AuthParameters {
        &self.params
    }

    #[must_use]
    pub fn get_storage(&self) -> StormEyeStorage {
        self.storage
    }

    /// Attaches a spend along one of 1-5, proving `bloom` authorizes it under
    /// this covenant's current storage.
    pub fn attach_spend(
        &self,
        ft: &mut FinalTransaction,
        utxo: &UTXO,
        path: AuthSpendPath,
        bloom: StormTreeBloom,
    ) {
        ft.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(path.build_witness(self.storage, bloom)),
            ),
            AuthSpendPath::required_signature(),
        );
    }

    /// Attaches a 6 rescue spend: no signature or Storm Tree proof needed once the
    /// rescue block number is reached.
    pub fn attach_rescue_spend(&self, ft: &mut FinalTransaction, utxo: &UTXO, output_index: u32) {
        ft.add_program_input(
            PartialInput::new(utxo.clone()).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(build_rescue_witness(self.storage, output_index)),
            ),
            RequiredSignature::None,
        );
    }

    /// Adds an output that pays `amount` of `asset_id` to this Storm Eye.
    pub fn attach_storm_eye_output(
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
