use simplex::simplicityhl::elements::{AssetId, LockTime, Script, Sequence};
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, utxo::UTXO,
};

use crate::artifacts::auth::AuthProgram;
use crate::auth::params::AuthParameters;
use crate::auth::storage::AuthStorage;
use crate::auth::storm_tree::StormTreeBloom;
use crate::auth::witness::{AuthSpendPath, build_rescue_witness};

/// The Storm Eye covenant: the network's authorization anchor.
pub struct Auth {
    program: AuthProgram,
    params: AuthParameters,
    storage: AuthStorage,
}

impl Auth {
    #[must_use]
    pub fn new(params: AuthParameters, storage: AuthStorage) -> Self {
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
    pub fn get_storage(&self) -> AuthStorage {
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

        ft.set_locktime(
            LockTime::from_height(self.storage.rescue_block_number)
                .expect("rescue_block_number is a valid block height"),
        );
    }

    /// # Panics
    /// Panics if `new_storage` changes both fields, or neither.
    #[must_use]
    pub fn attach_storage_update(
        &self,
        ft: &mut FinalTransaction,
        utxo: &UTXO,
        new_storage: AuthStorage,
        bloom: StormTreeBloom,
    ) -> Self {
        let root_changed = new_storage.merkle_root != self.storage.merkle_root;
        let rescue_changed = new_storage.rescue_block_number != self.storage.rescue_block_number;
        assert!(
            root_changed ^ rescue_changed,
            "a storage update rotates exactly one of merkle_root or rescue_block_number"
        );

        let output_index = ft.n_outputs() as u32;

        let path = if root_changed {
            AuthSpendPath::RootUpdate {
                new_merkle_root: new_storage.merkle_root,
                output_index,
            }
        } else {
            AuthSpendPath::RescueBlockUpdate {
                new_rescue_block_number: new_storage.rescue_block_number,
                output_index,
            }
        };

        self.attach_spend(ft, utxo, path, bloom);

        let rotated = Self::new(self.params, new_storage);

        ft.add_output(PartialOutput::new(
            rotated.get_script_pubkey(),
            utxo.explicit_amount(),
            utxo.explicit_asset(),
        ));

        rotated
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
