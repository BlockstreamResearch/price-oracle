//! Shared setup for the Storm Eye covenant tests.

use simplex::{
    provider::SimplicityNetwork,
    signer::SignerError,
    simplicityhl::elements::{AssetId, Script},
    transaction::{
        FinalTransaction, PartialInput, RequiredSignature, partial_input::IssuanceInput, utxo::UTXO,
    },
};

use storm_tree::smt::MerkleTree;

use contracts::auth::{
    Auth, AuthParameters, AuthSpendPath, Branch, StormEyeStorage, StormTreeBloom, WITNESS_DEPTH,
    WitnessStep, build_tree, witness_proof,
};

pub const STORM_EYE_SUPPLY: u64 = 10_000;

/// The upper bounds compiled into every test program. Spec §1.4.4 and §1.4.5 accept
/// `2..MAX`, exclusive.
pub const MAX_SPLIT_UTXOS_COUNT: u8 = 6;
pub const MAX_MERGE_UTXOS_COUNT: u8 = 4;

/// Only for point 6. 1-5 tests never used it
pub const UNUSED_RESCUE_OUTPUT_SCRIPT_HASH: [u8; 32] = [0u8; 32];

pub const DEFAULT_RESCUE_NUMBER: u32 = 1234;

/// Compiles the covenant with the given storage state, without funding it.
pub fn auth_with_storage(
    merkle_root: [u8; 32],
    rescue_block_number: u32,
    network: SimplicityNetwork,
) -> Auth {
    auth_with_rescue_output(
        merkle_root,
        rescue_block_number,
        UNUSED_RESCUE_OUTPUT_SCRIPT_HASH,
        network,
    )
}

/// As [`auth_with_storage`], but naming where §1.4.6 is allowed to send the funds.
pub fn auth_with_rescue_output(
    merkle_root: [u8; 32],
    rescue_block_number: u32,
    rescue_output_script_hash: [u8; 32],
    network: SimplicityNetwork,
) -> Auth {
    Auth::new(
        AuthParameters::new(MAX_SPLIT_UTXOS_COUNT, MAX_MERGE_UTXOS_COUNT, network)
            .with_rescue_output(rescue_output_script_hash),
        StormEyeStorage {
            merkle_root,
            rescue_block_number,
        },
    )
}

fn issue_storm_eye_asset(context: &simplex::TestContext, auth: &Auth) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    let issuance = final_utxo.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(STORM_EYE_SUPPLY, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    auth.attach_storm_eye_output(&mut final_utxo, STORM_EYE_SUPPLY, issuance.asset_id);

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(issuance.asset_id)
}

/// A compiled, funded Storm Eye covenant and the material every witness needs.
pub struct StormEyeFixture {
    pub auth: Auth,
    pub storm_tree: MerkleTree,
    pub signing_branch: Branch,
    pub proof: [WitnessStep; WITNESS_DEPTH],
    pub rescue_number: u32,
    pub asset: AssetId,
}

impl StormEyeFixture {
    /// Builds the Storm Tree, compiles the covenant with the tree root and rescue height
    /// in storage, and funds it with a single Storm Eye UTXO of [`STORM_EYE_SUPPLY`].
    pub fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        Self::with_rescue(
            context,
            DEFAULT_RESCUE_NUMBER,
            UNUSED_RESCUE_OUTPUT_SCRIPT_HASH,
        )
    }

    /// As [`StormEyeFixture::new`], but fixing the rescue height and destination that
    /// §1.4.6 will check against.
    pub fn with_rescue(
        context: &simplex::TestContext,
        rescue_number: u32,
        rescue_output_script_hash: [u8; 32],
    ) -> anyhow::Result<Self> {
        let signing_branch: Branch = context
            .get_default_signer()
            .get_schnorr_public_key()
            .serialize();

        // The other combinations the network could have signed with.
        let storm_tree = build_tree(&[signing_branch]);
        let proof =
            witness_proof(&storm_tree, &signing_branch).expect("proof fits the covenant depth");

        let auth = auth_with_rescue_output(
            storm_tree.root(),
            rescue_number,
            rescue_output_script_hash,
            *context.get_network(),
        );
        let asset = issue_storm_eye_asset(context, &auth)?;

        Ok(Self {
            auth,
            storm_tree,
            signing_branch,
            proof,
            rescue_number,
            asset,
        })
    }

    pub fn script_pubkey(&self) -> Script {
        self.auth.get_script_pubkey()
    }

    pub fn utxos(&self, context: &simplex::TestContext) -> anyhow::Result<Vec<UTXO>> {
        Ok(context
            .get_default_provider()
            .fetch_scripthash_utxos(&self.script_pubkey())?)
    }

    /// Fixture's own signing combination's authorization proof
    fn bloom(&self) -> StormTreeBloom {
        StormTreeBloom {
            signature: [0u8; 64],
            branch: self.signing_branch,
            proof: self.proof,
        }
    }

    /// Spends `utxo` through the covenant along the given spending path.
    pub fn add_storm_eye_input(&self, tx: &mut FinalTransaction, utxo: &UTXO, path: AuthSpendPath) {
        self.auth.attach_spend(tx, utxo, path, self.bloom());
    }

    /// Spends `utxo` through the rescue path with no signature and no Merkle proof.
    ///
    /// The caller has to call `set_locktime` on the transaction.
    pub fn add_rescue_input(&self, tx: &mut FinalTransaction, utxo: &UTXO, output_index: u32) {
        self.auth.attach_rescue_spend(tx, utxo, output_index);
    }

    /// Adds one covenant-owned output per entry in `amounts`.
    pub fn add_storm_eye_outputs(&self, tx: &mut FinalTransaction, amounts: &[u64]) {
        for amount in amounts {
            self.auth.attach_storm_eye_output(tx, *amount, self.asset);
        }
    }

    /// Splits the single funding UTXO along §1.4.4 and broadcasts.
    pub fn split_into(
        &self,
        context: &simplex::TestContext,
        amounts: &[u64],
    ) -> anyhow::Result<Vec<UTXO>> {
        let utxo = self.utxos(context)?[0].clone();
        assert_eq!(amounts.iter().sum::<u64>(), utxo.explicit_amount());

        let mut tx = FinalTransaction::new();

        self.add_storm_eye_input(
            &mut tx,
            &utxo,
            AuthSpendPath::Split {
                split_utxos_count: amounts.len() as u8,
            },
        );
        self.add_storm_eye_outputs(&mut tx, amounts);

        context.get_default_signer().broadcast(&tx)?.wait()?;

        let utxos = self.utxos(context)?;
        assert_eq!(utxos.len(), amounts.len());

        Ok(utxos)
    }
}

#[track_caller]
pub fn assert_covenant_rejects(context: &simplex::TestContext, tx: &FinalTransaction) {
    match context.get_default_signer().broadcast(tx) {
        Err(SignerError::CovenantExecution { index, source, .. }) => {
            println!("covenant rejected input {index} as expected: {source}");
        }
        Err(other) => panic!("expected the covenant to reject the transaction, got: {other}"),
        Ok(_) => panic!("expected the covenant to reject the transaction, but it was accepted"),
    }
}
