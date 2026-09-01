//! Shared setup for the Storm Eye covenant tests.

use simplex::either::Either;
use simplex::signer::SignerError;
use simplex::simplicityhl::elements::{AssetId, Script, Sequence};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::artifacts::auth::AuthProgram;
use contracts::artifacts::auth::derived_auth::{AuthArguments, AuthWitness};

use storm_tree::smt::MerkleTree;

use super::covenant::{Branch, WITNESS_DEPTH, WitnessStep, build_tree, witness_proof};

pub const STORM_EYE_SUPPLY: u64 = 10_000;

/// The upper bounds compiled into every test program. Spec §1.4.4 and §1.4.5 accept
/// `2..MAX`, exclusive.
pub const MAX_SPLIT_UTXOS_COUNT: u8 = 6;
pub const MAX_MERGE_UTXOS_COUNT: u8 = 4;

/// The witness arm selecting a spending path, mirroring `AuthKind` in `auth.simf`.
pub type AuthKind = Either<u32, Either<Either<([u8; 32], u32), (u32, u32)>, Either<u8, u8>>>;

/// One constructor per spending path, in the order `auth.simf` declares them.
pub mod kind {
    use super::{AuthKind, Either};

    pub fn inclusion(output_index: u32) -> AuthKind {
        Either::Left(output_index)
    }

    pub fn root_update(new_merkle_root: [u8; 32], output_index: u32) -> AuthKind {
        Either::Right(Either::Left(Either::Left((new_merkle_root, output_index))))
    }

    pub fn rescue_update(new_rescue_block_number: u32, output_index: u32) -> AuthKind {
        Either::Right(Either::Left(Either::Right((
            new_rescue_block_number,
            output_index,
        ))))
    }

    pub fn split(count: u8) -> AuthKind {
        Either::Right(Either::Right(Either::Left(count)))
    }

    pub fn merge(count: u8) -> AuthKind {
        Either::Right(Either::Right(Either::Right(count)))
    }
}

/// Storage slot 1.
pub fn rescue_block_slot_value(rescue_block_number: u32) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[28..32].copy_from_slice(&rescue_block_number.to_be_bytes());

    slot
}

/// Only for point 6. 1-5 tests never used it
pub const UNUSED_RESCUE_OUTPUT_SCRIPT_HASH: [u8; 32] = [0u8; 32];

pub const DEFAULT_RESCUE_NUMBER: u32 = 1234;

/// Compiles the covenant with the given storage state, without funding it.
pub fn program_with_storage(merkle_root: [u8; 32], rescue_block_number: u32) -> AuthProgram {
    program_with_rescue_output(
        merkle_root,
        rescue_block_number,
        UNUSED_RESCUE_OUTPUT_SCRIPT_HASH,
    )
}

/// As [`program_with_storage`], but naming where §1.4.6 is allowed to send the funds.
#[allow(unused_must_use)]
pub fn program_with_rescue_output(
    merkle_root: [u8; 32],
    rescue_block_number: u32,
    rescue_output_script_hash: [u8; 32],
) -> AuthProgram {
    let mut program = AuthProgram::new(&AuthArguments {
        max_merge_utxos_count: MAX_MERGE_UTXOS_COUNT,
        max_split_utxos_count: MAX_SPLIT_UTXOS_COUNT,
        rescue_output_script_hash,
    })
    .with_storage_capacity(2);

    program.set_storage_at(0, merkle_root);
    program.set_storage_at(1, rescue_block_slot_value(rescue_block_number));

    program
}

fn issue_storm_eye_asset(
    context: &simplex::TestContext,
    program: &AuthProgram,
) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    let issuance = final_utxo.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(STORM_EYE_SUPPLY, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    final_utxo.add_output(PartialOutput::new(
        program.get_script_pubkey(context.get_network()),
        STORM_EYE_SUPPLY,
        issuance.asset_id,
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(issuance.asset_id)
}

/// A compiled, funded Storm Eye covenant and the material every witness needs.
pub struct StormEyeFixture {
    pub program: AuthProgram,
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
        let proof = witness_proof(&storm_tree, &signing_branch);

        let program =
            program_with_rescue_output(storm_tree.root(), rescue_number, rescue_output_script_hash);
        let asset = issue_storm_eye_asset(context, &program)?;

        Ok(Self {
            program,
            storm_tree,
            signing_branch,
            proof,
            rescue_number,
            asset,
        })
    }

    pub fn script_pubkey(&self, context: &simplex::TestContext) -> Script {
        self.program.get_script_pubkey(context.get_network())
    }

    pub fn utxos(&self, context: &simplex::TestContext) -> anyhow::Result<Vec<UTXO>> {
        let script_pubkey = self.script_pubkey(context);

        Ok(context
            .get_default_provider()
            .fetch_scripthash_utxos(&script_pubkey)?)
    }

    /// Spends `utxo` through the covenant along the given spending path.
    pub fn add_storm_eye_input(&self, tx: &mut FinalTransaction, utxo: &UTXO, kind: AuthKind) {
        tx.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(AuthWitness {
                    path: Either::Left((
                        (self.storm_tree.root(), self.rescue_number),
                        ([0u8; 64], self.signing_branch, self.proof),
                        kind,
                    )),
                }),
            ),
            RequiredSignature::witness_tagged(
                "PATH",
                vec!["Left".to_string(), "1".to_string(), "0".to_string()],
                "OracleNetworkV1/StormEye",
            ),
        );
    }

    /// Spends `utxo` through §1.4.6, the rescue path — the `Either::Right` witness arm,
    /// with no signature and no Merkle proof.
    ///
    /// The sequence matters: at the default `Sequence::MAX` the transaction is *final*,
    /// which switches off nLockTime enforcement entirely, and `jet::check_lock_height`
    /// then fails no matter how the locktime is set. The caller still has to call
    /// `set_locktime` on the transaction.
    pub fn add_rescue_input(&self, tx: &mut FinalTransaction, utxo: &UTXO, output_index: u32) {
        tx.add_program_input(
            PartialInput::new(utxo.clone()).with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
            ProgramInput::new(
                Box::new(self.program.as_ref().clone()),
                Box::new(AuthWitness {
                    path: Either::Right((
                        (self.storm_tree.root(), self.rescue_number),
                        output_index,
                    )),
                }),
            ),
            RequiredSignature::None,
        );
    }

    /// Adds one covenant-owned output per entry in `amounts`.
    pub fn add_storm_eye_outputs(
        &self,
        context: &simplex::TestContext,
        tx: &mut FinalTransaction,
        amounts: &[u64],
    ) {
        let script_pubkey = self.script_pubkey(context);

        for amount in amounts {
            tx.add_output(PartialOutput::new(
                script_pubkey.clone(),
                *amount,
                self.asset,
            ));
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

        self.add_storm_eye_input(&mut tx, &utxo, kind::split(amounts.len() as u8));
        self.add_storm_eye_outputs(context, &mut tx, amounts);

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
