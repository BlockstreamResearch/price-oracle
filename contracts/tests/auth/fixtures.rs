//! Shared setup for the Storm Eye covenant tests.

use simplex::signer::SignerError;
use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use oracle_contracts::artifacts::auth::AuthProgram;
use oracle_contracts::artifacts::auth::derived_auth::AuthArguments;

use storm_tree::smt::MerkleTree;

use super::covenant::{Branch, build_tree};

pub const STORM_EYE_SUPPLY: u64 = 10_000;

/// The upper bound compiled into every test program. Spec §1.4.4 accepts a split into
/// `2..MAX_SPLIT_UTXOS_COUNT`, so with this value only 2 and 3 are legal.
pub const MAX_SPLIT_UTXOS_COUNT: u8 = 4;

/// Storage slot 1.
pub fn rescue_block_slot_value(rescue_block_number: u32) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[28..32].copy_from_slice(&rescue_block_number.to_be_bytes());

    slot
}

/// Compiles the covenant with the given storage state, without funding it.
#[allow(unused_must_use)]
pub fn program_with_storage(merkle_root: [u8; 32], rescue_block_number: u32) -> AuthProgram {
    let mut program = AuthProgram::new(&AuthArguments {
        max_split_utxos_count: MAX_SPLIT_UTXOS_COUNT,
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

/// Builds the Storm Tree, compiles the covenant with the tree root and rescue height in
/// storage, and funds it with the Storm Eye asset.
pub fn setup_storm_eye(
    context: &simplex::TestContext,
    rescue_number: u32,
) -> anyhow::Result<(AuthProgram, MerkleTree, Branch, AssetId)> {
    let signer = context.get_default_signer();
    let signing_branch: Branch = signer.get_schnorr_public_key().serialize();

    // The other combinations the network could have signed with.
    let branches = vec![signing_branch];

    let storm_tree = build_tree(&branches);
    let program = program_with_storage(storm_tree.root(), rescue_number);

    let storm_eye_asset = issue_storm_eye_asset(context, &program)?;

    Ok((program, storm_tree, signing_branch, storm_eye_asset))
}

/// Asserts the transaction is rejected by the covenant
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
