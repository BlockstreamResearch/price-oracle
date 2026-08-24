use simplex::either::Either;
use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use oracle_contracts::artifacts::auth::AuthProgram;
use oracle_contracts::artifacts::auth::derived_auth::{AuthArguments, AuthWitness};

use super::storm_tree::{Branch, StormTree, WITNESS_DEPTH, WitnessStep};

const STORM_EYE_SUPPLY: u64 = 10_000;
const RESCUE_BLOCK_NUMBER: u32 = 1_576_800;

/// Storage slot 1.
fn rescue_block_slot_value(rescue_block_number: u32) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[28..32].copy_from_slice(&rescue_block_number.to_be_bytes());

    slot
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
#[allow(unused_must_use)]
fn setup_storm_eye(
    context: &simplex::TestContext,
) -> anyhow::Result<(AuthProgram, StormTree, Branch, AssetId)> {
    let signer = context.get_default_signer();
    let signing_branch: Branch = signer.get_schnorr_public_key().serialize();

    // The other combinations the network could have signed with.
    let branches = vec![signing_branch];

    let storm_tree = StormTree::new(&branches);

    let mut program = AuthProgram::new(AuthArguments {}).with_storage_capacity(2);

    program.set_storage_at(0, storm_tree.root());
    program.set_storage_at(1, rescue_block_slot_value(RESCUE_BLOCK_NUMBER));

    let storm_eye_asset = issue_storm_eye_asset(context, &program)?;

    Ok((program, storm_tree, signing_branch, storm_eye_asset))
}

/// 1. Authorized inclusion in a transaction without storage updating.
#[simplex::test]
fn spends_storm_eye_without_updating_storage(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let (program, mut storm_tree, signing_branch, _) = setup_storm_eye(&context)?;
    let proof: [WitnessStep; WITNESS_DEPTH] = storm_tree.witness_proof(&signing_branch);

    let storm_eye_script_pubkey = program.get_script_pubkey(context.get_network());
    let storm_eye_utxo = provider.fetch_scripthash_utxos(&storm_eye_script_pubkey)?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    final_utxo.add_program_input(
        PartialInput::new(storm_eye_utxo.clone()),
        ProgramInput::new(
            Box::new(program.as_ref().clone()),
            Box::new(AuthWitness {
                path: Either::Left((
                    (storm_tree.root(), RESCUE_BLOCK_NUMBER),
                    ([0u8; 64], signing_branch, proof),
                    // output_index
                    Either::Left(0u32),
                )),
            }),
        ),
        RequiredSignature::WitnessWithPath(
            "PATH".to_string(),
            vec!["Left".to_string(), "1".to_string(), "0".to_string()],
        ),
    );

    // The Storm Eye UTXO goes back to the same covenant, untouched — same script, same
    // asset, same amount, and storage unchanged.
    final_utxo.add_output(PartialOutput::new(
        storm_eye_script_pubkey,
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(())
}
