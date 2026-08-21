use simplex::either::Either;
use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use oracle_contracts::artifacts::auth::AuthProgram;
use oracle_contracts::artifacts::auth::derived_auth::{AuthArguments, AuthWitness};

use super::storm_tree::{Branch, StormTree, WitnessStep, WITNESS_DEPTH};

const STORM_EYE_SUPPLY: u64 = 10_000;
const RESCUE_BLOCK_NUMBER: u32 = 1_576_800;
/// Decoy combinations. Their contents never reach the covenant — only their bytes inside
/// the cuts do, and the covenant treats those as opaque.
const DECOY_BRANCHES: usize = 2;

/// Storage slot 1. The covenant widens the height to 32 bytes, so this is 28 zero bytes
/// followed by the height big-endian — see `get_rescue_block_slot_leaf` in storage.simf.
fn rescue_block_slot_value(rescue_block_number: u32) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[28..32].copy_from_slice(&rescue_block_number.to_be_bytes());

    slot
}

/// Issues the Storm Eye asset directly to the covenant, so there is a Storm Eye UTXO to
/// spend. No policy-asset change output here: `finalize` selects the L-BTC for the fee and
/// appends change itself, and adding one would leave it nothing to pay from.
fn issue_storm_eye_asset(
    context: &simplex::TestContext,
    program: &AuthProgram,
) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();

    let issuance = ft.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(STORM_EYE_SUPPLY, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        program.get_script_pubkey(context.get_network()),
        STORM_EYE_SUPPLY,
        issuance.asset_id,
    ));

    signer.broadcast(&ft)?.wait()?;

    Ok(issuance.asset_id)
}

/// Builds the Storm Tree, compiles the covenant with the tree root and rescue height in
/// storage, and funds it with the Storm Eye asset.
#[allow(unused_must_use)]
fn setup_storm_eye(
    context: &simplex::TestContext,
) -> anyhow::Result<(AuthProgram, StormTree, Branch, AssetId)> {
    let signer = context.get_default_signer();

    // The signing combination's key. A real network aggregates m-of-n node keys with
    // MuSig2, but the covenant only ever sees a 32-byte x-only key and a BIP-340
    // signature over sig_all_hash, and a MuSig2 aggregate signature is exactly that.
    // Using the signer's own key lets the smplx signer produce the signature.
    let signing_branch: Branch = signer.get_schnorr_public_key().serialize();

    // The other combinations the network could have signed with.
    let mut branches = vec![signing_branch];
    branches.extend((0..DECOY_BRANCHES).map(|index| [index as u8 + 1; 32]));

    let storm_tree = StormTree::new(&branches);

    // No compilation parameters yet: §1.2 lists three, but the only one referenced so far
    // is RESCUE_OUTPUT_SCRIPT_HASH, and the rescue path is still a stub.
    let mut program = AuthProgram::new(AuthArguments {}).with_storage_capacity(2);

    program.set_storage_at(0, storm_tree.root());
    program.set_storage_at(1, rescue_block_slot_value(RESCUE_BLOCK_NUMBER));

    let storm_eye_asset = issue_storm_eye_asset(context, &program)?;

    Ok((program, storm_tree, signing_branch, storm_eye_asset))
}

/// §1.4.1 — authorized inclusion in a transaction without storage updating.
///
/// Exercises the whole path at once: the storage load rebuilds the address from the
/// witness values, the Merkle fold walks the branch up to the stored root, the signature
/// verifies against that branch, and the output returns the UTXO to the same covenant
/// with the same asset and amount.
#[simplex::test]
fn spends_storm_eye_without_updating_storage(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let (program, mut storm_tree, signing_branch, _) = setup_storm_eye(&context)?;
    let proof: [WitnessStep; WITNESS_DEPTH] = storm_tree.witness_proof(&signing_branch);

    let storm_eye_script_pubkey = program.get_script_pubkey(context.get_network());
    let storm_eye_utxo = provider.fetch_scripthash_utxos(&storm_eye_script_pubkey)?[0].clone();

    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(storm_eye_utxo.clone()),
        ProgramInput::new(
            Box::new(program.as_ref().clone()),
            Box::new(AuthWitness {
                path: Either::Left((
                    // Storage: the values the address commits to.
                    (storm_tree.root(), RESCUE_BLOCK_NUMBER),
                    // Storm Tree Bloom: signature, branch, inclusion proof. The signature
                    // is a placeholder; the signer fills it in below.
                    ([0u8; 64], signing_branch, proof),
                    // §1.4.1 takes the Left branch of AuthKind: just the output index.
                    Either::Left(0u32),
                )),
            }),
        ),
        // Witness `PATH`, Left branch, bloom at tuple position 1, signature at 0.
        RequiredSignature::WitnessWithPath(
            "PATH".to_string(),
            vec!["Left".to_string(), "1".to_string(), "0".to_string()],
        ),
    );

    // The Storm Eye UTXO goes back to the same covenant, untouched — same script, same
    // asset, same amount, and storage unchanged.
    ft.add_output(PartialOutput::new(
        storm_eye_script_pubkey,
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&ft)?.wait()?;

    Ok(())
}
