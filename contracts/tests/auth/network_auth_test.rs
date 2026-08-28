//! Exercises `assert_network_authorization` on its own, before the full flow.

use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use oracle_contracts::artifacts::auth_helpers::network_auth_test::NetworkAuthTestProgram;
use oracle_contracts::artifacts::auth_helpers::network_auth_test::derived_network_auth_test::{
    NetworkAuthTestArguments, NetworkAuthTestWitness,
};

use super::covenant::{Branch, WITNESS_DEPTH, WitnessStep, build_tree, witness_proof};

const SUPPLY: u64 = 500_000;

fn issue_asset_to(
    context: &simplex::TestContext,
    program: &NetworkAuthTestProgram,
) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    let issuance = final_utxo.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(SUPPLY, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    final_utxo.add_output(PartialOutput::new(
        program.get_script_pubkey(context.get_network()),
        SUPPLY,
        issuance.asset_id,
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(issuance.asset_id)
}

/// Proves a branch is in the tree committed to by `merkle_root`.
#[simplex::test]
fn accepts_a_valid_inclusion_proof(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let signing_branch: Branch = signer.get_schnorr_public_key().serialize();
    let branches = vec![signing_branch, [1u8; 32], [2u8; 32]];
    let storm_tree = build_tree(&branches);
    let proof: [WitnessStep; WITNESS_DEPTH] = witness_proof(&storm_tree, &signing_branch);

    let program = NetworkAuthTestProgram::new(&NetworkAuthTestArguments {});
    let script_pubkey = program.get_script_pubkey(context.get_network());
    issue_asset_to(&context, &program)?;

    let utxo = provider.fetch_scripthash_utxos(&script_pubkey)?[0].clone();

    let mut final_utxo = FinalTransaction::new();
    final_utxo.add_program_input(
        PartialInput::new(utxo.clone()),
        ProgramInput::new(
            Box::new(program.as_ref().clone()),
            Box::new(NetworkAuthTestWitness {
                merkle_root: storm_tree.root(),
                storm_tree_bloom: ([0u8; 64], signing_branch, proof),
            }),
        ),
        RequiredSignature::tagged(
            "STORM_TREE_BLOOM",
            vec!["0".to_string()],
            "OracleNetworkV1/StormEye",
        ),
    );

    // The covenant inspects no outputs, so this one only has to carry the asset somewhere.
    final_utxo.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        utxo.explicit_amount(),
        utxo.explicit_asset(),
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(())
}
