use simplex::either::Either;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::artifacts::auth::AuthProgram;
use contracts::artifacts::auth::derived_auth::AuthWitness;

use super::covenant::{WITNESS_DEPTH, WitnessStep, build_tree, witness_proof};
use super::fixtures::{program_with_storage, setup_storm_eye};

/// 1. Authorized inclusion in a transaction without storage updating.
#[simplex::test]
fn spends_storm_eye_without_updating_storage(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let rescue_number = 1234;
    let (program, storm_tree, signing_branch, _) = setup_storm_eye(&context, rescue_number)?;
    let proof: [WitnessStep; WITNESS_DEPTH] = witness_proof(&storm_tree, &signing_branch);

    let storm_eye_script_pubkey = program.get_script_pubkey(context.get_network());
    let storm_eye_utxo = provider.fetch_scripthash_utxos(&storm_eye_script_pubkey)?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    final_utxo.add_program_input(
        PartialInput::new(storm_eye_utxo.clone()),
        ProgramInput::new(
            Box::new(program.as_ref().clone()),
            Box::new(AuthWitness {
                path: Either::Left((
                    (storm_tree.root(), rescue_number),
                    ([0u8; 64], signing_branch, proof),
                    // output_index
                    Either::Left(0u32),
                )),
            }),
        ),
        RequiredSignature::witness_tagged(
            "PATH",
            vec!["Left".to_string(), "1".to_string(), "0".to_string()],
            "OracleNetworkV1/StormEye",
        ),
    );

    final_utxo.add_output(PartialOutput::new(
        storm_eye_script_pubkey,
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(())
}

fn rotated_program(new_merkle_root: [u8; 32], new_rescue_number: u32) -> AuthProgram {
    program_with_storage(new_merkle_root, new_rescue_number)
}

/// 2. Authorized inclusion in a transaction with an update to the
/// Storm Tree root using the network signature.
#[simplex::test]
fn spends_storm_eye_with_update_storm_tree_root(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let rescue_number = 1234;
    let (program, storm_tree, signing_branch, _) = setup_storm_eye(&context, rescue_number)?;
    let proof: [WitnessStep; WITNESS_DEPTH] = witness_proof(&storm_tree, &signing_branch);

    let rotated_tree = build_tree(&[signing_branch, [7u8; 32]]);
    let rotated = rotated_program(rotated_tree.root(), rescue_number);

    let storm_eye_script_pubkey = program.get_script_pubkey(context.get_network());
    let rotated_script_pubkey = rotated.get_script_pubkey(context.get_network());
    let storm_eye_utxo = provider.fetch_scripthash_utxos(&storm_eye_script_pubkey)?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    final_utxo.add_program_input(
        PartialInput::new(storm_eye_utxo.clone()),
        ProgramInput::new(
            Box::new(program.as_ref().clone()),
            Box::new(AuthWitness {
                path: Either::Left((
                    (storm_tree.root(), rescue_number),
                    ([0u8; 64], signing_branch, proof),
                    Either::Right(Either::Left(Either::Left((
                        rotated_tree.root(),
                        // output_index
                        0u32,
                    )))),
                )),
            }),
        ),
        RequiredSignature::witness_tagged(
            "PATH",
            vec!["Left".to_string(), "1".to_string(), "0".to_string()],
            "OracleNetworkV1/StormEye",
        ),
    );

    final_utxo.add_output(PartialOutput::new(
        rotated_script_pubkey,
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(())
}

/// 3. Authorized inclusion in a transaction with an update to the
/// rescue block number using a network signature.
#[simplex::test]
fn spends_storm_eye_with_update_rescue_block_number(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let rescue_number = 1234;
    let (program, storm_tree, signing_branch, _) = setup_storm_eye(&context, rescue_number)?;
    let proof: [WitnessStep; WITNESS_DEPTH] = witness_proof(&storm_tree, &signing_branch);

    let rotated_rescue_number = rescue_number + 1_576_800;
    let rotated = rotated_program(storm_tree.root(), rotated_rescue_number);

    let storm_eye_script_pubkey = program.get_script_pubkey(context.get_network());
    let rotated_script_pubkey = rotated.get_script_pubkey(context.get_network());
    let storm_eye_utxo = provider.fetch_scripthash_utxos(&storm_eye_script_pubkey)?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    final_utxo.add_program_input(
        PartialInput::new(storm_eye_utxo.clone()),
        ProgramInput::new(
            Box::new(program.as_ref().clone()),
            Box::new(AuthWitness {
                path: Either::Left((
                    (storm_tree.root(), rescue_number),
                    ([0u8; 64], signing_branch, proof),
                    Either::Right(Either::Left(Either::Right((rotated_rescue_number, 0u32)))),
                )),
            }),
        ),
        RequiredSignature::witness_tagged(
            "PATH",
            vec!["Left".to_string(), "1".to_string(), "0".to_string()],
            "OracleNetworkV1/StormEye",
        ),
    );

    final_utxo.add_output(PartialOutput::new(
        rotated_script_pubkey,
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&final_utxo)?.wait()?;

    Ok(())
}
