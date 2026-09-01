use simplex::transaction::{FinalTransaction, PartialOutput};

use super::covenant::build_tree;
use super::fixtures::{StormEyeFixture, kind, program_with_storage};

/// 1. Authorized inclusion in a transaction without storage updating.
#[simplex::test]
fn spends_storm_eye_without_updating_storage(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let storm_eye_utxo = fixture.utxos(&context)?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    fixture.add_storm_eye_input(&mut final_utxo, &storm_eye_utxo, kind::inclusion(0));
    fixture.add_storm_eye_outputs(
        &context,
        &mut final_utxo,
        &[storm_eye_utxo.explicit_amount()],
    );

    context
        .get_default_signer()
        .broadcast(&final_utxo)?
        .wait()?;

    Ok(())
}

/// 2. Authorized inclusion in a transaction with an update to the
/// Storm Tree root using the network signature.
#[simplex::test]
fn spends_storm_eye_with_update_storm_tree_root(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let storm_eye_utxo = fixture.utxos(&context)?[0].clone();

    let rotated_tree = build_tree(&[fixture.signing_branch, [7u8; 32]]);
    let rotated = program_with_storage(rotated_tree.root(), fixture.rescue_number);

    let mut final_utxo = FinalTransaction::new();

    fixture.add_storm_eye_input(
        &mut final_utxo,
        &storm_eye_utxo,
        kind::root_update(rotated_tree.root(), 0),
    );

    // The output pays to the rotated covenant, not the current one.
    final_utxo.add_output(PartialOutput::new(
        rotated.get_script_pubkey(context.get_network()),
        storm_eye_utxo.explicit_amount(),
        fixture.asset,
    ));

    context
        .get_default_signer()
        .broadcast(&final_utxo)?
        .wait()?;

    Ok(())
}

/// 3. Authorized inclusion in a transaction with an update to the
/// rescue block number using a network signature.
#[simplex::test]
fn spends_storm_eye_with_update_rescue_block_number(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let storm_eye_utxo = fixture.utxos(&context)?[0].clone();

    let rotated_rescue_number = fixture.rescue_number + 1_576_800;
    let rotated = program_with_storage(fixture.storm_tree.root(), rotated_rescue_number);

    let mut final_utxo = FinalTransaction::new();

    fixture.add_storm_eye_input(
        &mut final_utxo,
        &storm_eye_utxo,
        kind::rescue_update(rotated_rescue_number, 0),
    );

    final_utxo.add_output(PartialOutput::new(
        rotated.get_script_pubkey(context.get_network()),
        storm_eye_utxo.explicit_amount(),
        fixture.asset,
    ));

    context
        .get_default_signer()
        .broadcast(&final_utxo)?
        .wait()?;

    Ok(())
}
