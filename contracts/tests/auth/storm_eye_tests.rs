use simplex::transaction::FinalTransaction;

use contracts::auth::{AuthSpendPath, AuthStorage, build_tree};

use super::fixtures::StormEyeFixture;

/// 1. Authorized inclusion in a transaction without storage updating.
#[simplex::test]
fn spends_storm_eye_without_updating_storage(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let storm_eye_utxo = fixture.utxos(&context)?[0].clone();

    let mut final_utxo = FinalTransaction::new();

    fixture.add_storm_eye_input(
        &mut final_utxo,
        &storm_eye_utxo,
        AuthSpendPath::Inclusion { output_index: 0 },
    );
    fixture.add_storm_eye_outputs(&mut final_utxo, &[storm_eye_utxo.explicit_amount()]);

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

    let mut final_utxo = FinalTransaction::new();

    let _ = fixture.auth.attach_storage_update(
        &mut final_utxo,
        &storm_eye_utxo,
        AuthStorage {
            merkle_root: rotated_tree.root(),
            rescue_block_number: fixture.rescue_number,
        },
        fixture.bloom(),
    );

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

    let mut final_utxo = FinalTransaction::new();

    let _ = fixture.auth.attach_storage_update(
        &mut final_utxo,
        &storm_eye_utxo,
        AuthStorage {
            merkle_root: fixture.storm_tree.root(),
            rescue_block_number: rotated_rescue_number,
        },
        fixture.bloom(),
    );

    context
        .get_default_signer()
        .broadcast(&final_utxo)?
        .wait()?;

    Ok(())
}
