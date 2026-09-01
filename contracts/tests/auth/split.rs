//! 4. Authorized splitting of a Storm Eye UTXO into multiple UTXOs (spec §1.4.4).

use simplex::transaction::FinalTransaction;

use super::fixtures::{MAX_SPLIT_UTXOS_COUNT, StormEyeFixture, assert_covenant_rejects, kind};

/// One Storm Eye input declaring `declared_count`, and one covenant output per entry in `amounts`.
fn split_transaction(
    fixture: &StormEyeFixture,
    context: &simplex::TestContext,
    declared_count: u8,
    amounts: &[u64],
) -> anyhow::Result<FinalTransaction> {
    let utxo = fixture.utxos(context)?[0].clone();
    let mut tx = FinalTransaction::new();

    fixture.add_storm_eye_input(&mut tx, &utxo, kind::split(declared_count));
    fixture.add_storm_eye_outputs(context, &mut tx, amounts);

    Ok(tx)
}

/// The happy path: any distribution, as long as it sums to the input amount.
#[simplex::test]
fn splits_storm_eye_into_multiple_utxos(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let amounts = [5_000u64, 3_000, 2_000];

    let tx = split_transaction(&fixture, &context, amounts.len() as u8, &amounts)?;
    context.get_default_signer().broadcast(&tx)?.wait()?;

    Ok(())
}

/// Spec §1.4.4 check 6 is `split_utxos_count < MAX_SPLIT_UTXOS_COUNT`, so the bound itself
/// is out of range. Guards against the `lt_8`/`le_8` confusion, which the happy path
/// cannot see because it splits strictly below the bound.
#[simplex::test]
fn rejects_split_at_the_maximum_count(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;

    let amounts = [3_000u64, 2_500, 2_000, 1_500, 700, 300];
    assert_eq!(amounts.len() as u8, MAX_SPLIT_UTXOS_COUNT);

    let tx = split_transaction(&fixture, &context, amounts.len() as u8, &amounts)?;
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

/// Spec §1.4.4 check 6 also demands `split_utxos_count > 1`: a "split" into one output is
/// a plain inclusion and must go through §1.4.1 instead.
#[simplex::test]
fn rejects_split_into_a_single_utxo(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let amounts = [10_000u64];

    let tx = split_transaction(&fixture, &context, amounts.len() as u8, &amounts)?;
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

/// Check 8, value conservation: the outputs the covenant counts must add back up to the
/// amount it is spending, or the remainder leaves the covenant.
#[simplex::test]
fn rejects_split_that_does_not_conserve_value(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;

    // Declares three outputs but only lets the covenant see two of them, so the third
    // 2_000 is unaccounted for and free to leave.
    let amounts = [5_000u64, 3_000, 2_000];
    let tx = split_transaction(&fixture, &context, 2, &amounts)?;

    assert_covenant_rejects(&context, &tx);

    Ok(())
}
