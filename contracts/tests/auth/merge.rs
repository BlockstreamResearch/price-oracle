//! 5. Authorized merging of multiple Storm Eyes into a single Storm Eye (spec §1.4.5).

use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialOutput};

use super::fixtures::{MAX_MERGE_UTXOS_COUNT, StormEyeFixture, assert_covenant_rejects, kind};

fn merge_transaction(
    fixture: &StormEyeFixture,
    context: &simplex::TestContext,
    utxos: &[UTXO],
    declared_count: u8,
    output_amount: u64,
) -> FinalTransaction {
    let mut tx = FinalTransaction::new();

    for utxo in utxos {
        fixture.add_storm_eye_input(&mut tx, utxo, kind::merge(declared_count));
    }
    fixture.add_storm_eye_outputs(context, &mut tx, &[output_amount]);

    tx
}

fn total(utxos: &[UTXO]) -> u64 {
    utxos.iter().map(UTXO::explicit_amount).sum()
}

/// The happy path: N Storm Eyes in, one carrying their sum out.
#[simplex::test]
fn merges_multiple_utxos_into_single_storm_eye(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;

    let utxos = fixture.split_into(&context, &[5_000, 3_000, 2_000])?;

    let tx = merge_transaction(&fixture, &context, &utxos, utxos.len() as u8, total(&utxos));
    context.get_default_signer().broadcast(&tx)?.wait()?;

    Ok(())
}

/// Spec §1.4.5 check 5 is `utxos_to_merge < MAX_MERGE_UTXOS_COUNT`.
#[simplex::test]
fn rejects_merge_at_the_maximum_count(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;

    let utxos = fixture.split_into(&context, &[4_000, 3_000, 2_000, 1_000])?;
    assert_eq!(utxos.len() as u8, MAX_MERGE_UTXOS_COUNT);

    let tx = merge_transaction(&fixture, &context, &utxos, utxos.len() as u8, total(&utxos));
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

/// `utxos_to_merge > 1` check: merging one UTXO into one is an inclusion,
/// and must go through §1.4.1 instead.
#[simplex::test]
fn rejects_merge_of_a_single_utxo(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let utxos = fixture.utxos(&context)?;

    let tx = merge_transaction(&fixture, &context, &utxos, 1, total(&utxos));
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

/// `output(0)` must carry the sum of the merged inputs, or the difference leaves the covenant.
#[simplex::test]
fn rejects_merge_that_does_not_conserve_value(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = StormEyeFixture::new(&context)?;
    let utxos = fixture.split_into(&context, &[5_000, 3_000, 2_000])?;

    let tx = merge_transaction(
        &fixture,
        &context,
        &utxos,
        utxos.len() as u8,
        total(&utxos) - 1_000,
    );
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

#[simplex::test]
fn rejects_merge_ignoring_an_extra_storm_eye_input(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let fixture = StormEyeFixture::new(&context)?;
    let utxos = fixture.split_into(&context, &[5_000, 3_000, 2_000])?;

    // Declares two inputs but spends all three; the third is unaccounted for.
    let counted = total(&utxos[..2]);
    let escaped = total(&utxos) - counted;

    let mut tx = FinalTransaction::new();

    for utxo in &utxos {
        fixture.add_storm_eye_input(&mut tx, utxo, kind::merge(2));
    }
    fixture.add_storm_eye_outputs(&context, &mut tx, &[counted]);

    // Out of the covenant entirely.
    tx.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        escaped,
        fixture.asset,
    ));

    assert_covenant_rejects(&context, &tx);

    Ok(())
}
