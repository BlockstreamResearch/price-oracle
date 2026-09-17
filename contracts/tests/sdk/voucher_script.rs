use simplex::transaction::FinalTransaction;
use simplex::utils::{hash_script, tr_unspendable_key};

use contracts::artifacts::tests::sdk::voucher_script_test::VoucherScriptTestProgram;
use contracts::artifacts::tests::sdk::voucher_script_test::derived_voucher_script_test::{
    VoucherScriptTestArguments, VoucherScriptTestWitness,
};
use contracts::voucher::Voucher;

use super::fixtures::{
    Consumer, ORACLE_SECRET, OTHER_SECRET, VoucherIssuer, assert_covenant_rejects, x_only,
};

/// Spends a consumer that rebuilds a voucher script from `witness` and compares it with
/// `expected`'s script hash.
fn script_check(
    context: &simplex::TestContext,
    expected: &Voucher,
    witness: VoucherScriptTestWitness,
) -> anyhow::Result<FinalTransaction> {
    let consumer = Consumer::funded(
        context,
        &VoucherScriptTestProgram::new(&VoucherScriptTestArguments {
            expected_script_hash: hash_script(&expected.get_script_pubkey()),
        }),
    )?;

    consumer.spend(context, witness)
}

#[simplex::test]
fn rebuilds_the_script_of_a_verifier(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let issuer = VoucherIssuer::new(&context)?;
    let verifier = Voucher::new_with_taproot_pubkey(issuer.get_parameters(), oracle);

    let ft = script_check(
        &context,
        &verifier,
        VoucherScriptTestWitness {
            internal_key: oracle.serialize(),
            tapleaf_hash: verifier.get_tapleaf_hash(),
        },
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

/// A Tick has no key of its own: `Voucher::new` commits to the unspendable key.
#[simplex::test]
fn rebuilds_the_script_of_a_tick(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let tick = Voucher::new(issuer.get_parameters());

    let ft = script_check(
        &context,
        &tick,
        VoucherScriptTestWitness {
            internal_key: tr_unspendable_key().serialize(),
            tapleaf_hash: tick.get_tapleaf_hash(),
        },
    )?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_a_script_rebuilt_from_another_key(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let verifier = Voucher::new_with_taproot_pubkey(issuer.get_parameters(), x_only(ORACLE_SECRET));

    let ft = script_check(
        &context,
        &verifier,
        VoucherScriptTestWitness {
            internal_key: x_only(OTHER_SECRET).serialize(),
            tapleaf_hash: verifier.get_tapleaf_hash(),
        },
    )?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}
