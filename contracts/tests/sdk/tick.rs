use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::FinalTransaction;

use contracts::artifacts::sdk::tick_test::TickTestProgram;
use contracts::artifacts::sdk::tick_test::derived_tick_test::{TickTestArguments, TickTestWitness};
use contracts::voucher::Voucher;

use super::fixtures::{
    Consumer, SUPPLY, TICK_TIME, VoucherIssuer, assert_covenant_rejects, asset_bytes, issue_asset,
};

/// Spends a consumer expecting a Tick of `tick_asset` that carries `expected_time`, alongside
/// `tick` at input 1.
fn tick_check(
    context: &simplex::TestContext,
    issuer: &VoucherIssuer,
    tick: &Voucher,
    tick_asset: AssetId,
    expected_time: u64,
) -> anyhow::Result<FinalTransaction> {
    let consumer = Consumer::funded(
        context,
        &TickTestProgram::new(&TickTestArguments {
            tick_asset_id: asset_bytes(tick_asset),
            expected_time,
        }),
    )?;

    consumer.spend_with_vouchers(
        context,
        TickTestWitness {
            tick_input_index: 1,
        },
        &[tick],
        issuer.get_auth_asset(),
    )
}

#[simplex::test]
fn reads_the_time_from_a_tick(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let (tick, tick_asset) = issuer.issue_tick(&context)?;

    let ft = tick_check(&context, &issuer, &tick, tick_asset, TICK_TIME)?;

    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_a_time_other_than_the_tick_amount(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let (tick, tick_asset) = issuer.issue_tick(&context)?;

    let ft = tick_check(&context, &issuer, &tick, tick_asset, TICK_TIME + 1)?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_a_tick_of_another_asset(context: simplex::TestContext) -> anyhow::Result<()> {
    let issuer = VoucherIssuer::new(&context)?;
    let (tick, _) = issuer.issue_tick(&context)?;
    let decoy_asset = issue_asset(&context, SUPPLY)?;

    let ft = tick_check(&context, &issuer, &tick, decoy_asset, TICK_TIME)?;

    assert_covenant_rejects(&context, &ft);

    Ok(())
}
