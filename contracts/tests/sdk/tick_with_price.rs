use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::FinalTransaction;

use contracts::artifacts::tests::sdk::tick_with_price_test::TickWithPriceTestProgram;
use contracts::artifacts::tests::sdk::tick_with_price_test::derived_tick_with_price_test::{
    TickWithPriceTestArguments, TickWithPriceTestWitness,
};
use contracts::sdk::SignedPrice;
use contracts::voucher::Voucher;
use price_feed::PriceFeedData;

use super::fixtures::{
    Consumer, ORACLE_SECRET, SUPPLY, TICK_TIME, VoucherIssuer, assert_covenant_rejects,
    asset_bytes, issue_asset, network_signed_price, x_only,
};

const TICK_INDEX: u32 = 1;
const VERIFIER_INDEX: u32 = 2;

/// Fresh at the Tick's time: `valid_until` is after `TICK_TIME`.
const PRICE: PriceFeedData = PriceFeedData {
    feed_id: 4,
    price: 9_876_543_210,
    decimals: 8,
    received_at: TICK_TIME - 10,
    valid_until: TICK_TIME + 50,
};

/// A Tick carrying `TICK_TIME` and a Verifier committed to the oracle key.
struct TickWithPriceFixture {
    issuer: VoucherIssuer,
    tick: Voucher,
    tick_asset: AssetId,
    verifier: Voucher,
    verifier_asset: AssetId,
}

impl TickWithPriceFixture {
    fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        let issuer = VoucherIssuer::new(context)?;
        let (tick, tick_asset) = issuer.issue_tick(context)?;
        let (verifier, verifier_asset) = issuer.issue_verifier(context, x_only(ORACLE_SECRET))?;

        Ok(Self {
            issuer,
            tick,
            tick_asset,
            verifier,
            verifier_asset,
        })
    }

    /// A consumer that accepts Ticks of `tick_asset` and expects the time `TICK_TIME`.
    fn consumer(
        &self,
        context: &simplex::TestContext,
        tick_asset: AssetId,
    ) -> anyhow::Result<Consumer> {
        Consumer::funded(
            context,
            &TickWithPriceTestProgram::new(&TickWithPriceTestArguments {
                tick_asset_id: asset_bytes(tick_asset),
                verifier_asset_id: asset_bytes(self.verifier_asset),
                expected_time: TICK_TIME,
            }),
        )
    }

    fn spend(
        &self,
        context: &simplex::TestContext,
        consumer: &Consumer,
        signed: &SignedPrice,
    ) -> anyhow::Result<FinalTransaction> {
        consumer.spend_with_vouchers(
            context,
            TickWithPriceTestWitness {
                tick_input_index: TICK_INDEX,
                verifier_input_index: VERIFIER_INDEX,
                verifier_tapleaf_hash: self.verifier.get_tapleaf_hash(),
                signer: signed.get_signer(),
                price_signature: signed.get_signature(),
                price_feed_data: signed.get_price_witness(),
            },
            &[&self.tick, &self.verifier],
            self.issuer.get_auth_asset(),
        )
    }
}

#[simplex::test]
fn accepts_a_fresh_price_at_the_tick_time(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = TickWithPriceFixture::new(&context)?;
    let consumer = fixture.consumer(&context, fixture.tick_asset)?;

    let signed = network_signed_price(x_only(ORACLE_SECRET), ORACLE_SECRET, PRICE);

    let ft = fixture.spend(&context, &consumer, &signed)?;
    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_a_price_expired_at_the_tick_time(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = TickWithPriceFixture::new(&context)?;
    let consumer = fixture.consumer(&context, fixture.tick_asset)?;

    let signed = network_signed_price(
        x_only(ORACLE_SECRET),
        ORACLE_SECRET,
        PriceFeedData {
            valid_until: TICK_TIME,
            ..PRICE
        },
    );
    signed.verify()?;

    let ft = fixture.spend(&context, &consumer, &signed)?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// A genuine price does not rescue a Tick of the wrong asset.
#[simplex::test]
fn rejects_a_tick_of_another_asset_with_a_valid_price(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = TickWithPriceFixture::new(&context)?;
    let decoy_asset = issue_asset(&context, SUPPLY)?;
    let consumer = fixture.consumer(&context, decoy_asset)?;

    let signed = network_signed_price(x_only(ORACLE_SECRET), ORACLE_SECRET, PRICE);
    signed.verify()?;

    let ft = fixture.spend(&context, &consumer, &signed)?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}
