use simplex::simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey;
use simplex::transaction::FinalTransaction;

use contracts::artifacts::tests::sdk::voucher_test::VoucherTestProgram;
use contracts::artifacts::tests::sdk::voucher_test::derived_voucher_test::{
    VoucherTestArguments, VoucherTestWitness,
};
use contracts::sdk::{SignedPrice, SignedPriceError};
use contracts::voucher::Voucher;
use price_feed::PriceFeedData;

use super::fixtures::{
    Consumer, ORACLE_SECRET, OTHER_SECRET, TICK_TIME, VoucherIssuer, assert_covenant_rejects,
    asset_bytes, network_signed_price, x_only,
};

const PRICE: PriceFeedData = PriceFeedData {
    feed_id: 4,
    price: 9_876_543_210,
    decimals: 8,
    received_at: TICK_TIME - 10,
    valid_until: TICK_TIME + 50,
};

// Input layout of `PriceFixture::spend`: the consumer, then the Tick, then the Verifier.
const TICK_INDEX: u32 = 1;
const VERIFIER_INDEX: u32 = 2;

/// A Tick, a Verifier committed to `verifier_key`, and the consumer that checks both.
struct PriceFixture {
    issuer: VoucherIssuer,
    consumer: Consumer,
    tick: Voucher,
    verifier: Voucher,
}

impl PriceFixture {
    fn new(context: &simplex::TestContext, verifier_key: XOnlyPublicKey) -> anyhow::Result<Self> {
        let issuer = VoucherIssuer::new(context)?;
        let (tick, tick_asset) = issuer.issue_tick(context)?;
        let (verifier, verifier_asset) = issuer.issue_verifier(context, verifier_key)?;

        let consumer = Consumer::funded(
            context,
            &VoucherTestProgram::new(&VoucherTestArguments {
                tick_asset_id: asset_bytes(tick_asset),
                verifier_asset_id: asset_bytes(verifier_asset),
            }),
        )?;

        Ok(Self {
            issuer,
            consumer,
            tick,
            verifier,
        })
    }

    /// The consumer's witness, built from `signed` and the Verifier at `verifier_input_index`.
    fn witness(&self, signed: &SignedPrice, verifier_input_index: u32) -> VoucherTestWitness {
        VoucherTestWitness {
            tick_input_index: TICK_INDEX,
            verifier_input_index,
            verifier_tapleaf_hash: self.verifier.get_tapleaf_hash(),
            signer: signed.get_signer(),
            price_signature: signed.get_signature(),
            price_feed_data: signed.get_price_witness(),
        }
    }

    fn spend(
        &self,
        context: &simplex::TestContext,
        witness: VoucherTestWitness,
    ) -> anyhow::Result<FinalTransaction> {
        self.consumer.spend_with_vouchers(
            context,
            witness,
            &[&self.tick, &self.verifier],
            self.issuer.get_auth_asset(),
        )
    }
}

#[simplex::test]
fn accepts_a_genuine_price(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let fixture = PriceFixture::new(&context, oracle)?;

    let signed = network_signed_price(oracle, ORACLE_SECRET, PRICE);
    signed.verify()?;

    let ft = fixture.spend(&context, fixture.witness(&signed, VERIFIER_INDEX))?;
    context.get_default_signer().broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_a_tampered_price(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let fixture = PriceFixture::new(&context, oracle)?;

    let genuine = network_signed_price(oracle, ORACLE_SECRET, PRICE);
    let tampered = SignedPrice::new(
        PriceFeedData {
            price: PRICE.price + 1,
            ..PRICE
        },
        genuine.get_signer(),
        genuine.get_signature(),
    );
    assert_eq!(tampered.verify(), Err(SignedPriceError::SignatureMismatch));

    let ft = fixture.spend(&context, fixture.witness(&tampered, VERIFIER_INDEX))?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_a_price_signed_by_another_key(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let fixture = PriceFixture::new(&context, oracle)?;

    let signed = network_signed_price(oracle, OTHER_SECRET, PRICE);
    assert_eq!(signed.verify(), Err(SignedPriceError::SignatureMismatch));

    let ft = fixture.spend(&context, fixture.witness(&signed, VERIFIER_INDEX))?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// A genuine Verifier committed to someone else cannot vouch for the oracle's signature, even
/// though the signature itself is valid.
#[simplex::test]
fn rejects_a_verifier_committed_to_another_key(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = PriceFixture::new(&context, x_only(OTHER_SECRET))?;

    let signed = network_signed_price(x_only(ORACLE_SECRET), ORACLE_SECRET, PRICE);
    signed.verify()?;

    let ft = fixture.spend(&context, fixture.witness(&signed, VERIFIER_INDEX))?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}

#[simplex::test]
fn rejects_an_expired_price(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let fixture = PriceFixture::new(&context, oracle)?;

    let signed = network_signed_price(
        oracle,
        ORACLE_SECRET,
        PriceFeedData {
            valid_until: TICK_TIME,
            ..PRICE
        },
    );

    let ft = fixture.spend(&context, fixture.witness(&signed, VERIFIER_INDEX))?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}

/// The Tick runs the same covenant as the Verifier, so only its asset tells them apart.
#[simplex::test]
fn rejects_a_tick_in_place_of_the_verifier(context: simplex::TestContext) -> anyhow::Result<()> {
    let oracle = x_only(ORACLE_SECRET);
    let fixture = PriceFixture::new(&context, oracle)?;

    let signed = network_signed_price(oracle, ORACLE_SECRET, PRICE);

    let ft = fixture.spend(&context, fixture.witness(&signed, TICK_INDEX))?;
    assert_covenant_rejects(&context, &ft);

    Ok(())
}
