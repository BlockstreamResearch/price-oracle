//! 6. Inclusion in a transaction upon reaching the rescue block number (spec §1.4.6).

use simplex::simplicityhl::elements::{LockTime, Script};
use simplex::transaction::{FinalTransaction, PartialOutput};
use simplex::utils::hash_script;

use super::fixtures::{StormEyeFixture, assert_covenant_rejects};

/// How far below the chain tip to put the rescue height.
const HEIGHT_MARGIN: u32 = 10;

struct RescueFixture {
    storm_eye: StormEyeFixture,
    rescue_script_pubkey: Script,
}

impl RescueFixture {
    fn new(context: &simplex::TestContext) -> anyhow::Result<Self> {
        let rescue_script_pubkey = context.get_default_signer().get_address().script_pubkey();

        let tip = context.get_default_provider().fetch_tip_height()?;
        let rescue_number = tip.saturating_sub(HEIGHT_MARGIN);

        let storm_eye = StormEyeFixture::with_rescue(
            context,
            rescue_number,
            hash_script(&rescue_script_pubkey),
        )?;

        Ok(Self {
            storm_eye,
            rescue_script_pubkey,
        })
    }

    /// A rescue spend paying `script_pubkey` and declaring `locktime`
    fn rescue_transaction(
        &self,
        context: &simplex::TestContext,
        script_pubkey: Script,
        locktime: u32,
    ) -> anyhow::Result<FinalTransaction> {
        let utxo = self.storm_eye.utxos(context)?[0].clone();
        let mut tx = FinalTransaction::new();

        self.storm_eye.add_rescue_input(&mut tx, &utxo, 0);

        // §1.4.6 preserves the UTXO, so asset and amount carry over untouched.
        tx.add_output(PartialOutput::new(
            script_pubkey,
            utxo.explicit_amount(),
            self.storm_eye.asset,
        ));
        tx.set_locktime(LockTime::from_height(locktime)?);

        Ok(tx)
    }
}

#[simplex::test]
fn rescues_storm_eye_after_the_rescue_block_number(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = RescueFixture::new(&context)?;

    let tx = fixture.rescue_transaction(
        &context,
        fixture.rescue_script_pubkey.clone(),
        fixture.storm_eye.rescue_number,
    )?;
    context.get_default_signer().broadcast(&tx)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_rescue_before_the_rescue_block_number(
    context: simplex::TestContext,
) -> anyhow::Result<()> {
    let fixture = RescueFixture::new(&context)?;

    let tx = fixture.rescue_transaction(
        &context,
        fixture.rescue_script_pubkey.clone(),
        fixture.storm_eye.rescue_number - 1,
    )?;
    assert_covenant_rejects(&context, &tx);

    Ok(())
}

#[simplex::test]
fn rejects_rescue_to_another_script(context: simplex::TestContext) -> anyhow::Result<()> {
    let fixture = RescueFixture::new(&context)?;

    let elsewhere = fixture.storm_eye.script_pubkey(&context);
    assert_ne!(elsewhere, fixture.rescue_script_pubkey);

    let tx = fixture.rescue_transaction(&context, elsewhere, fixture.storm_eye.rescue_number)?;
    assert_covenant_rejects(&context, &tx);

    Ok(())
}
