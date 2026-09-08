//! 6. Treasury contract (spec §6.3.1): network-authorized spending.

#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, fund_script, issue_asset};

use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::treasury::Treasury;

const STORM_EYE_SUPPLY: u64 = 10_000;
const TREASURY_AMOUNT: u64 = 1_000;

fn spend_transaction(
    context: &simplex::TestContext,
    treasury: &Treasury,
    treasury_utxo: &UTXO,
    auth_utxo: &UTXO,
) -> FinalTransaction {
    let signer = context.get_default_signer();
    let mut ft = FinalTransaction::new();

    treasury.attach_spend(&mut ft, treasury_utxo, 1);
    ft.add_input(
        PartialInput::new(auth_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    ft.add_output(PartialOutput::new(
        treasury.get_script_pubkey(context.get_network()),
        treasury_utxo.explicit_amount(),
        treasury_utxo.explicit_asset(),
    ));
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        auth_utxo.explicit_amount(),
        auth_utxo.explicit_asset(),
    ));

    ft
}

#[simplex::test]
fn spends_treasury_when_storm_eye_is_present(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    let treasury = Treasury::new(storm_eye_asset);

    let treasury_script_pubkey = treasury.get_script_pubkey(context.get_network());
    let treasury_utxo = fund_script(&context, &treasury_script_pubkey, TREASURY_AMOUNT)?;
    let storm_eye_utxo = signer.get_utxos_asset(storm_eye_asset)?[0].clone();

    let ft = spend_transaction(&context, &treasury, &treasury_utxo, &storm_eye_utxo);
    signer.broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_treasury_spend_without_storm_eye(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    let decoy_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    assert_ne!(storm_eye_asset, decoy_asset);

    let treasury = Treasury::new(storm_eye_asset);

    let treasury_script_pubkey = treasury.get_script_pubkey(context.get_network());
    let treasury_utxo = fund_script(&context, &treasury_script_pubkey, TREASURY_AMOUNT)?;

    let decoy_utxo = signer.get_utxos_asset(decoy_asset)?[0].clone();

    let ft = spend_transaction(&context, &treasury, &treasury_utxo, &decoy_utxo);
    assert_covenant_rejects(&context, &ft);

    Ok(())
}
