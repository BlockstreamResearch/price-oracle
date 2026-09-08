//! 6. Treasury contract (spec §6.3.1): network-authorized spending.

#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, issue_asset};

use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::treasury::{Treasury, TreasuryParameters};

const STORM_EYE_SUPPLY: u64 = 10_000;
const TREASURY_AMOUNT: u64 = 1_000;

/// Funds `treasury` with `amount` of the policy asset and returns the resulting UTXO.
fn fund_treasury(
    context: &simplex::TestContext,
    treasury: &Treasury,
    amount: u64,
) -> anyhow::Result<UTXO> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();
    ft.add_input(
        PartialInput::new(funding_utxo),
        RequiredSignature::NativeEcdsa,
    );

    treasury.attach_treasury_output(&mut ft, amount, context.get_network().policy_asset());

    signer.broadcast(&ft)?.wait()?;

    context
        .get_default_provider()
        .fetch_scripthash_utxos(&treasury.get_script_pubkey())?
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("funding transaction produced no UTXO"))
}

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

    treasury.attach_treasury_output(
        &mut ft,
        treasury_utxo.explicit_amount(),
        treasury_utxo.explicit_asset(),
    );
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
    let treasury = Treasury::new(TreasuryParameters {
        storm_eye_asset_id: storm_eye_asset,
        network: *context.get_network(),
    });

    let treasury_utxo = fund_treasury(&context, &treasury, TREASURY_AMOUNT)?;
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

    let treasury = Treasury::new(TreasuryParameters {
        storm_eye_asset_id: storm_eye_asset,
        network: *context.get_network(),
    });

    let treasury_utxo = fund_treasury(&context, &treasury, TREASURY_AMOUNT)?;

    let decoy_utxo = signer.get_utxos_asset(decoy_asset)?[0].clone();

    let ft = spend_transaction(&context, &treasury, &treasury_utxo, &decoy_utxo);
    assert_covenant_rejects(&context, &ft);

    Ok(())
}
