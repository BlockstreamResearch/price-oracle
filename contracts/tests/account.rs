#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, issue_asset};

use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

use contracts::account::{Account, AccountParameters};

const STORM_EYE_SUPPLY: u64 = 10_000;
const ACCOUNT_AMOUNT: u64 = 1_000;

const ACCOUNT_OWNER_PUBKEY: [u8; 32] = [0u8; 32];

/// Funds `account` with `amount` of the policy asset and returns the resulting UTXO.
fn fund_account(
    context: &simplex::TestContext,
    account: &Account,
    amount: u64,
) -> anyhow::Result<UTXO> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();
    ft.add_input(
        PartialInput::new(funding_utxo),
        RequiredSignature::NativeEcdsa,
    );

    account.attach_account_output(&mut ft, amount, context.get_network().policy_asset());

    signer.broadcast(&ft)?.wait()?;

    context
        .get_default_provider()
        .fetch_scripthash_utxos(&account.get_script_pubkey())?
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("funding transaction produced no UTXO"))
}

/// Spends the Account UTXO while claiming input 1 is the Storm Eye.
fn spend_transaction(
    context: &simplex::TestContext,
    account: &Account,
    account_utxo: &UTXO,
    auth_utxo: &UTXO,
) -> FinalTransaction {
    let signer = context.get_default_signer();
    let mut ft = FinalTransaction::new();

    account.attach_spend(&mut ft, account_utxo, 1);
    ft.add_input(
        PartialInput::new(auth_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    account.attach_account_output(
        &mut ft,
        account_utxo.explicit_amount(),
        account_utxo.explicit_asset(),
    );
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        auth_utxo.explicit_amount(),
        auth_utxo.explicit_asset(),
    ));

    ft
}

#[simplex::test]
fn spends_account_when_storm_eye_is_present(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    let account = Account::new(AccountParameters {
        storm_eye_asset_id: storm_eye_asset,
        account_owner_pubkey: ACCOUNT_OWNER_PUBKEY,
        network: *context.get_network(),
    });

    let account_utxo = fund_account(&context, &account, ACCOUNT_AMOUNT)?;
    let storm_eye_utxo = signer.get_utxos_asset(storm_eye_asset)?[0].clone();

    let ft = spend_transaction(&context, &account, &account_utxo, &storm_eye_utxo);
    signer.broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn rejects_account_spend_without_storm_eye(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();

    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    let decoy_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;
    assert_ne!(storm_eye_asset, decoy_asset);

    let account = Account::new(AccountParameters {
        storm_eye_asset_id: storm_eye_asset,
        account_owner_pubkey: ACCOUNT_OWNER_PUBKEY,
        network: *context.get_network(),
    });

    let account_utxo = fund_account(&context, &account, ACCOUNT_AMOUNT)?;

    // Asset that simply is not the Storm Eye
    let decoy_utxo = signer.get_utxos_asset(decoy_asset)?[0].clone();

    let ft = spend_transaction(&context, &account, &account_utxo, &decoy_utxo);
    assert_covenant_rejects(&context, &ft);

    Ok(())
}
