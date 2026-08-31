#[path = "common/mod.rs"]
mod common;

use common::{assert_covenant_rejects, fund_script, issue_asset};

use simplex::transaction::utxo::UTXO;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use contracts::artifacts::account::AccountProgram;
use contracts::artifacts::account::derived_account::{AccountArguments, AccountWitness};

const STORM_EYE_SUPPLY: u64 = 10_000;
const ACCOUNT_AMOUNT: u64 = 1_000;

const ACCOUNT_OWNER_PUBKEY: [u8; 32] = [0u8; 32];

/// Spends the Account UTXO while claiming input 1 is the Storm Eye.
fn spend_transaction(
    context: &simplex::TestContext,
    account: &AccountProgram,
    account_utxo: &UTXO,
    auth_utxo: &UTXO,
) -> FinalTransaction {
    let signer = context.get_default_signer();
    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(account_utxo.clone()),
        ProgramInput::new(
            Box::new(account.as_ref().clone()),
            Box::new(AccountWitness {
                storm_eye_input_index: 1,
            }),
        ),
        RequiredSignature::None,
    );
    ft.add_input(
        PartialInput::new(auth_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    ft.add_output(PartialOutput::new(
        account.get_script_pubkey(context.get_network()),
        account_utxo.explicit_amount(),
        account_utxo.explicit_asset(),
    ));
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
    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
        account_owner_pubkey: ACCOUNT_OWNER_PUBKEY,
    });

    let account_script_pubkey = account.get_script_pubkey(context.get_network());
    let account_utxo = fund_script(&context, &account_script_pubkey, ACCOUNT_AMOUNT)?;
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

    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
        account_owner_pubkey: ACCOUNT_OWNER_PUBKEY,
    });

    let account_script_pubkey = account.get_script_pubkey(context.get_network());
    let account_utxo = fund_script(&context, &account_script_pubkey, ACCOUNT_AMOUNT)?;

    // Asset that simply is not the Storm Eye
    let decoy_utxo = signer.get_utxos_asset(decoy_asset)?[0].clone();

    let ft = spend_transaction(&context, &account, &account_utxo, &decoy_utxo);
    assert_covenant_rejects(&context, &ft);

    Ok(())
}
