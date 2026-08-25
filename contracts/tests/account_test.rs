mod common;

use simplex::either::Either;
use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use oracle_contracts::artifacts::account::AccountProgram;
use oracle_contracts::artifacts::account::derived_account::{AccountArguments, AccountWitness};

use crate::common::issue_asset;

const STORM_EYE_SUPPLY: u64 = 10_000;
const ACCOUNT_BALANCE: u64 = 10_000;
const AMOUNT: u64 = 500;

/// Issues the stand-in Storm Eye asset, compiles the account for the default signer's key,
/// and funds it with L-BTC.
fn setup_account(context: &simplex::TestContext) -> anyhow::Result<(AccountProgram, AssetId)> {
    let signer = context.get_default_signer();

    let storm_eye_asset = issue_asset(context, STORM_EYE_SUPPLY)?;

    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
        account_owner_pubkey: signer.get_schnorr_public_key().serialize(),
    });

    signer
        .send(
            account.get_script_pubkey(context.get_network()),
            ACCOUNT_BALANCE,
        )?
        .wait()?;

    Ok((account, storm_eye_asset))
}

#[simplex::test]
fn user_tops_up_the_account(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let (account, _) = setup_account(&context)?;

    let account_script_pubkey = account.get_script_pubkey(context.get_network());
    let account_utxo = provider.fetch_scripthash_utxos(&account_script_pubkey)?[0].clone();

    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(account_utxo.clone()),
        ProgramInput::new(
            Box::new(account.as_ref().clone()),
            Box::new(AccountWitness {
                path: Either::Left((AMOUNT, 0u32, [0u8; 64])),
            }),
        ),
        // The signature lives in witness `Path`, Left branch, tuple position 2; the signer
        // fills it in over sig_all_hash once the transaction is assembled.
        RequiredSignature::WitnessWithPath(
            "Path".to_string(),
            vec!["Left".to_string(), "2".to_string()],
        ),
    );

    ft.add_output(PartialOutput::new(
        account_script_pubkey,
        account_utxo.explicit_amount() + AMOUNT,
        account_utxo.explicit_asset(),
    ));

    // The deposit itself needs L-BTC that the account input does not carry; finalize()
    // selects it and appends it after our input, so index 0 stays the account.
    signer.broadcast(&ft)?.wait()?;

    Ok(())
}

#[simplex::test]
fn network_withdraws_from_the_account(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let (account, storm_eye_asset) = setup_account(&context)?;

    let account_script_pubkey = account.get_script_pubkey(context.get_network());
    let account_utxo = provider.fetch_scripthash_utxos(&account_script_pubkey)?[0].clone();
    let storm_eye_utxo = signer.get_utxos_asset(storm_eye_asset)?[0].clone();

    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(account_utxo.clone()),
        ProgramInput::new(
            Box::new(account.as_ref().clone()),
            Box::new(AccountWitness {
                path: Either::Right((1u32, AMOUNT, 0u32)),
            }),
        ),
        RequiredSignature::None,
    );
    ft.add_input(
        PartialInput::new(storm_eye_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    ft.add_output(PartialOutput::new(
        account_script_pubkey,
        account_utxo.explicit_amount() - AMOUNT,
        account_utxo.explicit_asset(),
    ));
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&ft)?.wait()?;

    Ok(())
}
