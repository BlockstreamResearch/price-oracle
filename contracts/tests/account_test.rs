mod common;

use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use oracle_contracts::artifacts::account::AccountProgram;
use oracle_contracts::artifacts::account::derived_account::{AccountArguments, AccountWitness};

use crate::common::issue_asset;

const STORM_EYE_SUPPLY: u64 = 10_000;
const ACCOUNT_AMOUNT: u64 = 1_000;

/// The covenant only binds the owner key as a parameter; nothing verifies against it yet,
/// so the tests compile the account with an empty one.
const ACCOUNT_OWNER_PUBKEY: [u8; 32] = [0u8; 32];

// TODO: Refactor code and add more tests.
#[simplex::test]
fn user_asset_auth(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;

    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
        account_owner_pubkey: ACCOUNT_OWNER_PUBKEY,
    });
    let account_script_pubkey = account.get_script_pubkey(context.get_network());

    signer
        .send(account_script_pubkey.clone(), ACCOUNT_AMOUNT)?
        .wait()?;

    let account_utxo = provider.fetch_scripthash_utxos(&account_script_pubkey)?[0].clone();
    let storm_eye_utxo = signer.get_utxos_asset(storm_eye_asset)?[0].clone();

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
        PartialInput::new(storm_eye_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    ft.add_output(PartialOutput::new(
        account_script_pubkey,
        account_utxo.explicit_amount(),
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
