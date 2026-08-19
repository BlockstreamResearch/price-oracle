use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature,
};

use simplex_contracts::artifacts::treasury::TreasuryProgram;
use simplex_contracts::artifacts::treasury::derived_treasury::{TreasuryArguments, TreasuryWitness};

const STORM_EYE_SUPPLY: u64 = 10_000;
const TREASURY_AMOUNT: u64 = 1_000;

fn issue_asset(context: &simplex::TestContext, amount: u64) -> anyhow::Result<AssetId> {
    let signer = context.get_default_signer();
    let funding_utxo = signer.get_utxos_asset(context.get_network().policy_asset())?[0].clone();

    let mut ft = FinalTransaction::new();

    let issuance = ft.add_issuance_input(
        PartialInput::new(funding_utxo),
        IssuanceInput::new_issuance(amount, 0, [1u8; 32]),
        RequiredSignature::NativeEcdsa,
    );
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        amount,
        issuance.asset_id,
    ));

    signer.broadcast(&ft)?.wait()?;

    Ok(issuance.asset_id)
}

#[simplex::test]
fn spends_treasury_when_storm_eye_is_present(context: simplex::TestContext) -> anyhow::Result<()> {
    let signer = context.get_default_signer();
    let provider = context.get_default_provider();

    let storm_eye_asset = issue_asset(&context, STORM_EYE_SUPPLY)?;

    let treasury = TreasuryProgram::new(TreasuryArguments {
        storm_eye_asset_id: storm_eye_asset.into_inner().to_byte_array(),
    });
    let treasury_script_pubkey = treasury.get_script_pubkey(context.get_network());

    signer
        .send(treasury_script_pubkey.clone(), TREASURY_AMOUNT)?
        .wait()?;

    let treasury_utxo = provider.fetch_scripthash_utxos(&treasury_script_pubkey)?[0].clone();
    let storm_eye_utxo = signer.get_utxos_asset(storm_eye_asset)?[0].clone();

    let mut ft = FinalTransaction::new();

    ft.add_program_input(
        PartialInput::new(treasury_utxo.clone()),
        ProgramInput::new(
            Box::new(treasury.as_ref().clone()),
            Box::new(TreasuryWitness {
                storm_eye_input_index: 1,
                treasury_utxo_output_index: 0,
            }),
        ),
        RequiredSignature::None,
    );
    ft.add_input(
        PartialInput::new(storm_eye_utxo.clone()),
        RequiredSignature::NativeEcdsa,
    );

    ft.add_output(PartialOutput::new(
        treasury_script_pubkey,
        treasury_utxo.explicit_amount(),
        treasury_utxo.explicit_asset(),
    ));
    ft.add_output(PartialOutput::new(
        signer.get_address().script_pubkey(),
        storm_eye_utxo.explicit_amount(),
        storm_eye_utxo.explicit_asset(),
    ));

    signer.broadcast(&ft)?.wait()?;

    Ok(())
}
