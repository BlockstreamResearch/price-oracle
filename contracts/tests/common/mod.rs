#![allow(dead_code)]
use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

// TODO: Make general purpose
pub fn issue_asset(context: &simplex::TestContext, amount: u64) -> anyhow::Result<AssetId> {
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
