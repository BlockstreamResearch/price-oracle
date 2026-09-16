#![allow(dead_code)]
use simplex::provider::ProviderError;
use simplex::signer::SignerError;
use simplex::simplicityhl::elements::AssetId;
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::{
    FinalTransaction, PartialInput, PartialOutput, RequiredSignature, TxReceipt,
};

const CONFIRMATION_ATTEMPTS: usize = 5;

pub fn wait_for_confirmation(receipt: &TxReceipt<'_>) -> Result<(), ProviderError> {
    for attempt in 1..=CONFIRMATION_ATTEMPTS {
        match receipt.wait() {
            Ok(()) => return Ok(()),
            Err(ProviderError::Confirmation()) if attempt < CONFIRMATION_ATTEMPTS => {}
            Err(error) => return Err(error),
        }
    }

    unreachable!("confirmation attempts are non-zero")
}

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

    wait_for_confirmation(&signer.broadcast(&ft)?)?;

    Ok(issuance.asset_id)
}

/// Asserts the transaction is rejected by the covenant
#[track_caller]
pub fn assert_covenant_rejects(context: &simplex::TestContext, tx: &FinalTransaction) {
    match context.get_default_signer().broadcast(tx) {
        Err(SignerError::CovenantExecution { index, source, .. }) => {
            println!("covenant rejected input {index} as expected: {source}");
        }
        Err(other) => panic!("expected the covenant to reject the transaction, got: {other}"),
        Ok(_) => panic!("expected the covenant to reject the transaction, but it was accepted"),
    }
}
