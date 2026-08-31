#![allow(dead_code)]
use simplex::signer::SignerError;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

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

/// Sends `amount` of the policy asset to `script_pubkey` and returns the resulting UTXO,
/// which is how a covenant under test gets something to guard.
pub fn fund_script(
    context: &simplex::TestContext,
    script_pubkey: &Script,
    amount: u64,
) -> anyhow::Result<UTXO> {
    context
        .get_default_signer()
        .send(script_pubkey.clone(), amount)?
        .wait()?;

    context
        .get_default_provider()
        .fetch_scripthash_utxos(script_pubkey)?
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("funding transaction produced no UTXO"))
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
