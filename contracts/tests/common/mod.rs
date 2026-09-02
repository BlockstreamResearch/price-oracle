#![allow(dead_code)]
use std::sync::atomic::{AtomicU32, Ordering};

use simplex::signer::SignerError;
use simplex::simplicityhl::elements::{AssetId, Script};
use simplex::transaction::partial_input::IssuanceInput;
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, RequiredSignature};

// Prevent contracts failed with:
// Error: Covenant input 1 did not execute (transaction locktime 0, input sequence 4294967295): Failed to prune program: Jet failed during execution
pub fn unique_contract_hash() -> [u8; 32] {
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&std::process::id().to_le_bytes());
    hash[4..8].copy_from_slice(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());

    dbg!(hash);
    hash
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
