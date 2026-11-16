use std::str::FromStr;

use bitcoincore_rpc::{Client, RpcApi};
use contracts::artifacts::treasury::{TreasuryProgram, derived_treasury::TreasuryWitness};
use serde::Deserialize;
use simplex::{
    program::ProgramError,
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, BlockHash, Script, opcodes, pset::PartiallySignedTransaction, script::Instruction,
    },
    transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature, UTXO},
};

#[derive(Deserialize)]
pub(crate) struct ChainInfo {
    pub(crate) chain: String,
}

#[derive(Deserialize)]
pub(crate) struct SidechainInfo {
    pub(crate) pegged_asset: String,
}

#[derive(Deserialize)]
pub(crate) struct RawTransactionInfo {
    #[serde(default)]
    pub(crate) confirmations: u64,
    #[serde(default, rename = "blockhash")]
    pub(crate) block_hash: Option<String>,
}

/// Adds each of `utxos` as a Treasury input that defers to the Storm Eye at input 0.
pub(crate) fn add_treasury_inputs<'a>(
    transaction: &mut FinalTransaction,
    treasury: &TreasuryProgram,
    utxos: impl IntoIterator<Item = &'a UTXO>,
) {
    for utxo in utxos {
        transaction.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(treasury.as_ref().clone()),
                TreasuryWitness {
                    storm_eye_input_index: 0,
                },
            ),
            RequiredSignature::None,
        );
    }
}

/// Sets the final witness of every input of `pset` from the program that
/// `transaction` spends it with; `all_programs` is the panic message for an
/// input without one.
pub(crate) fn finalize_program_inputs(
    pset: &mut PartiallySignedTransaction,
    transaction: &FinalTransaction,
    network: &SimplicityNetwork,
    all_programs: &str,
) -> Result<(), ProgramError> {
    for (index, input) in transaction.inputs().iter().enumerate() {
        let program_input = input.program_input.as_ref().expect(all_programs);
        pset.inputs_mut()[index].final_script_witness = Some(
            program_input
                .program
                .finalize(pset, &program_input.witness, index, network)?
                .into(),
        );
    }
    Ok(())
}

/// The data of `script` when it is exactly `OP_RETURN <one data push>`.
pub(crate) fn op_return_data(script: &Script) -> Option<&[u8]> {
    let mut instructions = script.instructions_minimal();
    if !matches!(
        instructions.next(),
        Some(Ok(Instruction::Op(opcodes::all::OP_RETURN)))
    ) {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
        return None;
    };
    instructions.next().is_none().then_some(data)
}

/// The network of the Elements node behind `client`. A regtest policy asset or
/// genesis hash that does not parse becomes `invalid(message)`, and any chain
/// but Liquid, Liquid Testnet and regtest becomes `unsupported(chain)`.
pub(crate) fn network<E: From<bitcoincore_rpc::Error>>(
    client: &Client,
    invalid: fn(String) -> E,
    unsupported: impl FnOnce(String) -> E,
) -> Result<SimplicityNetwork, E> {
    let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
    match chain.chain.as_str() {
        "liquidv1" => Ok(SimplicityNetwork::Liquid),
        "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elementsregtest" => {
            let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
            let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
            Ok(SimplicityNetwork::ElementsCustom {
                policy_asset: AssetId::from_str(&sidechain.pegged_asset)
                    .map_err(|_| invalid("invalid regtest policy asset".into()))?,
                genesis_hash: BlockHash::from_str(&genesis_hash)
                    .map_err(|_| invalid("invalid regtest genesis hash".into()))?,
            })
        }
        _ => Err(unsupported(chain.chain)),
    }
}
