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
            elements_regtest_network(&sidechain.pegged_asset, &genesis_hash, invalid)
        }
        _ => Err(unsupported(chain.chain)),
    }
}

/// The regtest network whose policy asset and genesis hash Elements reported;
/// either one that does not parse becomes `invalid(message)`.
pub(crate) fn elements_regtest_network<E>(
    policy_asset: &str,
    genesis_hash: &str,
    invalid: fn(String) -> E,
) -> Result<SimplicityNetwork, E> {
    Ok(SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_str(policy_asset)
            .map_err(|_| invalid("invalid regtest policy asset".into()))?,
        genesis_hash: BlockHash::from_str(genesis_hash)
            .map_err(|_| invalid("invalid regtest genesis block hash".into()))?,
    })
}
#[cfg(test)]
mod tests {
    use simplex::simplicityhl::elements::{OutPoint, TxOut, script::Builder};

    use super::*;

    #[test]
    fn reads_only_one_minimal_push_after_op_return() {
        let data = [7; 5];
        assert_eq!(
            op_return_data(&Script::new_op_return(&data)),
            Some(&data[..])
        );
        let bare = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script();
        assert_eq!(op_return_data(&bare), None);
        let no_op_return = Builder::new().push_slice(&data).into_script();
        assert_eq!(op_return_data(&no_op_return), None);
        let two_pushes = Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(&data)
            .push_slice(&data)
            .into_script();
        assert_eq!(op_return_data(&two_pushes), None);
        // OP_RETURN OP_PUSHDATA1 5 <5 bytes>: a push that has a shorter encoding.
        let non_minimal = Script::from(vec![0x6a, 0x4c, 5, 7, 7, 7, 7, 7]);
        assert_eq!(op_return_data(&non_minimal), None);
    }

    #[test]
    #[should_panic(expected = "every input is a program input")]
    fn finalizing_an_input_without_a_program_panics() {
        let mut transaction = FinalTransaction::new();
        transaction.add_input(
            PartialInput::new(UTXO {
                outpoint: OutPoint::default(),
                txout: TxOut::default(),
                secrets: None,
            }),
            RequiredSignature::None,
        );
        let mut pset = PartiallySignedTransaction::new_v2();
        let _ = finalize_program_inputs(
            &mut pset,
            &transaction,
            &SimplicityNetwork::Liquid,
            "every input is a program input",
        );
    }

    #[test]
    fn uses_stock_regtest_genesis_for_simplicity_environment() {
        let policy_asset = SimplicityNetwork::default_regtest()
            .policy_asset()
            .to_string();
        let genesis_hash = "cd179c84c35f51825f20a3b91a18d45f0c53b5ceb744a5b6ef8f0babe809396f";

        let network =
            elements_regtest_network(&policy_asset, genesis_hash, |message: String| message)
                .unwrap();

        assert_eq!(network.genesis_block_hash().to_string(), genesis_hash);
        assert_eq!(network.policy_asset().to_string(), policy_asset);
    }
}
