use std::str::FromStr;

use bitcoincore_rpc::{Client, RpcApi};
use serde::Deserialize;
use simplex::{
    provider::SimplicityNetwork,
    simplicityhl::elements::{AssetId, BlockHash, Script, opcodes, script::Instruction},
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
