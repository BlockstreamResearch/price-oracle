use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use serde::Deserialize;
use simplex::provider::SimplicityNetwork;

use crate::{config::ElementsRpcConfig, db::user_request::FeeUtxo};

pub(super) trait FeeUtxoValidator: Send + Sync {
    fn validate(
        &self,
        fee_utxos: &[FeeUtxo],
        account_owner_pubkey: [u8; 32],
        storm_eye_asset_id: [u8; 32],
    ) -> Result<(), Error>;
}

#[derive(Debug, thiserror::Error)]
pub(super) enum Error {
    #[error("fee UTXO '{0}' does not exist or is already spent")]
    Missing(String),
    #[error("fee UTXO '{0}' is not LBTC")]
    InvalidAsset(String),
    #[error("fee UTXO '{0}' is not controlled by the requesting user's account")]
    InvalidScript(String),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("Elements RPC returned invalid {0}")]
    InvalidRpcResponse(&'static str),
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
}

impl Error {
    pub(super) fn is_invalid_request(&self) -> bool {
        matches!(
            self,
            Self::Missing(_) | Self::InvalidAsset(_) | Self::InvalidScript(_)
        )
    }
}

pub(super) struct ElementsFeeUtxoValidator {
    rpc_url: String,
    auth: Auth,
}

impl ElementsFeeUtxoValidator {
    pub(super) fn new(config: &ElementsRpcConfig) -> Self {
        Self {
            rpc_url: config.url.clone(),
            auth: Auth::UserPass(config.username.clone(), config.password.clone()),
        }
    }

    fn client(&self) -> Result<Client, Error> {
        Ok(Client::new(&self.rpc_url, self.auth.clone())?)
    }
}

impl FeeUtxoValidator for ElementsFeeUtxoValidator {
    fn validate(
        &self,
        fee_utxos: &[FeeUtxo],
        account_owner_pubkey: [u8; 32],
        storm_eye_asset_id: [u8; 32],
    ) -> Result<(), Error> {
        let client = self.client()?;
        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
        let network = simplicity_network(&chain.chain)?;
        let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
        let expected_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id,
            account_owner_pubkey,
        })
        .get_script_pubkey(&network)
        .into_bytes();

        for fee_utxo in fee_utxos {
            let encoded = encode_outpoint(fee_utxo);
            let output: Option<GetTxOut> = client.call(
                "gettxout",
                &[
                    hex::encode(fee_utxo.txid).into(),
                    fee_utxo.output_index.into(),
                    true.into(),
                ],
            )?;
            let output = output.ok_or_else(|| Error::Missing(encoded.clone()))?;
            if !output.asset.eq_ignore_ascii_case(&sidechain.pegged_asset) {
                return Err(Error::InvalidAsset(encoded));
            }
            let script = hex::decode(&output.script_pub_key.hex)
                .map_err(|_| Error::InvalidRpcResponse("fee UTXO scriptPubKey"))?;
            if script != expected_script {
                return Err(Error::InvalidScript(encoded));
            }
        }

        Ok(())
    }
}

fn simplicity_network(chain: &str) -> Result<SimplicityNetwork, Error> {
    match chain {
        "liquidv1" => Ok(SimplicityNetwork::Liquid),
        "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elementsregtest" => Ok(SimplicityNetwork::default_regtest()),
        chain => Err(Error::UnsupportedChain(chain.to_string())),
    }
}

fn encode_outpoint(fee_utxo: &FeeUtxo) -> String {
    format!("{}:{}", hex::encode(fee_utxo.txid), fee_utxo.output_index)
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
}

#[derive(Deserialize)]
struct SidechainInfo {
    pegged_asset: String,
}

#[derive(Deserialize)]
struct GetTxOut {
    #[serde(rename = "scriptPubKey")]
    script_pub_key: GetTxOutScript,
    asset: String,
}

#[derive(Deserialize)]
struct GetTxOutScript {
    hex: String,
}

#[cfg(test)]
pub(super) struct AcceptAllFeeUtxos;

#[cfg(test)]
impl FeeUtxoValidator for AcceptAllFeeUtxos {
    fn validate(
        &self,
        _fee_utxos: &[FeeUtxo],
        _account_owner_pubkey: [u8; 32],
        _storm_eye_asset_id: [u8; 32],
    ) -> Result<(), Error> {
        Ok(())
    }
}
