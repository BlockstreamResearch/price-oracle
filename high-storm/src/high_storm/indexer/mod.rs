use std::str::FromStr;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use secp256k1_zkp::Secp256k1;
use simplex::{
    provider::SimplicityNetwork,
    simplicityhl::{
        elements::{AssetId, Block, BlockHash, Transaction, TxOut, encode},
        simplicity::hashes::Hash,
    },
};

use crate::{
    config::{ElementsRpcConfig, UserRequestsConfig},
    db::{
        monitored_utxo::{IndexedBlock, MonitoredUtxo, MonitoredUtxoStore},
        network_asset::{NetworkAssetStore, STORM_EYE_KIND, TICK_ASSET_KIND},
    },
};

use super::{
    assets::treasury_blinding_secret, issuance::IssuedTickDescriptor, user_requests::asset_id,
};

const RULE_SET: &str = "issued-utxo-burning-v1";

#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    #[error("indexer database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("failed to decode indexed block: {0}")]
    Block(#[from] encode::Error),
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid indexed data: {0}")]
    Invalid(String),
    #[error("chain reorganization detected at block {height}")]
    Reorganization { height: u64 },
}

#[derive(Clone)]
pub(crate) struct Indexer {
    store: MonitoredUtxoStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    tick_lifetime_blocks: u64,
}

impl Indexer {
    pub(crate) fn new(
        store: MonitoredUtxoStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        user_requests: &UserRequestsConfig,
    ) -> Self {
        Self {
            store,
            assets,
            elements_rpc,
            tick_lifetime_blocks: user_requests.tick_lifetime_blocks,
        }
    }

    pub(crate) async fn sync(&self) -> Result<u64, IndexerError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(IndexerError::MissingAsset(STORM_EYE_KIND))?;
        let tick_asset = self
            .assets
            .get(TICK_ASSET_KIND)
            .await?
            .ok_or(IndexerError::MissingAsset(TICK_ASSET_KIND))?;
        let tick_asset_id = AssetId::from_byte_array(tick_asset.asset_id);
        let client = self.client()?;
        let network = network(&client)?;
        let tip: u64 = client.call("getblockcount", &[])?;
        let cursor = self.store.cursor(RULE_SET).await?;

        if let Some(cursor) = &cursor {
            let canonical = block_hash(&client, cursor.height)?;
            if canonical != cursor.hash {
                return Err(IndexerError::Reorganization {
                    height: cursor.height,
                });
            }
        }

        let first_height = cursor.map_or(tick_asset.created_at_block, |cursor| cursor.height + 1);
        let mut indexed = 0;
        for height in first_height..=tip {
            let hash = block_hash(&client, height)?;
            let block = get_block(&client, hash)?;
            let issued = issued_tick_utxos(
                &client,
                &block.txdata,
                height,
                &storm_eye,
                &tick_asset,
                tick_asset_id,
                &network,
            )?;
            let spent = spent_monitored_outpoints(&block.txdata);
            self.store
                .apply_block(
                    RULE_SET,
                    &IndexedBlock { height, hash },
                    &issued,
                    &spent,
                    self.tick_lifetime_blocks,
                )
                .await?;
            indexed += 1;
        }

        Ok(indexed)
    }

    pub(crate) async fn cursor(&self) -> Result<Option<IndexedBlock>, IndexerError> {
        Ok(self.store.cursor(RULE_SET).await?)
    }

    fn client(&self) -> Result<Client, IndexerError> {
        let url = url::Url::parse(&self.elements_rpc.url)?;
        Ok(Client::new(
            url.as_str(),
            Auth::UserPass(
                self.elements_rpc.username.clone(),
                self.elements_rpc.password.clone(),
            ),
        )?)
    }
}

fn issued_tick_utxos(
    client: &Client,
    transactions: &[Transaction],
    height: u64,
    storm_eye: &crate::NetworkAsset,
    tick_asset: &crate::NetworkAsset,
    tick_asset_id: AssetId,
    network: &SimplicityNetwork,
) -> Result<Vec<MonitoredUtxo>, IndexerError> {
    let mut issued = Vec::new();
    for transaction in transactions {
        if !is_tick_issuance(client, transaction, storm_eye, tick_asset)? {
            continue;
        }
        issued.extend(indexed_tick_outputs(
            transaction,
            height,
            storm_eye,
            tick_asset_id,
            network,
        )?);
    }
    Ok(issued)
}

fn indexed_tick_outputs(
    transaction: &Transaction,
    height: u64,
    storm_eye: &crate::NetworkAsset,
    tick_asset_id: AssetId,
    network: &SimplicityNetwork,
) -> Result<Vec<MonitoredUtxo>, IndexerError> {
    let txid = transaction.txid();
    let mut descriptors = None;
    for output in &transaction.output {
        let Some(output_descriptors) = IssuedTickDescriptor::from_script(&output.script_pubkey)
            .map_err(IndexerError::Invalid)?
        else {
            continue;
        };
        if descriptors.is_some() {
            return Err(IndexerError::Invalid(
                "Tick issuance has multiple descriptor outputs".into(),
            ));
        }
        if output.asset.explicit() != Some(network.policy_asset())
            || output.value.explicit() != Some(0)
        {
            return Err(IndexerError::Invalid(
                "issued Tick descriptor output must have zero policy-asset value".into(),
            ));
        }
        descriptors = Some(output_descriptors);
    }
    let descriptors = descriptors.ok_or_else(|| {
        IndexerError::Invalid("Tick issuance descriptor output is missing".into())
    })?;
    let tick_output_count = transaction
        .output
        .iter()
        .filter(|output| output.asset.explicit() == Some(tick_asset_id))
        .count();
    if descriptors.len() != tick_output_count {
        return Err(IndexerError::Invalid(
            "Tick issuance descriptors do not match Tick outputs".into(),
        ));
    }

    let mut issued = Vec::with_capacity(descriptors.len());
    let mut described_ticks = std::collections::BTreeSet::new();
    let mut issued_amount = 0u64;
    for descriptor in descriptors {
        if !described_ticks.insert(descriptor.tick_output_index) {
            return Err(IndexerError::Invalid(
                "Tick output has duplicate issuance descriptors".into(),
            ));
        }
        let output = transaction
            .output
            .get(descriptor.tick_output_index as usize)
            .ok_or_else(|| IndexerError::Invalid("indexed Tick output is missing".into()))?;
        let amount = output
            .value
            .explicit()
            .ok_or_else(|| IndexerError::Invalid("indexed Tick output is confidential".into()))?;
        issued_amount = issued_amount
            .checked_add(amount)
            .ok_or_else(|| IndexerError::Invalid("indexed Tick amount overflow".into()))?;
        if output.asset.explicit() != Some(tick_asset_id)
            || !descriptor.matches_tick_script(storm_eye.asset_id, network, &output.script_pubkey)
        {
            return Err(IndexerError::Invalid(
                "indexed Tick output does not match its descriptor".into(),
            ));
        }
        let reserve = transaction
            .output
            .get(descriptor.reserve_output_index as usize)
            .ok_or_else(|| IndexerError::Invalid("indexed burn reserve is missing".into()))?;
        let account_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: descriptor.account_owner_pubkey,
        })
        .get_script_pubkey(network);
        if reserve.asset.explicit() != Some(network.policy_asset())
            || reserve.value.explicit().is_none_or(|value| value == 0)
            || reserve.script_pubkey != account_script
        {
            return Err(IndexerError::Invalid(
                "indexed burn reserve does not match its descriptor".into(),
            ));
        }

        issued.push(MonitoredUtxo {
            txid: txid.to_byte_array(),
            output_index: descriptor.tick_output_index,
            asset_kind: TICK_ASSET_KIND.into(),
            amount,
            script_pubkey: output.script_pubkey.as_bytes().to_vec(),
            auth_method: descriptor.auth_method_name().into(),
            auth_data: descriptor.auth_data.to_vec(),
            account_owner_pubkey: descriptor.account_owner_pubkey,
            burning_fee_txid: txid.to_byte_array(),
            burning_fee_output_index: descriptor.reserve_output_index,
            block_height: height,
            status: "active".into(),
            status_block_height: height,
            burn_txid: None,
        });
    }
    if transaction.input[1].asset_issuance.amount.explicit() != Some(issued_amount) {
        return Err(IndexerError::Invalid(
            "Tick reissuance amount does not match described outputs".into(),
        ));
    }
    Ok(issued)
}

fn is_tick_issuance(
    client: &Client,
    transaction: &Transaction,
    storm_eye: &crate::NetworkAsset,
    tick_asset: &crate::NetworkAsset,
) -> Result<bool, IndexerError> {
    if transaction.input.len() < 2 || transaction.output.len() < 2 {
        return Ok(false);
    }
    let issuance = transaction.input[1].asset_issuance;
    if issuance.is_null() {
        return Ok(false);
    }
    let txid = transaction.txid();
    if Some(issuance.asset_entropy) != tick_asset.entropy {
        tracing::debug!(
            %txid,
            actual = %hex::encode(issuance.asset_entropy),
            expected = %tick_asset.entropy.map(hex::encode).unwrap_or_default(),
            "rejected Tick issuance candidate: entropy mismatch"
        );
        return Ok(false);
    }
    if !issuance.inflation_keys.is_null() {
        tracing::debug!(%txid, "rejected Tick issuance candidate: inflation keys are not null");
        return Ok(false);
    }
    let storm_eye_input = previous_output(client, transaction.input[0].previous_output)?;
    let storm_eye_asset =
        asset_id(storm_eye.asset_id).map_err(|error| IndexerError::Invalid(error.to_string()))?;
    if storm_eye_input.asset.explicit() != Some(storm_eye_asset)
        || storm_eye_input.script_pubkey.as_bytes() != storm_eye.contract_script
        || transaction.output[0] != storm_eye_input
    {
        tracing::debug!(%txid, "rejected Tick issuance candidate: Storm Eye is not preserved");
        return Ok(false);
    }

    let token_input = previous_output(client, transaction.input[1].previous_output)?;
    let token_input_secrets = match token_input
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
    {
        Ok(secrets) => secrets,
        Err(_) => {
            tracing::debug!(%txid, "rejected Tick issuance candidate: token input cannot be unblinded");
            return Ok(false);
        }
    };
    let token_id = asset_id(
        tick_asset
            .reissuance_token_id
            .ok_or_else(|| IndexerError::Invalid("Tick token id is missing".into()))?,
    )
    .map_err(|error| IndexerError::Invalid(error.to_string()))?;
    if token_input_secrets.asset != token_id
        || token_input.script_pubkey.as_bytes() != tick_asset.contract_script
    {
        tracing::debug!(%txid, "rejected Tick issuance candidate: token input does not match Tick asset");
        return Ok(false);
    }
    let token_output = &transaction.output[1];
    let token_output_secrets = match token_output
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
    {
        Ok(secrets) => secrets,
        Err(_) => {
            tracing::debug!(%txid, "rejected Tick issuance candidate: token output cannot be unblinded");
            return Ok(false);
        }
    };
    let preserved = token_output_secrets.asset == token_input_secrets.asset
        && token_output_secrets.value == token_input_secrets.value
        && token_output.script_pubkey == token_input.script_pubkey;
    if !preserved {
        tracing::debug!(%txid, "rejected Tick issuance candidate: token is not preserved");
    }
    Ok(preserved)
}

fn previous_output(
    client: &Client,
    outpoint: simplex::simplicityhl::elements::OutPoint,
) -> Result<TxOut, IndexerError> {
    let encoded: String = client.call(
        "getrawtransaction",
        &[outpoint.txid.to_string().into(), false.into()],
    )?;
    let transaction: Transaction = encode::deserialize(
        &hex::decode(encoded)
            .map_err(|_| IndexerError::Invalid("invalid previous transaction encoding".into()))?,
    )?;
    transaction
        .output
        .get(outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| IndexerError::Invalid("previous transaction output is missing".into()))
}

fn network(client: &Client) -> Result<SimplicityNetwork, IndexerError> {
    #[derive(serde::Deserialize)]
    struct ChainInfo {
        chain: String,
    }
    #[derive(serde::Deserialize)]
    struct SidechainInfo {
        pegged_asset: String,
    }

    let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
    match chain.chain.as_str() {
        "liquidv1" => Ok(SimplicityNetwork::Liquid),
        "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elementsregtest" => {
            let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
            let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
            Ok(SimplicityNetwork::ElementsCustom {
                policy_asset: AssetId::from_str(&sidechain.pegged_asset)
                    .map_err(|_| IndexerError::Invalid("invalid regtest policy asset".into()))?,
                genesis_hash: BlockHash::from_str(&genesis_hash)
                    .map_err(|_| IndexerError::Invalid("invalid regtest genesis hash".into()))?,
            })
        }
        _ => Err(IndexerError::Invalid(format!(
            "unsupported Elements chain '{}'",
            chain.chain
        ))),
    }
}

fn spent_monitored_outpoints(transactions: &[Transaction]) -> Vec<([u8; 32], u32, [u8; 32])> {
    transactions
        .iter()
        .flat_map(|transaction| {
            let spending_txid = transaction.txid().to_byte_array();
            transaction.input.iter().map(move |input| {
                (
                    input.previous_output.txid.to_byte_array(),
                    input.previous_output.vout,
                    spending_txid,
                )
            })
        })
        .collect()
}

fn block_hash(client: &Client, height: u64) -> Result<[u8; 32], IndexerError> {
    let encoded: String = client.call("getblockhash", &[height.into()])?;
    BlockHash::from_str(&encoded)
        .map(|hash| hash.to_byte_array())
        .map_err(|_| IndexerError::Invalid("invalid block hash".into()))
}

fn get_block(client: &Client, hash: [u8; 32]) -> Result<Block, IndexerError> {
    let hash = BlockHash::from_byte_array(hash).to_string();
    let encoded: String = client.call("getblock", &[hash.into(), 0.into()])?;
    let bytes =
        hex::decode(encoded).map_err(|_| IndexerError::Invalid("invalid block encoding".into()))?;
    Ok(encode::deserialize(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use simplex::simplicityhl::elements::{Script, TxOut, Txid, confidential};

    #[test]
    fn collects_spent_outpoints_from_a_block() {
        let previous = simplex::simplicityhl::elements::OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 7,
        };
        let transaction = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![simplex::simplicityhl::elements::TxIn {
                previous_output: previous,
                ..Default::default()
            }],
            output: vec![],
        };
        let spending_txid = transaction.txid().to_byte_array();

        assert_eq!(
            spent_monitored_outpoints(&[transaction]),
            vec![([1; 32], 7, spending_txid)]
        );
    }

    #[test]
    fn indexes_confirmed_ticks_with_their_account_reserves() {
        let tick_asset = AssetId::from_byte_array([9; 32]);
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset: AssetId::from_byte_array([8; 32]),
            genesis_hash: BlockHash::from_byte_array([6; 32]),
        };
        let storm_eye = crate::NetworkAsset {
            kind: STORM_EYE_KIND.into(),
            name: "Storm Eye".into(),
            asset_id: [7; 32],
            reissuance_token_id: None,
            entropy: Some([1; 32]),
            issuance_txid: [2; 32],
            contract_script: vec![0x51],
            contract_data: None,
            supply: 10_000,
            created_at_block: 1,
        };
        let descriptors = [
            IssuedTickDescriptor {
                tick_output_index: 2,
                reserve_output_index: 4,
                account_owner_pubkey: [4; 32],
                auth_kind: 2,
                auth_data: [5; 32],
            },
            IssuedTickDescriptor {
                tick_output_index: 3,
                reserve_output_index: 5,
                account_owner_pubkey: [6; 32],
                auth_kind: 2,
                auth_data: [7; 32],
            },
        ];
        let tick_scripts = descriptors.each_ref().map(|descriptor| {
            descriptor
                .tick_program(storm_eye.asset_id)
                .get_script_pubkey(&network)
        });
        let account_scripts = descriptors.each_ref().map(|descriptor| {
            AccountProgram::new(&AccountArguments {
                storm_eye_asset_id: storm_eye.asset_id,
                account_owner_pubkey: descriptor.account_owner_pubkey,
            })
            .get_script_pubkey(&network)
        });
        let mut reissuance_input = simplex::simplicityhl::elements::TxIn::default();
        reissuance_input.asset_issuance.amount = confidential::Value::Explicit(3_400_000_001);
        let transaction = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![
                simplex::simplicityhl::elements::TxIn::default(),
                reissuance_input,
            ],
            output: vec![
                explicit_output(AssetId::from_byte_array([8; 32]), 1, Script::new()),
                explicit_output(AssetId::from_byte_array([8; 32]), 1, Script::new()),
                explicit_output(tick_asset, 1_700_000_000, tick_scripts[0].clone()),
                explicit_output(tick_asset, 1_700_000_001, tick_scripts[1].clone()),
                explicit_output(network.policy_asset(), 1_000, account_scripts[0].clone()),
                explicit_output(network.policy_asset(), 2_000, account_scripts[1].clone()),
                explicit_output(
                    network.policy_asset(),
                    0,
                    IssuedTickDescriptor::script_pubkey(&descriptors).unwrap(),
                ),
            ],
        };
        let txid = transaction.txid();

        let indexed =
            indexed_tick_outputs(&transaction, 42, &storm_eye, tick_asset, &network).unwrap();

        assert_eq!(indexed.len(), 2);
        assert_eq!(indexed[0].txid, txid.to_byte_array());
        assert_eq!(indexed[0].output_index, 2);
        assert_eq!(indexed[0].account_owner_pubkey, [4; 32]);
        assert_eq!(indexed[0].auth_data, vec![5; 32]);
        assert_eq!(indexed[0].burning_fee_txid, txid.to_byte_array());
        assert_eq!(indexed[0].burning_fee_output_index, 4);
        assert_eq!(indexed[1].output_index, 3);
        assert_eq!(indexed[1].account_owner_pubkey, [6; 32]);
        assert_eq!(indexed[1].auth_data, vec![7; 32]);
        assert_eq!(indexed[1].burning_fee_output_index, 5);

        let mut missing_descriptor = transaction.clone();
        missing_descriptor.output.pop();
        assert!(
            indexed_tick_outputs(&missing_descriptor, 42, &storm_eye, tick_asset, &network)
                .is_err()
        );

        let mut valued_descriptor = transaction;
        valued_descriptor.output[6].value = confidential::Value::Explicit(1);
        assert!(
            indexed_tick_outputs(&valued_descriptor, 42, &storm_eye, tick_asset, &network).is_err()
        );
    }

    fn explicit_output(asset: AssetId, amount: u64, script_pubkey: Script) -> TxOut {
        TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(amount),
            script_pubkey,
            ..Default::default()
        }
    }
}
