use bitcoin::{Amount, Denomination};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::auth::{AuthProgram, derived_auth::AuthArguments};
use contracts::artifacts::treasury::{TreasuryProgram, derived_treasury::TreasuryArguments};
use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::{
    AssetId, Script, Transaction, TxOut, TxOutSecrets,
    confidential::{AssetBlindingFactor, ValueBlindingFactor},
    encode,
};
use simplex::utils::hash_script;
use std::str::FromStr;
use storm::{PeerStatus, StormContext, StormHandle};
use url::Url;

use crate::{
    NetworkAsset, NetworkAssets,
    config::ElementsRpcConfig,
    db::network_asset::{NetworkAssetStore, PendingNetworkAsset, STORM_EYE_KIND, TICK_ASSET_KIND},
};

use super::{NodeMessage, NodeMessageKind, SigningError};

const STORM_EYE_NAME: &str = "Storm Eye";
const STORM_EYE_SUPPLY: u64 = 10_000;
const TICK_ASSET_NAME: &str = "Tick Asset";
const TICK_ASSET_SUPPLY: u64 = 0;
const REISSUANCE_TOKEN_SUPPLY: u64 = 1;
const STORM_EYE_ISSUANCE_FEE_SATS: u64 = 1_000;
const TICK_ISSUANCE_FEE_SATS: u64 = 1_000;
const MAX_MERGE_UTXOS_COUNT: u8 = 4;
const MAX_SPLIT_UTXOS_COUNT: u8 = 4;
const RESCUE_BLOCKS: u64 = 1_576_800;
const STORM_EYE_RPC_AMOUNT: f64 = 0.000_100_00;
const TREASURY_BLINDING_SECRET: [u8; 32] = [0x42; 32];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StormEyeContractData {
    pub(crate) storm_tree_root: [u8; 32],
    pub(crate) rescue_height: u32,
    pub(crate) rescue_output_script_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TickAssetContractData {
    pub(crate) issuance_tx: Vec<u8>,
    pub(crate) token_output_index: u32,
}

pub(crate) fn treasury_blinding_secret() -> SecretKey {
    SecretKey::from_slice(&TREASURY_BLINDING_SECRET)
        .expect("the fixed Treasury blinding secret is valid")
}

#[derive(Debug, thiserror::Error)]
pub enum AssetError {
    #[error("network asset database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("failed to encode network assets: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("failed to frame network assets: {0}")]
    Message(#[from] storm::MessageError),
    #[error("failed to announce network assets: {0}")]
    Transport(#[from] storm::Error),
    #[error("network asset kind '{0}' is already assigned to different metadata")]
    Conflict(String),
    #[error("invalid peer public key: {0}")]
    InvalidPeer(String),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("Elements RPC returned invalid {0}")]
    InvalidRpcResponse(&'static str),
    #[error("Elements wallet has no explicit spendable policy asset UTXO")]
    MissingFundingUtxo,
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
    #[error("Storm Eye rescue height does not fit in the contract")]
    RescueHeight,
    #[error("Storm Eye issuance task failed: {0}")]
    IssuanceTask(#[from] tokio::task::JoinError),
    #[error("Storm Tree state is unavailable: {0}")]
    Signing(#[from] SigningError),
    #[error("operating system randomness is unavailable")]
    Random,
    #[error("asset issuance produced confidential output {0}")]
    ConfidentialOutput(u32),
}

#[derive(Clone)]
pub(crate) struct Assets {
    store: NetworkAssetStore,
}

impl Assets {
    pub(crate) fn new(store: NetworkAssetStore) -> Self {
        Self { store }
    }

    pub(crate) async fn handle_announcement(
        &self,
        message: NodeMessage,
        _context: &StormContext,
    ) -> Result<(), AssetError> {
        let announcement: NetworkAssets = message.decode_payload()?;

        for asset in announcement.assets {
            if let Some(existing) = self.store.get(&asset.kind).await? {
                if existing != asset {
                    return Err(AssetError::Conflict(asset.kind));
                }
                continue;
            }

            if !self.store.insert_active(&asset).await? {
                let existing = self.store.get(&asset.kind).await?;
                if existing.as_ref() != Some(&asset) {
                    return Err(AssetError::Conflict(asset.kind));
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn announce_pending(&self, storm: &StormHandle) -> Result<(), AssetError> {
        let recipients = storm
            .peers()
            .await
            .into_iter()
            .filter(|peer| peer.status == PeerStatus::Active)
            .map(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key)
                    .map_err(|error| AssetError::InvalidPeer(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for recipient in recipients {
            let assets = self.store.list().await?;
            if assets.is_empty() {
                continue;
            }
            let kinds = assets
                .iter()
                .map(|asset| asset.kind.clone())
                .collect::<Vec<_>>();
            let mut snapshot_id = [0; 32];
            getrandom::fill(&mut snapshot_id).map_err(|_| AssetError::Random)?;
            let message = NodeMessage::new(
                NodeMessageKind::NetworkAssets,
                None,
                &NetworkAssets {
                    assets,
                    snapshot_id,
                },
            )?
            .into_storm_message()?;
            storm.send_message(message, &[recipient]).await?;
            self.store
                .mark_announced_to(&kinds, &recipient.serialize())
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn initialize_storm_eye(
        &self,
        storm: &StormHandle,
        config: &ElementsRpcConfig,
        storm_tree_root: [u8; 32],
    ) -> Result<NetworkAsset, AssetError> {
        let issuer = ElementsAssetIssuer::new(config)?;
        let asset = self.ensure_storm_eye(issuer, storm_tree_root).await?;
        self.announce_pending(storm).await?;

        Ok(asset)
    }

    pub(crate) async fn initialize_tick_asset(
        &self,
        storm: &StormHandle,
        config: &ElementsRpcConfig,
        storm_eye_asset_id: [u8; 32],
    ) -> Result<NetworkAsset, AssetError> {
        let issuer = ElementsAssetIssuer::new(config)?;
        let asset = self.ensure_tick_asset(issuer, storm_eye_asset_id).await?;
        self.announce_pending(storm).await?;

        Ok(asset)
    }

    async fn ensure_storm_eye<I>(
        &self,
        issuer: I,
        storm_tree_root: [u8; 32],
    ) -> Result<NetworkAsset, AssetError>
    where
        I: AssetIssuer + Clone + Send + 'static,
    {
        if let Some(asset) = self.store.get(STORM_EYE_KIND).await? {
            return Ok(asset);
        }

        let pending = if let Some(pending) = self.store.get_pending(STORM_EYE_KIND).await? {
            pending
        } else {
            let issuer = issuer.clone();
            let pending =
                tokio::task::spawn_blocking(move || issuer.prepare(storm_tree_root)).await??;

            if !self.store.insert_pending(&pending).await? {
                self.store
                    .get_pending(STORM_EYE_KIND)
                    .await?
                    .ok_or_else(|| AssetError::Conflict(STORM_EYE_KIND.to_string()))?
            } else {
                pending
            }
        };

        let issuer = issuer.clone();
        let issuance_tx = pending.issuance_tx.clone();
        let issuance_txid = pending.asset.issuance_txid;
        tokio::task::spawn_blocking(move || issuer.broadcast(&issuance_tx, issuance_txid))
            .await??;

        self.store.activate(STORM_EYE_KIND).await?;

        Ok(pending.asset)
    }

    async fn ensure_tick_asset<I>(
        &self,
        issuer: I,
        storm_eye_asset_id: [u8; 32],
    ) -> Result<NetworkAsset, AssetError>
    where
        I: TickAssetIssuer + Clone + Send + 'static,
    {
        if let Some(asset) = self.store.get(TICK_ASSET_KIND).await? {
            return Ok(asset);
        }

        let pending = if let Some(pending) = self.store.get_pending(TICK_ASSET_KIND).await? {
            pending
        } else {
            let issuer = issuer.clone();
            let pending =
                tokio::task::spawn_blocking(move || issuer.prepare_tick_asset(storm_eye_asset_id))
                    .await??;

            if !self.store.insert_pending(&pending).await? {
                self.store
                    .get_pending(TICK_ASSET_KIND)
                    .await?
                    .ok_or_else(|| AssetError::Conflict(TICK_ASSET_KIND.to_string()))?
            } else {
                pending
            }
        };

        let issuer = issuer.clone();
        let issuance_tx = pending.issuance_tx.clone();
        let issuance_txid = pending.asset.issuance_txid;
        tokio::task::spawn_blocking(move || issuer.broadcast(&issuance_tx, issuance_txid))
            .await??;

        self.store.activate(TICK_ASSET_KIND).await?;

        Ok(pending.asset)
    }

    pub(crate) async fn get(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        Ok(self.store.get(kind).await?)
    }

    pub(crate) async fn storm_eye(&self) -> Result<Option<NetworkAsset>, AssetError> {
        self.get(STORM_EYE_KIND).await
    }
}

pub(crate) fn storm_eye_program(asset: &NetworkAsset) -> Result<AuthProgram, AssetError> {
    let encoded = asset
        .contract_data
        .as_deref()
        .ok_or(AssetError::InvalidRpcResponse("Storm Eye contract data"))?;
    let data: StormEyeContractData = postcard::from_bytes(encoded)?;
    let mut program = AuthProgram::new(&AuthArguments {
        max_merge_utxos_count: MAX_MERGE_UTXOS_COUNT,
        max_split_utxos_count: MAX_SPLIT_UTXOS_COUNT,
        rescue_output_script_hash: data.rescue_output_script_hash,
    })
    .with_storage_capacity(2);
    program.set_storage_at(0, data.storm_tree_root);
    program.set_storage_at(1, rescue_block_slot(data.rescue_height));

    Ok(program)
}

trait AssetIssuer {
    fn prepare(&self, storm_tree_root: [u8; 32]) -> Result<PendingNetworkAsset, AssetError>;
    fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError>;
}

trait TickAssetIssuer: AssetIssuer {
    fn prepare_tick_asset(
        &self,
        storm_eye_asset_id: [u8; 32],
    ) -> Result<PendingNetworkAsset, AssetError>;
}

#[derive(Clone)]
struct ElementsAssetIssuer {
    rpc_url: String,
    auth: Auth,
}

impl ElementsAssetIssuer {
    fn new(config: &ElementsRpcConfig) -> Result<Self, AssetError> {
        let mut url = Url::parse(&config.url)?;
        url.path_segments_mut()
            .map_err(|_| AssetError::InvalidRpcResponse("wallet URL"))?
            .pop_if_empty()
            .push("wallet")
            .push(&config.wallet);

        Ok(Self {
            rpc_url: url.to_string(),
            auth: Auth::UserPass(config.username.clone(), config.password.clone()),
        })
    }

    fn client(&self) -> Result<Client, AssetError> {
        Ok(Client::new(&self.rpc_url, self.auth.clone())?)
    }

    fn prepare_storm_eye(
        &self,
        storm_tree_root: [u8; 32],
    ) -> Result<PendingNetworkAsset, AssetError> {
        let client = self.client()?;
        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
        let network = match chain.chain.as_str() {
            "liquidv1" => SimplicityNetwork::Liquid,
            "liquidtestnet" => SimplicityNetwork::LiquidTestnet,
            "elementsregtest" => SimplicityNetwork::default_regtest(),
            _ => return Err(AssetError::UnsupportedChain(chain.chain)),
        };
        let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
        let block_height: u64 = client.call("getblockcount", &[])?;
        let rescue_height =
            u32::try_from(block_height + RESCUE_BLOCKS).map_err(|_| AssetError::RescueHeight)?;

        let funding = client
            .call::<Vec<WalletUtxo>>("listunspent", &[0.into(), 9_999_999.into()])?
            .into_iter()
            .filter(|utxo| {
                utxo.spendable && utxo.asset == sidechain.pegged_asset && utxo.is_explicit()
            })
            .max_by(|left, right| left.amount.total_cmp(&right.amount))
            .ok_or(AssetError::MissingFundingUtxo)?;
        let rescue_script = Script::from(
            hex::decode(&funding.script_pub_key)
                .map_err(|_| AssetError::InvalidRpcResponse("funding UTXO script"))?,
        );

        let rescue_output_script_hash = hash_script(&rescue_script);
        let contract_data = StormEyeContractData {
            storm_tree_root,
            rescue_height,
            rescue_output_script_hash,
        };
        let mut program = AuthProgram::new(&AuthArguments {
            max_merge_utxos_count: MAX_MERGE_UTXOS_COUNT,
            max_split_utxos_count: MAX_SPLIT_UTXOS_COUNT,
            rescue_output_script_hash,
        })
        .with_storage_capacity(2);
        program.set_storage_at(0, storm_tree_root);
        program.set_storage_at(1, rescue_block_slot(rescue_height));
        let contract_address = program.as_ref().get_tr_address(&network).to_string();
        let contract_script = program.get_script_pubkey(&network).into_bytes();

        let funding_amount = Amount::from_btc(funding.amount)
            .map_err(|_| AssetError::InvalidRpcResponse("funding UTXO amount"))?;
        let change_sats = funding_amount
            .to_sat()
            .checked_sub(STORM_EYE_ISSUANCE_FEE_SATS)
            .ok_or(AssetError::MissingFundingUtxo)?;
        let change_amount = Amount::from_sat(change_sats).to_string_in(Denomination::Bitcoin);
        let fee_amount =
            Amount::from_sat(STORM_EYE_ISSUANCE_FEE_SATS).to_string_in(Denomination::Bitcoin);
        let raw: String = client.call(
            "createrawtransaction",
            &[
                json!([{ "txid": funding.txid, "vout": funding.vout }]),
                json!([
                    { (funding.address): change_amount },
                    { "fee": fee_amount },
                ]),
            ],
        )?;
        let issuances: Vec<RawIssuance> = client.call(
            "rawissueasset",
            &[
                raw.into(),
                json!([{
                    "asset_amount": STORM_EYE_RPC_AMOUNT,
                    "asset_address": contract_address,
                    "blind": false,
                }]),
            ],
        )?;
        let issuance = issuances
            .into_iter()
            .next()
            .ok_or(AssetError::InvalidRpcResponse("raw issuance"))?;
        let signed: SignedTransaction =
            client.call("signrawtransactionwithwallet", &[issuance.hex.into()])?;
        if !signed.complete {
            return Err(AssetError::InvalidRpcResponse(
                "complete signed transaction",
            ));
        }
        let decoded: DecodedTransaction =
            client.call("decoderawtransaction", &[signed.hex.clone().into()])?;
        ensure_explicit_outputs(&decoded)?;

        Ok(PendingNetworkAsset {
            asset: NetworkAsset {
                kind: STORM_EYE_KIND.to_string(),
                name: STORM_EYE_NAME.to_string(),
                asset_id: decode_asset_hash(&issuance.asset, "asset id")?,
                reissuance_token_id: None,
                entropy: Some(decode_asset_hash(&issuance.entropy, "asset entropy")?),
                issuance_txid: decode_hash(&decoded.txid, "issuance transaction id")?,
                contract_script,
                contract_data: Some(postcard::to_stdvec(&contract_data)?),
                supply: STORM_EYE_SUPPLY,
                created_at_block: block_height,
            },
            issuance_tx: hex::decode(signed.hex)
                .map_err(|_| AssetError::InvalidRpcResponse("signed transaction hex"))?,
        })
    }

    fn prepare_tick_asset(
        &self,
        storm_eye_asset_id: [u8; 32],
    ) -> Result<PendingNetworkAsset, AssetError> {
        let client = self.client()?;
        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
        let network = simplicity_network(&chain.chain)?;
        let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
        let block_height: u64 = client.call("getblockcount", &[])?;
        let treasury = TreasuryProgram::new(&TreasuryArguments { storm_eye_asset_id });
        let treasury_address = treasury.as_ref().get_tr_address(&network);
        let treasury_blinding_public_key =
            PublicKey::from_secret_key(&Secp256k1::new(), &treasury_blinding_secret());
        let confidential_treasury_address = treasury_address
            .to_confidential(treasury_blinding_public_key)
            .to_string();
        let treasury_script = treasury.get_script_pubkey(&network).into_bytes();

        let funding = client
            .call::<Vec<WalletUtxo>>("listunspent", &[0.into(), 9_999_999.into()])?
            .into_iter()
            .filter(|utxo| {
                utxo.spendable && utxo.asset == sidechain.pegged_asset && utxo.is_explicit()
            })
            .max_by(|left, right| left.amount.total_cmp(&right.amount))
            .ok_or(AssetError::MissingFundingUtxo)?;
        let funding_amount = Amount::from_btc(funding.amount)
            .map_err(|_| AssetError::InvalidRpcResponse("funding UTXO amount"))?;
        let change_sats = funding_amount
            .to_sat()
            .checked_sub(TICK_ISSUANCE_FEE_SATS)
            .ok_or(AssetError::MissingFundingUtxo)?;
        let change_amount = Amount::from_sat(change_sats).to_string_in(Denomination::Bitcoin);
        let fee_amount =
            Amount::from_sat(TICK_ISSUANCE_FEE_SATS).to_string_in(Denomination::Bitcoin);
        let raw: String = client.call(
            "createrawtransaction",
            &[
                json!([{ "txid": funding.txid, "vout": funding.vout }]),
                json!([
                    { (funding.address): change_amount },
                    { "fee": fee_amount },
                ]),
            ],
        )?;
        let issuances: Vec<RawIssuance> = client.call(
            "rawissueasset",
            &[
                raw.into(),
                json!([{
                    "token_amount": REISSUANCE_TOKEN_SUPPLY,
                    "token_address": confidential_treasury_address,
                    "blind": false,
                }]),
            ],
        )?;
        let issuance = issuances
            .into_iter()
            .next()
            .ok_or(AssetError::InvalidRpcResponse("raw Tick asset issuance"))?;
        let mut transaction: Transaction = encode::deserialize(
            &hex::decode(&issuance.hex)
                .map_err(|_| AssetError::InvalidRpcResponse("raw Tick issuance transaction"))?,
        )
        .map_err(|_| AssetError::InvalidRpcResponse("raw Tick issuance transaction"))?;
        let (token_output_index, token_output) = transaction
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.script_pubkey.as_bytes() == treasury_script)
            .ok_or(AssetError::InvalidRpcResponse("Treasury token output"))?;
        let token_output_index = u32::try_from(token_output_index)
            .map_err(|_| AssetError::InvalidRpcResponse("Treasury token output index"))?;
        let token_asset = token_output
            .asset
            .explicit()
            .ok_or(AssetError::InvalidRpcResponse(
                "explicit Treasury token asset",
            ))?;
        let token_value = token_output
            .value
            .explicit()
            .ok_or(AssetError::InvalidRpcResponse(
                "explicit Treasury token value",
            ))?;
        let funding_asset = AssetId::from_str(&funding.asset)
            .map_err(|_| AssetError::InvalidRpcResponse("funding asset id"))?;
        let issuance_secrets = [
            TxOutSecrets::new(
                funding_asset,
                AssetBlindingFactor::zero(),
                funding_amount.to_sat(),
                ValueBlindingFactor::zero(),
            ),
            TxOutSecrets::new(
                token_asset,
                AssetBlindingFactor::zero(),
                token_value,
                ValueBlindingFactor::zero(),
            ),
        ];
        let (blinded_token, _, _, _) = TxOut::new_last_confidential(
            &mut secp256k1_zkp::rand::thread_rng(),
            &Secp256k1::new(),
            token_value,
            token_asset,
            token_output.script_pubkey.clone(),
            treasury_blinding_public_key,
            &issuance_secrets,
            &[],
        )
        .map_err(|_| AssetError::InvalidRpcResponse("blinded Treasury token output"))?;
        transaction.output[token_output_index as usize] = blinded_token;
        let blinded = hex::encode(encode::serialize(&transaction));
        let signed: SignedTransaction =
            client.call("signrawtransactionwithwallet", &[blinded.into()])?;
        if !signed.complete {
            return Err(AssetError::InvalidRpcResponse(
                "complete signed Tick asset transaction",
            ));
        }
        let transaction: Transaction = encode::deserialize(
            &hex::decode(&signed.hex)
                .map_err(|_| AssetError::InvalidRpcResponse("signed Tick issuance transaction"))?,
        )
        .map_err(|_| AssetError::InvalidRpcResponse("signed Tick issuance transaction"))?;
        let (signed_token_output_index, token_txout) =
            confidential_token_output(&transaction, &treasury_script)?;
        if signed_token_output_index != token_output_index {
            return Err(AssetError::InvalidRpcResponse(
                "Treasury token output index",
            ));
        }
        let token_secrets = token_txout
            .unblind(&Secp256k1::new(), treasury_blinding_secret())
            .map_err(|_| AssetError::InvalidRpcResponse("unblinded Treasury token output"))?;
        if token_secrets.asset_bf == AssetBlindingFactor::zero() {
            return Err(AssetError::InvalidRpcResponse(
                "blinded Treasury token asset",
            ));
        }
        let decoded: DecodedTransaction =
            client.call("decoderawtransaction", &[signed.hex.clone().into()])?;

        Ok(PendingNetworkAsset {
            asset: NetworkAsset {
                kind: TICK_ASSET_KIND.to_string(),
                name: TICK_ASSET_NAME.to_string(),
                asset_id: decode_asset_hash(&issuance.asset, "Tick asset id")?,
                reissuance_token_id: Some(decode_asset_hash(
                    &issuance.token,
                    "Tick reissuance token id",
                )?),
                entropy: Some(decode_asset_hash(&issuance.entropy, "Tick asset entropy")?),
                issuance_txid: decode_hash(&decoded.txid, "Tick issuance transaction id")?,
                contract_script: treasury_script,
                contract_data: Some(
                    postcard::to_stdvec(&TickAssetContractData {
                        issuance_tx: encode::serialize(&transaction),
                        token_output_index,
                    })
                    .map_err(AssetError::Encoding)?,
                ),
                supply: TICK_ASSET_SUPPLY,
                created_at_block: block_height,
            },
            issuance_tx: hex::decode(signed.hex).map_err(|_| {
                AssetError::InvalidRpcResponse("signed Tick issuance transaction hex")
            })?,
        })
    }

    fn broadcast_transaction(
        &self,
        transaction: &[u8],
        expected_txid: [u8; 32],
    ) -> Result<(), AssetError> {
        let client = self.client()?;
        let expected_txid = hex::encode(expected_txid);

        if client
            .call::<Value>("gettransaction", &[expected_txid.clone().into()])
            .is_ok()
        {
            return Ok(());
        }

        let txid: String = client.call("sendrawtransaction", &[hex::encode(transaction).into()])?;
        if txid != expected_txid {
            return Err(AssetError::InvalidRpcResponse("broadcast transaction id"));
        }

        Ok(())
    }
}

impl AssetIssuer for ElementsAssetIssuer {
    fn prepare(&self, storm_tree_root: [u8; 32]) -> Result<PendingNetworkAsset, AssetError> {
        self.prepare_storm_eye(storm_tree_root)
    }

    fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError> {
        self.broadcast_transaction(transaction, expected_txid)
    }
}

impl TickAssetIssuer for ElementsAssetIssuer {
    fn prepare_tick_asset(
        &self,
        storm_eye_asset_id: [u8; 32],
    ) -> Result<PendingNetworkAsset, AssetError> {
        self.prepare_tick_asset(storm_eye_asset_id)
    }
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
struct WalletUtxo {
    txid: String,
    vout: u32,
    address: String,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: String,
    asset: String,
    amount: f64,
    spendable: bool,
    #[serde(default)]
    amountblinder: String,
    #[serde(default)]
    assetblinder: String,
}

impl WalletUtxo {
    fn is_explicit(&self) -> bool {
        let zero = "0".repeat(64);
        self.amountblinder == zero && self.assetblinder == zero
    }
}

#[derive(Deserialize)]
struct RawIssuance {
    hex: String,
    entropy: String,
    asset: String,
    token: String,
}

#[derive(Deserialize)]
struct SignedTransaction {
    hex: String,
    complete: bool,
}

#[derive(Deserialize)]
struct DecodedTransaction {
    txid: String,
    vout: Vec<DecodedOutput>,
}

#[derive(Deserialize)]
struct DecodedOutput {
    #[serde(rename = "n")]
    index: u32,
    #[serde(rename = "assetcommitment")]
    asset_commitment: Option<String>,
    #[serde(rename = "commitmentnonce")]
    nonce: Option<String>,
    #[serde(rename = "valuecommitment")]
    value_commitment: Option<String>,
}

fn ensure_explicit_outputs(transaction: &DecodedTransaction) -> Result<(), AssetError> {
    if let Some(output) = transaction.vout.iter().find(|output| {
        output.asset_commitment.is_some()
            || output.value_commitment.is_some()
            || output
                .nonce
                .as_deref()
                .is_some_and(|nonce| !nonce.is_empty())
    }) {
        return Err(AssetError::ConfidentialOutput(output.index));
    }

    Ok(())
}

fn confidential_token_output<'a>(
    transaction: &'a Transaction,
    treasury_script: &[u8],
) -> Result<(u32, &'a TxOut), AssetError> {
    let mut confidential_outputs = transaction.output.iter().enumerate().filter(|(_, output)| {
        output.asset.is_confidential()
            || output.value.is_confidential()
            || output.nonce.is_confidential()
    });
    let (token_index, token) =
        confidential_outputs
            .next()
            .ok_or(AssetError::InvalidRpcResponse(
                "confidential Treasury token output",
            ))?;
    if token.script_pubkey.as_bytes() != treasury_script {
        return Err(AssetError::InvalidRpcResponse(
            "confidential non-Treasury output",
        ));
    }
    if !token.asset.is_confidential() {
        return Err(AssetError::InvalidRpcResponse(
            "confidential Treasury token asset",
        ));
    }
    if !token.value.is_confidential() {
        return Err(AssetError::InvalidRpcResponse(
            "confidential Treasury token value",
        ));
    }
    if let Some((output_index, _)) = confidential_outputs.next() {
        return Err(AssetError::ConfidentialOutput(output_index as u32));
    }

    Ok((token_index as u32, token))
}

fn rescue_block_slot(rescue_height: u32) -> [u8; 32] {
    let mut slot = [0; 32];
    slot[28..].copy_from_slice(&rescue_height.to_be_bytes());
    slot
}

fn simplicity_network(chain: &str) -> Result<SimplicityNetwork, AssetError> {
    match chain {
        "liquidv1" => Ok(SimplicityNetwork::Liquid),
        "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elementsregtest" => Ok(SimplicityNetwork::default_regtest()),
        chain => Err(AssetError::UnsupportedChain(chain.to_string())),
    }
}

fn decode_hash(encoded: &str, name: &'static str) -> Result<[u8; 32], AssetError> {
    let bytes = hex::decode(encoded).map_err(|_| AssetError::InvalidRpcResponse(name))?;
    bytes
        .try_into()
        .map_err(|_| AssetError::InvalidRpcResponse(name))
}

fn decode_asset_hash(encoded: &str, name: &'static str) -> Result<[u8; 32], AssetError> {
    AssetId::from_str(encoded)
        .map(|asset| asset.into_inner().to_byte_array())
        .map_err(|_| AssetError::InvalidRpcResponse(name))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::db::Database;
    use simplex::simplicityhl::elements::hashes::sha256;

    use super::*;

    #[test]
    fn decodes_rpc_asset_id_to_consensus_bytes() {
        let displayed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let mut expected = hex::decode(displayed).unwrap();
        expected.reverse();

        assert_eq!(
            decode_asset_hash(displayed, "test").unwrap().as_slice(),
            expected
        );
    }

    #[test]
    fn derives_rpc_asset_id_from_decoded_entropy() {
        let asset = decode_asset_hash(
            "667c7d600018fae9173b923c64519cf478f1f61585317db793ddfbc303205a08",
            "test asset",
        )
        .unwrap();
        let entropy = decode_asset_hash(
            "4cab94f3f15a98cbd3eb3d6d6e8db3d7b884084c75e08bab24a3df1cbc27c451",
            "test entropy",
        )
        .unwrap();

        assert_eq!(
            AssetId::from_entropy(sha256::Midstate::from_byte_array(entropy)).into_inner(),
            AssetId::from_byte_array(asset).into_inner()
        );
    }

    #[test]
    fn accepts_only_zero_blinder_funding_utxos() {
        let mut utxo = WalletUtxo {
            txid: "00".repeat(32),
            vout: 0,
            address: "address".into(),
            script_pub_key: String::new(),
            asset: "asset".into(),
            amount: 1.0,
            spendable: true,
            amountblinder: "0".repeat(64),
            assetblinder: "0".repeat(64),
        };
        assert!(utxo.is_explicit());

        utxo.amountblinder = "1".repeat(64);
        assert!(!utxo.is_explicit());
    }

    #[test]
    fn rejects_confidential_issuance_outputs() {
        let transaction = DecodedTransaction {
            txid: "00".repeat(32),
            vout: vec![DecodedOutput {
                index: 2,
                asset_commitment: Some("0a".repeat(33)),
                nonce: None,
                value_commitment: None,
            }],
        };

        assert!(matches!(
            ensure_explicit_outputs(&transaction),
            Err(AssetError::ConfidentialOutput(2))
        ));
    }

    #[derive(Clone)]
    struct FakeIssuer {
        prepared: Arc<AtomicUsize>,
        broadcast: Arc<AtomicUsize>,
        pending: PendingNetworkAsset,
    }

    impl FakeIssuer {
        fn new() -> Self {
            Self {
                prepared: Arc::new(AtomicUsize::new(0)),
                broadcast: Arc::new(AtomicUsize::new(0)),
                pending: PendingNetworkAsset {
                    asset: NetworkAsset {
                        kind: STORM_EYE_KIND.to_string(),
                        name: STORM_EYE_NAME.to_string(),
                        asset_id: [1; 32],
                        reissuance_token_id: None,
                        entropy: Some([2; 32]),
                        issuance_txid: [3; 32],
                        contract_script: vec![0x51],
                        contract_data: None,
                        supply: STORM_EYE_SUPPLY,
                        created_at_block: 42,
                    },
                    issuance_tx: vec![4; 64],
                },
            }
        }
    }

    impl AssetIssuer for FakeIssuer {
        fn prepare(&self, _storm_tree_root: [u8; 32]) -> Result<PendingNetworkAsset, AssetError> {
            self.prepared.fetch_add(1, Ordering::SeqCst);
            Ok(self.pending.clone())
        }

        fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError> {
            assert_eq!(transaction, self.pending.issuance_tx);
            assert_eq!(expected_txid, self.pending.asset.issuance_txid);
            self.broadcast.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeTickAssetIssuer {
        prepared: Arc<AtomicUsize>,
        broadcast: Arc<AtomicUsize>,
        pending: PendingNetworkAsset,
    }

    impl FakeTickAssetIssuer {
        fn new() -> Self {
            Self {
                prepared: Arc::new(AtomicUsize::new(0)),
                broadcast: Arc::new(AtomicUsize::new(0)),
                pending: PendingNetworkAsset {
                    asset: NetworkAsset {
                        kind: TICK_ASSET_KIND.to_string(),
                        name: TICK_ASSET_NAME.to_string(),
                        asset_id: [5; 32],
                        reissuance_token_id: Some([6; 32]),
                        entropy: Some([7; 32]),
                        issuance_txid: [8; 32],
                        contract_script: vec![0x51],
                        contract_data: None,
                        supply: TICK_ASSET_SUPPLY,
                        created_at_block: 43,
                    },
                    issuance_tx: vec![9; 64],
                },
            }
        }
    }

    impl AssetIssuer for FakeTickAssetIssuer {
        fn prepare(&self, _storm_tree_root: [u8; 32]) -> Result<PendingNetworkAsset, AssetError> {
            unreachable!("Tick asset initialization uses prepare_tick_asset")
        }

        fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError> {
            assert_eq!(transaction, self.pending.issuance_tx);
            assert_eq!(expected_txid, self.pending.asset.issuance_txid);
            self.broadcast.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl TickAssetIssuer for FakeTickAssetIssuer {
        fn prepare_tick_asset(
            &self,
            _storm_eye_asset_id: [u8; 32],
        ) -> Result<PendingNetworkAsset, AssetError> {
            self.prepared.fetch_add(1, Ordering::SeqCst);
            Ok(self.pending.clone())
        }
    }

    async fn assets() -> Assets {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        Assets::new(database.network_assets())
    }

    #[tokio::test]
    async fn creates_and_activates_storm_eye_once() {
        let assets = assets().await;
        let issuer = FakeIssuer::new();

        let created = assets
            .ensure_storm_eye(issuer.clone(), [5; 32])
            .await
            .unwrap();
        let existing = assets
            .ensure_storm_eye(issuer.clone(), [6; 32])
            .await
            .unwrap();

        assert_eq!(created, issuer.pending.asset);
        assert_eq!(existing, issuer.pending.asset);
        assert_eq!(issuer.prepared.load(Ordering::SeqCst), 1);
        assert_eq!(issuer.broadcast.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn creates_and_activates_tick_asset_once() {
        let assets = assets().await;
        let issuer = FakeTickAssetIssuer::new();

        let created = assets
            .ensure_tick_asset(issuer.clone(), [1; 32])
            .await
            .unwrap();
        let existing = assets
            .ensure_tick_asset(issuer.clone(), [2; 32])
            .await
            .unwrap();

        assert_eq!(created, issuer.pending.asset);
        assert_eq!(created.supply, 0);
        assert_eq!(created.reissuance_token_id, Some([6; 32]));
        assert_eq!(existing, issuer.pending.asset);
        assert_eq!(issuer.prepared.load(Ordering::SeqCst), 1);
        assert_eq!(issuer.broadcast.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rebroadcasts_persisted_pending_transaction() {
        let assets = assets().await;
        let issuer = FakeIssuer::new();
        assets.store.insert_pending(&issuer.pending).await.unwrap();

        let created = assets
            .ensure_storm_eye(issuer.clone(), [5; 32])
            .await
            .unwrap();

        assert_eq!(created, issuer.pending.asset);
        assert_eq!(issuer.prepared.load(Ordering::SeqCst), 0);
        assert_eq!(issuer.broadcast.load(Ordering::SeqCst), 1);
        assert!(
            assets
                .store
                .get_pending(STORM_EYE_KIND)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn encodes_rescue_height_in_the_contract_storage_word() {
        let slot = rescue_block_slot(0x1234_5678);

        assert_eq!(&slot[..28], &[0; 28]);
        assert_eq!(&slot[28..], &[0x12, 0x34, 0x56, 0x78]);
    }
}
