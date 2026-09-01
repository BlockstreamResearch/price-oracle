use bitcoin::{Amount, Denomination};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::auth::{AuthProgram, derived_auth::AuthArguments};
use secp256k1_zkp::PublicKey;
use serde::Deserialize;
use serde_json::{Value, json};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::Script;
use simplex::utils::hash_script;
use storm::{PeerStatus, StormContext, StormHandle};
use url::Url;

use crate::{
    NetworkAsset, NetworkAssets,
    config::ElementsRpcConfig,
    db::network_asset::{NetworkAssetStore, PendingNetworkAsset, STORM_EYE_KIND},
};

use super::{NodeMessage, NodeMessageKind, SigningError};

const STORM_EYE_NAME: &str = "Storm Eye";
const STORM_EYE_SUPPLY: u64 = 10_000;
const MAX_MERGE_UTXOS_COUNT: u8 = 4;
const MAX_SPLIT_UTXOS_COUNT: u8 = 4;
const RESCUE_BLOCKS: u64 = 1_576_800;
const STORM_EYE_RPC_AMOUNT: f64 = 0.000_100_00;

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
    #[error("Elements wallet has no spendable policy asset UTXO")]
    MissingFundingUtxo,
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
    #[error("Storm Eye rescue height does not fit in the contract")]
    RescueHeight,
    #[error("Storm Eye issuance task failed: {0}")]
    IssuanceTask(#[from] tokio::task::JoinError),
    #[error("Storm Tree state is unavailable: {0}")]
    Signing(#[from] SigningError),
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
                    .map(|public_key| (public_key, peer.compressed_public_key))
                    .map_err(|error| AssetError::InvalidPeer(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (recipient, compressed_public_key) in recipients {
            let assets = self.store.pending_for_peer(&compressed_public_key).await?;
            if assets.is_empty() {
                continue;
            }
            let kinds = assets
                .iter()
                .map(|asset| asset.kind.clone())
                .collect::<Vec<_>>();
            let message = NodeMessage::new(
                NodeMessageKind::NetworkAssets,
                None,
                &NetworkAssets { assets },
            )?
            .into_storm_message()?;
            storm.send_message(message, &[recipient]).await?;
            self.store
                .mark_announced_to(&kinds, &compressed_public_key)
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

    pub(crate) async fn get(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        Ok(self.store.get(kind).await?)
    }

    pub(crate) async fn storm_eye(&self) -> Result<Option<NetworkAsset>, AssetError> {
        self.get(STORM_EYE_KIND).await
    }
}

trait AssetIssuer {
    fn prepare(&self, storm_tree_root: [u8; 32]) -> Result<PendingNetworkAsset, AssetError>;
    fn broadcast(&self, transaction: &[u8], expected_txid: [u8; 32]) -> Result<(), AssetError>;
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
            .find(|utxo| utxo.spendable && utxo.asset == sidechain.pegged_asset)
            .ok_or(AssetError::MissingFundingUtxo)?;
        let rescue_script = Script::from(
            hex::decode(&funding.script_pub_key)
                .map_err(|_| AssetError::InvalidRpcResponse("funding UTXO script"))?,
        );

        let mut program = AuthProgram::new(&AuthArguments {
            max_merge_utxos_count: MAX_MERGE_UTXOS_COUNT,
            max_split_utxos_count: MAX_SPLIT_UTXOS_COUNT,
            rescue_output_script_hash: hash_script(&rescue_script),
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
            .checked_sub(1)
            .ok_or(AssetError::MissingFundingUtxo)?;
        let change_amount = Amount::from_sat(change_sats).to_string_in(Denomination::Bitcoin);
        let raw: String = client.call(
            "createrawtransaction",
            &[
                json!([{ "txid": funding.txid, "vout": funding.vout }]),
                json!([
                    { (funding.address): change_amount },
                    { "fee": "0.00000001" },
                ]),
            ],
        )?;
        let funded: FundedTransaction = client.call(
            "fundrawtransaction",
            &[
                raw.into(),
                json!({
                    "add_inputs": false,
                    "fee_rate": "2.0",
                    "subtractFeeFromOutputs": [0],
                }),
            ],
        )?;
        let issuances: Vec<RawIssuance> = client.call(
            "rawissueasset",
            &[
                funded.hex.into(),
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

        Ok(PendingNetworkAsset {
            asset: NetworkAsset {
                kind: STORM_EYE_KIND.to_string(),
                name: STORM_EYE_NAME.to_string(),
                asset_id: decode_hash(&issuance.asset, "asset id")?,
                reissuance_token_id: None,
                entropy: Some(decode_hash(&issuance.entropy, "asset entropy")?),
                issuance_txid: decode_hash(&decoded.txid, "issuance transaction id")?,
                contract_script,
                supply: STORM_EYE_SUPPLY,
                created_at_block: block_height,
            },
            issuance_tx: hex::decode(signed.hex)
                .map_err(|_| AssetError::InvalidRpcResponse("signed transaction hex"))?,
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
}

#[derive(Deserialize)]
struct FundedTransaction {
    hex: String,
}

#[derive(Deserialize)]
struct RawIssuance {
    hex: String,
    entropy: String,
    asset: String,
}

#[derive(Deserialize)]
struct SignedTransaction {
    hex: String,
    complete: bool,
}

#[derive(Deserialize)]
struct DecodedTransaction {
    txid: String,
}

fn rescue_block_slot(rescue_height: u32) -> [u8; 32] {
    let mut slot = [0; 32];
    slot[28..].copy_from_slice(&rescue_height.to_be_bytes());
    slot
}

fn decode_hash(encoded: &str, name: &'static str) -> Result<[u8; 32], AssetError> {
    let bytes = hex::decode(encoded).map_err(|_| AssetError::InvalidRpcResponse(name))?;
    bytes
        .try_into()
        .map_err(|_| AssetError::InvalidRpcResponse(name))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::db::Database;

    use super::*;

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
