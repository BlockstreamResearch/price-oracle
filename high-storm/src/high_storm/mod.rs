use std::ops::{Deref, DerefMut};

use secp256k1_zkp::PublicKey;
use storm::{PeerStatus, Storm, StormHandle};

mod assets;
mod burning;
mod handler;
mod indexer;
mod issuance;
mod leader;
mod message;
mod signing;
mod state;
mod user_requests;
mod voting;

pub use assets::AssetError;
pub use burning::BurningError;
pub use indexer::IndexerError;
pub use message::{
    ApproveVotingRequest, BurnExpiredUtxos, ExecuteUserRequests, ExpiredUtxosBurned,
    ExternalRequests, MergeStormEyes, NetworkAsset, NetworkAssets, NetworkVoteKind,
    NetworkVoteRequest, NodeMessage, NodeMessageKind, SplitStormEye, StormEyeUtxo,
    UpdateNetworkMembers,
};
pub use signing::{SigningError, SigningResult};
use state::NetworkState;
pub use user_requests::UserRequestError;
pub use voting::{VOTING_TIMEOUT_BLOCKS, VotingApproval, VotingError, VotingRequest, VotingStatus};

/// A long-lived Oracle Network node and its higher-level protocol state.
pub struct HighStorm {
    storm: Storm,
    state: NetworkState,
}

pub(crate) struct HighStormDependencies {
    voting_store: crate::db::voting::VotingStore,
    network_assets: crate::db::network_asset::NetworkAssetStore,
    monitored_utxos: crate::db::monitored_utxo::MonitoredUtxoStore,
    user_requests: crate::db::user_request::UserRequestStore,
    elements_rpc: crate::config::ElementsRpcConfig,
    user_request_config: crate::config::UserRequestsConfig,
}

impl HighStormDependencies {
    pub(crate) fn new(
        voting_store: crate::db::voting::VotingStore,
        network_assets: crate::db::network_asset::NetworkAssetStore,
        monitored_utxos: crate::db::monitored_utxo::MonitoredUtxoStore,
        user_requests: crate::db::user_request::UserRequestStore,
        elements_rpc: crate::config::ElementsRpcConfig,
        user_request_config: crate::config::UserRequestsConfig,
    ) -> Self {
        Self {
            voting_store,
            network_assets,
            monitored_utxos,
            user_requests,
            elements_rpc,
            user_request_config,
        }
    }
}

#[derive(Clone)]
pub struct HighStormHandle {
    storm: StormHandle,
    state: NetworkState,
}

impl HighStorm {
    pub(crate) async fn new(
        storm: Storm,
        secret_key: [u8; 32],
        coordinator_public_key: [u8; 33],
        dependencies: HighStormDependencies,
    ) -> Self {
        let state =
            NetworkState::new(&storm, secret_key, coordinator_public_key, dependencies).await;
        let handler_state = state.clone();

        storm
            .register_custom_handler(move |message, context| {
                let state = handler_state.clone();
                async move {
                    if let Err(error) = handler::handle(state, message, context).await {
                        tracing::warn!(%error, "failed to handle high-storm NodeMessage");
                    }
                }
            })
            .await;

        Self { storm, state }
    }

    /// Returns the compressed public key of the node coordinating user requests.
    pub fn coordinator_public_key(&self) -> [u8; 33] {
        self.state.coordinator_public_key()
    }

    pub fn handle(&self) -> HighStormHandle {
        HighStormHandle {
            storm: self.storm.handle(),
            state: self.state.clone(),
        }
    }

    /// Returns whether this node is the coordinator for user requests.
    pub async fn is_coordinator(&self) -> bool {
        let local_public_key = self
            .peers()
            .await
            .into_iter()
            .find(|peer| peer.status == storm::PeerStatus::Controlled)
            .map(|peer| peer.compressed_public_key);

        local_public_key == Some(self.coordinator_public_key())
    }

    pub async fn current_leader(&self) -> Option<[u8; 33]> {
        leader::leader_for_height(&self.peers().await, self.state.block_height())
    }

    pub async fn is_leader(&self) -> bool {
        let peers = self.peers().await;
        leader::local_public_key(&peers)
            == leader::leader_for_height(&peers, self.state.block_height())
    }

    pub async fn sign_execute_user_requests(
        &self,
        tx: Vec<u8>,
        signing_hash: [u8; 32],
        external_requests: Vec<ExternalRequests>,
    ) -> Result<SigningResult, SigningError> {
        self.state
            .signing()
            .sign_execute_user_requests(&self.storm, tx, signing_hash, external_requests)
            .await
    }

    pub async fn create_voting_request(
        &self,
        request: NetworkVoteRequest,
        block_height: u64,
    ) -> Result<[u8; 32], VotingError> {
        self.state.set_block_height(block_height);
        self.state
            .voting()
            .create(&self.storm.handle(), request, block_height)
            .await
    }

    pub async fn approve_voting_request(
        &self,
        request_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(), VotingError> {
        self.state.set_block_height(block_height);
        self.state
            .voting()
            .approve(&self.storm.handle(), request_hash, block_height)
            .await
    }

    pub async fn voting_request(
        &self,
        request_hash: [u8; 32],
    ) -> Result<Option<VotingRequest>, VotingError> {
        self.state.voting().get(request_hash).await
    }

    pub async fn voting_requests(&self) -> Result<Vec<VotingRequest>, VotingError> {
        self.state.voting().list().await
    }

    pub async fn synchronize_voting_requests(&self) -> Result<(), VotingError> {
        self.state.voting().synchronize(&self.storm.handle()).await
    }

    pub async fn remove_expired_voting_requests(
        &self,
        block_height: u64,
    ) -> Result<u64, VotingError> {
        self.state.set_block_height(block_height);
        self.state.voting().remove_expired(block_height).await
    }

    pub fn set_block_height(&self, block_height: u64) {
        self.state.set_block_height(block_height);
    }

    pub async fn index_blocks(&self) -> Result<u64, IndexerError> {
        let indexed = self.state.indexer().sync().await?;
        if let Some(cursor) = self.state.indexer().cursor().await? {
            self.state.set_block_height(cursor.height);
        }
        Ok(indexed)
    }

    pub async fn announce_network_assets(&self) -> Result<(), AssetError> {
        self.state
            .assets()
            .announce_pending(&self.storm.handle())
            .await
    }

    pub async fn initialize_storm_eye(
        &self,
        config: &crate::config::ElementsRpcConfig,
    ) -> Result<Option<NetworkAsset>, AssetError> {
        if !self.is_coordinator().await {
            return Ok(None);
        }

        let storm_tree_root = self.state.signing().storm_tree_root().await?;
        self.state
            .assets()
            .initialize_storm_eye(&self.storm.handle(), config, storm_tree_root)
            .await
            .map(Some)
    }

    pub async fn initialize_tick_asset(
        &self,
        config: &crate::config::ElementsRpcConfig,
    ) -> Result<Option<NetworkAsset>, AssetError> {
        if !self.is_coordinator().await {
            return Ok(None);
        }

        let storm_eye = self
            .state
            .assets()
            .storm_eye()
            .await?
            .ok_or_else(|| AssetError::Conflict("Storm Eye is not initialized".to_string()))?;
        self.state
            .assets()
            .initialize_tick_asset(&self.storm.handle(), config, storm_eye.asset_id)
            .await
            .map(Some)
    }

    pub async fn network_asset(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().get(kind).await
    }

    pub async fn process_user_requests(&self) -> Result<usize, user_requests::UserRequestError> {
        if !self.is_coordinator().await {
            return Ok(0);
        }

        let prepared = match self.state.user_requests().prepare_round().await? {
            Some(prepared) => prepared,
            None => return Ok(0),
        };
        self.state
            .user_requests()
            .validate_execute(&prepared.request)
            .await?;
        let signing = self
            .state
            .signing()
            .sign_execute_user_requests(
                &self.storm,
                prepared.request.tx.clone(),
                prepared.request.signing_hash,
                prepared.request.external_requests.clone(),
            )
            .await
            .map_err(user_requests::UserRequestError::Signing)?;
        let proof = self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await
            .map_err(user_requests::UserRequestError::Signing)?;

        self.state
            .user_requests()
            .finalize_and_broadcast(prepared, signing, proof)
            .await
    }

    pub async fn burn_expired_utxos(&self) -> Result<usize, BurningError> {
        let block_height = self.state.block_height();
        let reconciled = self.state.burning().reconcile_mempool(block_height).await?;
        if reconciled > 0 {
            tracing::info!(
                reconciled,
                "recovered in-flight Tick burns from the mempool"
            );
        }

        let peers = self.peers().await;
        if !leader::is_local_leader(&peers, block_height) {
            return Ok(0);
        }

        let prepared = match self.state.burning().prepare_round(block_height).await? {
            Some(prepared) => prepared,
            None => return Ok(0),
        };
        self.state
            .burning()
            .validate_request(&prepared.request)
            .await?;
        let signing = self
            .state
            .signing()
            .sign_burn_expired_utxos(
                &self.storm,
                prepared.request.tx.clone(),
                prepared.request.signing_hash,
                block_height,
            )
            .await?;
        let proof = self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await?;
        let notification = self
            .state
            .burning()
            .finalize_and_broadcast(prepared, signing, proof, block_height)
            .await?;
        let count = notification.utxos.len();
        if let Err(error) = self.announce_burn(&notification).await {
            tracing::warn!(%error, "failed to announce broadcast Tick burn");
        }

        Ok(count)
    }

    async fn announce_burn(&self, notification: &ExpiredUtxosBurned) -> Result<(), SigningError> {
        let recipients = self
            .peers()
            .await
            .into_iter()
            .filter(|peer| peer.status == PeerStatus::Active)
            .map(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key).map_err(|_| {
                    SigningError::InvalidMessage("invalid burn notification recipient".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if recipients.is_empty() {
            return Ok(());
        }
        let message = NodeMessage::new(NodeMessageKind::ExpiredUtxosBurned, None, notification)?
            .into_storm_message()?;
        self.storm.send_message(message, &recipients).await?;

        Ok(())
    }

    pub async fn reconcile_user_requests(&self) -> Result<usize, user_requests::UserRequestError> {
        if !self.is_coordinator().await {
            return Ok(0);
        }

        self.state.user_requests().reconcile_confirmations().await
    }

    pub async fn storm_eye_asset(&self) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().storm_eye().await
    }
}

impl HighStormHandle {
    pub fn coordinator_public_key(&self) -> [u8; 33] {
        self.state.coordinator_public_key()
    }

    pub fn block_height(&self) -> u64 {
        self.state.block_height()
    }

    pub async fn peers(&self) -> Vec<storm::Peer> {
        self.storm.peers().await
    }

    pub async fn is_coordinator(&self) -> bool {
        self.storm
            .peers()
            .await
            .into_iter()
            .find(|peer| peer.status == storm::PeerStatus::Controlled)
            .map(|peer| peer.compressed_public_key)
            == Some(self.coordinator_public_key())
    }

    pub async fn create_voting_request(
        &self,
        request: NetworkVoteRequest,
    ) -> Result<[u8; 32], VotingError> {
        self.state
            .voting()
            .create(&self.storm, request, self.state.block_height())
            .await
    }

    pub async fn approve_voting_request(&self, request_hash: [u8; 32]) -> Result<(), VotingError> {
        self.state
            .voting()
            .approve(&self.storm, request_hash, self.state.block_height())
            .await
    }

    pub async fn voting_request(
        &self,
        request_hash: [u8; 32],
    ) -> Result<Option<VotingRequest>, VotingError> {
        self.state.voting().get(request_hash).await
    }

    pub async fn voting_requests(&self) -> Result<Vec<VotingRequest>, VotingError> {
        self.state.voting().list().await
    }

    pub async fn network_asset(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().get(kind).await
    }
}

impl Deref for HighStorm {
    type Target = Storm;

    fn deref(&self) -> &Self::Target {
        &self.storm
    }
}

impl DerefMut for HighStorm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.storm
    }
}
