use std::{
    collections::BTreeSet,
    ops::{Deref, DerefMut},
};

use secp256k1_zkp::PublicKey;
use storm::{PeerStatus, Storm, StormHandle};

mod assets;
mod burning;
mod droplets;
mod handler;
mod indexer;
mod issuance;
mod leader;
mod message;
mod signing;
mod state;
mod user_requests;
mod voting;
mod voting_execution;

pub use assets::AssetError;
pub use burning::BurningError;
pub use droplets::DropletsError;
pub(crate) use droplets::exchange_recipient_amount;
pub use indexer::IndexerError;
pub use message::{
    ApproveVotingRequest, BurnExpiredUtxos, ExchangeRewards, ExecuteUserRequests,
    ExecuteVotingRequest, ExpiredUtxosBurned, ExternalRequests, MergeStormEyes, NetworkAsset,
    NetworkAssets, NetworkVoteKind, NetworkVoteRequest, NodeMessage, NodeMessageKind,
    SplitStormEye, StormEyeUtxo, UpdateNetworkMembers,
};
pub use signing::{SigningError, SigningResult};
use state::NetworkState;
pub use user_requests::UserRequestError;
pub use voting::{VOTING_TIMEOUT_BLOCKS, VotingApproval, VotingError, VotingRequest, VotingStatus};
pub use voting_execution::{StormEyeInventoryItem, StormEyeState, VotingExecutionError};

/// A long-lived Oracle Network node and its higher-level protocol state.
pub struct HighStorm {
    storm: Storm,
    state: NetworkState,
}

pub(crate) struct HighStormDependencies {
    network_store: crate::db::network::NetworkStore,
    voting_store: crate::db::voting::VotingStore,
    network_assets: crate::db::network_asset::NetworkAssetStore,
    monitored_utxos: crate::db::monitored_utxo::MonitoredUtxoStore,
    droplets: crate::db::droplet::DropletStore,
    user_requests: crate::db::user_request::UserRequestStore,
    elements_rpc: crate::config::ElementsRpcConfig,
    protocol_config: crate::config::ProtocolConfig,
}

impl HighStormDependencies {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        network_store: crate::db::network::NetworkStore,
        voting_store: crate::db::voting::VotingStore,
        network_assets: crate::db::network_asset::NetworkAssetStore,
        monitored_utxos: crate::db::monitored_utxo::MonitoredUtxoStore,
        droplets: crate::db::droplet::DropletStore,
        user_requests: crate::db::user_request::UserRequestStore,
        elements_rpc: crate::config::ElementsRpcConfig,
        protocol_config: crate::config::ProtocolConfig,
    ) -> Self {
        Self {
            network_store,
            voting_store,
            network_assets,
            monitored_utxos,
            droplets,
            user_requests,
            elements_rpc,
            protocol_config,
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
        storm
            .handle()
            .set_peer_table_authority(coordinator_public_key)
            .await
            .expect("the configured coordinator has a validated public key");
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

    pub(crate) async fn restore_member_migration(&self) -> Result<(), VotingError> {
        self.state
            .voting()
            .restore_member_migration(&self.storm.handle())
            .await
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

    pub async fn exchange_droplets(
        &self,
        tx: Vec<u8>,
        signing_hash: [u8; 32],
        block_height: u64,
    ) -> Result<[u8; 32], DropletsError> {
        self.state.set_block_height(block_height);
        let peers = self.peers().await;
        let local = leader::local_public_key(&peers);
        let current = leader::leader_for_height(&peers, block_height);
        if local.is_none() || local != current {
            return Err(DropletsError::Invalid(
                "only the current network leader may exchange Droplets".into(),
            ));
        }
        let local = local.expect("local leader was checked");
        let exchange = self
            .state
            .droplets()
            .validate_transaction(&tx, signing_hash, local)
            .await?;
        self.state
            .droplets()
            .lock_exchange(&exchange, block_height, &tx)
            .await?;

        let request = ExchangeRewards {
            tx: tx.clone(),
            final_tx: None,
            signing_hash,
            signing_storm_tree_branch: [0; 32],
            block_height,
        };
        match self
            .state
            .signing()
            .sign_exchange_rewards(&self.storm, tx, signing_hash, block_height)
            .await
        {
            Ok(signing) => {
                let proof = self
                    .state
                    .signing()
                    .storm_tree_proof(&signing.signing_storm_tree_branch)
                    .await?;
                let request = ExchangeRewards {
                    signing_storm_tree_branch: signing.signing_storm_tree_branch,
                    ..request
                };
                let (txid, final_tx) = self
                    .state
                    .droplets()
                    .finalize_and_broadcast(&request, signing, proof, &exchange)
                    .await?;
                let notification = ExchangeRewards {
                    final_tx: Some(final_tx),
                    ..request
                };
                if let Err(error) = self.announce_exchange(&notification).await {
                    tracing::warn!(%error, "failed to announce broadcast Droplets exchange");
                }

                Ok(txid)
            }
            Err(error) => {
                self.state
                    .droplets()
                    .unlock_exchange(exchange.member, block_height)
                    .await?;
                Err(error.into())
            }
        }
    }

    pub async fn process_droplet_exchange_request(
        &self,
    ) -> Result<Option<[u8; 32]>, DropletsError> {
        let peers = self.peers().await;
        if !leader::is_local_leader(&peers, self.state.block_height()) {
            return Ok(None);
        }
        let Some(local) = leader::local_public_key(&peers) else {
            return Ok(None);
        };
        let member = PublicKey::from_slice(&local)
            .map_err(|_| DropletsError::Invalid("invalid local public key".into()))?
            .x_only_public_key()
            .0
            .serialize();
        let Some(request) = self.state.droplets().state(member).await?.1 else {
            return Ok(None);
        };
        if request.status != "pending" {
            return Ok(None);
        }

        match self
            .exchange_droplets(
                request.transaction.clone(),
                request.signing_hash,
                self.state.block_height(),
            )
            .await
        {
            Ok(txid) => {
                self.state
                    .droplets()
                    .complete_request(&request, txid)
                    .await?;
                Ok(Some(txid))
            }
            Err(error) if error.is_retryable() => Err(error),
            Err(error) => {
                self.state
                    .droplets()
                    .fail_request(&request, &error.to_string())
                    .await?;
                Err(error)
            }
        }
    }

    async fn announce_exchange(&self, notification: &ExchangeRewards) -> Result<(), SigningError> {
        let recipients = self
            .peers()
            .await
            .into_iter()
            .filter(|peer| peer.status == PeerStatus::Active)
            .map(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key).map_err(|_| {
                    SigningError::InvalidMessage("invalid exchange notification recipient".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if recipients.is_empty() {
            return Ok(());
        }
        let message = NodeMessage::new(NodeMessageKind::ExchangeRewards, None, notification)?
            .into_storm_message()?;
        self.storm.send_message(message, &recipients).await?;

        Ok(())
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
            self.state
                .indexer()
                .recover_droplet_exchanges(cursor.height, self.is_leader().await)
                .await?;
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
        let initial_members = self
            .peers()
            .await
            .into_iter()
            .map(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key)
                    .expect("Storm peers contain validated public keys")
                    .x_only_public_key()
                    .0
                    .serialize()
            })
            .collect();
        self.state
            .assets()
            .initialize_storm_eye(
                &self.storm.handle(),
                config,
                storm_tree_root,
                initial_members,
            )
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

    pub async fn process_user_requests(
        &self,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<usize, user_requests::UserRequestError> {
        if !self.is_coordinator().await {
            return Ok(0);
        }

        let prepared = match self
            .state
            .user_requests()
            .prepare_round(storm_eye_lane, max_transaction_weight)
            .await?
        {
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

    pub async fn burn_expired_utxos(
        &self,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<usize, BurningError> {
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

        let prepared = match self
            .state
            .burning()
            .prepare_round(block_height, storm_eye_lane, max_transaction_weight)
            .await?
        {
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

    pub async fn storm_eye_utxo_count(&self) -> Result<usize, user_requests::UserRequestError> {
        self.state.user_requests().storm_eye_utxo_count().await
    }

    pub async fn reconcile_voting_executions(&self) -> Result<usize, VotingExecutionError> {
        self.handle().reconcile_voting_executions().await
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

    pub(crate) async fn current_leader(&self) -> Option<[u8; 33]> {
        leader::leader_for_height(&self.peers().await, self.state.block_height())
    }

    pub(crate) async fn next_local_leader_height(&self) -> Option<u64> {
        leader::next_local_leader_height(&self.peers().await, self.state.block_height())
    }

    pub(crate) async fn droplet_state(
        &self,
    ) -> Result<
        (
            Option<crate::db::droplet::DropletBalance>,
            Option<crate::db::droplet::DropletExchangeRequest>,
        ),
        DropletsError,
    > {
        let local = leader::local_public_key(&self.peers().await)
            .ok_or_else(|| DropletsError::Invalid("local network member is missing".into()))?;
        let member = PublicKey::from_slice(&local)
            .map_err(|_| DropletsError::Invalid("invalid local public key".into()))?
            .x_only_public_key()
            .0
            .serialize();
        self.state.droplets().state(member).await
    }

    pub(crate) async fn droplet_history(
        &self,
    ) -> Result<Vec<crate::db::droplet::DropletExchangeRequest>, DropletsError> {
        let local = leader::local_public_key(&self.peers().await)
            .ok_or_else(|| DropletsError::Invalid("local network member is missing".into()))?;
        let member = PublicKey::from_slice(&local)
            .map_err(|_| DropletsError::Invalid("invalid local public key".into()))?
            .x_only_public_key()
            .0
            .serialize();
        self.state.droplets().history(member).await
    }

    pub(crate) fn droplet_exchange_fee_sats(&self) -> u64 {
        self.state.droplets().transaction_fee_sats()
    }

    pub(crate) async fn queue_droplet_exchange(
        &self,
        amount: u64,
        destination: &str,
    ) -> Result<crate::db::droplet::DropletExchangeRequest, DropletsError> {
        let local = leader::local_public_key(&self.peers().await)
            .ok_or_else(|| DropletsError::Invalid("local network member is missing".into()))?;
        self.state
            .droplets()
            .prepare_and_queue_exchange(amount, destination, local, self.state.block_height())
            .await
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

    pub async fn execute_voting_request(
        &self,
        request_hash: [u8; 32],
    ) -> Result<[u8; 32], VotingExecutionError> {
        self.spawn_voting_execution(request_hash)?
            .await
            .map_err(|error| {
                VotingExecutionError::Invalid(format!("voting execution task failed: {error}"))
            })?
    }

    fn spawn_voting_execution(
        &self,
        request_hash: [u8; 32],
    ) -> Result<tokio::task::JoinHandle<Result<[u8; 32], VotingExecutionError>>, VotingExecutionError>
    {
        let attempt = self
            .state
            .begin_voting_execution(request_hash)
            .ok_or(VotingExecutionError::AlreadyExecuting)?;
        let handle = self.clone();
        Ok(tokio::spawn(async move {
            let _attempt = attempt;
            let result = handle.execute_voting_request_inner(request_hash).await;
            if let Err(error) = &result {
                tracing::warn!(request_hash = %hex::encode(request_hash), %error, "voting execution attempt failed");
            }
            result
        }))
    }

    async fn execute_voting_request_inner(
        &self,
        request_hash: [u8; 32],
    ) -> Result<[u8; 32], VotingExecutionError> {
        let peers = self.peers().await;
        let current_members = voting_member_keys(&peers)?;
        let vote = self
            .state
            .voting()
            .get(request_hash)
            .await
            .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
            .ok_or_else(|| VotingExecutionError::UnknownRequest(hex::encode(request_hash)))?;
        if let Some(target_members) = member_migration_target(&vote.request, &current_members)? {
            self.state
                .ensure_member_migration(&self.storm, request_hash, target_members)
                .await
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
            if !self.storm.member_migration_ready().await {
                return Err(VotingExecutionError::MemberMigrationNotReady);
            }
        }
        let request = self
            .state
            .voting_execution()
            .prepare(request_hash, &current_members)
            .await?;
        let proposer = request.proposer_public_key;
        let local = leader::local_public_key(&self.peers().await).ok_or_else(|| {
            VotingExecutionError::Invalid("local network member is missing".into())
        })?;
        let local = PublicKey::from_slice(&local)
            .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
            .x_only_public_key()
            .0
            .serialize();
        if local != proposer {
            return Err(VotingExecutionError::Invalid(
                "only the node that proposed a voting request may execute it".into(),
            ));
        }

        self.state
            .voting_execution()
            .begin(
                request_hash,
                &request,
                self.state.block_height(),
                &current_members,
            )
            .await?;
        let signing = match self
            .state
            .signing()
            .sign_execute_voting_request(
                &self.storm,
                request_hash,
                request.tx.clone(),
                request.signing_hashes.clone(),
                proposer,
            )
            .await
        {
            Ok(signing) => signing,
            Err(error) => return Err(error.into()),
        };
        let proof = match self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await
        {
            Ok(proof) => proof,
            Err(error) => return Err(error.into()),
        };
        let prepared = match self
            .state
            .voting_execution()
            .prepare_finalization(request_hash, &request, &current_members)
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                let message = error.to_string();
                return Err(VotingExecutionError::Invalid(message));
            }
        };
        let (txid, notification) = match self
            .state
            .voting_execution()
            .finalize(prepared, signing, proof)
        {
            Ok(finalized) => finalized,
            Err(error) => {
                let message = error.to_string();
                drop(error);
                return Err(VotingExecutionError::Invalid(message));
            }
        };
        self.state
            .voting_execution()
            .record_broadcast(request_hash, txid, &notification)
            .await?;
        self.state
            .voting_execution()
            .broadcast(txid, &notification)?;
        if let Err(error) = self
            .announce_voting_execution(request_hash, &notification)
            .await
        {
            tracing::warn!(%error, "failed to announce executed voting request");
        }
        Ok(txid)
    }

    async fn activate_member_migration(
        &self,
        request_hash: [u8; 32],
        txid: [u8; 32],
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<(), VotingExecutionError> {
        activate_member_migration_state(
            &self.state,
            &self.storm,
            request_hash,
            txid,
            current_members,
        )
        .await
    }

    pub async fn reconcile_voting_executions(&self) -> Result<usize, VotingExecutionError> {
        let mut confirmed = 0;
        if let Some(request_hash) = self.state.member_migration_request().await
            && self
                .state
                .voting()
                .get(request_hash)
                .await
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
                .is_some_and(|request| request.status == VotingStatus::Executed)
        {
            finish_member_migration_state(&self.state, &self.storm).await?;
        }

        for (request_hash, txid, request) in
            self.state.voting_execution().pending_broadcasts().await?
        {
            self.state.voting_execution().broadcast(txid, &request)?;
            if let Err(error) = self.announce_voting_execution(request_hash, &request).await {
                tracing::warn!(%error, "failed to reannounce voting execution");
            }
            if !self.state.voting_execution().is_confirmed(txid)? {
                continue;
            }

            let current_members = voting_member_keys(&self.peers().await)?;
            let vote = self
                .state
                .voting()
                .get(request_hash)
                .await
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
                .ok_or_else(|| VotingExecutionError::UnknownRequest(hex::encode(request_hash)))?;
            if member_migration_target(&vote.request, &current_members)?.is_some() {
                self.activate_member_migration(request_hash, txid, &current_members)
                    .await?;
            } else {
                self.state
                    .voting_execution()
                    .confirm(request_hash, txid)
                    .await?;
            }
            confirmed += 1;
        }

        let local = leader::local_public_key(&self.peers().await)
            .and_then(|key| PublicKey::from_slice(&key).ok())
            .map(|key| key.x_only_public_key().0.serialize());
        for (request_hash, proposer) in self.state.voting_execution().unfinished_attempts().await? {
            if Some(proposer) != local {
                continue;
            }
            match self.spawn_voting_execution(request_hash) {
                Ok(task) => drop(task),
                Err(VotingExecutionError::AlreadyExecuting) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(confirmed)
    }

    async fn announce_voting_execution(
        &self,
        request_hash: [u8; 32],
        notification: &ExecuteVotingRequest,
    ) -> Result<(), SigningError> {
        let recipients = self
            .peers()
            .await
            .into_iter()
            .filter(|peer| peer.status == PeerStatus::Active)
            .map(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key).map_err(|_| {
                    SigningError::InvalidMessage("invalid voting notification recipient".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if recipients.is_empty() {
            return Ok(());
        }
        let message = NodeMessage::new(
            NodeMessageKind::ExecuteVotingRequest,
            Some(request_hash),
            notification,
        )?
        .into_storm_message()?;
        self.storm.send_message(message, &recipients).await?;
        Ok(())
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

    pub async fn storm_eye_utxos(
        &self,
    ) -> Result<Vec<StormEyeInventoryItem>, VotingExecutionError> {
        self.state
            .voting_execution()
            .storm_eye_utxos(self.state.block_height())
            .await
    }

    pub async fn network_asset(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().get(kind).await
    }
}

fn voting_member_keys(peers: &[storm::Peer]) -> Result<BTreeSet<[u8; 32]>, VotingExecutionError> {
    peers
        .iter()
        .map(|peer| {
            PublicKey::from_slice(&peer.compressed_public_key)
                .map(|key| key.x_only_public_key().0.serialize())
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))
        })
        .collect()
}

fn member_migration_target(
    request: &NetworkVoteRequest,
    current_members: &BTreeSet<[u8; 32]>,
) -> Result<Option<BTreeSet<[u8; 32]>>, VotingExecutionError> {
    if NetworkVoteKind::from_id(request.kind) != Some(NetworkVoteKind::UpdateNetworkMembers) {
        return Ok(None);
    }

    let update: UpdateNetworkMembers = postcard::from_bytes(&request.payload)?;
    let mut target = current_members.clone();
    for member in update.to_remove {
        target.remove(&member);
    }
    target.extend(update.to_accept);
    Ok(Some(target))
}

async fn activate_member_migration_state(
    state: &NetworkState,
    storm: &StormHandle,
    request_hash: [u8; 32],
    txid: [u8; 32],
    current_members: &BTreeSet<[u8; 32]>,
) -> Result<(), VotingExecutionError> {
    let _voting_guard = state.voting().lock_operations().await;
    let Some(asset) = state
        .voting_execution()
        .member_migration_asset(request_hash, current_members)
        .await?
    else {
        return Ok(());
    };
    let peers = storm
        .member_migration_peers()
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    let contract_data = asset.contract_data.as_deref().ok_or_else(|| {
        VotingExecutionError::Invalid("migrated Storm Eye contract data is missing".into())
    })?;
    state
        .network_store()
        .apply_member_migration(
            &peers,
            state.coordinator_public_key(),
            &asset.kind,
            &asset.contract_script,
            contract_data,
            crate::db::network::ConfirmedVotingExecution { request_hash, txid },
        )
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    finish_member_migration_state(state, storm).await
}

async fn finish_member_migration_state(
    state: &NetworkState,
    storm: &StormHandle,
) -> Result<(), VotingExecutionError> {
    let peers = storm
        .member_migration_peers()
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    state.signing().refresh_members(&peers).await?;
    storm
        .activate_member_migration()
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    state.complete_member_migration().await;

    if let Err(error) = state.assets().announce_pending(storm).await {
        tracing::warn!(%error, "failed to announce migrated network assets");
    }
    Ok(())
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
