use std::{
    ops::{Deref, DerefMut},
    time::Duration,
};

use storm::{Storm, StormHandle};
use storm_tree::NodePublicKey;

mod handler;
mod message;
mod signing;
mod state;
mod voting;

pub use message::{
    ApproveVotingRequest, MergeStormEyes, NetworkVoteKind, NetworkVoteRequest, NodeMessage,
    NodeMessageKind, SplitStormEye, StormEyeUtxo, TestNodeMessage, UpdateNetworkMembers,
};
pub use signing::{SigningError, SigningResult};
use state::NetworkState;
pub use voting::{VOTING_TIMEOUT_BLOCKS, VotingApproval, VotingError, VotingRequest, VotingStatus};

/// A long-lived Oracle Network node and its higher-level protocol state.
pub struct HighStorm {
    storm: Storm,
    state: NetworkState,
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
        voting_store: crate::db::voting::VotingStore,
    ) -> Self {
        let state =
            NetworkState::new(&storm, secret_key, coordinator_public_key, voting_store).await;
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

    /// Signs one or more dummy message hashes using an active Storm Tree branch.
    pub async fn sign_test(
        &self,
        message_hashes: Vec<[u8; 32]>,
    ) -> Result<SigningResult, SigningError> {
        self.state
            .signing()
            .sign_test(&self.storm, message_hashes)
            .await
    }

    /// Runs a temporary signing request with controls used by disconnect tests.
    pub async fn sign_test_with_delay(
        &self,
        message_hashes: Vec<[u8; 32]>,
        attempt_timeout: Duration,
        delayed_signer: NodePublicKey,
        delay: Duration,
    ) -> Result<SigningResult, SigningError> {
        self.state
            .signing()
            .sign_test_with_delay(
                &self.storm,
                message_hashes,
                attempt_timeout,
                delayed_signer,
                delay,
            )
            .await
    }

    /// Returns the signer subset HighStorm would currently choose.
    pub async fn selected_signers(&self) -> Result<Vec<NodePublicKey>, SigningError> {
        self.state.signing().selected_signers(&self.storm).await
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
