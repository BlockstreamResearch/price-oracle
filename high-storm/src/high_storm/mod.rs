use std::{
    collections::BTreeSet,
    ops::{Deref, DerefMut},
};

use secp256k1_zkp::PublicKey;
use storm::{PeerStatus, Storm, StormHandle};

use crate::monitoring::{self, RenewalOutcome};

mod assets;
mod burning;
mod droplets;
pub(crate) mod elements;
mod handler;
mod indexer;
mod issuance;
mod leader;
mod message;
mod node;
mod prices;
mod renewal;
mod signing;
mod state;
mod user_requests;
mod utxo;
mod voting;
mod voting_execution;

pub use assets::AssetError;
pub(crate) use assets::{StormEyeContractData, storm_eye_contract_data};
pub use burning::BurningError;
pub use droplets::DropletsError;
pub(crate) use droplets::exchange_recipient_amount;
pub use indexer::IndexerError;
pub use message::{
    ApproveVotingRequest, AttestPriceMsg, BurnExpiredUtxos, ChainTip, ExchangeRewards,
    ExecuteUserRequests, ExecuteVotingRequest, ExpiredUtxosBurned, ExternalRequests,
    MergeStormEyes, NetworkAsset, NetworkAssets, NetworkVoteKind, NetworkVoteRequest, NodeMessage,
    NodeMessageKind, PriceAttestation, RenewStormUtxos, SplitStormEye, StormEyeUtxo,
    UpdateNetworkMembers,
};
pub use prices::{
    ExchangeRateInfo, FeedRate, FeedSources, PollOutcome, PriceError, PriceSourceError,
    PriceSourceInfo,
};
pub(crate) use prices::{PriceHealth, SourceHealth};
pub use renewal::RenewalError;
pub use signing::{SigningError, SigningResult};
use state::NetworkState;
pub(crate) use user_requests::MAX_UNPRICED_REQUEST_BLOCKS;
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
    chain: crate::db::chain::ChainStore,
    voting_store: crate::db::voting::VotingStore,
    network_assets: crate::db::network_asset::NetworkAssetStore,
    monitored_utxos: crate::db::monitored_utxo::MonitoredUtxoStore,
    droplets: crate::db::droplet::DropletStore,
    user_requests: crate::db::user_request::UserRequestStore,
    price_attestations: crate::db::price_attestation::PriceAttestationStore,
    elements_rpc: crate::config::ElementsRpcConfig,
    protocol_config: crate::config::ProtocolConfig,
}

impl HighStormDependencies {
    pub(crate) fn new(
        network_store: crate::db::network::NetworkStore,
        elements_rpc: crate::config::ElementsRpcConfig,
        protocol_config: crate::config::ProtocolConfig,
    ) -> Self {
        Self {
            chain: network_store.chain(),
            voting_store: network_store.voting(),
            network_assets: network_store.network_assets(),
            monitored_utxos: network_store.monitored_utxos(),
            droplets: network_store.droplets(),
            user_requests: network_store.user_requests(),
            price_attestations: network_store.price_attestations(),
            network_store,
            elements_rpc,
            protocol_config,
        }
    }

    /// The protocol the node is given, for what else a test builds beside it.
    #[cfg(test)]
    pub(crate) fn protocol_config(&self) -> &crate::config::ProtocolConfig {
        &self.protocol_config
    }

    /// The stores of `database`, with an Elements node nothing listens on.
    #[cfg(test)]
    pub(crate) fn for_tests(database: &crate::db::Database) -> Self {
        Self::new(
            database.network(),
            crate::config::ElementsRpcConfig {
                url: "http://127.0.0.1:18884".to_string(),
                username: "unused".to_string(),
                password: "unused".to_string(),
                wallet: "unused".to_string(),
            },
            crate::config::ProtocolConfig {
                operational_fee_sats: 1_000,
                tick_burn_reserve_sats: 1_000,
                issuance_transaction_fee_sats: 1_000,
                burn_transaction_fee_sats: 500,
                exchange_transaction_fee_sats: 500,
                tick_lifetime_blocks: 60,
                finality_confirmations: 2,
            },
        )
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

    pub fn is_recovering(&self) -> bool {
        self.state.is_recovering()
    }

    fn is_transaction_production_blocked(&self) -> bool {
        self.is_recovering() || self.state.is_spending_paused()
    }

    pub fn set_block_height(&self, block_height: u64) {
        self.state.set_block_height(block_height);
    }

    pub async fn index_blocks(&self) -> Result<u64, IndexerError> {
        // Any other error says nothing about a halt, which is checked only once
        // the chain tip has been read.
        let indexed = match self.state.indexer().sync().await {
            Ok(indexed) => {
                monitoring::set_chain_safety_halt(false);
                indexed
            }
            Err(error) => {
                if matches!(error, IndexerError::SafetyHalt(_)) {
                    monitoring::set_chain_safety_halt(true);
                }
                return Err(error);
            }
        };
        if let Some(cursor) = self.state.indexer().cursor().await? {
            self.state.set_block_height(cursor.height);
            if !self.state.is_spending_paused()
                && let Err(error) = self
                    .state
                    .indexer()
                    .recover_droplet_exchanges(cursor.height, self.is_leader().await)
                    .await
            {
                // Indexing succeeded; a failed Droplets recovery must not halt burning.
                tracing::warn!(%error, "Droplets exchange recovery failed");
            }
        }
        Ok(indexed)
    }
}

impl HighStormHandle {
    fn is_transaction_production_blocked(&self) -> bool {
        self.state.is_recovering() || self.state.is_spending_paused()
    }

    pub fn is_spending_paused(&self) -> bool {
        self.state.is_spending_paused()
    }

    pub(crate) fn is_recovering(&self) -> bool {
        self.state.is_recovering()
    }

    pub fn coordinator_public_key(&self) -> [u8; 33] {
        self.state.coordinator_public_key()
    }

    pub fn block_height(&self) -> u64 {
        self.state.block_height()
    }

    pub async fn peers(&self) -> Vec<storm::Peer> {
        self.storm.peers().await
    }

    pub(crate) async fn connected_peer_keys(&self) -> BTreeSet<[u8; 33]> {
        self.storm.connected_peer_keys().await
    }

    pub(crate) async fn is_local_member(&self) -> bool {
        self.storm.is_local_member().await
    }

    pub(crate) async fn current_leader(&self) -> Option<[u8; 33]> {
        leader::leader_for_height(&self.peers().await, self.state.block_height())
    }

    pub(crate) async fn is_leader(&self) -> bool {
        leader::is_local_leader(&self.peers().await, self.state.block_height())
    }

    pub(crate) async fn next_local_leader_height(&self) -> Option<u64> {
        leader::next_local_leader_height(&self.peers().await, self.state.block_height())
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
}

/// A round that had nothing to do is not counted.
fn round_outcome<E>(result: &Result<usize, E>) -> Option<&'static str> {
    match result {
        Ok(0) => None,
        Ok(_) => Some("broadcast"),
        Err(_) => Some("failed"),
    }
}

/// Sends `payload` as a `kind` message to every active peer of `storm`, if there
/// is any; `invalid_recipient` is the error for a peer whose key does not parse.
async fn announce<T: serde::Serialize>(
    storm: &StormHandle,
    kind: NodeMessageKind,
    linked_to: Option<[u8; 32]>,
    payload: &T,
    invalid_recipient: &str,
) -> Result<(), SigningError> {
    let recipients = storm
        .peers()
        .await
        .into_iter()
        .filter(|peer| peer.status == PeerStatus::Active)
        .map(|peer| {
            PublicKey::from_slice(&peer.compressed_public_key)
                .map_err(|_| SigningError::InvalidMessage(invalid_recipient.into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if recipients.is_empty() {
        return Ok(());
    }
    let message = NodeMessage::new(kind, linked_to, payload)?.into_storm_message()?;
    storm.send_message(message, &recipients).await?;

    Ok(())
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

#[cfg(test)]
pub(crate) mod test_rpc;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_rounds_that_had_work() {
        assert_eq!(round_outcome::<()>(&Ok(0)), None);
        assert_eq!(round_outcome::<()>(&Ok(2)), Some("broadcast"));
        assert_eq!(round_outcome(&Err(())), Some("failed"));
    }
}
