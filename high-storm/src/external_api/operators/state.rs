use axum::{Json, extract::State, http::HeaderMap};
use secp256k1::PublicKey;
use serde::Serialize;
use storm::PeerStatus;

use super::auth::authenticate_bearer;
use crate::{
    VotingStatus,
    external_api::{ApiError, ExternalApiState},
};

#[derive(Serialize)]
pub(super) struct NetworkStateResponse {
    block_height: u64,
    local_public_key: String,
    coordinator_public_key: String,
    is_coordinator: bool,
    total_peers: usize,
    online_peers: usize,
    inactive_peers: usize,
    banned_peers: usize,
    pending_votings: usize,
    approved_votings: usize,
}

#[derive(Serialize)]
pub(super) struct NetworkPeerResponse {
    public_key: String,
    socket_address: Option<String>,
    last_seen: Option<u64>,
    status: &'static str,
    is_local: bool,
    is_coordinator: bool,
    is_leader: bool,
}

pub(super) async fn get_network_state(
    State(state): State<ExternalApiState>,
    headers: HeaderMap,
) -> Result<Json<NetworkStateResponse>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    let peers = state.node.peers().await;
    let votings = state.node.voting_requests().await?;
    let coordinator_public_key = state.node.coordinator_public_key();
    let local_public_key = peers
        .iter()
        .find(|peer| peer.status == PeerStatus::Controlled)
        .map(|peer| peer.compressed_public_key)
        .ok_or_else(|| ApiError::internal("local peer is missing from the peer table"))?;
    let online_peers = peers
        .iter()
        .filter(|peer| matches!(peer.status, PeerStatus::Controlled | PeerStatus::Active))
        .count();
    let pending_votings = votings
        .iter()
        .filter(|voting| voting.status == VotingStatus::Pending)
        .count();

    Ok(Json(NetworkStateResponse {
        block_height: state.node.block_height(),
        local_public_key: xonly_public_key(local_public_key)?,
        coordinator_public_key: xonly_public_key(coordinator_public_key)?,
        is_coordinator: local_public_key == coordinator_public_key,
        total_peers: peers.len(),
        online_peers,
        inactive_peers: peers
            .iter()
            .filter(|peer| peer.status == PeerStatus::Inactive)
            .count(),
        banned_peers: peers
            .iter()
            .filter(|peer| peer.status == PeerStatus::Banned)
            .count(),
        pending_votings,
        approved_votings: votings.len() - pending_votings,
    }))
}

pub(super) async fn get_network_peers(
    State(state): State<ExternalApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NetworkPeerResponse>>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    let coordinator_public_key = state.node.coordinator_public_key();
    let current_leader = state.node.current_leader().await;
    let peers = state
        .node
        .peers()
        .await
        .into_iter()
        .map(|peer| {
            Ok(NetworkPeerResponse {
                public_key: xonly_public_key(peer.compressed_public_key)?,
                socket_address: peer.socket_address,
                last_seen: peer.last_seen,
                status: peer_status_name(peer.status),
                is_local: peer.status == PeerStatus::Controlled,
                is_coordinator: peer.compressed_public_key == coordinator_public_key,
                is_leader: Some(peer.compressed_public_key) == current_leader,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    Ok(Json(peers))
}

fn xonly_public_key(compressed: [u8; 33]) -> Result<String, ApiError> {
    PublicKey::from_slice(&compressed)
        .map(|key| hex::encode(key.x_only_public_key().0.serialize()))
        .map_err(|_| ApiError::internal("network contains an invalid secp256k1 public key"))
}

fn peer_status_name(status: PeerStatus) -> &'static str {
    match status {
        PeerStatus::Controlled => "controlled",
        PeerStatus::Active => "active",
        PeerStatus::Inactive => "inactive",
        PeerStatus::Banned => "banned",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_transport_keys_instead_of_serializing_them() {
        assert!(xonly_public_key([0; 33]).is_err());
    }
}
