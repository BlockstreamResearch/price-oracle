use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use secp256k1_zkp::PublicKey;
#[cfg(test)]
use secp256k1_zkp::Secp256k1;

use crate::{
    MessageContext, Peer, PeerStatus, StormHandle, StormMessage, StormState,
    message::StormErrorCode, message_handlers::StormMessagePayloadType,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PeerSocketInfo {
    compressed_public_key: Vec<u8>,
    socket_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedPeerSocketInfo {
    compressed_public_key: [u8; 33],
    socket_address: String,
}

pub(crate) fn message(peers: &[Peer]) -> Result<StormMessage, (StormErrorCode, String)> {
    let peers_socket_info = peers
        .iter()
        .map(|peer| {
            let socket_address = peer.socket_address.clone().ok_or_else(|| {
                (
                    StormErrorCode::Busy,
                    format!(
                        "Socket address is unknown for peer {}",
                        hex::encode(peer.compressed_public_key)
                    ),
                )
            })?;

            Ok(PeerSocketInfo {
                compressed_public_key: peer.compressed_public_key.to_vec(),
                socket_address,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let payload = postcard::to_stdvec(&peers_socket_info).map_err(|error| {
        (
            StormErrorCode::InternalError,
            format!("Failed to serialize PeersSocketInfo: {error}"),
        )
    })?;

    Ok(StormMessage::new(
        StormMessagePayloadType::PeersSocketInfo,
        payload,
    ))
}

pub(super) async fn handle(
    storm: &StormHandle,
    context: MessageContext,
    message: StormMessage,
) -> Result<(), (StormErrorCode, String)> {
    let peers_socket_info: Vec<PeerSocketInfo> = match postcard::from_bytes(&message.payload) {
        Ok(info) => info,
        Err(_) => {
            return Err((
                StormErrorCode::InvalidPayload,
                "Failed to deserialize PeersSocketInfo".to_string(),
            ));
        }
    };

    let peers_socket_info = validate(peers_socket_info)?;

    let changed = {
        let mut state = storm.inner.write().await;
        let received_members = peers_socket_info
            .iter()
            .map(|info| StormState::x_only_public_key(&info.compressed_public_key))
            .collect::<std::collections::BTreeSet<_>>();
        if state
            .migration_members
            .as_ref()
            .is_some_and(|members| members == &received_members)
        {
            require_peer_table_authority(&state, context.peer_public_key)?;
            replace_migration_peers(&mut state, peers_socket_info);
            drop(state);
            storm.connect_migration_peers().await;
            return Ok(());
        }

        let sender = state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == context.peer_public_key)
            .expect("authenticated peer must remain in the peer table");

        let sender_is_discovery = sender.discovery;
        if sender_is_discovery {
            replace_discovered_peers(&mut state, peers_socket_info, context.peer_public_key)?;
            true
        } else if state.migration_members.is_none()
            && state.peer_table_authority == Some(context.peer_public_key)
            && cache_migration_peer_hints(&mut state, &peers_socket_info, context.peer_public_key)?
        {
            false
        } else {
            validate_known_peer_keys(&state, &peers_socket_info)?;
            false
        }
    };

    if changed {
        storm.connect_known_peers().await;
    }

    Ok(())
}

fn require_peer_table_authority(
    state: &StormState,
    sender_public_key: [u8; 33],
) -> Result<(), (StormErrorCode, String)> {
    if state.peer_table_authority != Some(sender_public_key) {
        return Err((
            StormErrorCode::Unauthorized,
            "Migration PeersSocketInfo must be sent by the configured authority".to_string(),
        ));
    }

    Ok(())
}

fn cache_migration_peer_hints(
    state: &mut StormState,
    peers_socket_info: &[ValidatedPeerSocketInfo],
    sender_public_key: [u8; 33],
) -> Result<bool, (StormErrorCode, String)> {
    let received_keys = peers_socket_info
        .iter()
        .map(|info| info.compressed_public_key)
        .collect::<HashSet<_>>();
    let active_keys = state
        .peers
        .iter()
        .map(|peer| peer.compressed_public_key)
        .collect::<HashSet<_>>();
    if received_keys == active_keys {
        return Ok(false);
    }
    if !received_keys.contains(&sender_public_key) {
        return Err((
            StormErrorCode::InvalidPayload,
            "Migration PeersSocketInfo must contain the sending peer".to_string(),
        ));
    }

    replace_migration_peers(state, peers_socket_info.to_vec());
    Ok(true)
}

fn replace_migration_peers(
    state: &mut StormState,
    peers_socket_info: Vec<ValidatedPeerSocketInfo>,
) {
    let local_public_key = state.initializer_public_key;
    let mut existing = std::mem::take(&mut state.migration_peers)
        .into_iter()
        .map(|peer| (peer.compressed_public_key, peer))
        .collect::<HashMap<_, _>>();
    state.migration_peers = peers_socket_info
        .into_iter()
        .map(|info| {
            let mut peer = existing
                .remove(&info.compressed_public_key)
                .unwrap_or_else(|| Peer::new(info.compressed_public_key));
            peer.socket_address = Some(info.socket_address);
            if peer.compressed_public_key == local_public_key {
                peer.status = PeerStatus::Controlled;
            } else if state.connections.contains_key(&peer.compressed_public_key) {
                peer.status = PeerStatus::Active;
            } else if peer.status != PeerStatus::Banned {
                peer.status = PeerStatus::Inactive;
            }
            peer.discovery = false;
            peer
        })
        .collect();
    state.apply_address_overrides();
}

fn validate_known_peer_keys(
    state: &StormState,
    peers_socket_info: &[ValidatedPeerSocketInfo],
) -> Result<(), (StormErrorCode, String)> {
    let received_keys = peers_socket_info
        .iter()
        .map(|info| info.compressed_public_key)
        .collect::<HashSet<_>>();
    let local_keys = state
        .peers
        .iter()
        .map(|peer| peer.compressed_public_key)
        .collect::<HashSet<_>>();

    if received_keys != local_keys {
        return Err((
            StormErrorCode::InvalidPayload,
            "PeersSocketInfo public keys do not match the local peer table".to_string(),
        ));
    }

    Ok(())
}

fn validate(
    peers_socket_info: Vec<PeerSocketInfo>,
) -> Result<Vec<ValidatedPeerSocketInfo>, (StormErrorCode, String)> {
    if peers_socket_info.is_empty() {
        return Err((
            StormErrorCode::InvalidPayload,
            "PeersSocketInfo cannot be empty".to_string(),
        ));
    }

    let mut identities = HashSet::with_capacity(peers_socket_info.len());
    let mut validated = Vec::with_capacity(peers_socket_info.len());
    for info in peers_socket_info {
        let public_key = PublicKey::from_slice(&info.compressed_public_key).map_err(|_| {
            (
                StormErrorCode::InvalidPayload,
                "PeersSocketInfo contains an invalid public key".to_string(),
            )
        })?;
        crate::peer::socket_address_port(&info.socket_address).ok_or_else(|| {
            (
                StormErrorCode::InvalidPayload,
                format!("Invalid peer socket address: {}", info.socket_address),
            )
        })?;

        let compressed_public_key = public_key.serialize();
        if !identities.insert(StormState::canonical_identity_key(&compressed_public_key)) {
            return Err((
                StormErrorCode::InvalidPayload,
                "PeersSocketInfo contains duplicate x-only public keys".to_string(),
            ));
        }

        validated.push(ValidatedPeerSocketInfo {
            compressed_public_key,
            socket_address: info.socket_address,
        });
    }

    Ok(validated)
}

fn replace_discovered_peers(
    state: &mut StormState,
    peers_socket_info: Vec<ValidatedPeerSocketInfo>,
    discovery_peer_public_key: [u8; 33],
) -> Result<(), (StormErrorCode, String)> {
    let local_public_key = state.initializer_public_key;
    let received_keys = peers_socket_info
        .iter()
        .map(|info| info.compressed_public_key)
        .collect::<HashSet<_>>();

    if !received_keys.contains(&local_public_key)
        || !received_keys.contains(&discovery_peer_public_key)
    {
        return Err((
            StormErrorCode::InvalidPayload,
            "Discovery PeersSocketInfo must contain both local and discovery peers".to_string(),
        ));
    }

    let banned_keys = state
        .peers
        .iter()
        .filter(|peer| peer.status == PeerStatus::Banned)
        .map(|peer| peer.compressed_public_key)
        .collect::<HashSet<_>>();
    state.connections.retain(|public_key, _| {
        received_keys.contains(public_key) && !banned_keys.contains(public_key)
    });

    let mut existing = std::mem::take(&mut state.peers)
        .into_iter()
        .map(|peer| (peer.compressed_public_key, peer))
        .collect::<HashMap<_, _>>();
    state.peers = peers_socket_info
        .into_iter()
        .map(|info| {
            let mut peer = existing
                .remove(&info.compressed_public_key)
                .unwrap_or_else(|| Peer::new(info.compressed_public_key));
            if peer.compressed_public_key != discovery_peer_public_key
                || peer.socket_address.is_none()
            {
                peer.socket_address = Some(info.socket_address);
            }
            if state.connections.contains_key(&peer.compressed_public_key)
                && peer.compressed_public_key != local_public_key
                && peer.status != PeerStatus::Banned
            {
                peer.status = PeerStatus::Active;
            }
            peer
        })
        .collect();
    state.apply_address_overrides();
    state.discovery_table_received = true;

    Ok(())
}

#[cfg(test)]
mod tests;
