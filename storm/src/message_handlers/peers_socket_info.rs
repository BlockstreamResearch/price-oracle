use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use secp256k1_zkp::PublicKey;
#[cfg(test)]
use secp256k1_zkp::Secp256k1;

use crate::{
    MessageContext, Peer, PeerStatus, StormHandle, StormMessage, StormMessageHeader, StormState,
    constants, message::StormErrorCode, message_handlers::StormMessagePayloadType,
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

    Ok(StormMessage {
        header: StormMessageHeader {
            payload_id: StormMessagePayloadType::PeersSocketInfo as u32,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload,
    })
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
        let sender = state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == context.peer_public_key)
            .expect("authenticated peer must remain in the peer table");

        let sender_is_discovery = sender.discovery;
        if sender_is_discovery {
            replace_discovered_peers(&mut state, peers_socket_info, context.peer_public_key)?;
            true
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

    let mut keys = HashSet::with_capacity(peers_socket_info.len());
    let mut validated = Vec::with_capacity(peers_socket_info.len());
    for info in peers_socket_info {
        let public_key = PublicKey::from_slice(&info.compressed_public_key).map_err(|_| {
            (
                StormErrorCode::InvalidPayload,
                "PeersSocketInfo contains an invalid public key".to_string(),
            )
        })?;
        info.socket_address.parse::<SocketAddr>().map_err(|_| {
            (
                StormErrorCode::InvalidPayload,
                format!("Invalid peer socket address: {}", info.socket_address),
            )
        })?;

        let compressed_public_key = public_key.serialize();
        if !keys.insert(compressed_public_key) {
            return Err((
                StormErrorCode::InvalidPayload,
                "PeersSocketInfo contains duplicate public keys".to_string(),
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
    state.discovery_table_received = true;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1_zkp::{SecretKey, rand};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn generated_peer() -> (SecretKey, Peer) {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = secret_key.public_key(&Secp256k1::new()).serialize();
        (secret_key, Peer::new(public_key))
    }

    fn socket_info(peer: &Peer, socket_address: &str) -> ValidatedPeerSocketInfo {
        ValidatedPeerSocketInfo {
            compressed_public_key: peer.compressed_public_key,
            socket_address: socket_address.to_string(),
        }
    }

    #[test]
    fn known_table_cannot_update_peer_addresses() {
        let (local_secret_key, mut local_peer) = generated_peer();
        local_peer.socket_address = Some("127.0.0.1:1000".to_string());
        let (_, mut active_peer) = generated_peer();
        active_peer.status = PeerStatus::Active;
        active_peer.socket_address = Some("127.0.0.1:2000".to_string());
        let (_, mut inactive_peer) = generated_peer();
        inactive_peer.socket_address = Some("127.0.0.1:3000".to_string());
        let state = StormState::new(
            local_secret_key,
            vec![
                local_peer.clone(),
                active_peer.clone(),
                inactive_peer.clone(),
            ],
        );

        validate_known_peer_keys(
            &state,
            &[
                socket_info(&local_peer, "127.0.0.1:1001"),
                socket_info(&active_peer, "127.0.0.1:2001"),
                socket_info(&inactive_peer, "127.0.0.1:3001"),
            ],
        )
        .unwrap();

        assert_eq!(state.peers[0].socket_address, local_peer.socket_address);
        assert_eq!(state.peers[1].socket_address, active_peer.socket_address);
        assert_eq!(state.peers[2].socket_address, inactive_peer.socket_address);
    }

    #[test]
    fn known_table_rejects_a_different_public_key_set() {
        let (local_secret_key, local_peer) = generated_peer();
        let (_, known_peer) = generated_peer();
        let (_, unknown_peer) = generated_peer();
        let state = StormState::new(local_secret_key, vec![local_peer.clone(), known_peer]);

        let error = validate_known_peer_keys(
            &state,
            &[
                socket_info(&local_peer, "127.0.0.1:1000"),
                socket_info(&unknown_peer, "127.0.0.1:2000"),
            ],
        )
        .unwrap_err();

        assert!(matches!(error.0, StormErrorCode::InvalidPayload));
    }

    #[test]
    fn discovery_table_adds_peers_and_preserves_active_state() {
        let (local_secret_key, local_peer) = generated_peer();
        let (_, mut discovery_peer) = generated_peer();
        discovery_peer.status = PeerStatus::Active;
        discovery_peer.discovery = true;
        discovery_peer.socket_address = Some("127.0.0.1:2000".to_string());
        let (_, retained_peer) = generated_peer();
        let (_, omitted_peer) = generated_peer();
        let mut state = StormState::new(
            local_secret_key,
            vec![local_peer.clone(), discovery_peer.clone()],
        );
        let (discovery_sender, _discovery_receiver) =
            tokio::sync::mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
        let (retained_sender, _retained_receiver) =
            tokio::sync::mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
        let (omitted_sender, mut omitted_receiver) =
            tokio::sync::mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
        state
            .connections
            .insert(discovery_peer.compressed_public_key, discovery_sender);
        state
            .connections
            .insert(retained_peer.compressed_public_key, retained_sender);
        state
            .connections
            .insert(omitted_peer.compressed_public_key, omitted_sender);

        replace_discovered_peers(
            &mut state,
            vec![
                socket_info(&local_peer, "127.0.0.1:1000"),
                socket_info(&discovery_peer, "0.0.0.0:2000"),
                socket_info(&retained_peer, "127.0.0.1:3000"),
            ],
            discovery_peer.compressed_public_key,
        )
        .unwrap();

        assert!(state.discovery_table_received);
        assert_eq!(state.peers.len(), 3);
        let preserved_discovery_peer = state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == discovery_peer.compressed_public_key)
            .unwrap();
        assert_eq!(preserved_discovery_peer.status, PeerStatus::Active);
        assert!(preserved_discovery_peer.discovery);
        assert_eq!(
            preserved_discovery_peer.socket_address.as_deref(),
            Some("127.0.0.1:2000")
        );
        let retained_peer = state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == retained_peer.compressed_public_key)
            .unwrap();
        assert_eq!(retained_peer.status, PeerStatus::Active);
        assert!(
            state
                .connections
                .contains_key(&retained_peer.compressed_public_key)
        );
        assert!(
            !state
                .connections
                .contains_key(&omitted_peer.compressed_public_key)
        );
        assert!(omitted_receiver.try_recv().is_err());
        assert!(omitted_receiver.is_closed());
    }

    #[test]
    fn discovery_table_preserves_ban_and_drops_stale_connection() {
        let (local_secret_key, local_peer) = generated_peer();
        let (_, mut discovery_peer) = generated_peer();
        discovery_peer.status = PeerStatus::Active;
        discovery_peer.discovery = true;
        let (_, mut banned_peer) = generated_peer();
        banned_peer.status = PeerStatus::Banned;
        let mut state = StormState::new(
            local_secret_key,
            vec![
                local_peer.clone(),
                discovery_peer.clone(),
                banned_peer.clone(),
            ],
        );
        let (banned_sender, banned_receiver) =
            tokio::sync::mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
        state
            .connections
            .insert(banned_peer.compressed_public_key, banned_sender);

        replace_discovered_peers(
            &mut state,
            vec![
                socket_info(&local_peer, "127.0.0.1:1000"),
                socket_info(&discovery_peer, "127.0.0.1:2000"),
                socket_info(&banned_peer, "127.0.0.1:3000"),
            ],
            discovery_peer.compressed_public_key,
        )
        .unwrap();

        let banned_peer = state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == banned_peer.compressed_public_key)
            .unwrap();
        assert_eq!(banned_peer.status, PeerStatus::Banned);
        assert!(
            !state
                .connections
                .contains_key(&banned_peer.compressed_public_key)
        );
        assert!(banned_receiver.is_closed());
    }

    #[tokio::test]
    async fn discovery_table_accepts_a_temporarily_unreachable_peer() {
        let secp = Secp256k1::new();
        let local_secret_key = SecretKey::from_slice(&[2; 32]).unwrap();
        let mut local_peer = Peer::new(local_secret_key.public_key(&secp).serialize());
        local_peer.status = PeerStatus::Controlled;
        local_peer.socket_address = Some("127.0.0.1:1000".to_string());

        let discovery_secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let mut discovery_peer = Peer::new(discovery_secret_key.public_key(&secp).serialize());
        discovery_peer.status = PeerStatus::Active;
        discovery_peer.discovery = true;
        discovery_peer.socket_address = Some("127.0.0.1:2000".to_string());

        let unavailable_secret_key = SecretKey::from_slice(&[3; 32]).unwrap();
        let mut unavailable_peer = Peer::new(unavailable_secret_key.public_key(&secp).serialize());
        unavailable_peer.socket_address = Some("127.0.0.1:0".to_string());

        let state = Arc::new(RwLock::new(StormState::new(
            local_secret_key,
            vec![local_peer.clone(), discovery_peer.clone()],
        )));
        let storm = StormHandle { inner: state };
        let table =
            message(&[local_peer, discovery_peer.clone(), unavailable_peer.clone()]).unwrap();

        let result = handle(
            &storm,
            MessageContext {
                peer_public_key: discovery_peer.compressed_public_key,
            },
            table,
        )
        .await;

        assert!(result.is_ok());
        let state = storm.inner.read().await;
        assert!(state.discovery_table_received);
        assert!(
            state
                .peers
                .iter()
                .find(|peer| { peer.compressed_public_key == discovery_peer.compressed_public_key })
                .unwrap()
                .discovery
        );
        assert_eq!(
            state
                .peers
                .iter()
                .find(|peer| {
                    peer.compressed_public_key == unavailable_peer.compressed_public_key
                })
                .unwrap()
                .status,
            PeerStatus::Inactive
        );
    }
}
