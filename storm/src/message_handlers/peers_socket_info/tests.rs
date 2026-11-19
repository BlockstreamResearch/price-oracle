use super::*;
use crate::constants;
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
fn dns_peer_table_round_trip_accepts_mixed_endpoints() {
    let mut peers = Vec::new();
    for address in [
        "127.0.0.1:9000",
        "[::1]:9000",
        "node.storm.svc.cluster.local:9000",
    ] {
        let (_, mut peer) = generated_peer();
        peer.socket_address = Some(address.into());
        peers.push(peer);
    }
    let encoded = message(&peers).unwrap();
    let decoded = validate(postcard::from_bytes(&encoded.payload).unwrap()).unwrap();

    for (info, peer) in decoded.iter().zip(&peers) {
        assert_eq!(info.compressed_public_key, peer.compressed_public_key);
        assert_eq!(Some(&info.socket_address), peer.socket_address.as_ref());
    }
}

#[test]
fn dns_overrides_survive_discovery_and_migration_tables() {
    let (local_secret_key, local_peer) = generated_peer();
    let (_, discovery_peer) = generated_peer();
    let mut state = StormState::new(
        local_secret_key,
        vec![local_peer.clone(), discovery_peer.clone()],
    );
    state
        .address_overrides
        .insert(local_peer.compressed_public_key, "local.storm:9000".into());
    state.address_overrides.insert(
        discovery_peer.compressed_public_key,
        "coordinator.storm:9000".into(),
    );
    let table = vec![
        socket_info(&local_peer, "127.0.0.1:1000"),
        socket_info(&discovery_peer, "127.0.0.1:2000"),
    ];

    replace_discovered_peers(
        &mut state,
        table.clone(),
        discovery_peer.compressed_public_key,
    )
    .unwrap();
    replace_migration_peers(&mut state, table);

    for peers in [&state.peers, &state.migration_peers] {
        assert_eq!(peers[0].socket_address.as_deref(), Some("local.storm:9000"));
        assert_eq!(
            peers[1].socket_address.as_deref(),
            Some("coordinator.storm:9000")
        );
    }
}

#[test]
fn rejects_opposite_parity_encodings_of_one_x_only_identity() {
    let (_, peer) = generated_peer();
    let mut opposite_parity = peer.compressed_public_key;
    opposite_parity[0] = if opposite_parity[0] == 2 { 3 } else { 2 };

    let error = validate(vec![
        PeerSocketInfo {
            compressed_public_key: peer.compressed_public_key.to_vec(),
            socket_address: "127.0.0.1:1000".to_string(),
        },
        PeerSocketInfo {
            compressed_public_key: opposite_parity.to_vec(),
            socket_address: "127.0.0.1:2000".to_string(),
        },
    ])
    .unwrap_err();

    assert_eq!(error.0, StormErrorCode::InvalidPayload);
    assert!(error.1.contains("duplicate x-only public keys"));
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

#[tokio::test]
async fn caches_authenticated_migration_table_before_vote_staging() {
    let (local_secret_key, mut local_peer) = generated_peer();
    local_peer.socket_address = Some("127.0.0.1:1000".to_string());
    let (_, mut sender_peer) = generated_peer();
    sender_peer.status = PeerStatus::Active;
    sender_peer.socket_address = Some("127.0.0.1:2000".to_string());
    let (_, mut joining_peer) = generated_peer();
    joining_peer.socket_address = Some("127.0.0.1:3000".to_string());
    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![local_peer.clone(), sender_peer.clone()],
    )));
    let storm = StormHandle { inner: state };
    storm
        .set_peer_table_authority(sender_peer.compressed_public_key)
        .await
        .unwrap();
    let table = message(&[local_peer, sender_peer.clone(), joining_peer.clone()]).unwrap();

    handle(
        &storm,
        MessageContext {
            peer_public_key: sender_peer.compressed_public_key,
        },
        table,
    )
    .await
    .unwrap();

    let state = storm.inner.read().await;
    assert!(state.migration_members.is_none());
    assert!(state.migration_peers.iter().any(|peer| {
        peer.compressed_public_key == joining_peer.compressed_public_key
            && peer.socket_address == joining_peer.socket_address
    }));
    assert_eq!(state.peers.len(), 2);
}

#[tokio::test]
async fn caches_migration_table_that_removes_local_member() {
    let (local_secret_key, local_peer) = generated_peer();
    let (_, mut sender_peer) = generated_peer();
    sender_peer.status = PeerStatus::Active;
    sender_peer.socket_address = Some("127.0.0.1:2000".to_string());
    let (_, mut joining_peer) = generated_peer();
    joining_peer.socket_address = Some("127.0.0.1:3000".to_string());
    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![local_peer.clone(), sender_peer.clone()],
    )));
    let storm = StormHandle { inner: state };
    storm
        .set_peer_table_authority(sender_peer.compressed_public_key)
        .await
        .unwrap();
    let table = message(&[sender_peer.clone(), joining_peer.clone()]).unwrap();

    handle(
        &storm,
        MessageContext {
            peer_public_key: sender_peer.compressed_public_key,
        },
        table,
    )
    .await
    .unwrap();

    let state = storm.inner.read().await;
    assert!(state.migration_members.is_none());
    assert_eq!(state.migration_peers.len(), 2);
    assert!(
        !state
            .migration_peers
            .iter()
            .any(|peer| { peer.compressed_public_key == local_peer.compressed_public_key })
    );
    assert!(
        state
            .migration_peers
            .iter()
            .any(|peer| { peer.compressed_public_key == joining_peer.compressed_public_key })
    );
}

#[tokio::test]
async fn rejects_migration_addresses_from_a_non_authority() {
    let (local_secret_key, mut local_peer) = generated_peer();
    local_peer.socket_address = Some("127.0.0.1:1000".to_string());
    let (_, mut authority) = generated_peer();
    authority.status = PeerStatus::Active;
    authority.socket_address = Some("127.0.0.1:2000".to_string());
    let (_, mut attacker) = generated_peer();
    attacker.status = PeerStatus::Active;
    attacker.socket_address = Some("127.0.0.1:3000".to_string());
    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![local_peer.clone(), authority.clone(), attacker.clone()],
    )));
    let storm = StormHandle { inner: state };
    storm
        .set_peer_table_authority(authority.compressed_public_key)
        .await
        .unwrap();
    let mut poisoned_local = local_peer.clone();
    poisoned_local.socket_address = Some("127.0.0.1:9000".to_string());
    let mut poisoned_authority = authority.clone();
    poisoned_authority.socket_address = Some("127.0.0.1:9001".to_string());
    let table = message(&[poisoned_local.clone(), poisoned_authority.clone()]).unwrap();

    let error = handle(
        &storm,
        MessageContext {
            peer_public_key: attacker.compressed_public_key,
        },
        table,
    )
    .await
    .unwrap_err();

    assert_eq!(error.0, StormErrorCode::InvalidPayload);
    assert!(storm.inner.read().await.migration_peers.is_empty());
    {
        let mut state = storm.inner.write().await;
        state.migration_members = Some(
            [
                local_peer.compressed_public_key,
                authority.compressed_public_key,
            ]
            .into_iter()
            .map(|key| StormState::x_only_public_key(&key))
            .collect(),
        );
        state.migration_peers = vec![local_peer.clone(), authority.clone()];
    }
    let table = message(&[poisoned_local, poisoned_authority]).unwrap();

    let error = handle(
        &storm,
        MessageContext {
            peer_public_key: attacker.compressed_public_key,
        },
        table,
    )
    .await
    .unwrap_err();

    assert_eq!(error.0, StormErrorCode::Unauthorized);
    let state = storm.inner.read().await;
    assert_eq!(
        state.migration_peers[0].socket_address,
        local_peer.socket_address
    );
    assert_eq!(
        state.migration_peers[1].socket_address,
        authority.socket_address
    );
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
    unavailable_peer.socket_address = Some("not-yet-deployed.invalid:9000".to_string());

    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![local_peer.clone(), discovery_peer.clone()],
    )));
    let storm = StormHandle { inner: state };
    let table = message(&[local_peer, discovery_peer.clone(), unavailable_peer.clone()]).unwrap();

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
            .find(|peer| { peer.compressed_public_key == unavailable_peer.compressed_public_key })
            .unwrap()
            .status,
        PeerStatus::Inactive
    );
}
