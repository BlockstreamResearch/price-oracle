use std::{
    mem::size_of,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use secp256k1_zkp::{Secp256k1, SecretKey, rand};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{RwLock, mpsc},
    task::JoinHandle,
    time::{Duration, timeout},
};

use super::*;
use crate::{
    constants, crypto, message, message_handlers,
    network::{read_frame, write_frame},
    state::StormState,
};

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn connect(
    address: SocketAddr,
    listener: &TcpListener,
    secret_key: &SecretKey,
    responder_public_key: &[u8; 33],
    state: Arc<RwLock<StormState>>,
) -> (TcpStream, JoinHandle<Result<(), Error>>) {
    let client = TcpStream::connect(address);
    let accepted = listener.accept();
    let (client_result, accepted_result) = tokio::join!(client, accepted);
    let mut client = client_result.unwrap();
    let (server, peer_address) = accepted_result.unwrap();
    let server_handle = tokio::spawn(Storm::handle_connection(server, peer_address, state));

    let mut handshake = crypto::noise_builder()
        .local_private_key(&secret_key.secret_bytes())
        .unwrap()
        .remote_public_key(responder_public_key)
        .unwrap()
        .prologue(constants::NOISE_PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut buffer = [0_u8; 256];
    let mut payload = [0_u8; 256];

    let length = handshake.write_message(&[], &mut buffer).unwrap();
    write_frame(&mut client, &buffer[..length]).await.unwrap();
    let response = read_frame(&mut client).await.unwrap();
    handshake.read_message(&response, &mut payload).unwrap();
    handshake.into_transport_mode().unwrap();

    (client, server_handle)
}

async fn wait_for_status(
    state: &Arc<RwLock<StormState>>,
    expected: PeerStatus,
    server: &mut JoinHandle<Result<(), Error>>,
) {
    timeout(Duration::from_secs(1), async {
        loop {
            if state.read().await.peers[0].status == expected {
                return;
            }
            if server.is_finished() {
                panic!("server exited early: {:?}", server.await.unwrap());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn wait_for_peer_status(storm: &Storm, peer_public_key: [u8; 33], expected: PeerStatus) {
    timeout(Duration::from_secs(1), async {
        loop {
            let state = storm.inner.read().await;
            let status = state
                .peers
                .iter()
                .find(|peer| peer.compressed_public_key == peer_public_key)
                .unwrap()
                .status;
            drop(state);

            if status == expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn wait_for_discovery_completion(storm: &Storm, peer_count: usize) {
    let result = timeout(Duration::from_secs(2), async {
        loop {
            let state = storm.inner.read().await;
            let local_public_key = state.initializer_public_key;
            let complete = state.discovery_table_received
                && state.peers.len() == peer_count
                && state.peers.iter().all(|peer| !peer.discovery)
                && state.peers.iter().all(|peer| {
                    peer.compressed_public_key == local_public_key
                        || peer.status == PeerStatus::Active
                        || peer.status == PeerStatus::Banned
                });
            drop(state);

            if complete {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    if result.is_err() {
        let state = storm.inner.read().await;
        panic!(
            "discovery did not complete: table_received={}, expected_peer_count={peer_count}, peers={:?}",
            state.discovery_table_received, state.peers
        );
    }
}

#[tokio::test]
async fn authenticated_peer_is_active_once_and_inactive_after_disconnect() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let server_secret_key = SecretKey::new(&mut random);
    let server_public_key = server_secret_key.public_key(&secp).serialize();
    let peer_secret_key = SecretKey::new(&mut random);
    let peer_public_key = peer_secret_key.public_key(&secp);
    let state = Arc::new(RwLock::new(StormState::new(
        server_secret_key,
        vec![Peer::new(peer_public_key.serialize())],
    )));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let (first_client, mut first_server) = connect(
        address,
        &listener,
        &peer_secret_key,
        &server_public_key,
        Arc::clone(&state),
    )
    .await;
    wait_for_status(&state, PeerStatus::Active, &mut first_server).await;

    let (second_client, second_server) = connect(
        address,
        &listener,
        &peer_secret_key,
        &server_public_key,
        Arc::clone(&state),
    )
    .await;
    let second_result = timeout(Duration::from_secs(1), second_server)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(second_result, Err(Error::PeerAlreadyConnected)));
    assert_eq!(state.read().await.peers[0].status, PeerStatus::Active);

    drop(second_client);
    drop(first_client);
    let first_result = timeout(Duration::from_secs(1), first_server)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(first_result, Err(Error::Io(_))));
    assert_eq!(state.read().await.peers[0].status, PeerStatus::Inactive);
}

#[tokio::test]
async fn initialization_modes_normalize_peer_state() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let remote_secret_key = SecretKey::new(&mut random);
    let remote_public_key = remote_secret_key.public_key(&secp).serialize();
    let banned_secret_key = SecretKey::new(&mut random);
    let banned_public_key = banned_secret_key.public_key(&secp).serialize();

    let host_secret_key = SecretKey::new(&mut random);
    let host_public_key = host_secret_key.public_key(&secp).serialize();
    let mut registered_peer = Peer::new(remote_public_key);
    registered_peer.socket_address = Some("127.0.0.1:9000".to_string());
    registered_peer.status = PeerStatus::Active;
    registered_peer.discovery = true;
    let mut banned_peer = Peer::new(banned_public_key);
    banned_peer.status = PeerStatus::Banned;
    banned_peer.discovery = true;
    let host = Storm::discovery(host_secret_key, vec![registered_peer, banned_peer]);
    let host_peers = host.peers().await;
    let local_host = host_peers
        .iter()
        .find(|peer| peer.compressed_public_key == host_public_key)
        .unwrap();
    let registered_peer = host_peers
        .iter()
        .find(|peer| peer.compressed_public_key == remote_public_key)
        .unwrap();
    assert_eq!(local_host.status, PeerStatus::Controlled);
    assert!(local_host.discovery);
    assert_eq!(registered_peer.status, PeerStatus::Inactive);
    assert!(!registered_peer.discovery);
    assert_eq!(
        registered_peer.socket_address.as_deref(),
        Some("127.0.0.1:9000")
    );
    let banned_peer = host_peers
        .iter()
        .find(|peer| peer.compressed_public_key == banned_public_key)
        .unwrap();
    assert_eq!(banned_peer.status, PeerStatus::Banned);
    assert!(!banned_peer.discovery);

    let client_secret_key = SecretKey::new(&mut random);
    let client_public_key = client_secret_key.public_key(&secp).serialize();
    let mut discovery_peer = Peer::new(remote_public_key);
    discovery_peer.socket_address = Some("127.0.0.1:9001".to_string());
    discovery_peer.status = PeerStatus::Active;
    let client = Storm::discoverable(client_secret_key, discovery_peer).unwrap();
    let client_peers = client.peers().await;
    let local_client = client_peers
        .iter()
        .find(|peer| peer.compressed_public_key == client_public_key)
        .unwrap();
    let discovery_peer = client_peers
        .iter()
        .find(|peer| peer.compressed_public_key == remote_public_key)
        .unwrap();
    assert_eq!(local_client.status, PeerStatus::Controlled);
    assert!(!local_client.discovery);
    assert_eq!(discovery_peer.status, PeerStatus::Inactive);
    assert!(discovery_peer.discovery);

    let saved_secret_key = SecretKey::new(&mut random);
    let saved_public_key = saved_secret_key.public_key(&secp).serialize();
    let mut saved_local_peer = Peer::new(saved_public_key);
    saved_local_peer.status = PeerStatus::Active;
    saved_local_peer.discovery = true;
    let mut saved_remote_peer = Peer::new(remote_public_key);
    saved_remote_peer.status = PeerStatus::Active;
    saved_remote_peer.discovery = true;
    let saved = Storm::from_peers(saved_secret_key, vec![saved_local_peer, saved_remote_peer]);
    let saved_peers = saved.peers().await;
    assert!(saved_peers.iter().all(|peer| !peer.discovery));
    assert_eq!(
        saved_peers
            .iter()
            .find(|peer| peer.compressed_public_key == saved_public_key)
            .unwrap()
            .status,
        PeerStatus::Controlled
    );
    assert_eq!(
        saved_peers
            .iter()
            .find(|peer| peer.compressed_public_key == remote_public_key)
            .unwrap()
            .status,
        PeerStatus::Inactive
    );
}

#[tokio::test]
async fn discovery_host_rejects_an_unregistered_public_key() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let host_secret_key = SecretKey::new(&mut random);
    let host_public_key = host_secret_key.public_key(&secp).serialize();
    let registered_secret_key = SecretKey::new(&mut random);
    let registered_public_key = registered_secret_key.public_key(&secp).serialize();
    let unregistered_secret_key = SecretKey::new(&mut random);
    let unregistered_public_key = unregistered_secret_key.public_key(&secp).serialize();
    let host = Storm::discovery(host_secret_key, vec![Peer::new(registered_public_key)]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let (_client, server) = connect(
        listener.local_addr().unwrap(),
        &listener,
        &unregistered_secret_key,
        &host_public_key,
        Arc::clone(&host.inner),
    )
    .await;
    let result = timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();

    assert!(matches!(result, Err(Error::UnauthorizedConnection)));
    assert!(
        host.peers()
            .await
            .iter()
            .all(|peer| peer.compressed_public_key != unregistered_public_key)
    );
}

#[tokio::test]
async fn discoverable_node_accepts_unregistered_connection_but_rejects_messages() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let discovery_secret_key = SecretKey::new(&mut random);
    let unknown_secret_key = SecretKey::new(&mut random);
    let unknown_public_key = unknown_secret_key.public_key(&Secp256k1::new()).serialize();
    let mut discovery_peer = Peer::new(
        discovery_secret_key
            .public_key(&Secp256k1::new())
            .serialize(),
    );
    discovery_peer.socket_address = Some("127.0.0.1:9000".to_string());
    let storm = Storm::discoverable(local_secret_key, discovery_peer).unwrap();

    let connection_receiver = Storm::claim_connection(&storm.inner, unknown_public_key, None)
        .await
        .unwrap();

    assert!(
        storm
            .inner
            .read()
            .await
            .connections
            .contains_key(&unknown_public_key)
    );
    assert!(
        storm
            .peers()
            .await
            .iter()
            .all(|peer| peer.compressed_public_key != unknown_public_key)
    );

    let heartbeat = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
            timestamp: 123,
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    };
    let result = Storm::handle_message(&storm.inner, unknown_public_key, heartbeat).await;
    assert!(matches!(result, Err(Error::UnauthorizedConnection)));
    assert!(connection_receiver.is_empty());

    Storm::release_connection(&storm.inner, unknown_public_key).await;
    storm.inner.write().await.discovery_table_received = true;
    let result = Storm::claim_connection(&storm.inner, unknown_public_key, None).await;
    assert!(matches!(result, Err(Error::UnauthorizedConnection)));
}

#[tokio::test]
async fn discoverable_node_limits_provisional_connections() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let discovery_secret_key = SecretKey::new(&mut random);
    let discovery_public_key = discovery_secret_key
        .public_key(&Secp256k1::new())
        .serialize();
    let mut discovery_peer = Peer::new(discovery_public_key);
    discovery_peer.socket_address = Some("127.0.0.1:9000".to_string());
    let storm = Storm::discoverable(local_secret_key, discovery_peer).unwrap();
    let mut provisional_receivers = Vec::new();

    for _ in 0..constants::MAX_PROVISIONAL_CONNECTIONS {
        let unknown_public_key = SecretKey::new(&mut random)
            .public_key(&Secp256k1::new())
            .serialize();
        provisional_receivers.push(
            Storm::claim_connection(&storm.inner, unknown_public_key, None)
                .await
                .unwrap(),
        );
    }

    let excess_public_key = SecretKey::new(&mut random)
        .public_key(&Secp256k1::new())
        .serialize();
    let error = Storm::claim_connection(&storm.inner, excess_public_key, None)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::ProvisionalConnectionLimit));

    let registered_receiver = Storm::claim_connection(&storm.inner, discovery_public_key, None)
        .await
        .unwrap();
    assert_eq!(
        provisional_receivers.len(),
        constants::MAX_PROVISIONAL_CONNECTIONS
    );
    assert!(registered_receiver.is_empty());
}

#[tokio::test]
async fn accepted_connection_can_complete_client_discovery() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let local_public_key = local_secret_key.public_key(&secp).serialize();
    let discovery_secret_key = SecretKey::new(&mut random);
    let discovery_public_key = discovery_secret_key.public_key(&secp).serialize();
    let inbound_secret_key = SecretKey::new(&mut random);
    let inbound_public_key = inbound_secret_key.public_key(&secp).serialize();

    let mut local_peer = Peer::new(local_public_key);
    local_peer.status = PeerStatus::Controlled;
    let mut discovery_peer = Peer::new(discovery_public_key);
    discovery_peer.status = PeerStatus::Active;
    discovery_peer.discovery = true;
    let inbound_peer = Peer::new(inbound_public_key);
    let mut state = StormState::new(
        local_secret_key,
        vec![local_peer, discovery_peer, inbound_peer],
    );
    state.discovery_table_received = true;
    let (discovery_sender, _discovery_receiver) = mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
    state
        .connections
        .insert(discovery_public_key, discovery_sender);
    let state = Arc::new(RwLock::new(state));
    let handle = StormHandle {
        inner: Arc::clone(&state),
    };

    let _inbound_receiver = Storm::claim_connection(&state, inbound_public_key, None)
        .await
        .unwrap();
    handle.finish_client_discovery_if_connected().await;

    let state = state.read().await;
    assert_eq!(
        state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == inbound_public_key)
            .unwrap()
            .status,
        PeerStatus::Active
    );
    assert!(state.peers.iter().all(|peer| !peer.discovery));
}

#[tokio::test]
async fn banned_peer_cannot_connect_or_process_messages_and_remains_banned() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let banned_secret_key = SecretKey::new(&mut random);
    let banned_public_key = banned_secret_key.public_key(&Secp256k1::new()).serialize();
    let mut banned_peer = Peer::new(banned_public_key);
    banned_peer.status = PeerStatus::Banned;
    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![banned_peer],
    )));

    let result = Storm::claim_connection(&state, banned_public_key, None).await;
    assert!(matches!(result, Err(Error::UnauthorizedConnection)));
    assert_eq!(state.read().await.peers[0].status, PeerStatus::Banned);

    let heartbeat = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
            timestamp: 123,
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    };
    let result = Storm::handle_message(&state, banned_public_key, heartbeat).await;
    assert!(matches!(result, Err(Error::UnauthorizedConnection)));
    assert_eq!(state.read().await.peers[0].status, PeerStatus::Banned);

    let (connection, _receiver) = mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
    state
        .write()
        .await
        .connections
        .insert(banned_public_key, connection);
    Storm::release_connection(&state, banned_public_key).await;
    assert_eq!(state.read().await.peers[0].status, PeerStatus::Banned);
}

#[tokio::test]
async fn registered_custom_handler_receives_decoded_message() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let peer_secret_key = SecretKey::new(&mut random);
    let peer_public_key = peer_secret_key.public_key(&Secp256k1::new()).serialize();
    let storm = Storm::from_peers(local_secret_key, vec![Peer::new(peer_public_key)]);
    let (callback_sender, mut callback_receiver) = mpsc::unbounded_channel();
    let (connection_sender, mut connection_receiver) =
        mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
    storm
        .inner
        .write()
        .await
        .connections
        .insert(peer_public_key, connection_sender);

    storm
        .register_custom_handler(move |message, context| {
            let callback_sender = callback_sender.clone();
            async move {
                context
                    .storm_handle
                    .send_response(context.storm_message.clone(), &context.message_context)
                    .await
                    .unwrap();
                callback_sender.send((message, context)).unwrap();
            }
        })
        .await;

    let custom_message = CustomMsg {
        domain: "oracle".to_string(),
        payload: vec![1, 2, 3],
    };
    let message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Custom as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: postcard::to_stdvec(&custom_message).unwrap(),
    };

    Storm::handle_message(&storm.inner, peer_public_key, message.clone())
        .await
        .unwrap();

    let (received_message, context) = callback_receiver.recv().await.unwrap();
    assert_eq!(received_message, custom_message);
    assert_eq!(context.storm_message, message);
    assert_eq!(context.message_context.peer_public_key, peer_public_key);
    assert_eq!(context.storm_handle.peers().await, storm.peers().await);
    let framed_response = connection_receiver.recv().await.unwrap();
    assert_eq!(
        StormMessage::from_bytes(&framed_response[size_of::<u32>()..]).unwrap(),
        message
    );
}

#[tokio::test]
async fn outbound_queue_rejects_messages_when_full() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let peer_secret_key = SecretKey::new(&mut random);
    let peer_public_key = peer_secret_key.public_key(&Secp256k1::new());
    let storm = Storm::from_peers(
        local_secret_key,
        vec![Peer::new(peer_public_key.serialize())],
    );
    let (connection_sender, _connection_receiver) =
        mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
    storm
        .inner
        .write()
        .await
        .connections
        .insert(peer_public_key.serialize(), connection_sender);
    let message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    };

    for _ in 0..constants::OUTBOUND_QUEUE_CAPACITY {
        storm
            .send_message(message.clone(), &[peer_public_key])
            .await
            .unwrap();
    }
    let error = storm
        .send_message(message, &[peer_public_key])
        .await
        .unwrap_err();

    assert!(matches!(error, Error::PeerQueueFull(_)));
}

#[tokio::test]
async fn authenticated_messages_reject_stale_timestamps_and_replays() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let peer_secret_key = SecretKey::new(&mut random);
    let peer_public_key = peer_secret_key.public_key(&Secp256k1::new()).serialize();
    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![Peer::new(peer_public_key)],
    )));
    let message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    };

    Storm::handle_message(&state, peer_public_key, message.clone())
        .await
        .unwrap();
    let replay_error = Storm::handle_message(&state, peer_public_key, message)
        .await
        .unwrap_err();
    assert!(matches!(replay_error, Error::ReplayedMessage));

    let stale_message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
            timestamp: current_timestamp()
                .saturating_sub(constants::MESSAGE_CLOCK_SKEW.as_secs() + 1),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: Vec::new(),
    };
    let stale_error = Storm::handle_message(&state, peer_public_key, stale_message)
        .await
        .unwrap_err();
    assert!(matches!(stale_error, Error::MessageTimestampOutsideWindow));
}

#[tokio::test]
async fn authenticated_messages_cannot_evict_replay_fingerprints() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let peer_secret_key = SecretKey::new(&mut random);
    let peer_public_key = peer_secret_key.public_key(&Secp256k1::new()).serialize();
    let state = Arc::new(RwLock::new(StormState::new(
        local_secret_key,
        vec![Peer::new(peer_public_key)],
    )));

    for sequence in 0..constants::REPLAY_CACHE_CAPACITY {
        let message = StormMessage {
            header: StormMessageHeader {
                payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
                timestamp: current_timestamp(),
                protocol_version: constants::PROTOCOL_VERSION,
            },
            payload: sequence.to_be_bytes().to_vec(),
        };
        Storm::handle_message(&state, peer_public_key, message)
            .await
            .unwrap();
    }

    let excess_message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Heartbeat as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: b"excess".to_vec(),
    };
    let error = Storm::handle_message(&state, peer_public_key, excess_message)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::MessageRateLimit));
}

#[test]
fn custom_message_constructor_uses_the_custom_wire_format() {
    let custom_message = CustomMsg {
        domain: "oracle.price".to_string(),
        payload: vec![1, 2, 3],
    };

    let message = custom_message.clone().into_storm_message().unwrap();

    assert_eq!(
        message.header.payload_id,
        message_handlers::StormMessagePayloadType::Custom as u32
    );
    assert_eq!(message.header.protocol_version, constants::PROTOCOL_VERSION);
    assert_eq!(
        postcard::from_bytes::<CustomMsg>(&message.payload).unwrap(),
        custom_message
    );
}

#[tokio::test]
async fn handler_failure_sends_error_without_error_response_loops() {
    let mut random = rand::thread_rng();
    let local_secret_key = SecretKey::new(&mut random);
    let peer_secret_key = SecretKey::new(&mut random);
    let peer_public_key = peer_secret_key.public_key(&Secp256k1::new()).serialize();
    let mut peer = Peer::new(peer_public_key);
    peer.status = PeerStatus::Active;
    let mut state = StormState::new(local_secret_key, vec![peer]);
    let (sender, mut receiver) = mpsc::channel(constants::OUTBOUND_QUEUE_CAPACITY);
    state.connections.insert(peer_public_key, sender);
    let state = Arc::new(RwLock::new(state));
    let invalid_custom_message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Custom as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: vec![0x80],
    };

    Storm::handle_message(&state, peer_public_key, invalid_custom_message)
        .await
        .unwrap();

    let framed_response = receiver.recv().await.unwrap();
    let response = StormMessage::from_bytes(&framed_response[size_of::<u32>()..]).unwrap();
    let error = message_handlers::error::decode(&response).unwrap();
    assert_eq!(error.code, message::StormErrorCode::InvalidPayload);
    assert_eq!(error.message, "Failed to deserialize Custom payload");
    assert_eq!(
        error.request_payload_id,
        message_handlers::StormMessagePayloadType::Custom as u32
    );

    let unsupported_version = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Custom as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION + 1,
        },
        payload: Vec::new(),
    };
    Storm::handle_message(&state, peer_public_key, unsupported_version)
        .await
        .unwrap();

    let framed_response = receiver.recv().await.unwrap();
    let response = StormMessage::from_bytes(&framed_response[size_of::<u32>()..]).unwrap();
    let error = message_handlers::error::decode(&response).unwrap();
    assert_eq!(error.code, message::StormErrorCode::UnsupportedVersion);
    assert_eq!(
        error.request_payload_id,
        message_handlers::StormMessagePayloadType::Custom as u32
    );

    let invalid_error = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Error as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: vec![0x80],
    };
    Storm::handle_message(&state, peer_public_key, invalid_error)
        .await
        .unwrap();
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn connects_available_addressed_peers_and_reports_missing_message_recipient() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let sender_secret_key = SecretKey::new(&mut random);
    let sender_public_key = sender_secret_key.public_key(&secp);
    let receiver_secret_key = SecretKey::new(&mut random);
    let receiver_public_key = receiver_secret_key.public_key(&secp);
    let disconnected_secret_key = SecretKey::new(&mut random);
    let disconnected_public_key = disconnected_secret_key.public_key(&secp);
    let disconnected_address = "127.0.0.1:1".to_string();
    let mut receiver_disconnected_peer = Peer::new(disconnected_public_key.serialize());
    receiver_disconnected_peer.socket_address = Some(disconnected_address.clone());
    let mut receiver = Storm::from_peers(
        receiver_secret_key,
        vec![
            Peer::new(sender_public_key.serialize()),
            receiver_disconnected_peer,
        ],
    );
    receiver
        .start(Some("127.0.0.1:0".to_string()))
        .await
        .unwrap();
    let mut receiver_peer = Peer::new(receiver_public_key.serialize());
    receiver_peer.socket_address = Some(receiver.listener_address.unwrap().to_string());
    let mut disconnected_peer = Peer::new(disconnected_public_key.serialize());
    disconnected_peer.socket_address = Some(disconnected_address);
    let mut sender = Storm::from_peers(sender_secret_key, vec![receiver_peer, disconnected_peer]);

    sender.start(Some("127.0.0.1:0".to_string())).await.unwrap();
    wait_for_peer_status(&sender, receiver_public_key.serialize(), PeerStatus::Active).await;
    wait_for_peer_status(&receiver, sender_public_key.serialize(), PeerStatus::Active).await;

    let message = StormMessage {
        header: StormMessageHeader {
            payload_id: message_handlers::StormMessagePayloadType::Custom as u32,
            timestamp: current_timestamp(),
            protocol_version: constants::PROTOCOL_VERSION,
        },
        payload: vec![1, 2, 3],
    };
    let error = sender
        .send_message(
            message.clone(),
            &[receiver_public_key, disconnected_public_key],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, Error::PeerNotConnected(key) if key == hex::encode(disconnected_public_key.serialize()))
    );

    sender
        .send_message(message, &[receiver_public_key])
        .await
        .unwrap();
}

#[tokio::test]
async fn connections_close_on_shutdown_and_drop() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let sender_secret_key = SecretKey::new(&mut random);
    let sender_public_key = sender_secret_key.public_key(&secp);
    let receiver_secret_key = SecretKey::new(&mut random);
    let receiver_public_key = receiver_secret_key.public_key(&secp);
    let mut receiver = Storm::from_peers(
        receiver_secret_key,
        vec![Peer::new(sender_public_key.serialize())],
    );
    receiver
        .start(Some("127.0.0.1:0".to_string()))
        .await
        .unwrap();
    let mut receiver_peer = Peer::new(receiver_public_key.serialize());
    receiver_peer.socket_address = Some(receiver.listener_address.unwrap().to_string());
    let mut sender = Storm::from_peers(sender_secret_key, vec![receiver_peer]);
    sender.start(Some("127.0.0.1:0".to_string())).await.unwrap();
    wait_for_peer_status(&receiver, sender_public_key.serialize(), PeerStatus::Active).await;

    sender.shutdown().await;
    wait_for_peer_status(
        &sender,
        receiver_public_key.serialize(),
        PeerStatus::Inactive,
    )
    .await;
    wait_for_peer_status(
        &receiver,
        sender_public_key.serialize(),
        PeerStatus::Inactive,
    )
    .await;

    sender.start(None).await.unwrap();
    wait_for_peer_status(&receiver, sender_public_key.serialize(), PeerStatus::Active).await;
    drop(sender);
    wait_for_peer_status(
        &receiver,
        sender_public_key.serialize(),
        PeerStatus::Inactive,
    )
    .await;
}

#[tokio::test]
async fn discovery_coordinator_broadcasts_complete_table_and_clients_connect() {
    let secp = Secp256k1::new();
    let mut random = rand::thread_rng();
    let discovery_secret_key = SecretKey::new(&mut random);
    let discovery_public_key = discovery_secret_key.public_key(&secp);
    let first_secret_key = SecretKey::new(&mut random);
    let first_public_key = first_secret_key.public_key(&secp);
    let second_secret_key = SecretKey::new(&mut random);
    let second_public_key = second_secret_key.public_key(&secp);

    let mut discovery = Storm::discovery(
        discovery_secret_key,
        vec![
            Peer::new(first_public_key.serialize()),
            Peer::new(second_public_key.serialize()),
        ],
    );
    discovery
        .start(Some("127.0.0.1:0".to_string()))
        .await
        .unwrap();
    let discovery_address = discovery.listener_address.unwrap();

    let mut first_discovery_peer = Peer::new(discovery_public_key.serialize());
    first_discovery_peer.socket_address = Some(discovery_address.to_string());
    let mut first = Storm::discoverable(first_secret_key, first_discovery_peer).unwrap();
    first.start(Some("127.0.0.1:0".to_string())).await.unwrap();
    let first_address = first.listener_address.unwrap();

    let mut second_discovery_peer = Peer::new(discovery_public_key.serialize());
    second_discovery_peer.socket_address = Some(discovery_address.to_string());
    let mut second = Storm::discoverable(second_secret_key, second_discovery_peer).unwrap();
    second.start(Some("127.0.0.1:0".to_string())).await.unwrap();
    let second_address = second.listener_address.unwrap();

    wait_for_discovery_completion(&first, 3).await;
    wait_for_discovery_completion(&second, 3).await;

    let state = discovery.inner.read().await;
    assert_eq!(
        state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == first_public_key.serialize())
            .unwrap()
            .socket_address
            .as_deref(),
        Some(first_address.to_string().as_str())
    );
    assert_eq!(
        state
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == second_public_key.serialize())
            .unwrap()
            .socket_address
            .as_deref(),
        Some(second_address.to_string().as_str())
    );
}
