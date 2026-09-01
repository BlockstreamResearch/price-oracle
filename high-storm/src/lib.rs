pub mod cli;
pub mod config;
pub mod db;
pub mod external_api;
pub mod high_storm;
pub mod ipc;

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use db::network::NetworkStore;
use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use storm::{Peer, Storm};

use crate::config::Config;
pub use high_storm::{
    ApproveVotingRequest, AssetError, HighStorm, HighStormHandle, MergeStormEyes, NetworkAsset,
    NetworkAssets, NetworkVoteKind, NetworkVoteRequest, NodeMessage, NodeMessageKind, SigningError,
    SigningResult, SplitStormEye, StormEyeUtxo, TestNodeMessage, UpdateNetworkMembers,
    VOTING_TIMEOUT_BLOCKS, VotingApproval, VotingError, VotingRequest, VotingStatus,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Config(#[from] config::Error),
    #[error(transparent)]
    Database(#[from] db::network::Error),
    #[error(transparent)]
    Storm(#[from] storm::Error),
    #[error("invalid signer private key: {0}")]
    PrivateKey(String),
    #[error("invalid compressed public key '{0}'")]
    PublicKey(String),
    #[error("invalid discovery socket address '{0}'")]
    DiscoveryAddress(String),
}

pub async fn initialize_host(
    config: &Config,
    store: &NetworkStore,
    public_keys: &[String],
) -> Result<HighStorm, Error> {
    let secret_key = secret_key(config)?;
    let secret_key_bytes = secret_key.secret_bytes();
    let host_public_key = secret_key.public_key(&Secp256k1::new()).serialize();

    let mut seen = HashSet::from([host_public_key]);
    let mut peers = vec![Peer::new(host_public_key)];
    peers.extend(
        public_keys
            .iter()
            .map(|key| parse_public_key(key))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|key| seen.insert(*key))
            .map(Peer::new),
    );

    tracing::info!(
        public_key = %hex::encode(host_public_key),
        member_count = peers.len(),
        "initializing discovery host"
    );

    let storm = Storm::discovery(secret_key, peers);
    initialize(config, store, storm, secret_key_bytes, host_public_key).await
}

pub async fn initialize_join(
    config: &Config,
    store: &NetworkStore,
    discovery_public_key: &str,
    discovery_address: &str,
) -> Result<HighStorm, Error> {
    discovery_address
        .parse::<SocketAddr>()
        .map_err(|_| Error::DiscoveryAddress(discovery_address.to_string()))?;
    let coordinator_public_key = parse_public_key(discovery_public_key)?;

    let mut discovery_peer = Peer::new(coordinator_public_key);
    discovery_peer.socket_address = Some(discovery_address.to_string());

    let secret_key = secret_key(config)?;
    let secret_key_bytes = secret_key.secret_bytes();
    let local_public_key = secret_key.public_key(&Secp256k1::new()).serialize();

    tracing::info!(
        public_key = %hex::encode(local_public_key),
        discovery_public_key,
        discovery_address,
        "initializing node through discovery host"
    );

    let storm = Storm::discoverable(secret_key, discovery_peer)?;
    initialize(
        config,
        store,
        storm,
        secret_key_bytes,
        coordinator_public_key,
    )
    .await
}

pub async fn start_initialized(config: &Config, store: &NetworkStore) -> Result<HighStorm, Error> {
    let peers = store.load().await?;
    let coordinator_public_key = store.load_coordinator_public_key().await?;
    tracing::info!(peer_count = peers.len(), "loaded persisted network state");

    let secret_key = secret_key(config)?;
    let secret_key_bytes = secret_key.secret_bytes();
    let mut storm = Storm::from_peers(secret_key, peers);

    let listen_address = listen_address(config);
    tracing::info!(%listen_address, "starting initialized node");
    storm.start(Some(listen_address)).await?;
    tracing::info!("initialized node is running");

    Ok(HighStorm::new(
        storm,
        secret_key_bytes,
        coordinator_public_key,
        store.voting(),
        store.network_assets(),
    )
    .await)
}

async fn initialize(
    config: &Config,
    store: &NetworkStore,
    mut storm: Storm,
    secret_key: [u8; 32],
    coordinator_public_key: [u8; 33],
) -> Result<HighStorm, Error> {
    let listen_address = listen_address(config);
    tracing::info!(%listen_address, "starting Storm discovery listener");
    storm.start(Some(listen_address)).await?;

    let mut previous_peers = None;
    loop {
        let peers = storm.peers().await;

        if previous_peers.as_ref() != Some(&peers) {
            log_discovery_state(&peers);
            previous_peers = Some(peers.clone());
        }

        if peers.iter().all(|peer| !peer.discovery) {
            tracing::info!(peer_count = peers.len(), "network discovery completed");
            store.save(&peers, coordinator_public_key).await?;
            tracing::info!(
                peer_count = peers.len(),
                "initialized network state persisted"
            );
            return Ok(HighStorm::new(
                storm,
                secret_key,
                coordinator_public_key,
                store.voting(),
                store.network_assets(),
            )
            .await);
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
        storm.start(None).await?;
    }
}

fn log_discovery_state(peers: &[Peer]) {
    let pending = peers.iter().filter(|peer| peer.discovery).count();
    let active = peers
        .iter()
        .filter(|peer| peer.status == storm::PeerStatus::Active)
        .count();

    tracing::info!(
        peer_count = peers.len(),
        active_peers = active,
        pending_discovery = pending,
        "discovery state changed"
    );
    for peer in peers {
        tracing::debug!(
            public_key = %hex::encode(peer.compressed_public_key),
            address = peer.socket_address.as_deref().unwrap_or("unknown"),
            status = ?peer.status,
            discovery = peer.discovery,
            "peer state"
        );
    }

    if pending > 0 {
        tracing::info!("waiting for all configured members to join the discovery host");
    }
}

fn secret_key(config: &Config) -> Result<SecretKey, Error> {
    let encoded = &config.service.signer.private_key;
    let bytes = hex::decode(encoded).map_err(|error| Error::PrivateKey(error.to_string()))?;
    SecretKey::from_slice(&bytes).map_err(|error| Error::PrivateKey(error.to_string()))
}

fn parse_public_key(encoded: &str) -> Result<[u8; 33], Error> {
    let bytes = hex::decode(encoded).map_err(|_| Error::PublicKey(encoded.to_string()))?;
    PublicKey::from_slice(&bytes)
        .map(|public_key| public_key.serialize())
        .map_err(|_| Error::PublicKey(encoded.to_string()))
}

fn listen_address(config: &Config) -> String {
    format!("0.0.0.0:{}", config.service.port)
}
