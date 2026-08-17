pub mod cli;
pub mod config;
pub mod db;

use std::{collections::HashSet, net::SocketAddr, time::Duration};

use db::network::NetworkStore;
use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use storm::{Peer, Storm};

use crate::config::Config;

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
) -> Result<Storm, Error> {
    let secret_key = secret_key(config)?;
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
    initialize(config, store, storm).await
}

pub async fn initialize_join(
    config: &Config,
    store: &NetworkStore,
    discovery_public_key: &str,
    discovery_address: &str,
) -> Result<Storm, Error> {
    discovery_address
        .parse::<SocketAddr>()
        .map_err(|_| Error::DiscoveryAddress(discovery_address.to_string()))?;
    let mut discovery_peer = Peer::new(parse_public_key(discovery_public_key)?);
    discovery_peer.socket_address = Some(discovery_address.to_string());
    let secret_key = secret_key(config)?;
    let local_public_key = secret_key.public_key(&Secp256k1::new()).serialize();
    tracing::info!(
        public_key = %hex::encode(local_public_key),
        discovery_public_key,
        discovery_address,
        "initializing node through discovery host"
    );
    let storm = Storm::discoverable(secret_key, discovery_peer)?;
    initialize(config, store, storm).await
}

pub async fn start_initialized(config: &Config, store: &NetworkStore) -> Result<Storm, Error> {
    let peers = store.load().await?;
    tracing::info!(peer_count = peers.len(), "loaded persisted network state");
    let mut storm = Storm::from_peers(secret_key(config)?, peers);
    let listen_address = listen_address(config);
    tracing::info!(%listen_address, "starting initialized node");
    storm.start(Some(listen_address)).await?;
    tracing::info!("initialized node is running");
    Ok(storm)
}

async fn initialize(
    config: &Config,
    store: &NetworkStore,
    mut storm: Storm,
) -> Result<Storm, Error> {
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
            store.save(&peers).await?;
            tracing::info!(
                peer_count = peers.len(),
                "initialized network state persisted"
            );
            return Ok(storm);
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
