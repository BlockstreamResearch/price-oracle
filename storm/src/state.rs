use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
};

use secp256k1_zkp::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::{CustomHandler, Error, Peer, PeerStatus, StormMessage, constants};

struct RecentMessage {
    fingerprint: [u8; 32],
    received_at: u64,
}

pub(crate) struct ConnectionPlan {
    pub(crate) initializer_secret_key: [u8; 32],
    pub(crate) initializer_public_key: [u8; 33],
    pub(crate) listener_port: Option<u16>,
    pub(crate) targets: Vec<ConnectionTarget>,
}

pub(crate) struct ConnectionTarget {
    pub(crate) public_key: [u8; 33],
    pub(crate) socket_address: String,
    pub(crate) status: PeerStatus,
    pub(crate) discovery: bool,
}

impl ConnectionPlan {
    pub(crate) fn should_connect(&self, target: &ConnectionTarget) -> bool {
        if target.public_key == self.initializer_public_key || target.status != PeerStatus::Inactive
        {
            return false;
        }

        target.discovery || self.initializer_public_key < target.public_key
    }
}

pub(crate) struct StormState {
    pub(crate) initializer_secret_key: SecretKey,
    pub(crate) initializer_public_key: [u8; 33],
    pub(crate) peers: Vec<Peer>,
    pub(crate) connections: HashMap<[u8; 33], mpsc::Sender<Vec<u8>>>,
    pub(crate) discovery_table_received: bool,
    pub(crate) custom_handler: Option<CustomHandler>,
    recent_messages: HashMap<[u8; 33], VecDeque<RecentMessage>>,
}

impl StormState {
    pub(crate) fn new(initializer_secret_key: SecretKey, peers: Vec<Peer>) -> Self {
        let initializer_public_key = initializer_secret_key
            .public_key(&Secp256k1::new())
            .serialize();

        Self {
            initializer_secret_key,
            initializer_public_key,
            peers,
            connections: HashMap::new(),
            discovery_table_received: false,
            custom_handler: None,
            recent_messages: HashMap::new(),
        }
    }

    pub(crate) fn connection_plan(&self) -> ConnectionPlan {
        let listener_port = self
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == self.initializer_public_key)
            .and_then(|peer| peer.socket_address.as_deref())
            .and_then(|address| address.parse::<SocketAddr>().ok())
            .map(|address| address.port());
        let targets = self
            .peers
            .iter()
            .filter_map(|peer| {
                Some(ConnectionTarget {
                    public_key: peer.compressed_public_key,
                    socket_address: peer.socket_address.clone()?,
                    status: peer.status,
                    discovery: peer.discovery,
                })
            })
            .collect();

        ConnectionPlan {
            initializer_secret_key: self.initializer_secret_key.secret_bytes(),
            initializer_public_key: self.initializer_public_key,
            listener_port,
            targets,
        }
    }

    pub(crate) fn accepts_unregistered_connections(&self) -> bool {
        !self.discovery_table_received
            && self.peers.iter().any(|peer| {
                peer.compressed_public_key != self.initializer_public_key && peer.discovery
            })
    }

    pub(crate) fn register_message(
        &mut self,
        peer_public_key: [u8; 33],
        message: &StormMessage,
        received_at: u64,
    ) -> Result<(), Error> {
        if message.header.timestamp.abs_diff(received_at) > constants::MESSAGE_CLOCK_SKEW.as_secs()
        {
            return Err(Error::MessageTimestampOutsideWindow);
        }

        let mut hasher = Sha256::new();
        hasher.update(b"storm-message-v1");
        hasher.update(message.header.payload_id.to_be_bytes());
        hasher.update(message.header.timestamp.to_be_bytes());
        hasher.update(message.header.protocol_version.to_be_bytes());
        hasher.update(&message.payload);
        let fingerprint = hasher.finalize().into();

        let recent_messages = self.recent_messages.entry(peer_public_key).or_default();
        recent_messages.retain(|entry| {
            received_at.saturating_sub(entry.received_at) <= constants::MESSAGE_CLOCK_SKEW.as_secs()
        });
        if recent_messages
            .iter()
            .any(|entry| entry.fingerprint == fingerprint)
        {
            return Err(Error::ReplayedMessage);
        }
        if recent_messages.len() >= constants::REPLAY_CACHE_CAPACITY {
            return Err(Error::MessageRateLimit);
        }
        recent_messages.push_back(RecentMessage {
            fingerprint,
            received_at,
        });

        Ok(())
    }
}
