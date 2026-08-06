use std::{collections::HashMap, net::SocketAddr};

use secp256k1_zkp::{Secp256k1, SecretKey};
use tokio::sync::mpsc;

use crate::{CustomHandler, Peer, PeerStatus};

pub(crate) struct ConnectionPlan {
    pub(crate) initializer_secret_key: [u8; 32],
    pub(crate) initializer_public_key: [u8; 33],
    pub(crate) listener_port: Option<u16>,
    pub(crate) discovery_in_progress: bool,
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

        !self.discovery_in_progress
            || self.initializer_public_key <= target.public_key
            || target.discovery
    }
}

pub(crate) struct StormState {
    pub(crate) initializer_secret_key: SecretKey,
    pub(crate) initializer_public_key: [u8; 33],
    pub(crate) peers: Vec<Peer>,
    pub(crate) connections: HashMap<[u8; 33], mpsc::UnboundedSender<Vec<u8>>>,
    pub(crate) discovery_table_received: bool,
    pub(crate) custom_handler: Option<CustomHandler>,
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
            discovery_in_progress: self.peers.iter().any(|peer| peer.discovery),
            targets,
        }
    }

    pub(crate) fn accepts_unregistered_connections(&self) -> bool {
        !self.discovery_table_received
            && self.peers.iter().any(|peer| {
                peer.compressed_public_key != self.initializer_public_key && peer.discovery
            })
    }
}
