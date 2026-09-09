use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    net::SocketAddr,
};

use secp256k1_zkp::{Parity, PublicKey, Secp256k1, SecretKey};
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
    pub(crate) fn should_connect(&self, target: &ConnectionTarget, reverse: bool) -> bool {
        if target.public_key == self.initializer_public_key || target.status != PeerStatus::Inactive
        {
            return false;
        }

        target.discovery
            || if reverse {
                self.initializer_public_key > target.public_key
            } else {
                self.initializer_public_key < target.public_key
            }
    }
}

pub(crate) struct StormState {
    pub(crate) initializer_secret_key: SecretKey,
    pub(crate) initializer_public_key: [u8; 33],
    pub(crate) peers: Vec<Peer>,
    pub(crate) connections: HashMap<[u8; 33], mpsc::Sender<Vec<u8>>>,
    pub(crate) discovery_table_received: bool,
    pub(crate) custom_handler: Option<CustomHandler>,
    pub(crate) peer_table_authority: Option<[u8; 33]>,
    pub(crate) migration_members: Option<BTreeSet<[u8; 32]>>,
    pub(crate) migration_peers: Vec<Peer>,
    recent_messages: HashMap<[u8; 33], VecDeque<RecentMessage>>,
    recent_control_messages: HashMap<[u8; 33], VecDeque<u64>>,
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
            peer_table_authority: None,
            migration_members: None,
            migration_peers: Vec::new(),
            recent_messages: HashMap::new(),
            recent_control_messages: HashMap::new(),
        }
    }

    pub(crate) fn x_only_public_key(compressed_public_key: &[u8; 33]) -> [u8; 32] {
        let canonical = Self::canonical_identity_key(compressed_public_key);
        canonical[1..]
            .try_into()
            .expect("a compressed public key has a 32-byte x coordinate")
    }

    pub(crate) fn canonical_identity_key(compressed_public_key: &[u8; 33]) -> [u8; 33] {
        PublicKey::from_slice(compressed_public_key)
            .expect("Storm peers contain validated public keys")
            .x_only_public_key()
            .0
            .public_key(Parity::Even)
            .serialize()
    }

    pub(crate) fn migration_contains(&self, compressed_public_key: &[u8; 33]) -> bool {
        self.migration_members.as_ref().is_some_and(|members| {
            members.contains(&Self::x_only_public_key(compressed_public_key))
        })
    }

    pub(crate) fn peer_identities_unique(peers: &[Peer]) -> bool {
        peers
            .iter()
            .map(|peer| Self::x_only_public_key(&peer.compressed_public_key))
            .collect::<BTreeSet<_>>()
            .len()
            == peers.len()
    }

    pub(crate) fn migration_peer_identities_valid(&self) -> bool {
        let Some(members) = &self.migration_members else {
            return false;
        };
        let identities = self
            .migration_peers
            .iter()
            .map(|peer| Self::x_only_public_key(&peer.compressed_public_key))
            .collect::<BTreeSet<_>>();

        identities.len() == self.migration_peers.len() && identities.is_subset(members)
    }

    pub(crate) fn migration_peer_table_matches_members(&self) -> bool {
        let Some(members) = &self.migration_members else {
            return false;
        };
        let identities = self
            .migration_peers
            .iter()
            .map(|peer| Self::x_only_public_key(&peer.compressed_public_key))
            .collect::<BTreeSet<_>>();

        identities.len() == self.migration_peers.len() && &identities == members
    }

    pub(crate) fn migration_ready(&self) -> bool {
        if !self.migration_peer_table_matches_members() {
            return false;
        }
        let members = self
            .migration_members
            .as_ref()
            .expect("migration is staged");
        let connected = self
            .migration_peers
            .iter()
            .filter(|peer| {
                peer.compressed_public_key == self.initializer_public_key
                    || peer.status == PeerStatus::Active
            })
            .map(|peer| Self::x_only_public_key(&peer.compressed_public_key))
            .collect::<BTreeSet<_>>();

        &connected == members
    }

    pub(crate) fn migration_table_complete(&self) -> bool {
        if !self.migration_peer_table_matches_members() {
            return false;
        }
        let members = self
            .migration_members
            .as_ref()
            .expect("migration is staged");
        let known = self
            .migration_peers
            .iter()
            .filter(|peer| peer.socket_address.is_some())
            .map(|peer| Self::x_only_public_key(&peer.compressed_public_key))
            .collect::<BTreeSet<_>>();

        &known == members
    }

    pub(crate) fn connection_plan(&self) -> ConnectionPlan {
        self.connection_plan_for(&self.peers)
    }

    pub(crate) fn migration_connection_plan(&self) -> Option<ConnectionPlan> {
        self.migration_members
            .as_ref()
            .map(|_| self.connection_plan_for(&self.migration_peers))
    }

    fn connection_plan_for(&self, peers: &[Peer]) -> ConnectionPlan {
        let listener_port = self
            .peers
            .iter()
            .find(|peer| peer.compressed_public_key == self.initializer_public_key)
            .and_then(|peer| peer.socket_address.as_deref())
            .and_then(|address| address.parse::<SocketAddr>().ok())
            .map(|address| address.port());
        let targets = peers
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

    pub(crate) fn accepts_unregistered_connection(&self, compressed_public_key: &[u8; 33]) -> bool {
        self.migration_contains(compressed_public_key)
            || (!self.discovery_table_received
                && self.peers.iter().any(|peer| {
                    peer.compressed_public_key != self.initializer_public_key && peer.discovery
                }))
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

        if message.header.payload_id <= 3 {
            let recent = self
                .recent_control_messages
                .entry(peer_public_key)
                .or_default();
            recent.retain(|timestamp| {
                received_at.saturating_sub(*timestamp)
                    < constants::CONTROL_MESSAGE_RATE_WINDOW.as_secs()
            });
            if recent.len() >= constants::CONTROL_MESSAGE_RATE_CAPACITY {
                return Err(Error::MessageRateLimit);
            }
            recent.push_back(received_at);
            return Ok(());
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
