use std::collections::{BTreeSet, HashMap, VecDeque};

use secp256k1_zkp::{Parity, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::{CustomHandler, Error, Peer, PeerStatus, StormMessage, constants};

/// X-only public keys that identify Storm members.
type Identities = BTreeSet<[u8; 32]>;

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
    pub(crate) address_overrides: HashMap<[u8; 33], String>,
    pub(crate) listener_port: Option<u16>,
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
            address_overrides: HashMap::new(),
            listener_port: None,
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

    fn identities<'a>(peers: impl IntoIterator<Item = &'a Peer>) -> Identities {
        peers
            .into_iter()
            .map(|peer| Self::x_only_public_key(&peer.compressed_public_key))
            .collect()
    }

    pub(crate) fn peer_identities_unique(peers: &[Peer]) -> bool {
        Self::identities(peers).len() == peers.len()
    }

    /// The staged members and the identities of the staged peer table, if a
    /// migration is staged and no identity repeats in the table.
    fn unique_migration_identities(&self) -> Option<(&Identities, Identities)> {
        let members = self.migration_members.as_ref()?;
        let identities = Self::identities(&self.migration_peers);
        (identities.len() == self.migration_peers.len()).then_some((members, identities))
    }

    pub(crate) fn migration_peer_identities_valid(&self) -> bool {
        self.unique_migration_identities()
            .is_some_and(|(members, identities)| identities.is_subset(members))
    }

    pub(crate) fn migration_peer_table_matches_members(&self) -> bool {
        self.unique_migration_identities()
            .is_some_and(|(members, identities)| &identities == members)
    }

    /// Whether the staged peers that pass `include` are exactly the staged members.
    fn migration_members_among(&self, include: impl Fn(&Peer) -> bool) -> bool {
        if !self.migration_peer_table_matches_members() {
            return false;
        }
        let members = self
            .migration_members
            .as_ref()
            .expect("migration is staged");

        &Self::identities(self.migration_peers.iter().filter(|peer| include(peer))) == members
    }

    pub(crate) fn migration_ready(&self) -> bool {
        self.migration_members_among(|peer| {
            peer.compressed_public_key == self.initializer_public_key
                || peer.status == PeerStatus::Active
        })
    }

    pub(crate) fn migration_table_complete(&self) -> bool {
        self.migration_members_among(|peer| peer.socket_address.is_some())
    }

    /// The checks a staged peer table passes before it can be read or activated.
    pub(crate) fn ensure_migration_activatable(&self) -> Result<(), Error> {
        if self.migration_members.is_none() {
            return Err(Error::MigrationNotStaged);
        }
        if !self.migration_peer_identities_valid() {
            return Err(Error::InvalidMigrationPeerTable);
        }
        if !self.migration_ready()
            && (self.migration_contains(&self.initializer_public_key)
                || !self.migration_table_complete())
        {
            return Err(Error::MigrationNotReady);
        }
        if !self.migration_peer_table_matches_members() {
            return Err(Error::InvalidMigrationPeerTable);
        }
        Ok(())
    }

    pub(crate) fn connection_plan(&self) -> ConnectionPlan {
        self.connection_plan_for(&self.peers)
    }

    pub(crate) fn apply_address_overrides(&mut self) {
        for peer in self.peers.iter_mut().chain(&mut self.migration_peers) {
            if let Some(address) = self.address_overrides.get(&peer.compressed_public_key) {
                peer.socket_address = Some(address.clone());
            }
        }
    }

    pub(crate) fn migration_connection_plan(&self) -> Option<ConnectionPlan> {
        self.migration_members
            .as_ref()
            .map(|_| self.connection_plan_for(&self.migration_peers))
    }

    fn connection_plan_for(&self, peers: &[Peer]) -> ConnectionPlan {
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
            listener_port: self.listener_port,
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
