/// Current relationship between the local node and a known peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    /// The local node controls this peer entry.
    Controlled,
    /// An authenticated connection to the peer is active.
    Active,
    /// The peer is known but not currently connected.
    Inactive,
    /// Connections to and from the peer are prohibited.
    Banned,
}

/// Connection and discovery information for a Storm participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Compressed secp256k1 public key that identifies the peer.
    pub compressed_public_key: [u8; 33],
    /// TCP address used to connect to the peer, when known.
    pub socket_address: Option<String>,
    /// Last received-message time as seconds since the Unix epoch.
    pub last_seen: Option<u64>,
    /// Current connection policy and state.
    pub status: PeerStatus,
    /// Whether this peer currently participates in discovery coordination.
    pub discovery: bool,
}

impl Peer {
    /// Creates an inactive peer with no known address or activity.
    pub fn new(compressed_public_key: [u8; 33]) -> Self {
        Self {
            compressed_public_key,
            socket_address: None,
            last_seen: None,
            status: PeerStatus::Inactive,
            discovery: false,
        }
    }
}
