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
    /// TCP endpoint (`IP:port`, `[IPv6]:port`, or `hostname:port`), when known.
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

    pub(crate) fn update_observed_address(&mut self, address: std::net::SocketAddr) {
        if self
            .socket_address
            .as_ref()
            .is_none_or(|known| known.parse::<std::net::SocketAddr>().is_ok())
        {
            self.socket_address = Some(address.to_string());
        }
    }
}

/// Validates an IP or DNS TCP endpoint without performing a DNS lookup.
pub fn validate_socket_address(address: &str) -> Result<(), crate::Error> {
    socket_address_port(address)
        .map(|_| ())
        .ok_or_else(|| crate::Error::InvalidPeerAddress(address.to_string()))
}

pub(crate) fn socket_address_port(address: &str) -> Option<u16> {
    if let Ok(address) = address.parse::<std::net::SocketAddr>() {
        return Some(address.port());
    }

    let (hostname, port) = address.rsplit_once(':')?;
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    port.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_accepts_ip_and_dns_without_resolving() {
        for address in [
            "127.0.0.1:9000",
            "[::1]:9000",
            "localhost:9000",
            "coordinator.storm.svc.cluster.local:9000",
            "node-1.storm.example.:9000",
        ] {
            assert_eq!(socket_address_port(address), Some(9000), "{address}");
        }
    }

    #[test]
    fn endpoint_rejects_malformed_addresses() {
        for address in [
            "",
            "coordinator",
            ":9000",
            "http://coordinator:9000",
            "coordinator:65536",
            "coordinator:+9000",
            "coordinator:",
            "bad host:9000",
            "-node:9000",
            "node..example:9000",
            "999.999.999.999:9000",
            "::1:9000",
        ] {
            assert_eq!(socket_address_port(address), None, "{address}");
        }
    }
}
