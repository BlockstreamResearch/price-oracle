use crate::MessageError;

/// Errors produced while configuring, connecting, or exchanging Storm messages.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A socket or other I/O operation failed.
    #[error("Device I/O error occurred: {0}")]
    Io(#[from] std::io::Error),
    /// A Noise transport frame exceeded its 16-bit length limit.
    #[error("Message too large to send")]
    MessageTooLarge,
    /// A Noise handshake or transport operation failed.
    #[error("Noise protocol error occurred: {0}")]
    Noise(#[from] snow::Error),
    /// Application message encoding, decoding, or sizing failed.
    #[error("Application message error occurred: {0}")]
    Message(#[from] MessageError),
    /// The Noise handshake did not provide the remote static public key.
    #[error("Remote public key is absent")]
    AbsentRemotePublicKey,
    /// A peer was not permitted to establish or use a connection.
    #[error("Unauthorized connection attempt")]
    UnauthorizedConnection,
    /// A second connection was attempted for an already-connected peer.
    #[error("Peer already has an active connection")]
    PeerAlreadyConnected,
    /// No active connection exists for the peer identified by the hexadecimal key.
    #[error("No active connection exists for peer {0}")]
    PeerNotConnected(String),
    /// The peer connection closed before the message could be queued.
    #[error("Connection to peer {0} closed before the message could be queued")]
    PeerConnectionClosed(String),
    /// The peer identified by the hexadecimal key is not in the peer table.
    #[error("Peer {0} is not registered")]
    PeerNotFound(String),
    /// A discoverable node was configured to discover through itself.
    #[error("Discovery peer must not be the local peer")]
    DiscoveryPeerIsLocal,
    /// The configured discovery peer has no socket address.
    #[error("Discovery peer has no socket address")]
    DiscoveryPeerAddressMissing,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_errors_use_hex_keys() {
        let key = "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337";

        assert_eq!(
            Error::PeerNotConnected(key.to_string()).to_string(),
            "No active connection exists for peer 02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
        );
    }
}
