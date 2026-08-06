use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
use tokio::{sync::RwLock, task::JoinHandle};

use crate::{CustomMsg, Error, Peer, PeerStatus, StormMessage, state::StormState};

type CustomHandlerFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
pub(crate) type CustomHandler =
    Arc<dyn Fn(CustomMsg, StormContext) -> CustomHandlerFuture + Send + Sync>;

/// A Storm node and the listener task it owns.
///
/// Construct a node with [`Storm::discovery`], [`Storm::discoverable`], or
/// [`Storm::from_peers`], then call [`Storm::start`].
pub struct Storm {
    pub(crate) inner: Arc<RwLock<StormState>>,
    pub(crate) listener_address: Option<SocketAddr>,
    pub(crate) listener_handle: Option<JoinHandle<()>>,
}

/// A cloneable interface for operations that are safe inside message handlers.
#[derive(Clone)]
pub struct StormHandle {
    pub(crate) inner: Arc<RwLock<StormState>>,
}

/// Information about the peer that sent a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageContext {
    /// Compressed secp256k1 public key of the sending peer.
    pub peer_public_key: [u8; 33],
}

/// Node and message state passed to a custom message handler.
#[derive(Clone)]
pub struct StormContext {
    /// Cloneable node handle for sending messages and reading peers.
    pub storm_handle: StormHandle,
    /// Original encoded Storm message received from the peer.
    pub storm_message: StormMessage,
    /// Identity of the peer that sent the message.
    pub message_context: MessageContext,
}

impl Storm {
    /// Creates a discovery coordinator from the complete registered peer set.    
    pub fn discovery(initializer_secret_key: SecretKey, registered_peers: Vec<Peer>) -> Self {
        let mut state = Self::state_with_local_peer(initializer_secret_key, registered_peers);

        for peer in &mut state.peers {
            if peer.compressed_public_key == state.initializer_public_key {
                peer.status = PeerStatus::Controlled;
            } else if peer.status != PeerStatus::Banned {
                peer.status = PeerStatus::Inactive;
            }
            peer.discovery = peer.compressed_public_key == state.initializer_public_key;
        }

        Self::from_state(state)
    }

    /// Creates a node that obtains its peer table from one discovery peer.
    ///
    /// The discovery peer must identify a remote peer and contain a socket
    /// address.
    pub fn discoverable(
        initializer_secret_key: SecretKey,
        mut discovery_peer: Peer,
    ) -> Result<Self, Error> {
        let initializer_public_key = initializer_secret_key
            .public_key(&Secp256k1::new())
            .serialize();
        if discovery_peer.compressed_public_key == initializer_public_key {
            return Err(Error::DiscoveryPeerIsLocal);
        }
        if discovery_peer.socket_address.is_none() {
            return Err(Error::DiscoveryPeerAddressMissing);
        }

        discovery_peer.status = PeerStatus::Inactive;
        discovery_peer.discovery = true;
        let mut state = Self::state_with_local_peer(initializer_secret_key, vec![discovery_peer]);
        let local_peer = state
            .peers
            .iter_mut()
            .find(|peer| peer.compressed_public_key == state.initializer_public_key)
            .expect("local peer is inserted during initialization");
        local_peer.status = PeerStatus::Controlled;
        local_peer.discovery = false;

        Ok(Self::from_state(state))
    }

    /// Creates a node from a previously known or persisted peer table.
    pub fn from_peers(initializer_secret_key: SecretKey, peers: Vec<Peer>) -> Self {
        let mut state = Self::state_with_local_peer(initializer_secret_key, peers);

        for peer in &mut state.peers {
            peer.discovery = false;
            if peer.compressed_public_key == state.initializer_public_key {
                peer.status = PeerStatus::Controlled;
            } else if peer.status != PeerStatus::Banned {
                peer.status = PeerStatus::Inactive;
            }
        }

        Self::from_state(state)
    }

    fn state_with_local_peer(initializer_secret_key: SecretKey, peers: Vec<Peer>) -> StormState {
        let mut state = StormState::new(initializer_secret_key, peers);

        if !state
            .peers
            .iter()
            .any(|peer| peer.compressed_public_key == state.initializer_public_key)
        {
            state
                .peers
                .insert(0, Peer::new(state.initializer_public_key));
        }

        state
    }

    fn from_state(state: StormState) -> Self {
        Self {
            inner: Arc::new(RwLock::new(state)),
            listener_address: None,
            listener_handle: None,
        }
    }

    /// Returns a snapshot of the current peer table.
    pub async fn peers(&self) -> Vec<Peer> {
        self.inner.read().await.peers.clone()
    }

    /// Installs the handler invoked for incoming [`CustomMsg`] values.
    ///
    /// Registering another handler replaces the previous one. The supplied
    /// [`StormContext`] contains a [`StormHandle`] that can send replies.
    pub async fn register_custom_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(CustomMsg, StormContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.inner.write().await.custom_handler = Some(Arc::new(move |message, context| {
            Box::pin(handler(message, context))
        }));
    }

    /// Queues a message for each connected peer in `peers`.
    ///
    /// Returns an error if any requested peer has no active connection.
    pub async fn send_message(
        &self,
        message: StormMessage,
        peers: &[PublicKey],
    ) -> Result<(), Error> {
        let peers = peers.iter().map(PublicKey::serialize).collect::<Vec<_>>();
        self.handle()
            .send_message_by_public_keys(message, &peers)
            .await
    }

    pub(crate) fn handle(&self) -> StormHandle {
        StormHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}
