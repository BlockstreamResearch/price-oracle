use std::sync::Arc;

use secp256k1_zkp::PublicKey;
use tokio::net::TcpStream;

use crate::{
    Error, MessageContext, Peer, PeerStatus, Storm, StormHandle, StormMessage, message_handlers,
    state::ConnectionPlan,
};

impl StormHandle {
    /// Returns a snapshot of the current peer table.
    pub async fn peers(&self) -> Vec<Peer> {
        self.inner.read().await.peers.clone()
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
        self.send_message_by_public_keys(message, &peers).await
    }

    /// Queues a message for the peer identified by `context`.
    pub async fn send_response(
        &self,
        message: StormMessage,
        context: &MessageContext,
    ) -> Result<(), Error> {
        self.send_message_by_public_keys(message, &[context.peer_public_key])
            .await
    }

    pub(crate) async fn send_message_by_public_keys(
        &self,
        message: StormMessage,
        peers: &[[u8; 33]],
    ) -> Result<(), Error> {
        let framed_message = message.to_framed_bytes()?;
        let connections = {
            let state = self.inner.read().await;
            let mut connections = Vec::with_capacity(peers.len());

            for peer_public_key in peers {
                let connection = state
                    .connections
                    .get(peer_public_key)
                    .ok_or_else(|| Error::PeerNotConnected(hex::encode(peer_public_key)))?;

                if connection.is_closed() {
                    return Err(Error::PeerNotConnected(hex::encode(peer_public_key)));
                }

                connections.push((*peer_public_key, connection.clone()));
            }

            connections
        };

        for (peer_public_key, connection) in connections {
            connection
                .send(framed_message.clone())
                .map_err(|_| Error::PeerConnectionClosed(hex::encode(peer_public_key)))?;
        }

        Ok(())
    }

    pub(crate) async fn connect_to_peers(&self) -> Result<(), Error> {
        self.connect_known_peers().await;
        self.broadcast_discovery_table_if_ready().await?;
        Ok(())
    }

    pub(crate) async fn connect_known_peers(&self) {
        let plan = self.inner.read().await.connection_plan();
        self.connect_targets(&plan).await;
        self.finish_client_discovery_if_connected().await;
    }

    async fn connect_targets(&self, plan: &ConnectionPlan) {
        for target in plan
            .targets
            .iter()
            .filter(|target| plan.should_connect(target))
        {
            if let Err(error) = self
                .connect_peer(
                    target.public_key,
                    target.socket_address.clone(),
                    &plan.initializer_secret_key,
                    plan.listener_port,
                )
                .await
            {
                log::debug!(
                    "Failed to connect to peer {}: {error}",
                    hex::encode(target.public_key)
                );
            }
        }
    }

    async fn connect_peer(
        &self,
        peer_public_key: [u8; 33],
        socket_address: String,
        initializer_secret_key: &[u8],
        listener_port: Option<u16>,
    ) -> Result<(), Error> {
        let mut stream = TcpStream::connect(socket_address).await?;
        let transport = Storm::perform_initiator_handshake(
            &mut stream,
            initializer_secret_key,
            &peer_public_key,
            listener_port,
        )
        .await?;
        let receiver = Storm::claim_connection(&self.inner, peer_public_key, None).await?;
        self.finish_client_discovery_if_connected().await;
        let state = Arc::clone(&self.inner);

        tokio::spawn(async move {
            let result =
                Storm::run_connection(stream, transport, peer_public_key, &state, receiver).await;
            Storm::release_connection(&state, peer_public_key).await;

            if let Err(error) = result {
                log::error!(
                    "Connection with {} failed: {error}",
                    hex::encode(peer_public_key)
                );
            }
        });

        Ok(())
    }

    pub(crate) async fn broadcast_discovery_table_if_ready(&self) -> Result<(), Error> {
        let broadcast = {
            let state = self.inner.read().await;
            let local_public_key = state.initializer_public_key;
            let Some(local_peer) = state
                .peers
                .iter()
                .find(|peer| peer.compressed_public_key == local_public_key)
            else {
                return Ok(());
            };

            if local_peer.status != PeerStatus::Controlled || !local_peer.discovery {
                return Ok(());
            }

            let all_connected = state.peers.iter().all(|peer| {
                peer.socket_address.is_some()
                    && (peer.compressed_public_key == local_public_key
                        || peer.status == PeerStatus::Active
                        || peer.status == PeerStatus::Banned)
            });
            if !all_connected {
                return Ok(());
            }

            let recipients = state
                .peers
                .iter()
                .filter(|peer| {
                    peer.compressed_public_key != local_public_key
                        && peer.status == PeerStatus::Active
                })
                .map(|peer| peer.compressed_public_key)
                .collect::<Vec<_>>();
            let message = message_handlers::peers_socket_info::message(&state.peers)
                .map_err(|(_, message)| Error::Io(std::io::Error::other(message)))?;

            Some((local_public_key, recipients, message))
        };

        if let Some((local_public_key, recipients, message)) = broadcast {
            self.send_message_by_public_keys(message, &recipients)
                .await?;

            let mut state = self.inner.write().await;
            if let Some(local_peer) = state
                .peers
                .iter_mut()
                .find(|peer| peer.compressed_public_key == local_public_key)
            {
                local_peer.discovery = false;
            }
        }

        Ok(())
    }

    pub(crate) async fn finish_client_discovery_if_connected(&self) {
        let mut state = self.inner.write().await;
        let local_public_key = state.initializer_public_key;
        let is_discovery_coordinator = state.peers.iter().any(|peer| {
            peer.compressed_public_key == local_public_key
                && peer.status == PeerStatus::Controlled
                && peer.discovery
        });
        if is_discovery_coordinator {
            return;
        }
        if !state.discovery_table_received {
            return;
        }

        let all_connected = state.peers.iter().all(|peer| {
            peer.compressed_public_key == local_public_key
                || peer.status == PeerStatus::Active
                || peer.status == PeerStatus::Banned
        });
        if all_connected {
            for peer in &mut state.peers {
                peer.discovery = false;
            }
        }
    }
}
