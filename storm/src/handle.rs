use std::{collections::BTreeSet, sync::Arc};

use secp256k1_zkp::PublicKey;
use tokio::net::TcpStream;
use tokio::task::{JoinError, JoinSet};
use tokio::time::timeout;

use crate::{
    Error, MessageContext, Peer, PeerStatus, Storm, StormHandle, StormMessage, constants,
    message_handlers, state::ConnectionPlan,
};

impl StormHandle {
    /// Restricts migration peer tables to one Noise-authenticated transport identity.
    pub async fn set_peer_table_authority(&self, authority: [u8; 33]) -> Result<(), Error> {
        PublicKey::from_slice(&authority).map_err(|_| Error::UnauthorizedConnection)?;
        self.inner.write().await.peer_table_authority = Some(authority);
        Ok(())
    }

    /// Stages a target member set while retaining the active peer table.
    pub async fn begin_member_migration(&self, members: BTreeSet<[u8; 32]>) -> Result<(), Error> {
        {
            let mut state = self.inner.write().await;
            if let Some(staged) = &state.migration_members {
                if staged != &members {
                    return Err(Error::MigrationAlreadyStaged);
                }
                if !state.migration_peer_identities_valid() {
                    return Err(Error::InvalidMigrationPeerTable);
                }
            } else {
                let mut candidates = state
                    .peers
                    .iter()
                    .chain(&state.migration_peers)
                    .filter(|peer| {
                        members.contains(&crate::state::StormState::x_only_public_key(
                            &peer.compressed_public_key,
                        ))
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                candidates.sort_by_key(|peer| peer.compressed_public_key);
                candidates.dedup_by_key(|peer| peer.compressed_public_key);
                if !crate::state::StormState::peer_identities_unique(&candidates) {
                    return Err(Error::InvalidMigrationPeerTable);
                }
                state.migration_peers = candidates;
                state.migration_members = Some(members);
            }
        }

        self.connect_migration_peers().await;
        self.request_migration_peer_table().await?;
        self.broadcast_discovery_table_if_ready().await?;

        Ok(())
    }

    /// Returns whether every staged member has an authenticated connection.
    pub async fn member_migration_ready(&self) -> bool {
        self.inner.read().await.migration_ready()
    }

    /// Returns whether this node may process migration execution messages.
    pub async fn local_member_migration_ready(&self) -> bool {
        let state = self.inner.read().await;
        if state.migration_contains(&state.initializer_public_key) {
            state.migration_ready()
        } else {
            state.migration_table_complete()
        }
    }

    /// Returns the complete staged peer table when it is ready to activate.
    pub async fn member_migration_peers(&self) -> Result<Vec<Peer>, Error> {
        let state = self.inner.read().await;
        if state.migration_members.is_none() {
            return Err(Error::MigrationNotStaged);
        }
        if !state.migration_peer_identities_valid() {
            return Err(Error::InvalidMigrationPeerTable);
        }
        if !state.migration_ready()
            && (state.migration_contains(&state.initializer_public_key)
                || !state.migration_table_complete())
        {
            return Err(Error::MigrationNotReady);
        }
        if !state.migration_peer_table_matches_members() {
            return Err(Error::InvalidMigrationPeerTable);
        }
        Ok(state.migration_peers.clone())
    }

    /// Activates the staged peer table after every target member is connected.
    pub async fn activate_member_migration(&self) -> Result<Vec<Peer>, Error> {
        let mut state = self.inner.write().await;
        if state.migration_members.is_none() {
            return Err(Error::MigrationNotStaged);
        }
        if !state.migration_peer_identities_valid() {
            return Err(Error::InvalidMigrationPeerTable);
        }
        if !state.migration_ready()
            && (state.migration_contains(&state.initializer_public_key)
                || !state.migration_table_complete())
        {
            return Err(Error::MigrationNotReady);
        }
        if !state.migration_peer_table_matches_members() {
            return Err(Error::InvalidMigrationPeerTable);
        }

        state.peers = std::mem::take(&mut state.migration_peers);
        state.migration_members = None;
        let active_keys = state
            .peers
            .iter()
            .map(|peer| peer.compressed_public_key)
            .collect::<BTreeSet<_>>();
        state.connections.retain(|key, _| active_keys.contains(key));

        Ok(state.peers.clone())
    }

    /// Discards a staged member set without changing the active network.
    pub async fn cancel_member_migration(&self) {
        let mut state = self.inner.write().await;
        state.migration_members = None;
    }

    /// Returns a snapshot of the current peer table.
    pub async fn peers(&self) -> Vec<Peer> {
        self.inner.read().await.peers.clone()
    }

    /// Returns whether the local transport identity belongs to the active peer table.
    pub async fn is_local_member(&self) -> bool {
        let state = self.inner.read().await;
        state
            .peers
            .iter()
            .any(|peer| peer.compressed_public_key == state.initializer_public_key)
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
                .try_send(framed_message.clone())
                .map_err(|error| match error {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        Error::PeerQueueFull(hex::encode(peer_public_key))
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        Error::PeerConnectionClosed(hex::encode(peer_public_key))
                    }
                })?;
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
        self.connect_targets(&plan, false).await;
        self.finish_client_discovery_if_connected().await;
    }

    pub(crate) async fn connect_migration_peers(&self) {
        let plan = self.inner.read().await.migration_connection_plan();
        if let Some(plan) = plan {
            self.connect_targets(&plan, false).await;
        }
    }

    pub(crate) async fn reconnect_disconnected_peers(&self, reverse: bool) {
        let plan = self.inner.read().await.connection_plan();
        self.connect_targets(&plan, reverse).await;
        let migration_plan = self.inner.read().await.migration_connection_plan();
        if let Some(migration_plan) = migration_plan {
            self.connect_targets(&migration_plan, reverse).await;
        }
        if let Err(error) = self.request_migration_peer_table().await {
            log::debug!("Failed to request migration peer table: {error}");
        }
        self.finish_client_discovery_if_connected().await;
    }

    async fn request_migration_peer_table(&self) -> Result<(), Error> {
        let recipients = {
            let state = self.inner.read().await;
            if state.migration_ready() {
                return Ok(());
            }
            state
                .peers
                .iter()
                .filter(|peer| {
                    peer.compressed_public_key != state.initializer_public_key
                        && peer.status == PeerStatus::Active
                        && state.migration_contains(&peer.compressed_public_key)
                })
                .map(|peer| peer.compressed_public_key)
                .collect::<Vec<_>>()
        };
        if recipients.is_empty() {
            return Ok(());
        }

        self.send_message_by_public_keys(
            message_handlers::ask_peers_socket_info::message(),
            &recipients,
        )
        .await
    }

    async fn connect_targets(&self, plan: &ConnectionPlan, reverse: bool) {
        let mut attempts = JoinSet::new();

        for target in plan
            .targets
            .iter()
            .filter(|target| plan.should_connect(target, reverse))
        {
            let handle = self.clone();
            let peer_public_key = target.public_key;
            let socket_address = target.socket_address.clone();
            let initializer_secret_key = plan.initializer_secret_key;
            let listener_port = plan.listener_port;
            attempts.spawn(async move {
                let result = handle
                    .connect_peer(
                        peer_public_key,
                        socket_address,
                        &initializer_secret_key,
                        listener_port,
                    )
                    .await;
                (peer_public_key, result)
            });

            if attempts.len() >= constants::MAX_CONCURRENT_OUTBOUND_CONNECTIONS
                && let Some(result) = attempts.join_next().await
            {
                Self::log_connection_attempt(result);
            }
        }

        while let Some(result) = attempts.join_next().await {
            Self::log_connection_attempt(result);
        }
    }

    fn log_connection_attempt(result: Result<([u8; 33], Result<(), Error>), JoinError>) {
        match result {
            Ok((_, Ok(()))) => {}
            Ok((peer_public_key, Err(error))) => {
                log::debug!(
                    "Failed to connect to peer {}: {error}",
                    hex::encode(peer_public_key)
                );
            }
            Err(error) => log::error!("Peer connection task failed: {error}"),
        }
    }

    async fn connect_peer(
        &self,
        peer_public_key: [u8; 33],
        socket_address: String,
        initializer_secret_key: &[u8],
        listener_port: Option<u16>,
    ) -> Result<(), Error> {
        let mut stream = timeout(
            constants::CONNECT_TIMEOUT,
            TcpStream::connect(socket_address),
        )
        .await
        .map_err(|_| Error::ConnectionTimeout("connecting to a peer"))??;
        let transport = timeout(
            constants::HANDSHAKE_TIMEOUT,
            Storm::perform_initiator_handshake(
                &mut stream,
                initializer_secret_key,
                &peer_public_key,
                listener_port,
            ),
        )
        .await
        .map_err(|_| Error::ConnectionTimeout("performing the initiator handshake"))??;
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
        let migration_broadcast = {
            let state = self.inner.read().await;
            if state.migration_ready() {
                let recipients = state
                    .migration_peers
                    .iter()
                    .chain(&state.peers)
                    .filter(|peer| {
                        peer.compressed_public_key != state.initializer_public_key
                            && peer.status == PeerStatus::Active
                    })
                    .map(|peer| peer.compressed_public_key)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let message = message_handlers::peers_socket_info::message(&state.migration_peers)
                    .map_err(|(_, message)| Error::Io(std::io::Error::other(message)))?;
                Some((recipients, message))
            } else {
                None
            }
        };

        if let Some((recipients, message)) = migration_broadcast {
            self.send_message_by_public_keys(message, &recipients)
                .await?;
        }

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
