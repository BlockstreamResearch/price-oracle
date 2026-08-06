use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use secp256k1_zkp::PublicKey;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock, mpsc},
};

use crate::{
    Error, MessageContext, PeerStatus, Storm, StormHandle, StormMessage, constants, crypto,
    message, message_handlers, state::StormState,
};

impl Storm {
    /// Stops the listener, closes all connections, and marks active peers inactive.
    pub async fn shutdown(&mut self) {
        if let Some(listener_handle) = self.listener_handle.take() {
            listener_handle.abort();
        }
        self.listener_address = None;
        let mut state = self.inner.write().await;
        state.connections.clear();
        for peer in &mut state.peers {
            if peer.status == PeerStatus::Active {
                peer.status = PeerStatus::Inactive;
            }
        }
    }

    async fn listen(&mut self, address: Option<String>) -> Result<(), Error> {
        if self.listener_handle.is_some() {
            return Ok(());
        }

        let address = address.unwrap_or(constants::STORM_AUTO_BIND_SOCKET_ADDRESS.to_string());

        let listener = TcpListener::bind(address).await?;
        let addr = listener.local_addr()?;

        {
            let mut state = self.inner.write().await;
            let initializer_public_key = state.initializer_public_key;
            if let Some(peer) = state
                .peers
                .iter_mut()
                .find(|peer| peer.compressed_public_key == initializer_public_key)
            {
                peer.socket_address = Some(addr.to_string());
            }
        }

        let state = Arc::clone(&self.inner);

        let handle = tokio::spawn(async move {
            Self::run_listener(listener, state).await;
        });

        self.listener_address = Some(addr);
        self.listener_handle = Some(handle);

        Ok(())
    }

    /// Starts listening and attempts connections to all eligible known peers.
    ///
    /// `address` selects the local TCP bind address. When it is `None`, Storm
    /// binds to an operating-system-assigned port on all interfaces. Calling
    /// this method again reuses the existing listener and retries peer connections.
    pub async fn start(&mut self, address: Option<String>) -> Result<(), Error> {
        self.listen(address).await?;
        self.handle().connect_to_peers().await
    }

    async fn run_listener(listener: TcpListener, state: Arc<RwLock<StormState>>) {
        loop {
            match listener.accept().await {
                Ok((stream, peer_address)) => {
                    let state = Arc::clone(&state);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, peer_address, state).await {
                            log::error!("Connection with {} failed: {e}", peer_address);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept connection: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    pub(crate) async fn handle_connection(
        mut stream: TcpStream,
        peer_address: SocketAddr,
        state: Arc<RwLock<StormState>>,
    ) -> Result<(), Error> {
        let initializer_secret_key = {
            let state = state.read().await;
            state.initializer_secret_key.secret_bytes()
        };

        let (transport, remote_public_key, advertised_port) =
            Self::perform_responder_handshake(&mut stream, &initializer_secret_key).await?;

        let advertised_address = advertised_port
            .map(|port| SocketAddr::new(peer_address.ip(), port))
            .unwrap_or(peer_address);
        let receiver =
            Self::claim_connection(&state, remote_public_key, Some(advertised_address)).await?;

        let handle = StormHandle {
            inner: Arc::clone(&state),
        };
        handle.broadcast_discovery_table_if_ready().await?;
        handle.finish_client_discovery_if_connected().await;

        let result =
            Self::run_connection(stream, transport, remote_public_key, &state, receiver).await;

        Self::release_connection(&state, remote_public_key).await;

        result
    }

    pub(crate) async fn claim_connection(
        state: &Arc<RwLock<StormState>>,
        peer_public_key: [u8; 33],
        peer_address: Option<SocketAddr>,
    ) -> Result<mpsc::UnboundedReceiver<Vec<u8>>, Error> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let mut state = state.write().await;
        let peer_index = state
            .peers
            .iter()
            .position(|peer| peer.compressed_public_key == peer_public_key);

        if state.connections.contains_key(&peer_public_key) {
            return Err(Error::PeerAlreadyConnected);
        }

        if let Some(peer_index) = peer_index {
            let peer = &mut state.peers[peer_index];
            if peer.status == PeerStatus::Banned {
                return Err(Error::UnauthorizedConnection);
            }
            if peer.status == PeerStatus::Active {
                return Err(Error::PeerAlreadyConnected);
            }

            peer.status = PeerStatus::Active;
            if let Some(peer_address) = peer_address {
                peer.socket_address = Some(peer_address.to_string());
            }
        } else if !state.accepts_unregistered_connections() {
            return Err(Error::UnauthorizedConnection);
        }

        state.connections.insert(peer_public_key, sender);

        Ok(receiver)
    }

    pub(crate) async fn release_connection(
        state: &Arc<RwLock<StormState>>,
        peer_public_key: [u8; 33],
    ) {
        let mut state = state.write().await;
        state.connections.remove(&peer_public_key);
        if let Some(peer) = state
            .peers
            .iter_mut()
            .find(|peer| peer.compressed_public_key == peer_public_key)
            && peer.status == PeerStatus::Active
        {
            peer.status = PeerStatus::Inactive;
        }
    }

    pub(crate) fn run_connection<'a>(
        stream: TcpStream,
        transport: snow::TransportState,
        peer_public_key: [u8; 33],
        state: &'a Arc<RwLock<StormState>>,
        mut receiver: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(async move {
            let (mut reader, mut writer) = stream.into_split();
            let transport = Arc::new(Mutex::new(transport));
            let reader_transport = Arc::clone(&transport);

            let receive_messages = async {
                let mut buffer = vec![0u8; 65_535];
                let mut decoder = message::MessageDecoder::new();

                loop {
                    let ciphertext = read_frame(&mut reader).await?;
                    let plaintext_length = reader_transport
                        .lock()
                        .await
                        .read_message(&ciphertext, &mut buffer)?;
                    let plaintext = &buffer[..plaintext_length];

                    for message in decoder.push(plaintext)? {
                        Self::handle_message(state, peer_public_key, message).await?;
                    }
                }
            };

            let send_messages = async {
                let mut buffer = vec![0u8; 65_535];

                while let Some(message) = receiver.recv().await {
                    for chunk in message.chunks(constants::NOISE_MAX_PLAINTEXT_SIZE) {
                        let ciphertext_length =
                            transport.lock().await.write_message(chunk, &mut buffer)?;
                        write_frame(&mut writer, &buffer[..ciphertext_length]).await?;
                    }
                }

                Ok(())
            };

            tokio::select! {
                result = receive_messages => result,
                result = send_messages => result,
            }
        })
    }

    pub(crate) async fn handle_message(
        state: &Arc<RwLock<StormState>>,
        peer_public_key: [u8; 33],
        message: StormMessage,
    ) -> Result<(), Error> {
        let context = {
            let mut state = state.write().await;
            let peer = state
                .peers
                .iter_mut()
                .find(|peer| peer.compressed_public_key == peer_public_key)
                .ok_or(Error::UnauthorizedConnection)?;
            if peer.status == PeerStatus::Banned {
                return Err(Error::UnauthorizedConnection);
            }

            peer.last_seen = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );

            MessageContext { peer_public_key }
        };

        let handle = StormHandle {
            inner: Arc::clone(state),
        };
        let is_error = message_handlers::is_error(&message);
        let request_payload_id = message.header.payload_id;
        match message_handlers::storm_message(&handle, context, message).await {
            Ok(()) => Ok(()),
            Err((code, error)) => {
                log::error!(
                    "Failed to handle message from peer {}: {error}",
                    hex::encode(peer_public_key)
                );
                if is_error {
                    return Ok(());
                }

                let response = message_handlers::error::message(code, error, request_payload_id)?;
                handle
                    .send_message_by_public_keys(response, &[context.peer_public_key])
                    .await
            }
        }
    }

    pub(crate) async fn perform_responder_handshake(
        stream: &mut TcpStream,
        initializer_secret_key: &[u8],
    ) -> Result<(snow::TransportState, [u8; 33], Option<u16>), Error> {
        let builder = crypto::noise_builder();

        let mut noise = builder
            .local_private_key(initializer_secret_key)
            .expect("first initialization of the local private key")
            .prologue(constants::NOISE_PROLOGUE)
            .expect("first initialization of the prologue")
            .build_responder()
            .expect("should build valid handshake");

        let incoming = read_frame(stream).await?;

        let mut buffer = vec![0u8; 65_535];
        let payload_length = noise.read_message(&incoming, &mut buffer)?;
        let advertised_port = match payload_length {
            0 => None,
            2 => Some(u16::from_be_bytes([buffer[0], buffer[1]])),
            _ => return Err(Error::UnauthorizedConnection),
        };

        let response_len = noise.write_message(&[], &mut buffer)?;
        write_frame(stream, &buffer[..response_len]).await?;

        let remote_public_key = PublicKey::from_slice(
            noise
                .get_remote_static()
                .ok_or(Error::AbsentRemotePublicKey)?,
        )
        .map_err(|_| Error::UnauthorizedConnection)?
        .serialize();

        Ok((
            noise.into_transport_mode()?,
            remote_public_key,
            advertised_port,
        ))
    }

    pub(crate) async fn perform_initiator_handshake(
        stream: &mut TcpStream,
        initializer_secret_key: &[u8],
        peer_public_key: &[u8; 33],
        listener_port: Option<u16>,
    ) -> Result<snow::TransportState, Error> {
        let mut noise = crypto::noise_builder()
            .local_private_key(initializer_secret_key)
            .expect("first initialization of the local private key")
            .remote_public_key(peer_public_key)
            .expect("first initialization of the remote public key")
            .prologue(constants::NOISE_PROLOGUE)
            .expect("first initialization of the prologue")
            .build_initiator()
            .expect("should build valid handshake");
        let mut buffer = vec![0u8; 65_535];

        let listener_port = listener_port.map(u16::to_be_bytes);
        let message_length = noise.write_message(
            listener_port.as_ref().map_or(&[], |port| port.as_slice()),
            &mut buffer,
        )?;
        write_frame(stream, &buffer[..message_length]).await?;

        let response = read_frame(stream).await?;
        noise.read_message(&response, &mut buffer)?;

        Ok(noise.into_transport_mode()?)
    }
}

impl Drop for Storm {
    fn drop(&mut self) {
        if let Some(listener_handle) = self.listener_handle.take() {
            listener_handle.abort();
        }

        if let Ok(mut state) = self.inner.try_write() {
            state.connections.clear();
            for peer in &mut state.peers {
                if peer.status == PeerStatus::Active {
                    peer.status = PeerStatus::Inactive;
                }
            }
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let inner = Arc::clone(&self.inner);
            runtime.spawn(async move {
                let mut state = inner.write().await;
                state.connections.clear();
                for peer in &mut state.peers {
                    if peer.status == PeerStatus::Active {
                        peer.status = PeerStatus::Inactive;
                    }
                }
            });
        }
    }
}

pub(crate) async fn read_frame<R>(stream: &mut R) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 2];
    stream.read_exact(&mut length_bytes).await?;

    let length = usize::from(u16::from_be_bytes(length_bytes));
    let mut message = vec![0_u8; length];
    stream.read_exact(&mut message).await?;

    Ok(message)
}

pub(crate) async fn write_frame<W>(stream: &mut W, message: &[u8]) -> Result<(), Error>
where
    W: AsyncWrite + Unpin,
{
    let length = u16::try_from(message.len()).map_err(|_| Error::MessageTooLarge)?;

    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(message).await?;

    Ok(())
}
