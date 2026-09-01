use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use secp256k1::{
    Keypair, Parity, PublicKey as SigningPublicKey, SecretKey as SigningSecretKey, XOnlyPublicKey,
    musig::{
        AggregatedNonce, KeyAggCache, PartialSignature, PublicNonce, SecretNonce, Session,
        SessionSecretRand, new_nonce_pair,
    },
};
use secp256k1_zkp::PublicKey as TransportPublicKey;
use storm::{Peer, PeerStatus, Storm, StormContext, StormHandle};
use storm_tree::{NodePublicKey, StormTree, StormTreeBranch};
use tokio::{
    sync::{Mutex, oneshot},
    time::{Instant, timeout},
};

use super::message::{
    NodeMessage, NodeMessageKind, PartialSignaturesMessage, SigningNoncesMessage, TestNodeMessage,
};

const SIGNING_SESSION_TIMEOUT: Duration = Duration::from_secs(60);
type OutboundNodeMessage = (NodeMessage, Vec<[u8; 33]>);

/// A completed temporary signing request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningResult {
    /// Hash of the successful Test [`NodeMessage`].
    pub request_hash: [u8; 32],
    /// Storm Tree branch used by the successful attempt.
    pub signing_storm_tree_branch: StormTreeBranch,
    /// One BIP-340 MuSig2 signature for each requested message hash.
    pub signatures: Vec<[u8; 64]>,
}

/// Errors produced by higher-level message handling and signing.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("the network needs at least three configured members for signing")]
    TooFewMembers,
    #[error("no connected Storm Tree branch is available")]
    NoAvailableBranch,
    #[error("all available signer branches failed")]
    SigningFailed,
    #[error("invalid signing message: {0}")]
    InvalidMessage(String),
    #[error("unauthorized node message: {0}")]
    UnauthorizedMessage(String),
    #[error("Storm Tree operation failed: {0}")]
    StormTree(#[from] storm_tree::StormTreeError),
    #[error("Storm transport failed: {0}")]
    Storm(#[from] storm::Error),
    #[error("message encoding failed: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("Storm message encoding failed: {0}")]
    StormMessage(#[from] storm::MessageError),
}

struct SignerContribution {
    nonces: Option<Vec<PublicNonce>>,
    partial_signatures: Option<Vec<PartialSignature>>,
}

struct SigningSession {
    requestor: NodePublicKey,
    request: TestNodeMessage,
    signers: Vec<NodePublicKey>,
    contributions: BTreeMap<NodePublicKey, SignerContribution>,
    secret_nonces: Option<Vec<SecretNonce>>,
    completion: Option<oneshot::Sender<SigningResult>>,
    created_at: Instant,
}

struct SigningState {
    secret_key: SigningSecretKey,
    local_node: NodePublicKey,
    member_transport_keys: BTreeMap<NodePublicKey, [u8; 33]>,
    tree: Option<StormTree>,
    sessions: HashMap<[u8; 32], SigningSession>,
}

#[derive(Clone)]
pub(crate) struct Signing {
    state: Arc<Mutex<SigningState>>,
}

impl Signing {
    pub(crate) async fn new(storm: &Storm, secret_key: [u8; 32]) -> Self {
        let peers = storm.peers().await;
        let state = Arc::new(Mutex::new(SigningState::new(secret_key, &peers)));
        let cleanup_state = Arc::downgrade(&state);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SIGNING_SESSION_TIMEOUT).await;
                let Some(state) = cleanup_state.upgrade() else {
                    return;
                };
                state.lock().await.remove_expired_sessions();
            }
        });

        Self { state }
    }

    pub(crate) async fn storm_tree_root(&self) -> Result<[u8; 32], SigningError> {
        self.state
            .lock()
            .await
            .tree
            .as_ref()
            .map(StormTree::root)
            .ok_or(SigningError::TooFewMembers)
    }

    pub(crate) async fn sign_test(
        &self,
        storm: &Storm,
        message_hashes: Vec<[u8; 32]>,
    ) -> Result<SigningResult, SigningError> {
        self.sign_test_inner(storm, message_hashes, SIGNING_SESSION_TIMEOUT, None)
            .await
    }

    pub(crate) async fn sign_test_with_delay(
        &self,
        storm: &Storm,
        message_hashes: Vec<[u8; 32]>,
        attempt_timeout: Duration,
        delayed_signer: NodePublicKey,
        delay: Duration,
    ) -> Result<SigningResult, SigningError> {
        self.sign_test_inner(
            storm,
            message_hashes,
            attempt_timeout,
            Some((delayed_signer, delay)),
        )
        .await
    }

    pub(crate) async fn selected_signers(
        &self,
        storm: &Storm,
    ) -> Result<Vec<NodePublicKey>, SigningError> {
        let peers = storm.peers().await;
        let mut state = self.state.lock().await;
        state.refresh_members(&peers)?;
        let branch = state
            .select_branch(&peers, &BTreeSet::new())
            .ok_or(SigningError::NoAvailableBranch)?;
        Ok(state
            .tree
            .as_ref()
            .expect("tree exists when a branch was selected")
            .nodes_for_branch(&branch)?
            .to_vec())
    }

    async fn sign_test_inner(
        &self,
        storm: &Storm,
        message_hashes: Vec<[u8; 32]>,
        attempt_timeout: Duration,
        delay: Option<(NodePublicKey, Duration)>,
    ) -> Result<SigningResult, SigningError> {
        let mut attempted = BTreeSet::new();

        loop {
            let peers = storm.peers().await;
            let (request_hash, signers, requestor, initial, nonce_message, receiver) = {
                let mut state = self.state.lock().await;
                state.refresh_members(&peers)?;
                state.remove_expired_sessions();
                let Some(branch) = state.select_branch(&peers, &attempted) else {
                    return Err(if attempted.is_empty() {
                        SigningError::NoAvailableBranch
                    } else {
                        SigningError::SigningFailed
                    });
                };
                attempted.insert(branch);
                let signers = state
                    .tree
                    .as_ref()
                    .expect("tree exists when a branch was selected")
                    .nodes_for_branch(&branch)?
                    .to_vec();
                let request = TestNodeMessage {
                    signing_storm_tree_branch: branch,
                    message_hashes: message_hashes.clone(),
                    delayed_signer: delay.map(|(signer, _)| signer),
                    delay_millis: delay
                        .map(|(_, duration)| duration.as_millis().min(u128::from(u64::MAX)) as u64)
                        .unwrap_or(0),
                };
                let initial = NodeMessage::new(NodeMessageKind::Test, None, &request)?;
                let request_hash = initial.hash()?;
                let (sender, receiver) = oneshot::channel();
                let requestor = state.local_node;
                let nonce_message =
                    state.start_session(request_hash, requestor, request, Some(sender))?;
                (
                    request_hash,
                    signers,
                    requestor,
                    initial,
                    nonce_message,
                    receiver,
                )
            };

            let recipients = self.remote_transport_keys(&signers).await?;
            if send_from_storm(storm, initial, &recipients).await.is_err() {
                self.remove_attempt(request_hash).await;
                continue;
            }
            if let Some(nonce_message) = nonce_message {
                let recipients = self
                    .session_recipient_transport_keys(&signers, requestor)
                    .await?;
                if send_from_storm(storm, nonce_message, &recipients)
                    .await
                    .is_err()
                {
                    self.remove_attempt(request_hash).await;
                    continue;
                }
            }

            match timeout(attempt_timeout, receiver).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(_)) | Err(_) => self.remove_attempt(request_hash).await,
            }
        }
    }

    async fn remove_attempt(&self, request_hash: [u8; 32]) {
        self.state.lock().await.sessions.remove(&request_hash);
    }

    async fn remote_transport_keys(
        &self,
        nodes: &[NodePublicKey],
    ) -> Result<Vec<[u8; 33]>, SigningError> {
        let state = self.state.lock().await;
        nodes
            .iter()
            .filter(|node| **node != state.local_node)
            .map(|node| state.transport_key(node))
            .collect()
    }

    async fn session_recipient_transport_keys(
        &self,
        signers: &[NodePublicKey],
        requestor: NodePublicKey,
    ) -> Result<Vec<[u8; 33]>, SigningError> {
        let state = self.state.lock().await;
        recipient_transport_keys(&state, signers, requestor)
    }

    pub(crate) async fn handle_test(
        &self,
        message: NodeMessage,
        context: &StormContext,
    ) -> Result<(), SigningError> {
        let request: TestNodeMessage = message.decode_payload()?;
        let request_hash = message.hash()?;
        let delay = if request.delayed_signer == Some(self.state.lock().await.local_node) {
            Duration::from_millis(request.delay_millis)
        } else {
            Duration::ZERO
        };
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let peers = context.storm_handle.peers().await;
        let sender = node_key(&context.message_context.peer_public_key)?;
        let outbound = {
            let mut state = self.state.lock().await;
            state.refresh_members(&peers)?;
            state.remove_expired_sessions();
            state.start_session(request_hash, sender, request, None)?
        };
        if let Some(outbound) = outbound {
            send_from_handle(
                &context.storm_handle,
                outbound,
                self.session_recipients(request_hash).await?,
            )
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn handle_signing_nonces(
        &self,
        message: NodeMessage,
        context: &StormContext,
    ) -> Result<(), SigningError> {
        let linked_to = required_link(&message)?;
        let payload: SigningNoncesMessage = message.decode_payload()?;
        let sender = node_key(&context.message_context.peer_public_key)?;
        let outbound = self
            .state
            .lock()
            .await
            .accept_nonces(linked_to, sender, payload)?;
        if let Some((message, recipients)) = outbound {
            send_from_handle(&context.storm_handle, message, recipients).await?;
        }
        Ok(())
    }

    pub(crate) async fn handle_partial_signatures(
        &self,
        message: NodeMessage,
        context: &StormContext,
    ) -> Result<(), SigningError> {
        let linked_to = required_link(&message)?;
        let payload: PartialSignaturesMessage = message.decode_payload()?;
        let sender = node_key(&context.message_context.peer_public_key)?;
        self.state
            .lock()
            .await
            .accept_partial_signatures(linked_to, sender, payload)
    }

    async fn session_recipients(
        &self,
        request_hash: [u8; 32],
    ) -> Result<Vec<[u8; 33]>, SigningError> {
        let state = self.state.lock().await;
        let session = state
            .sessions
            .get(&request_hash)
            .ok_or_else(|| SigningError::InvalidMessage("signing session disappeared".into()))?;
        recipient_transport_keys(&state, &session.signers, session.requestor)
    }
}

impl SigningState {
    fn new(secret_key: [u8; 32], peers: &[Peer]) -> Self {
        let mut secret_key = SigningSecretKey::from_secret_bytes(secret_key)
            .expect("the transport signer key was already validated");
        let public_key = SigningPublicKey::from_secret_key(&secret_key);
        let (xonly, parity) = public_key.x_only_public_key();
        if parity == Parity::Odd {
            secret_key = secret_key.negate();
        }
        let local_node = xonly.serialize();
        let mut state = Self {
            secret_key,
            local_node,
            member_transport_keys: BTreeMap::new(),
            tree: None,
            sessions: HashMap::new(),
        };
        let _ = state.refresh_members(peers);
        state
    }

    fn refresh_members(&mut self, peers: &[Peer]) -> Result<(), SigningError> {
        let keys = peer_keys(peers)?;
        if keys == self.member_transport_keys {
            return Ok(());
        }
        self.tree = if keys.len() >= 3 {
            Some(StormTree::new(keys.keys().copied().collect())?)
        } else {
            None
        };
        self.member_transport_keys = keys;
        Ok(())
    }

    fn select_branch(
        &self,
        peers: &[Peer],
        attempted: &BTreeSet<StormTreeBranch>,
    ) -> Option<StormTreeBranch> {
        let tree = self.tree.as_ref()?;
        let active = peers
            .iter()
            .filter(|peer| matches!(peer.status, PeerStatus::Controlled | PeerStatus::Active))
            .filter_map(|peer| node_key(&peer.compressed_public_key).ok())
            .collect::<BTreeSet<_>>();
        tree.branches().find(|branch| {
            !attempted.contains(branch)
                && tree.nodes_for_branch(branch).is_ok_and(|nodes| {
                    nodes.contains(&self.local_node) && nodes.iter().all(|n| active.contains(n))
                })
        })
    }

    fn start_session(
        &mut self,
        request_hash: [u8; 32],
        requestor: NodePublicKey,
        request: TestNodeMessage,
        completion: Option<oneshot::Sender<SigningResult>>,
    ) -> Result<Option<NodeMessage>, SigningError> {
        if self.sessions.contains_key(&request_hash) {
            return Ok(None);
        }
        let signers = self
            .tree
            .as_ref()
            .ok_or(SigningError::TooFewMembers)?
            .nodes_for_branch(&request.signing_storm_tree_branch)?
            .to_vec();
        let mut contributions = signers
            .iter()
            .map(|signer| {
                (
                    *signer,
                    SignerContribution {
                        nonces: None,
                        partial_signatures: None,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let (secret_nonces, nonce_message) = if signers.contains(&self.local_node) {
            let cache = key_agg_cache(&signers)?;
            let local_public_key = SigningPublicKey::from_secret_key(&self.secret_key);
            let mut secret_nonces = Vec::with_capacity(request.message_hashes.len());
            let mut public_nonces = Vec::with_capacity(request.message_hashes.len());
            for message_hash in &request.message_hashes {
                let session_secret = SessionSecretRand::from_rng(&mut secp256k1::rand::rng());
                let (secret_nonce, public_nonce) = new_nonce_pair(
                    session_secret,
                    Some(&cache),
                    Some(self.secret_key),
                    local_public_key,
                    Some(message_hash),
                    None,
                );
                secret_nonces.push(secret_nonce);
                public_nonces.push(public_nonce);
            }
            contributions
                .get_mut(&self.local_node)
                .expect("local signer belongs to the branch")
                .nonces = Some(public_nonces.clone());
            let payload = SigningNoncesMessage {
                signer: self.local_node,
                nonces: public_nonces
                    .iter()
                    .map(|nonce| nonce.serialize().to_vec())
                    .collect(),
            };
            (
                Some(secret_nonces),
                Some(NodeMessage::new(
                    NodeMessageKind::SigningNonces,
                    Some(request_hash),
                    &payload,
                )?),
            )
        } else {
            (None, None)
        };
        self.sessions.insert(
            request_hash,
            SigningSession {
                requestor,
                request,
                signers,
                contributions,
                secret_nonces,
                completion,
                created_at: Instant::now(),
            },
        );
        Ok(nonce_message)
    }

    fn accept_nonces(
        &mut self,
        request_hash: [u8; 32],
        sender: NodePublicKey,
        message: SigningNoncesMessage,
    ) -> Result<Option<OutboundNodeMessage>, SigningError> {
        if sender != message.signer {
            return Err(SigningError::InvalidMessage(
                "nonce contributor does not match authenticated sender".into(),
            ));
        }
        let secret_key = self.secret_key;
        let local_node = self.local_node;
        let Some(session) = self.sessions.get_mut(&request_hash) else {
            return Ok(None);
        };
        if message.nonces.len() != session.request.message_hashes.len() {
            return Err(SigningError::InvalidMessage("wrong nonce count".into()));
        }
        let contribution = session
            .contributions
            .get_mut(&sender)
            .ok_or_else(|| SigningError::InvalidMessage("nonce from a non-signer".into()))?;
        if contribution.nonces.is_some() {
            return Ok(None);
        }
        contribution.nonces = Some(
            message
                .nonces
                .iter()
                .map(|nonce| {
                    let bytes: &[u8; 66] = nonce.as_slice().try_into().map_err(|_| {
                        SigningError::InvalidMessage("invalid public nonce size".into())
                    })?;
                    PublicNonce::from_byte_array(bytes)
                        .map_err(|_| SigningError::InvalidMessage("invalid public nonce".into()))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        if !session.signers.contains(&local_node)
            || session.secret_nonces.is_none()
            || !session
                .contributions
                .values()
                .all(|contribution| contribution.nonces.is_some())
        {
            return Ok(None);
        }

        let cache = key_agg_cache(&session.signers)?;
        let keypair = Keypair::from_secret_key(&secret_key);
        let secret_nonces = session
            .secret_nonces
            .take()
            .expect("secret nonces were checked above");
        let mut partial_signatures = Vec::with_capacity(session.request.message_hashes.len());
        for (index, (message_hash, secret_nonce)) in session
            .request
            .message_hashes
            .iter()
            .zip(secret_nonces)
            .enumerate()
        {
            let signing_session = musig_session(session, &cache, index, message_hash)?;
            partial_signatures.push(signing_session.partial_sign(secret_nonce, &keypair, &cache));
        }
        session
            .contributions
            .get_mut(&local_node)
            .expect("local signer belongs to the branch")
            .partial_signatures = Some(partial_signatures.clone());
        let payload = PartialSignaturesMessage {
            signer: local_node,
            partial_signatures: partial_signatures
                .iter()
                .map(PartialSignature::serialize)
                .collect(),
        };
        let mut recipient_nodes = session.signers.iter().copied().collect::<BTreeSet<_>>();
        recipient_nodes.insert(session.requestor);
        recipient_nodes.remove(&local_node);
        let recipients = recipient_nodes
            .iter()
            .map(|node| {
                self.member_transport_keys
                    .get(node)
                    .copied()
                    .ok_or_else(|| {
                        SigningError::InvalidMessage("signer is not a configured member".into())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some((
            NodeMessage::new(
                NodeMessageKind::PartialSignatures,
                Some(request_hash),
                &payload,
            )?,
            recipients,
        )))
    }

    fn accept_partial_signatures(
        &mut self,
        request_hash: [u8; 32],
        sender: NodePublicKey,
        message: PartialSignaturesMessage,
    ) -> Result<(), SigningError> {
        if sender != message.signer {
            return Err(SigningError::InvalidMessage(
                "partial-signature contributor does not match authenticated sender".into(),
            ));
        }
        let local_node = self.local_node;
        let Some(session) = self.sessions.get_mut(&request_hash) else {
            return Ok(());
        };
        if message.partial_signatures.len() != session.request.message_hashes.len() {
            return Err(SigningError::InvalidMessage(
                "wrong partial signature count".into(),
            ));
        }
        let contribution = session
            .contributions
            .get_mut(&sender)
            .ok_or_else(|| SigningError::InvalidMessage("signature from a non-signer".into()))?;
        if contribution.partial_signatures.is_some() {
            return Ok(());
        }
        contribution.partial_signatures = Some(
            message
                .partial_signatures
                .iter()
                .map(|signature| {
                    PartialSignature::from_byte_array(signature).map_err(|_| {
                        SigningError::InvalidMessage("invalid partial signature".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
        if session.requestor != local_node
            || !session
                .contributions
                .values()
                .all(|contribution| contribution.partial_signatures.is_some())
        {
            return Ok(());
        }

        let cache = key_agg_cache(&session.signers)?;
        let mut signatures = Vec::with_capacity(session.request.message_hashes.len());
        for (index, message_hash) in session.request.message_hashes.iter().enumerate() {
            let signing_session = musig_session(session, &cache, index, message_hash)?;
            let partials = session
                .signers
                .iter()
                .map(|signer| {
                    &session.contributions[signer]
                        .partial_signatures
                        .as_ref()
                        .expect("all partial signatures were checked above")[index]
                })
                .collect::<Vec<_>>();
            let signature = signing_session
                .partial_sig_agg(&partials)
                .verify(&cache.agg_pk(), message_hash)
                .map_err(|_| {
                    SigningError::InvalidMessage("aggregate signature failed verification".into())
                })?;
            signatures.push(signature.to_byte_array());
        }
        if let Some(completion) = session.completion.take() {
            let _ = completion.send(SigningResult {
                request_hash,
                signing_storm_tree_branch: session.request.signing_storm_tree_branch,
                signatures,
            });
        }
        self.sessions.remove(&request_hash);
        Ok(())
    }

    fn remove_expired_sessions(&mut self) {
        self.sessions
            .retain(|_, session| session.created_at.elapsed() < SIGNING_SESSION_TIMEOUT);
    }

    fn transport_key(&self, node: &NodePublicKey) -> Result<[u8; 33], SigningError> {
        self.member_transport_keys
            .get(node)
            .copied()
            .ok_or_else(|| SigningError::InvalidMessage("signer is not a configured member".into()))
    }
}

fn musig_session(
    session: &SigningSession,
    cache: &KeyAggCache,
    index: usize,
    message_hash: &[u8; 32],
) -> Result<Session, SigningError> {
    let nonces = session
        .signers
        .iter()
        .map(|signer| {
            session.contributions[signer]
                .nonces
                .as_ref()
                .and_then(|nonces| nonces.get(index))
                .ok_or_else(|| SigningError::InvalidMessage("missing signer nonce".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Session::new(
        cache,
        AggregatedNonce::new(&nonces),
        message_hash,
    ))
}

fn key_agg_cache(signers: &[NodePublicKey]) -> Result<KeyAggCache, SigningError> {
    let public_keys = signers
        .iter()
        .map(|key| {
            XOnlyPublicKey::from_byte_array(*key)
                .map(|key| key.public_key(Parity::Even))
                .map_err(|_| SigningError::InvalidMessage("invalid signer public key".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(KeyAggCache::new(&public_keys.iter().collect::<Vec<_>>()))
}

fn peer_keys(peers: &[Peer]) -> Result<BTreeMap<NodePublicKey, [u8; 33]>, SigningError> {
    peers
        .iter()
        .map(|peer| {
            Ok((
                node_key(&peer.compressed_public_key)?,
                peer.compressed_public_key,
            ))
        })
        .collect()
}

fn node_key(compressed: &[u8; 33]) -> Result<NodePublicKey, SigningError> {
    SigningPublicKey::from_slice(compressed)
        .map(|key| key.x_only_public_key().0.serialize())
        .map_err(|_| SigningError::InvalidMessage("invalid member public key".into()))
}

fn required_link(message: &NodeMessage) -> Result<[u8; 32], SigningError> {
    message
        .linked_to
        .ok_or_else(|| SigningError::InvalidMessage("signing contribution is not linked".into()))
}

fn recipient_transport_keys(
    state: &SigningState,
    signers: &[NodePublicKey],
    requestor: NodePublicKey,
) -> Result<Vec<[u8; 33]>, SigningError> {
    let mut nodes = signers.iter().copied().collect::<BTreeSet<_>>();
    nodes.insert(requestor);
    nodes.remove(&state.local_node);
    nodes.iter().map(|node| state.transport_key(node)).collect()
}

async fn send_from_storm(
    storm: &Storm,
    message: NodeMessage,
    recipients: &[[u8; 33]],
) -> Result<(), SigningError> {
    let recipients = transport_public_keys(recipients)?;
    storm
        .send_message(message.into_storm_message()?, &recipients)
        .await?;
    Ok(())
}

async fn send_from_handle(
    handle: &StormHandle,
    message: NodeMessage,
    recipients: Vec<[u8; 33]>,
) -> Result<(), SigningError> {
    if recipients.is_empty() {
        return Ok(());
    }
    let recipients = transport_public_keys(&recipients)?;
    handle
        .send_message(message.into_storm_message()?, &recipients)
        .await?;
    Ok(())
}

fn transport_public_keys(recipients: &[[u8; 33]]) -> Result<Vec<TransportPublicKey>, SigningError> {
    recipients
        .iter()
        .map(|key| {
            TransportPublicKey::from_slice(key)
                .map_err(|_| SigningError::InvalidMessage("invalid transport public key".into()))
        })
        .collect()
}
