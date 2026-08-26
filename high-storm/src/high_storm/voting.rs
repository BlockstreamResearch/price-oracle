use std::{collections::BTreeSet, sync::Arc};

use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey, schnorr};
use secp256k1_zkp::PublicKey as TransportPublicKey;
use storm::{Peer, PeerStatus, StormContext, StormHandle};
use tokio::sync::Mutex;

use crate::db::voting::{StoredVotingRequest, VotingStore};

use super::message::{
    ApproveVotingRequest, MergeStormEyes, NetworkVoteKind, NetworkVoteRequest, NodeMessage,
    NodeMessageKind, SplitStormEye, UpdateNetworkMembers, VotingSyncApproval, VotingSyncMessage,
    VotingSyncRequest,
};

pub const VOTING_TIMEOUT_BLOCKS: u64 = 10_080;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VotingStatus {
    Pending,
    Approved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VotingApproval {
    pub public_key: [u8; 32],
    pub block_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VotingRequest {
    pub message_hash: [u8; 32],
    pub request: NetworkVoteRequest,
    pub block_height: u64,
    pub status: VotingStatus,
    pub approvals: Vec<VotingApproval>,
}

#[derive(Debug, thiserror::Error)]
pub enum VotingError {
    #[error("invalid voting request: {0}")]
    InvalidRequest(String),
    #[error("invalid voting approval: {0}")]
    InvalidApproval(String),
    #[error("voting request {0} does not exist")]
    UnknownRequest(String),
    #[error("voting request {0} already exists")]
    DuplicateRequest(String),
    #[error("node {0} has already approved this voting request")]
    DuplicateApproval(String),
    #[error(transparent)]
    Store(#[from] crate::db::voting::Error),
    #[error(transparent)]
    Encoding(#[from] postcard::Error),
    #[error(transparent)]
    StormMessage(#[from] storm::MessageError),
    #[error(transparent)]
    Storm(#[from] storm::Error),
}

#[derive(Clone)]
pub(crate) struct Voting {
    store: VotingStore,
    keypair: Keypair,
    operations: Arc<Mutex<()>>,
}

impl Voting {
    pub(crate) fn new(secret_key: [u8; 32], store: VotingStore) -> Self {
        let secret_key = SecretKey::from_secret_bytes(secret_key)
            .expect("the transport signer key was already validated");
        Self {
            store,
            keypair: Keypair::from_secret_key(&secret_key),
            operations: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) async fn create(
        &self,
        storm: &StormHandle,
        request: NetworkVoteRequest,
        block_height: u64,
    ) -> Result<[u8; 32], VotingError> {
        let peers = storm.peers().await;
        validate_request(&request, &peers)?;
        let message = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request)?;
        let hash = message.hash()?;
        let encoded = postcard::to_stdvec(&message)?;
        let _guard = self.operations.lock().await;
        if !self
            .store
            .insert_request(hash, &encoded, block_height)
            .await?
        {
            return Err(VotingError::DuplicateRequest(hex::encode(hash)));
        }
        send_from_storm(storm, message, &active_remote_peers(&peers)).await?;
        Ok(hash)
    }

    pub(crate) async fn approve(
        &self,
        storm: &StormHandle,
        request_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(), VotingError> {
        let peers = storm.peers().await;
        let local_key = self.keypair.x_only_public_key().0.serialize();
        let approval = ApproveVotingRequest {
            public_key: local_key,
            signature: schnorr::sign(&request_hash, &self.keypair)
                .to_byte_array()
                .to_vec(),
        };
        let message = NodeMessage::new(
            NodeMessageKind::ApproveVotingRequest,
            Some(request_hash),
            &approval,
        )?;
        self.accept_approval(
            message.clone(),
            approval,
            request_hash,
            block_height,
            &peers,
        )
        .await?;
        send_from_storm(storm, message, &active_remote_peers(&peers)).await
    }

    pub(crate) async fn synchronize(&self, storm: &StormHandle) -> Result<(), VotingError> {
        let peers = storm.peers().await;
        let request = VotingSyncMessage {
            is_response: false,
            requests: Vec::new(),
        };
        let message = NodeMessage::new(NodeMessageKind::AskAboutVotings, None, &request)?;
        send_from_storm(storm, message, &active_remote_peers(&peers)).await
    }

    pub(crate) async fn handle_request(
        &self,
        message: NodeMessage,
        context: &StormContext,
        block_height: u64,
    ) -> Result<(), VotingError> {
        if message.linked_to.is_some() {
            return Err(VotingError::InvalidRequest(
                "a voting request cannot link to another message".into(),
            ));
        }
        let request: NetworkVoteRequest = message.decode_payload()?;
        let peers = context.storm_handle.peers().await;
        validate_request(&request, &peers)?;
        let hash = message.hash()?;
        let encoded = postcard::to_stdvec(&message)?;
        let _guard = self.operations.lock().await;
        self.store
            .insert_request(hash, &encoded, block_height)
            .await?;
        Ok(())
    }

    pub(crate) async fn handle_approval(
        &self,
        message: NodeMessage,
        context: &StormContext,
        block_height: u64,
    ) -> Result<(), VotingError> {
        let request_hash = message.linked_to.ok_or_else(|| {
            VotingError::InvalidApproval("approval does not link to a voting request".into())
        })?;
        let approval: ApproveVotingRequest = message.decode_payload()?;
        let peers = context.storm_handle.peers().await;
        self.accept_approval(message, approval, request_hash, block_height, &peers)
            .await
    }

    pub(crate) async fn handle_synchronization(
        &self,
        message: NodeMessage,
        context: &StormContext,
    ) -> Result<(), VotingError> {
        if message.linked_to.is_some() {
            return Err(VotingError::InvalidRequest(
                "ask-about-votings cannot link to another message".into(),
            ));
        }
        let sync: VotingSyncMessage = message.decode_payload()?;
        if sync.is_response {
            self.accept_synchronized(sync.requests, &context.storm_handle.peers().await)
                .await
        } else {
            if !sync.requests.is_empty() {
                return Err(VotingError::InvalidRequest(
                    "an ask-about-votings request cannot contain voting records".into(),
                ));
            }
            let requests = self
                .store
                .list()
                .await?
                .into_iter()
                .map(|request| VotingSyncRequest {
                    message_hash: request.message_hash,
                    message: request.message,
                    block_height: request.block_height,
                    approvals: request
                        .approvals
                        .into_iter()
                        .map(|approval| VotingSyncApproval {
                            message: approval.message,
                            block_height: approval.block_height,
                        })
                        .collect(),
                })
                .collect();
            let response = VotingSyncMessage {
                is_response: true,
                requests,
            };
            let response = NodeMessage::new(NodeMessageKind::AskAboutVotings, None, &response)?;
            send_from_handle(
                &context.storm_handle,
                response,
                context.message_context.peer_public_key,
            )
            .await
        }
    }

    async fn accept_synchronized(
        &self,
        requests: Vec<VotingSyncRequest>,
        peers: &[Peer],
    ) -> Result<(), VotingError> {
        for synchronized in requests {
            let message: NodeMessage = postcard::from_bytes(&synchronized.message)?;
            if message.decoded_kind() != Some(NodeMessageKind::NetworkVoteRequest)
                || message.linked_to.is_some()
                || message.hash()? != synchronized.message_hash
            {
                return Err(VotingError::InvalidRequest(
                    "synchronized voting request metadata does not match its message".into(),
                ));
            }
            let request: NetworkVoteRequest = message.decode_payload()?;
            validate_request(&request, peers)?;
            {
                let _guard = self.operations.lock().await;
                self.store
                    .insert_request(
                        synchronized.message_hash,
                        &synchronized.message,
                        synchronized.block_height,
                    )
                    .await?;
            }

            for synchronized_approval in synchronized.approvals {
                let approval_message: NodeMessage =
                    postcard::from_bytes(&synchronized_approval.message)?;
                if approval_message.decoded_kind() != Some(NodeMessageKind::ApproveVotingRequest)
                    || approval_message.linked_to != Some(synchronized.message_hash)
                {
                    return Err(VotingError::InvalidApproval(
                        "synchronized approval does not match its voting request".into(),
                    ));
                }
                let approval: ApproveVotingRequest = approval_message.decode_payload()?;
                match self
                    .accept_approval(
                        approval_message,
                        approval,
                        synchronized.message_hash,
                        synchronized_approval.block_height,
                        peers,
                    )
                    .await
                {
                    Ok(()) | Err(VotingError::DuplicateApproval(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    async fn accept_approval(
        &self,
        message: NodeMessage,
        approval: ApproveVotingRequest,
        request_hash: [u8; 32],
        block_height: u64,
        peers: &[Peer],
    ) -> Result<(), VotingError> {
        let public_key = XOnlyPublicKey::from_byte_array(approval.public_key)
            .map_err(|error| VotingError::InvalidApproval(error.to_string()))?;
        if !member_keys(peers)?.contains(&approval.public_key) {
            return Err(VotingError::InvalidApproval(format!(
                "{} is not a network member",
                hex::encode(approval.public_key)
            )));
        }
        let signature_bytes: [u8; 64] =
            approval
                .signature
                .try_into()
                .map_err(|signature: Vec<u8>| {
                    VotingError::InvalidApproval(format!(
                        "signature has {} bytes instead of 64",
                        signature.len()
                    ))
                })?;
        let signature = schnorr::Signature::from_byte_array(signature_bytes);
        schnorr::verify(&signature, &request_hash, &public_key)
            .map_err(|error| VotingError::InvalidApproval(error.to_string()))?;

        let _guard = self.operations.lock().await;
        if self.store.get(request_hash).await?.is_none() {
            return Err(VotingError::UnknownRequest(hex::encode(request_hash)));
        }
        let required = required_approvals(peers.len());
        let encoded = postcard::to_stdvec(&message)?;
        if !self
            .store
            .insert_approval(
                request_hash,
                approval.public_key,
                &encoded,
                block_height,
                required,
            )
            .await?
        {
            return Err(VotingError::DuplicateApproval(hex::encode(
                approval.public_key,
            )));
        }
        Ok(())
    }

    pub(crate) async fn get(&self, hash: [u8; 32]) -> Result<Option<VotingRequest>, VotingError> {
        self.store.get(hash).await?.map(decode_stored).transpose()
    }

    pub(crate) async fn list(&self) -> Result<Vec<VotingRequest>, VotingError> {
        self.store
            .list()
            .await?
            .into_iter()
            .map(decode_stored)
            .collect()
    }

    pub(crate) async fn remove_expired(&self, block_height: u64) -> Result<u64, VotingError> {
        Ok(self
            .store
            .delete_expired(block_height, VOTING_TIMEOUT_BLOCKS)
            .await?)
    }
}

fn validate_request(request: &NetworkVoteRequest, peers: &[Peer]) -> Result<(), VotingError> {
    match NetworkVoteKind::from_id(request.kind) {
        Some(NetworkVoteKind::UpdateNetworkMembers) => {
            let update: UpdateNetworkMembers = postcard::from_bytes(&request.payload)?;
            let current = member_keys(peers)?;
            let accepted = checked_unique_keys(&update.to_accept, "accepted")?;
            let removed = checked_unique_keys(&update.to_remove, "removed")?;
            if accepted.is_empty() && removed.is_empty() {
                return Err(VotingError::InvalidRequest(
                    "member update does not change the network".into(),
                ));
            }
            if let Some(key) = accepted.intersection(&current).next() {
                return Err(VotingError::InvalidRequest(format!(
                    "accepted key {} is already a member",
                    hex::encode(key)
                )));
            }
            if let Some(key) = removed.difference(&current).next() {
                return Err(VotingError::InvalidRequest(format!(
                    "removed key {} is not a member",
                    hex::encode(key)
                )));
            }
            let resulting_count = current.len() + accepted.len() - removed.len();
            if resulting_count < 3 {
                return Err(VotingError::InvalidRequest(
                    "member update must leave at least three members".into(),
                ));
            }
        }
        Some(NetworkVoteKind::MergeStormEyes) => {
            let merge: MergeStormEyes = postcard::from_bytes(&request.payload)?;
            let unique = merge
                .utxos_to_merge
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            if merge.utxos_to_merge.len() < 2 {
                return Err(VotingError::InvalidRequest(
                    "at least two Storm Eye UTXOs are required for a merge".into(),
                ));
            }
            if unique.len() != merge.utxos_to_merge.len() {
                return Err(VotingError::InvalidRequest(
                    "a Storm Eye UTXO cannot appear twice in a merge".into(),
                ));
            }
        }
        Some(NetworkVoteKind::SplitStormEye) => {
            let split: SplitStormEye = postcard::from_bytes(&request.payload)?;
            if split.number_of_splits < 2 {
                return Err(VotingError::InvalidRequest(
                    "a Storm Eye must be split into at least two outputs".into(),
                ));
            }
        }
        None => {
            return Err(VotingError::InvalidRequest(format!(
                "unknown voting kind {}",
                request.kind
            )));
        }
    }
    Ok(())
}

fn checked_unique_keys(keys: &[[u8; 32]], label: &str) -> Result<BTreeSet<[u8; 32]>, VotingError> {
    for key in keys {
        XOnlyPublicKey::from_byte_array(*key)
            .map_err(|error| VotingError::InvalidRequest(error.to_string()))?;
    }
    let unique = keys.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != keys.len() {
        return Err(VotingError::InvalidRequest(format!(
            "{label} member keys must be unique"
        )));
    }
    Ok(unique)
}

fn member_keys(peers: &[Peer]) -> Result<BTreeSet<[u8; 32]>, VotingError> {
    peers
        .iter()
        .map(|peer| {
            PublicKey::from_slice(&peer.compressed_public_key)
                .map(|key| key.x_only_public_key().0.serialize())
                .map_err(|error| VotingError::InvalidRequest(error.to_string()))
        })
        .collect()
}

fn required_approvals(member_count: usize) -> usize {
    (member_count * 2).div_ceil(3)
}

fn active_remote_peers(peers: &[Peer]) -> Vec<[u8; 33]> {
    peers
        .iter()
        .filter(|peer| peer.status == PeerStatus::Active)
        .map(|peer| peer.compressed_public_key)
        .collect()
}

fn decode_stored(stored: StoredVotingRequest) -> Result<VotingRequest, VotingError> {
    let message: NodeMessage = postcard::from_bytes(&stored.message)?;
    let request = message.decode_payload()?;
    Ok(VotingRequest {
        message_hash: stored.message_hash,
        request,
        block_height: stored.block_height,
        status: if stored.approved_at_block_height.is_some() {
            VotingStatus::Approved
        } else {
            VotingStatus::Pending
        },
        approvals: stored
            .approvals
            .into_iter()
            .map(|approval| VotingApproval {
                public_key: approval.public_key,
                block_height: approval.block_height,
            })
            .collect(),
    })
}

async fn send_from_storm(
    storm: &StormHandle,
    message: NodeMessage,
    recipients: &[[u8; 33]],
) -> Result<(), VotingError> {
    let recipients = transport_keys(recipients)?;
    if !recipients.is_empty() {
        storm
            .send_message(message.into_storm_message()?, &recipients)
            .await?;
    }
    Ok(())
}

async fn send_from_handle(
    handle: &StormHandle,
    message: NodeMessage,
    recipient: [u8; 33],
) -> Result<(), VotingError> {
    let recipient = TransportPublicKey::from_slice(&recipient)
        .map_err(|error| VotingError::InvalidRequest(error.to_string()))?;
    handle
        .send_message(message.into_storm_message()?, &[recipient])
        .await?;
    Ok(())
}

fn transport_keys(keys: &[[u8; 33]]) -> Result<Vec<TransportPublicKey>, VotingError> {
    keys.iter()
        .map(|key| {
            TransportPublicKey::from_slice(key)
                .map_err(|error| VotingError::InvalidRequest(error.to_string()))
        })
        .collect()
}
