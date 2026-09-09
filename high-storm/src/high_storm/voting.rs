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
    Executing,
    Executed,
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
    pub proposer_public_key: Option<[u8; 32]>,
    pub block_height: u64,
    pub status: VotingStatus,
    pub execution_txid: Option<[u8; 32]>,
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
    coordinator: [u8; 32],
    operations: Arc<Mutex<()>>,
}

impl Voting {
    pub(crate) fn new(
        secret_key: [u8; 32],
        coordinator_public_key: [u8; 33],
        store: VotingStore,
    ) -> Self {
        let secret_key = SecretKey::from_secret_bytes(secret_key)
            .expect("the transport signer key was already validated");
        let coordinator = PublicKey::from_slice(&coordinator_public_key)
            .expect("the coordinator transport key was already validated")
            .x_only_public_key()
            .0
            .serialize();
        Self {
            store,
            keypair: Keypair::from_secret_key(&secret_key),
            coordinator,
            operations: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) async fn create(
        &self,
        storm: &StormHandle,
        request: NetworkVoteRequest,
        block_height: u64,
    ) -> Result<[u8; 32], VotingError> {
        let _guard = self.operations.lock().await;
        let peers = storm.peers().await;
        validate_request(&request, &peers, self.coordinator)?;
        let message = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request)?;
        let hash = message.hash()?;
        let encoded = postcard::to_stdvec(&message)?;
        let proposer = controlled_member_key(&peers)?;
        if !self
            .store
            .insert_request(hash, &encoded, proposer, block_height)
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
        let duplicate = match self
            .accept_approval(message.clone(), approval, request_hash, block_height, storm)
            .await
        {
            Ok(()) => None,
            Err(VotingError::DuplicateApproval(public_key))
                if public_key == hex::encode(local_key) =>
            {
                Some(public_key)
            }
            Err(error) => return Err(error),
        };
        let peers = storm.peers().await;
        let broadcast = send_from_storm(storm, message, &active_remote_peers(&peers)).await;
        let staging = self
            .stage_member_migration_if_approved(storm, request_hash)
            .await;

        broadcast?;
        staging?;
        if let Some(public_key) = duplicate {
            return Err(VotingError::DuplicateApproval(public_key));
        }

        Ok(())
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
        let _guard = self.operations.lock().await;
        let peers = context.storm_handle.peers().await;
        validate_request(&request, &peers, self.coordinator)?;
        let hash = message.hash()?;
        let encoded = postcard::to_stdvec(&message)?;
        let proposer = node_key(context.message_context.peer_public_key)?;
        ensure_current_member(&peers, proposer, "voting request proposer")?;
        self.store
            .insert_request(hash, &encoded, proposer, block_height)
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
        self.accept_approval(
            message,
            approval,
            request_hash,
            block_height,
            &context.storm_handle,
        )
        .await?;
        self.stage_member_migration_if_approved(&context.storm_handle, request_hash)
            .await
    }

    pub(crate) async fn handle_synchronization(
        &self,
        message: NodeMessage,
        context: &StormContext,
        block_height: u64,
    ) -> Result<(), VotingError> {
        if message.linked_to.is_some() {
            return Err(VotingError::InvalidRequest(
                "ask-about-votings cannot link to another message".into(),
            ));
        }
        let sync: VotingSyncMessage = message.decode_payload()?;
        if sync.is_response {
            self.accept_synchronized(
                sync.requests,
                &context.storm_handle,
                context.message_context.peer_public_key,
                block_height,
            )
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
                .filter(|request| !request.execution_confirmed)
                .map(|request| VotingSyncRequest {
                    message_hash: request.message_hash,
                    message: request.message,
                    approvals: request
                        .approvals
                        .into_iter()
                        .map(|approval| VotingSyncApproval {
                            message: approval.message,
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
        storm: &StormHandle,
        sender_public_key: [u8; 33],
        block_height: u64,
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
            {
                let _guard = self.operations.lock().await;
                if self.store.get(synchronized.message_hash).await?.is_none() {
                    let peers = storm.peers().await;
                    ensure_current_member(
                        &peers,
                        node_key(sender_public_key)?,
                        "voting synchronization sender",
                    )?;
                    let request: NetworkVoteRequest = message.decode_payload()?;
                    validate_request(&request, &peers, self.coordinator)?;
                    self.store
                        .insert_synchronized_request(
                            synchronized.message_hash,
                            &synchronized.message,
                            None,
                            block_height,
                        )
                        .await?;
                }
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
                        block_height,
                        storm,
                    )
                    .await
                {
                    Ok(()) | Err(VotingError::DuplicateApproval(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            self.stage_member_migration_if_approved(storm, synchronized.message_hash)
                .await?;
        }
        Ok(())
    }

    async fn stage_member_migration_if_approved(
        &self,
        storm: &StormHandle,
        request_hash: [u8; 32],
    ) -> Result<(), VotingError> {
        let Some(request) = self.get(request_hash).await? else {
            return Ok(());
        };
        if request.status != VotingStatus::Approved
            || NetworkVoteKind::from_id(request.request.kind)
                != Some(NetworkVoteKind::UpdateNetworkMembers)
        {
            return Ok(());
        }

        self.stage_member_migration(storm, &request)
            .await
            .map(|_| ())
    }

    pub(crate) async fn restore_member_migration(
        &self,
        storm: &StormHandle,
    ) -> Result<(), VotingError> {
        for request in self.list().await?.into_iter().filter(|request| {
            matches!(
                request.status,
                VotingStatus::Approved | VotingStatus::Executing
            ) && NetworkVoteKind::from_id(request.request.kind)
                == Some(NetworkVoteKind::UpdateNetworkMembers)
        }) {
            if self.stage_member_migration(storm, &request).await? {
                break;
            }
        }

        Ok(())
    }

    async fn stage_member_migration(
        &self,
        storm: &StormHandle,
        request: &VotingRequest,
    ) -> Result<bool, VotingError> {
        let update: UpdateNetworkMembers = postcard::from_bytes(&request.request.payload)?;
        let current_members = member_keys(&storm.peers().await)?;
        let mut members = current_members.clone();
        for member in update.to_remove {
            members.remove(&member);
        }
        members.extend(update.to_accept);
        if members == current_members {
            return Ok(false);
        }

        match storm.begin_member_migration(members).await {
            Ok(()) => Ok(true),
            Err(storm::Error::MigrationAlreadyStaged) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    async fn accept_approval(
        &self,
        message: NodeMessage,
        approval: ApproveVotingRequest,
        request_hash: [u8; 32],
        block_height: u64,
        storm: &StormHandle,
    ) -> Result<(), VotingError> {
        let _guard = self.operations.lock().await;
        let peers = storm.peers().await;
        let public_key = XOnlyPublicKey::from_byte_array(approval.public_key)
            .map_err(|error| VotingError::InvalidApproval(error.to_string()))?;
        if !member_keys(&peers)?.contains(&approval.public_key) {
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

    pub(crate) async fn lock_operations(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.operations.clone().lock_owned().await
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

fn validate_request(
    request: &NetworkVoteRequest,
    peers: &[Peer],
    coordinator: [u8; 32],
) -> Result<(), VotingError> {
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
            if removed.contains(&coordinator) {
                return Err(VotingError::InvalidRequest(
                    "member update cannot remove the coordinator without a replacement protocol"
                        .into(),
                ));
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
            if merge.utxos_to_merge.len() > 3 {
                return Err(VotingError::InvalidRequest(
                    "at most three Storm Eye UTXOs can be merged".into(),
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
            if split.number_of_splits > 3 {
                return Err(VotingError::InvalidRequest(
                    "a Storm Eye can be split into at most three outputs".into(),
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

fn ensure_current_member(
    peers: &[Peer],
    public_key: [u8; 32],
    role: &str,
) -> Result<(), VotingError> {
    if !member_keys(peers)?.contains(&public_key) {
        return Err(VotingError::InvalidRequest(format!(
            "{role} {} is not a network member",
            hex::encode(public_key)
        )));
    }

    Ok(())
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
        proposer_public_key: stored.proposer_public_key,
        block_height: stored.block_height,
        status: if stored.execution_confirmed {
            VotingStatus::Executed
        } else if stored.execution_started || stored.execution_txid.is_some() {
            VotingStatus::Executing
        } else if stored.approved_at_block_height.is_some() {
            VotingStatus::Approved
        } else {
            VotingStatus::Pending
        },
        execution_txid: stored.execution_txid,
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

fn controlled_member_key(peers: &[Peer]) -> Result<[u8; 32], VotingError> {
    let peer = peers
        .iter()
        .find(|peer| peer.status == PeerStatus::Controlled)
        .ok_or_else(|| VotingError::InvalidRequest("local network member is missing".into()))?;
    node_key(peer.compressed_public_key)
}

fn node_key(encoded: [u8; 33]) -> Result<[u8; 32], VotingError> {
    PublicKey::from_slice(&encoded)
        .map(|key| key.x_only_public_key().0.serialize())
        .map_err(|error| VotingError::InvalidRequest(error.to_string()))
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

#[cfg(test)]
mod reshape_tests {
    use super::*;
    use crate::StormEyeUtxo;
    use secp256k1_zkp::{Secp256k1, SecretKey};

    #[test]
    fn broadcast_vote_remains_executing_until_confirmed() {
        let request = NetworkVoteRequest::new(
            NetworkVoteKind::SplitStormEye,
            &SplitStormEye {
                utxo_to_split: StormEyeUtxo {
                    txid: [9; 32],
                    output_index: 0,
                },
                number_of_splits: 2,
            },
        )
        .unwrap();
        let message =
            NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request).unwrap();
        let mut stored = StoredVotingRequest {
            message_hash: [1; 32],
            message: postcard::to_allocvec(&message).unwrap(),
            proposer_public_key: Some([2; 32]),
            block_height: 3,
            approved_at_block_height: Some(4),
            execution_started: true,
            execution_transaction: Some(vec![5]),
            execution_request: Some(vec![6]),
            execution_txid: Some([7; 32]),
            execution_confirmed: false,
            approvals: Vec::new(),
        };

        assert_eq!(
            decode_stored(stored.clone()).unwrap().status,
            VotingStatus::Executing
        );

        stored.execution_confirmed = true;
        assert_eq!(
            decode_stored(stored).unwrap().status,
            VotingStatus::Executed
        );
    }

    #[test]
    fn accepts_two_or_three_reshape_outputs_only() {
        for count in 2..=3 {
            let merge = NetworkVoteRequest::new(
                NetworkVoteKind::MergeStormEyes,
                &MergeStormEyes {
                    utxos_to_merge: (0..count).map(storm_eye).collect(),
                },
            )
            .unwrap();
            assert!(validate_request(&merge, &[], [0; 32]).is_ok());

            let split = NetworkVoteRequest::new(
                NetworkVoteKind::SplitStormEye,
                &SplitStormEye {
                    utxo_to_split: storm_eye(0),
                    number_of_splits: count.into(),
                },
            )
            .unwrap();
            assert!(validate_request(&split, &[], [0; 32]).is_ok());
        }

        let merge = NetworkVoteRequest::new(
            NetworkVoteKind::MergeStormEyes,
            &MergeStormEyes {
                utxos_to_merge: (0..4).map(storm_eye).collect(),
            },
        )
        .unwrap();
        assert!(matches!(
            validate_request(&merge, &[], [0; 32]),
            Err(VotingError::InvalidRequest(_))
        ));

        let split = NetworkVoteRequest::new(
            NetworkVoteKind::SplitStormEye,
            &SplitStormEye {
                utxo_to_split: storm_eye(0),
                number_of_splits: 4,
            },
        )
        .unwrap();
        assert!(matches!(
            validate_request(&split, &[], [0; 32]),
            Err(VotingError::InvalidRequest(_))
        ));
    }

    #[test]
    fn member_update_cannot_remove_the_fixed_coordinator() {
        let secp = Secp256k1::new();
        let peers = (1..=3)
            .map(|byte| {
                Peer::new(
                    SecretKey::from_slice(&[byte; 32])
                        .unwrap()
                        .public_key(&secp)
                        .serialize(),
                )
            })
            .collect::<Vec<_>>();
        let coordinator = member_keys(&peers).unwrap().into_iter().next().unwrap();
        let accepted = SecretKey::from_slice(&[4; 32])
            .unwrap()
            .public_key(&secp)
            .x_only_public_key()
            .0
            .serialize();
        let update = NetworkVoteRequest::new(
            NetworkVoteKind::UpdateNetworkMembers,
            &UpdateNetworkMembers {
                to_accept: vec![accepted],
                to_remove: vec![coordinator],
            },
        )
        .unwrap();

        assert!(matches!(
            validate_request(&update, &peers, coordinator),
            Err(VotingError::InvalidRequest(message))
                if message.contains("cannot remove the coordinator")
        ));
    }

    fn storm_eye(byte: u8) -> StormEyeUtxo {
        StormEyeUtxo {
            txid: [byte; 32],
            output_index: byte.into(),
        }
    }
}
