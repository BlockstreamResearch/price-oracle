use std::{collections::BTreeSet, sync::Arc};

use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey, schnorr};
use secp256k1_zkp::PublicKey as TransportPublicKey;
use storm::{Peer, PeerStatus, StormContext, StormHandle};
use tokio::sync::Mutex;

use crate::{
    db::voting::{StoredVotingRequest, VotingStore},
    monitoring,
};

use super::message::{
    ApproveVotingRequest, ExecuteVotingRequest, MergeStormEyes, NetworkVoteKind,
    NetworkVoteRequest, NodeMessage, NodeMessageKind, SplitStormEye, UpdateNetworkMembers,
    VotingSyncApproval, VotingSyncMessage, VotingSyncRequest,
};

pub const VOTING_TIMEOUT_BLOCKS: u64 = 10_080;
const MAX_ACTIVE_VOTINGS_PER_PROPOSER: usize = 50;
const MAX_PROPOSAL_FUTURE_BLOCKS: u64 = 1;
const MAX_MISSING_EXECUTIONS_PER_SYNC: usize = 64;

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
        let proposer = controlled_member_key(&peers)?;
        self.ensure_unique_active_request(&request, Some(proposer), block_height)
            .await?;
        let kind = kind_label(&request);
        let unsigned = NodeMessage::new_voting_request(request.clone(), block_height)?;
        let proposal = super::message::SignedVotingProposal {
            request,
            created_at_block_height: block_height,
            proposer_public_key: proposer,
            signature: schnorr::sign(&unsigned.hash()?, &self.keypair)
                .to_byte_array()
                .to_vec(),
        };
        let message = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &proposal)?;
        let hash = message.hash()?;
        let encoded = postcard::to_stdvec(&message)?;
        if !self
            .store
            .insert_request(hash, &encoded, proposer, block_height)
            .await?
        {
            return Err(VotingError::DuplicateRequest(hex::encode(hash)));
        }
        monitoring::record_voting_request_created(kind, proposer_label(&peers, Some(proposer)));
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
        let missing_executions = self
            .store
            .list()
            .await?
            .into_iter()
            .filter(|request| {
                request.approved_at_block_height.is_some()
                    && request.execution_txid.is_none()
                    && !request.execution_confirmed
            })
            .map(|request| request.message_hash)
            .take(MAX_MISSING_EXECUTIONS_PER_SYNC)
            .collect();
        let request = VotingSyncMessage {
            is_response: false,
            requests: Vec::new(),
            missing_executions,
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
        let (request, created_at_block_height) = message.decode_voting_proposal()?;
        validate_proposal_height(created_at_block_height, block_height)?;
        let _guard = self.operations.lock().await;
        let peers = context.storm_handle.peers().await;
        validate_request(&request, &peers, self.coordinator)?;
        let proposer = node_key(context.message_context.peer_public_key)?;
        ensure_current_member(&peers, proposer, "voting request proposer")?;
        if verified_proposer(&message)?.is_some_and(|origin| origin != proposer) {
            return Err(VotingError::InvalidRequest(
                "voting request proposer does not match its sender".into(),
            ));
        }
        self.ensure_unique_active_request(&request, Some(proposer), block_height)
            .await?;
        let hash = message.hash()?;
        let encoded = postcard::to_stdvec(&message)?;
        if self
            .store
            .insert_request(hash, &encoded, proposer, block_height)
            .await?
        {
            monitoring::record_voting_request_created(
                kind_label(&request),
                proposer_label(&peers, Some(proposer)),
            );
        }
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
        self.remove_expired(block_height).await?;
        if sync.is_response {
            self.accept_synchronized(
                sync.requests,
                &context.storm_handle,
                context.message_context.peer_public_key,
                block_height,
            )
            .await
        } else {
            if !sync.requests.is_empty()
                || sync.missing_executions.len() > MAX_MISSING_EXECUTIONS_PER_SYNC
            {
                return Err(VotingError::InvalidRequest(
                    "an ask-about-votings request cannot contain voting records".into(),
                ));
            }
            let stored = self.store.list().await?;
            let notices = execution_notices(&stored, &sync.missing_executions)?;
            let requests = stored
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
                missing_executions: Vec::new(),
            };
            let response = NodeMessage::new(NodeMessageKind::AskAboutVotings, None, &response)?;
            let requester = context.message_context.peer_public_key;
            send_from_handle(&context.storm_handle, response, requester).await?;
            for notice in notices {
                send_from_handle(&context.storm_handle, notice, requester).await?;
            }
            Ok(())
        }
    }

    async fn accept_synchronized(
        &self,
        requests: Vec<VotingSyncRequest>,
        storm: &StormHandle,
        sender_public_key: [u8; 33],
        block_height: u64,
    ) -> Result<(), VotingError> {
        let mut first_error = None;
        for synchronized in requests {
            if let Err(error) = self
                .accept_synchronized_request(synchronized, storm, sender_public_key, block_height)
                .await
            {
                tracing::debug!(%error, "skipped a synchronized voting record");
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn accept_synchronized_request(
        &self,
        synchronized: VotingSyncRequest,
        storm: &StormHandle,
        sender_public_key: [u8; 33],
        block_height: u64,
    ) -> Result<(), VotingError> {
        {
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
                let known = self.store.get(synchronized.message_hash).await?;
                if known
                    .as_ref()
                    .is_some_and(|known| known.execution_confirmed)
                {
                    return Ok(());
                }
                if known.is_none() {
                    let peers = storm.peers().await;
                    ensure_current_member(
                        &peers,
                        node_key(sender_public_key)?,
                        "voting synchronization sender",
                    )?;
                    let (request, created_at_block_height) = message.decode_voting_proposal()?;
                    if created_at_block_height.is_some_and(|created_at| {
                        created_at.saturating_add(VOTING_TIMEOUT_BLOCKS) <= block_height
                    }) {
                        return Ok(());
                    }
                    validate_proposal_height(created_at_block_height, block_height)?;
                    validate_synchronized_request(&request, &peers, self.coordinator)?;
                    let proposer = verified_proposer(&message)?;
                    if let Some(proposer) = proposer {
                        ensure_current_member(&peers, proposer, "voting request proposer")?;
                    }
                    self.store
                        .delete_expired(block_height, VOTING_TIMEOUT_BLOCKS)
                        .await?;
                    if self
                        .store
                        .active_request_count_for_proposer(proposer)
                        .await?
                        >= MAX_ACTIVE_VOTINGS_PER_PROPOSER
                    {
                        return Ok(());
                    }
                    self.ensure_unique_active_request(&request, proposer, block_height)
                        .await?;
                    if self
                        .store
                        .insert_synchronized_request(
                            synchronized.message_hash,
                            &synchronized.message,
                            proposer,
                            block_height,
                        )
                        .await?
                    {
                        monitoring::record_voting_request_created(
                            kind_label(&request),
                            proposer_label(&peers, proposer),
                        );
                    }
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

        let Some(stored) = self.store.get(request_hash).await? else {
            return Err(VotingError::UnknownRequest(hex::encode(request_hash)));
        };
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
        monitoring::record_voting_approval(stored_kind_label(&stored.message));
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

    /// The kind of every vote not yet executed and confirmed. Expired votes
    /// count until the main loop removes them.
    pub(crate) async fn unconfirmed_kinds(&self) -> Result<Vec<&'static str>, VotingError> {
        Ok(self
            .store
            .unconfirmed_request_messages()
            .await?
            .iter()
            .map(|(message, _, _)| stored_kind_label(message))
            .collect())
    }

    pub(crate) async fn remove_expired(&self, block_height: u64) -> Result<u64, VotingError> {
        let _guard = self.operations.lock().await;
        Ok(self
            .store
            .delete_expired(block_height, VOTING_TIMEOUT_BLOCKS)
            .await?)
    }

    async fn ensure_unique_active_request(
        &self,
        request: &NetworkVoteRequest,
        proposer: Option<[u8; 32]>,
        block_height: u64,
    ) -> Result<(), VotingError> {
        self.store
            .delete_expired(block_height, VOTING_TIMEOUT_BLOCKS)
            .await?;
        let canonical_hash = request.canonical_hash()?;
        for (message, created_at, approved_at) in self.store.unconfirmed_request_messages().await? {
            let timeout_start = approved_at.unwrap_or(created_at);
            if timeout_start.saturating_add(VOTING_TIMEOUT_BLOCKS) <= block_height {
                continue;
            }

            let message: NodeMessage = postcard::from_bytes(&message)?;
            if message.decode_voting_request()?.canonical_hash()? == canonical_hash {
                return Err(VotingError::DuplicateRequest(hex::encode(canonical_hash)));
            }
        }

        if self
            .store
            .active_request_count_for_proposer(proposer)
            .await?
            >= MAX_ACTIVE_VOTINGS_PER_PROPOSER
        {
            let requester = proposer
                .map(hex::encode)
                .unwrap_or_else(|| "legacy unattributed bucket".into());
            return Err(VotingError::InvalidRequest(format!(
                "requester {requester} already has {MAX_ACTIVE_VOTINGS_PER_PROPOSER} active voting requests"
            )));
        }

        Ok(())
    }
}

fn verified_proposer(message: &NodeMessage) -> Result<Option<[u8; 32]>, VotingError> {
    let Ok(proposal) = message.decode_payload::<super::message::SignedVotingProposal>() else {
        return Ok(None);
    };
    let public_key = XOnlyPublicKey::from_byte_array(proposal.proposer_public_key)
        .map_err(|error| VotingError::InvalidRequest(error.to_string()))?;
    let signature_bytes: [u8; 64] =
        proposal
            .signature
            .try_into()
            .map_err(|signature: Vec<u8>| {
                VotingError::InvalidRequest(format!(
                    "proposer signature has {} bytes instead of 64",
                    signature.len()
                ))
            })?;
    let unsigned =
        NodeMessage::new_voting_request(proposal.request, proposal.created_at_block_height)?;
    schnorr::verify(
        &schnorr::Signature::from_byte_array(signature_bytes),
        &unsigned.hash()?,
        &public_key,
    )
    .map_err(|error| VotingError::InvalidRequest(error.to_string()))?;
    Ok(Some(proposal.proposer_public_key))
}

fn validate_proposal_height(
    created_at_block_height: Option<u64>,
    observed_block_height: u64,
) -> Result<(), VotingError> {
    let Some(created_at_block_height) = created_at_block_height else {
        return Ok(());
    };
    if created_at_block_height > observed_block_height.saturating_add(MAX_PROPOSAL_FUTURE_BLOCKS) {
        return Err(VotingError::InvalidRequest(
            "voting proposal was created too far in the future".into(),
        ));
    }
    if created_at_block_height.saturating_add(VOTING_TIMEOUT_BLOCKS) <= observed_block_height {
        return Err(VotingError::InvalidRequest(
            "voting proposal has expired".into(),
        ));
    }

    Ok(())
}

fn validate_request(
    request: &NetworkVoteRequest,
    peers: &[Peer],
    coordinator: [u8; 32],
) -> Result<(), VotingError> {
    validate_request_structure(request)?;

    if NetworkVoteKind::from_id(request.kind) != Some(NetworkVoteKind::UpdateNetworkMembers) {
        return Ok(());
    }

    let update: UpdateNetworkMembers = postcard::from_bytes(&request.payload)?;
    let current = member_keys(peers)?;
    let accepted = update.to_accept.into_iter().collect::<BTreeSet<_>>();
    let removed = update.to_remove.into_iter().collect::<BTreeSet<_>>();
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
            "member update cannot remove the coordinator without a replacement protocol".into(),
        ));
    }
    let resulting_count = current.len() + accepted.len() - removed.len();
    if resulting_count < 3 {
        return Err(VotingError::InvalidRequest(
            "member update must leave at least three members".into(),
        ));
    }

    Ok(())
}

fn validate_synchronized_request(
    request: &NetworkVoteRequest,
    peers: &[Peer],
    coordinator: [u8; 32],
) -> Result<(), VotingError> {
    validate_request_structure(request)?;

    if NetworkVoteKind::from_id(request.kind) == Some(NetworkVoteKind::UpdateNetworkMembers) {
        let update: UpdateNetworkMembers = postcard::from_bytes(&request.payload)?;
        let current = member_keys(peers)?;
        let accepted = update.to_accept.into_iter().collect::<BTreeSet<_>>();
        let removed = update.to_remove.into_iter().collect::<BTreeSet<_>>();
        let already_applied = accepted.is_subset(&current) && removed.is_disjoint(&current);
        if already_applied && !removed.contains(&coordinator) {
            return Ok(());
        }
    }

    validate_request(request, peers, coordinator)
}

fn validate_request_structure(request: &NetworkVoteRequest) -> Result<(), VotingError> {
    match NetworkVoteKind::from_id(request.kind) {
        Some(NetworkVoteKind::UpdateNetworkMembers) => {
            let update: UpdateNetworkMembers = postcard::from_bytes(&request.payload)?;
            let accepted = checked_unique_keys(&update.to_accept, "accepted")?;
            let removed = checked_unique_keys(&update.to_remove, "removed")?;
            if accepted.is_empty() && removed.is_empty() {
                return Err(VotingError::InvalidRequest(
                    "member update does not change the network".into(),
                ));
            }
            if let Some(key) = accepted.intersection(&removed).next() {
                return Err(VotingError::InvalidRequest(format!(
                    "member key {} cannot be both accepted and removed",
                    hex::encode(key)
                )));
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

pub(super) fn member_keys(peers: &[Peer]) -> Result<BTreeSet<[u8; 32]>, VotingError> {
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

fn kind_label(request: &NetworkVoteRequest) -> &'static str {
    NetworkVoteKind::from_id(request.kind).map_or("unknown", NetworkVoteKind::as_str)
}

fn stored_kind_label(message: &[u8]) -> &'static str {
    postcard::from_bytes::<NodeMessage>(message)
        .ok()
        .and_then(|message| message.decode_voting_request().ok())
        .map_or("unknown", |request| kind_label(&request))
}

/// The proposer's transport key, as the `peer` label of other metrics shows it.
fn proposer_label(peers: &[Peer], proposer: Option<[u8; 32]>) -> String {
    proposer
        .and_then(|proposer| {
            peers.iter().find(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key)
                    .is_ok_and(|key| key.x_only_public_key().0.serialize() == proposer)
            })
        })
        .map_or_else(
            || "unknown".into(),
            |peer| hex::encode(peer.compressed_public_key),
        )
}

fn required_approvals(member_count: usize) -> usize {
    (member_count * 2).div_ceil(3)
}

pub(super) fn active_remote_peers(peers: &[Peer]) -> Vec<[u8; 33]> {
    peers
        .iter()
        .filter(|peer| peer.status == PeerStatus::Active)
        .map(|peer| peer.compressed_public_key)
        .collect()
}

fn execution_notices(
    stored: &[StoredVotingRequest],
    missing: &[[u8; 32]],
) -> Result<Vec<NodeMessage>, VotingError> {
    let mut notices = Vec::new();
    for request in stored
        .iter()
        .filter(|request| missing.contains(&request.message_hash))
    {
        let (Some(encoded), Some(_)) = (&request.execution_request, request.execution_txid) else {
            continue;
        };
        let notice: ExecuteVotingRequest = postcard::from_bytes(encoded)?;
        if notice.final_tx.is_none() {
            continue;
        }
        notices.push(NodeMessage::new(
            NodeMessageKind::ExecuteVotingRequest,
            Some(request.message_hash),
            &notice,
        )?);
    }
    Ok(notices)
}

fn decode_stored(stored: StoredVotingRequest) -> Result<VotingRequest, VotingError> {
    let message: NodeMessage = postcard::from_bytes(&stored.message)?;
    let request = message.decode_voting_request()?;
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
mod tests;
