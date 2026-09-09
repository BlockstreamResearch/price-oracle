use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::{
    auth::derived_auth::AuthWitness,
    treasury::{
        TreasuryProgram,
        derived_treasury::{TreasuryArguments, TreasuryWitness},
    },
};
use secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::Deserialize;
use simplex::{
    either::Either,
    program::ProgramTrait,
    provider::SimplicityNetwork,
    simplicityhl::{
        elements::{
            AssetId, BlockHash, Script, TxOut, Txid, encode, pset::PartiallySignedTransaction,
        },
        simplicity::hashes::Hash,
    },
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage,
        UTXO,
    },
};
use storm_tree::{StormTree, StormTreeProof};
use url::Url;

use crate::{
    ExecuteVotingRequest, MergeStormEyes, NetworkAsset, NetworkVoteKind, NodeMessage,
    SplitStormEye, StormEyeUtxo, UpdateNetworkMembers,
    config::ElementsRpcConfig,
    db::{
        droplet::{DropletStore, TreasuryUtxo},
        network_asset::{NetworkAssetStore, STORM_EYE_KIND},
        voting::{StoredVotingRequest, VotingStore},
    },
};

use super::{
    SigningResult,
    assets::{StormEyeContractData, migrated_members_script, storm_eye_program},
    droplets::member_script,
    user_requests::{
        STORM_EYE_TAG, asset_id, get_explicit_outpoint, get_optional_explicit_outpoint,
        is_fully_explicit_output, pack_proof, witness_utxo,
    },
};

const MAX_RESHAPE_COUNT: usize = 3;

#[derive(Debug, thiserror::Error)]
pub enum VotingExecutionError {
    #[error("voting request {0} does not exist")]
    UnknownRequest(String),
    #[error("voting request has not reached approval")]
    NotApproved,
    #[error("voting request execution is already in progress")]
    AlreadyExecuting,
    #[error("voting request has already been executed")]
    AlreadyExecuted,
    #[error("the new Storm is waiting for all target members to connect")]
    MemberMigrationNotReady,
    #[error("voting request has no known proposer")]
    MissingProposer,
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid voting execution: {0}")]
    Invalid(String),
    #[error("voting database operation failed: {0}")]
    VotingStore(#[from] crate::db::voting::Error),
    #[error("Droplets database operation failed: {0}")]
    DropletsStore(#[from] sqlx::Error),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("failed to decode voting transaction: {0}")]
    Transaction(#[from] encode::Error),
    #[error("failed to decode voting request: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("failed to reconstruct network covenant: {0}")]
    Asset(#[from] super::assets::AssetError),
    #[error("failed to evaluate network covenant: {0}")]
    Program(#[from] simplex::program::ProgramError),
    #[error("shared transaction validation failed: {0}")]
    TransactionHelper(#[from] super::user_requests::UserRequestError),
    #[error("distributed signing failed: {0}")]
    Signing(#[from] super::signing::SigningError),
    #[error("failed to extract final voting transaction: {0}")]
    Pset(String),
}

pub(crate) struct PreparedVotingExecution {
    pub(crate) request: ExecuteVotingRequest,
    transaction: FinalTransaction,
    pset: PartiallySignedTransaction,
    spent_utxos: Vec<TxOut>,
    storm_eye_inputs: usize,
    operation: ReshapeOperation,
    network: SimplicityNetwork,
    storm_eye: NetworkAsset,
}

#[derive(Clone, Debug)]
enum ReshapeOperation {
    Merge(Vec<StormEyeUtxo>),
    Split(StormEyeUtxo, u8),
    UpdateMembers {
        members: Vec<[u8; 32]>,
        new_root: [u8; 32],
    },
}

#[derive(Clone)]
pub(crate) struct VotingExecution {
    votes: VotingStore,
    droplets: DropletStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    transaction_fee_sats: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormEyeState {
    Available,
    Proposed,
    Executing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StormEyeInventoryItem {
    pub txid: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
    pub confirmations: u64,
    pub state: StormEyeState,
    pub voting_request_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StormEyeReservation {
    state: StormEyeState,
    voting_request_hashes: Vec<[u8; 32]>,
}

impl VotingExecution {
    pub(crate) fn new(
        votes: VotingStore,
        droplets: DropletStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        transaction_fee_sats: u64,
    ) -> Self {
        Self {
            votes,
            droplets,
            assets,
            elements_rpc,
            transaction_fee_sats,
        }
    }

    pub(crate) async fn prepare(
        &self,
        request_hash: [u8; 32],
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<ExecuteVotingRequest, VotingExecutionError> {
        let stored = self.stored_vote(request_hash).await?;
        require_retryable(&stored)?;
        self.prepare_transaction(&stored, current_members)
            .await
            .map(|prepared| prepared.request)
    }

    pub(crate) async fn member_migration_asset(
        &self,
        request_hash: [u8; 32],
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<Option<NetworkAsset>, VotingExecutionError> {
        let stored = self.stored_vote(request_hash).await?;
        let operation = decode_operation(&stored, current_members)?;
        let ReshapeOperation::UpdateMembers { new_root, .. } = operation else {
            return Ok(None);
        };
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(VotingExecutionError::MissingAsset(STORM_EYE_KIND))?;
        let network = network(&self.client()?)?;
        Ok(Some(migrated_storm_eye(&storm_eye, new_root, &network)?))
    }

    pub(crate) async fn storm_eye_utxos(
        &self,
        block_height: u64,
    ) -> Result<Vec<StormEyeInventoryItem>, VotingExecutionError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(VotingExecutionError::MissingAsset(STORM_EYE_KIND))?;
        let reservations = storm_eye_reservations(&self.votes.list().await?)?;
        let client = self.client()?;
        let descriptor = format!("raw({})", hex::encode(&storm_eye.contract_script));
        let scan: ScanResult = client.call(
            "scantxoutset",
            &["start".into(), serde_json::json!([descriptor])],
        )?;
        let expected_asset = asset_id(storm_eye.asset_id)?;
        let mut inventory = Vec::new();

        for unspent in scan.unspents {
            let txid = Txid::from_str(&unspent.txid)
                .map_err(|_| VotingExecutionError::Invalid("invalid Storm Eye txid".into()))?;
            let Some(utxo) = get_optional_explicit_outpoint(&client, txid, unspent.vout)? else {
                continue;
            };
            if utxo.asset() != expected_asset
                || utxo.txout.script_pubkey.as_bytes() != storm_eye.contract_script
            {
                continue;
            }

            let outpoint = StormEyeUtxo {
                txid: txid.to_byte_array(),
                output_index: unspent.vout,
            };
            let reservation = reservations.get(&outpoint);
            inventory.push(StormEyeInventoryItem {
                txid: outpoint.txid,
                output_index: outpoint.output_index,
                amount: utxo.amount(),
                confirmations: unspent
                    .height
                    .map(|height| block_height.saturating_sub(height).saturating_add(1))
                    .unwrap_or(0),
                state: reservation
                    .map(|reservation| reservation.state)
                    .unwrap_or(StormEyeState::Available),
                voting_request_hashes: reservation
                    .map(|reservation| reservation.voting_request_hashes.clone())
                    .unwrap_or_default(),
            });
        }

        inventory.sort_by_key(|utxo| (utxo.txid, utxo.output_index));
        Ok(inventory)
    }

    pub(crate) async fn prepare_finalization(
        &self,
        request_hash: [u8; 32],
        request: &ExecuteVotingRequest,
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<PreparedVotingExecution, VotingExecutionError> {
        let stored = self.stored_vote(request_hash).await?;
        require_approved_or_executing(&stored, &request.tx)?;
        let prepared = self.prepare_transaction(&stored, current_members).await?;
        if prepared.request.tx != request.tx
            || prepared.request.signing_hashes != request.signing_hashes
            || prepared.request.proposer_public_key != request.proposer_public_key
        {
            return Err(VotingExecutionError::Invalid(
                "voting transaction changed before finalization".into(),
            ));
        }
        Ok(prepared)
    }

    async fn prepare_transaction(
        &self,
        stored: &StoredVotingRequest,
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<PreparedVotingExecution, VotingExecutionError> {
        let proposer = stored
            .proposer_public_key
            .ok_or(VotingExecutionError::MissingProposer)?;
        let operation = decode_operation(stored, current_members)?;
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(VotingExecutionError::MissingAsset(STORM_EYE_KIND))?;
        let indexed_treasury = self.droplets.treasury_utxos().await?;
        let client = self.client()?;
        let network = network(&client)?;
        let storm_eye_utxos = operation_utxos(&client, &storm_eye, &operation)?;
        let treasury_utxos = self.select_treasury_utxos(&client, &network, indexed_treasury)?;
        let prepared = build_transaction(
            proposer,
            operation,
            storm_eye,
            storm_eye_utxos,
            treasury_utxos,
            network,
            self.transaction_fee_sats,
        )?;
        Ok(prepared)
    }

    pub(crate) async fn begin(
        &self,
        request_hash: [u8; 32],
        request: &ExecuteVotingRequest,
        block_height: u64,
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<(), VotingExecutionError> {
        if request.final_tx.is_some() {
            return Err(VotingExecutionError::Invalid(
                "signing request unexpectedly contains a final transaction".into(),
            ));
        }

        let stored = self.stored_vote(request_hash).await?;
        require_retryable(&stored)?;
        self.validate_transaction(request_hash, request, false, false, true, current_members)
            .await?;

        if stored.execution_started
            && stored.execution_transaction.as_deref() != Some(request.tx.as_slice())
        {
            self.cancel(request_hash, request.proposer_public_key, block_height)
                .await?;
        }

        let started = self
            .votes
            .start_execution(request_hash, &request.tx)
            .await?;
        if !started && stored.execution_transaction.as_deref() != Some(request.tx.as_slice()) {
            return Err(VotingExecutionError::AlreadyExecuting);
        }
        if !self
            .droplets
            .lock_exchange(
                request.proposer_public_key,
                self.transaction_fee_sats,
                block_height,
                &request.tx,
            )
            .await?
        {
            if started {
                self.votes.cancel_execution(request_hash).await?;
            }
            return Err(VotingExecutionError::Invalid(
                "proposer has insufficient or locked Droplets for the transaction fee".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn cancel(
        &self,
        request_hash: [u8; 32],
        proposer: [u8; 32],
        block_height: u64,
    ) -> Result<(), VotingExecutionError> {
        let voting_result = self.votes.cancel_execution(request_hash).await;
        let droplets_result = self.droplets.unlock_exchange(proposer, block_height).await;
        voting_result?;
        droplets_result?;
        Ok(())
    }

    async fn validate_transaction(
        &self,
        request_hash: [u8; 32],
        request: &ExecuteVotingRequest,
        allow_spent_inputs: bool,
        allow_missing_proposer: bool,
        allow_execution_replacement: bool,
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<(), VotingExecutionError> {
        let stored = self.stored_vote(request_hash).await?;
        if allow_execution_replacement {
            require_retryable(&stored)?;
        } else {
            require_approved_or_executing(&stored, &request.tx)?;
        }
        if stored.proposer_public_key != Some(request.proposer_public_key)
            && !(allow_missing_proposer && stored.proposer_public_key.is_none())
        {
            return Err(VotingExecutionError::Invalid(
                "voting proposer does not match the execution request".into(),
            ));
        }
        let operation = decode_operation(&stored, current_members)?;
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(VotingExecutionError::MissingAsset(STORM_EYE_KIND))?;
        let indexed_treasury = self.droplets.treasury_utxos().await?;
        let client = self.client()?;
        let network = network(&client)?;
        let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
        validate_layout(
            &client,
            &pset,
            &request.signing_hashes,
            request.proposer_public_key,
            &operation,
            &storm_eye,
            &network,
            self.transaction_fee_sats,
            &indexed_treasury,
            allow_spent_inputs,
        )
    }

    pub(crate) fn finalize(
        &self,
        mut prepared: PreparedVotingExecution,
        signing: SigningResult,
        proof: StormTreeProof,
    ) -> Result<([u8; 32], ExecuteVotingRequest), VotingExecutionError> {
        let signatures = verified_signatures(&prepared, &signing, &proof)?;
        let contract_data = contract_data(&prepared.storm_eye)?;
        for (index, signature) in signatures.iter().copied().enumerate() {
            let witness = reshape_witness(
                &contract_data,
                &signing,
                &proof,
                &prepared.operation,
                signature,
                index as u32,
            )?;
            prepared.transaction.inputs_mut()[index]
                .program_input
                .as_mut()
                .expect("Storm Eye is a program input")
                .witness = Box::new(witness);
        }
        for (index, input) in prepared.transaction.inputs().iter().enumerate() {
            let program_input = input
                .program_input
                .as_ref()
                .expect("all voting transaction inputs are covenant inputs");
            prepared.pset.inputs_mut()[index].final_script_witness =
                Some(program_input.program.finalize(
                    &prepared.pset,
                    &program_input.witness.build_witness(),
                    index,
                    &prepared.network,
                )?);
        }
        if signing_hashes(
            &prepared.pset,
            &prepared.storm_eye,
            &prepared.network,
            prepared.storm_eye_inputs,
        )? != prepared.request.signing_hashes
        {
            return Err(VotingExecutionError::Invalid(
                "final voting execution signing hash changed".into(),
            ));
        }
        let final_tx = prepared
            .pset
            .extract_tx()
            .map_err(|error| VotingExecutionError::Pset(error.to_string()))?;
        verify_voting_amounts(&final_tx, &prepared.spent_utxos)?;
        let final_bytes = encode::serialize(&final_tx);
        let txid = final_tx.txid();
        prepared.request.final_tx = Some(final_bytes);
        prepared.request.signing_storm_tree_branch = signing.signing_storm_tree_branch;
        Ok((txid.to_byte_array(), prepared.request))
    }

    pub(crate) fn broadcast(
        &self,
        txid: [u8; 32],
        request: &ExecuteVotingRequest,
    ) -> Result<(), VotingExecutionError> {
        let final_tx = request
            .final_tx
            .as_deref()
            .ok_or_else(|| VotingExecutionError::Invalid("final transaction is missing".into()))?;
        let expected_txid = Txid::from_byte_array(txid);
        let client = self.client()?;
        match client.call::<String>("sendrawtransaction", &[hex::encode(final_tx).into()]) {
            Ok(broadcast_txid) if broadcast_txid == expected_txid.to_string() => Ok(()),
            Ok(_) => Err(VotingExecutionError::Invalid(
                "broadcast transaction id mismatch".into(),
            )),
            Err(error) => {
                let mempool: Vec<String> = client.call("getrawmempool", &[])?;
                if mempool
                    .iter()
                    .any(|known| known == &expected_txid.to_string())
                    || client
                        .call::<RawTransactionInfo>(
                            "getrawtransaction",
                            &[expected_txid.to_string().into(), true.into()],
                        )
                        .is_ok_and(|transaction| transaction.confirmations > 0)
                {
                    Ok(())
                } else {
                    Err(error.into())
                }
            }
        }
    }

    pub(crate) async fn record_broadcast(
        &self,
        request_hash: [u8; 32],
        txid: [u8; 32],
        request: &ExecuteVotingRequest,
    ) -> Result<(), VotingExecutionError> {
        let encoded = postcard::to_allocvec(request)?;
        self.votes
            .record_broadcast(
                request_hash,
                request.proposer_public_key,
                &request.tx,
                &encoded,
                txid,
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn confirm(
        &self,
        request_hash: [u8; 32],
        txid: [u8; 32],
    ) -> Result<(), VotingExecutionError> {
        self.votes.confirm_execution(request_hash, txid).await?;
        Ok(())
    }

    pub(crate) async fn pending_broadcasts(
        &self,
    ) -> Result<Vec<([u8; 32], [u8; 32], ExecuteVotingRequest)>, VotingExecutionError> {
        self.votes
            .list()
            .await?
            .into_iter()
            .filter(|vote| vote.execution_txid.is_some() && !vote.execution_confirmed)
            .map(|vote| {
                let txid = vote.execution_txid.ok_or_else(|| {
                    VotingExecutionError::Invalid("broadcast voting txid is missing".into())
                })?;
                let request = vote
                    .execution_request
                    .as_deref()
                    .ok_or_else(|| {
                        VotingExecutionError::Invalid(
                            "broadcast voting execution request is missing".into(),
                        )
                    })
                    .and_then(|request| postcard::from_bytes(request).map_err(Into::into))?;
                Ok((vote.message_hash, txid, request))
            })
            .collect()
    }

    pub(crate) async fn unfinished_attempts(
        &self,
    ) -> Result<Vec<([u8; 32], [u8; 32])>, VotingExecutionError> {
        self.votes
            .list()
            .await?
            .into_iter()
            .filter(|vote| vote.execution_started && vote.execution_txid.is_none())
            .map(|vote| {
                vote.proposer_public_key
                    .map(|proposer| (vote.message_hash, proposer))
                    .ok_or(VotingExecutionError::MissingProposer)
            })
            .collect()
    }

    pub(crate) fn is_confirmed(&self, txid: [u8; 32]) -> Result<bool, VotingExecutionError> {
        let transaction: RawTransactionInfo = self.client()?.call(
            "getrawtransaction",
            &[Txid::from_byte_array(txid).to_string().into(), true.into()],
        )?;
        Ok(transaction.confirmations > 0)
    }

    pub(crate) async fn observe_broadcast(
        &self,
        request_hash: [u8; 32],
        request: &ExecuteVotingRequest,
        current_members: &BTreeSet<[u8; 32]>,
        block_height: u64,
    ) -> Result<[u8; 32], VotingExecutionError> {
        let final_bytes = request
            .final_tx
            .as_deref()
            .ok_or_else(|| VotingExecutionError::Invalid("final transaction is missing".into()))?;
        let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
        let unsigned = pset
            .extract_tx()
            .map_err(|error| VotingExecutionError::Pset(error.to_string()))?;
        let final_tx: simplex::simplicityhl::elements::Transaction =
            encode::deserialize(final_bytes)?;
        if final_tx.txid() != unsigned.txid() {
            return Err(VotingExecutionError::Invalid(
                "final transaction does not match the approved execution".into(),
            ));
        }

        let txid = final_tx.txid().to_byte_array();
        let stored = self.stored_vote(request_hash).await?;
        if let Some(stored_txid) = stored.execution_txid {
            let encoded = postcard::to_allocvec(request)?;
            if stored_txid != txid || stored.execution_request.as_deref() != Some(&encoded) {
                return Err(VotingExecutionError::Invalid(
                    "finalized voting execution changed after broadcast".into(),
                ));
            }
            self.broadcast(txid, request)?;
            return Ok(txid);
        }

        self.validate_transaction(request_hash, request, true, true, true, current_members)
            .await?;

        if stored.execution_started
            && stored.execution_transaction.as_deref() != Some(request.tx.as_slice())
        {
            self.cancel(request_hash, request.proposer_public_key, block_height)
                .await?;
        }

        self.record_broadcast(request_hash, txid, request).await?;
        self.broadcast(txid, request)?;
        Ok(txid)
    }

    async fn stored_vote(
        &self,
        request_hash: [u8; 32],
    ) -> Result<StoredVotingRequest, VotingExecutionError> {
        self.votes
            .get(request_hash)
            .await?
            .ok_or_else(|| VotingExecutionError::UnknownRequest(hex::encode(request_hash)))
    }

    fn select_treasury_utxos(
        &self,
        client: &Client,
        network: &SimplicityNetwork,
        indexed_utxos: Vec<TreasuryUtxo>,
    ) -> Result<Vec<UTXO>, VotingExecutionError> {
        let policy_asset = network.policy_asset();
        let mut selected = Vec::new();
        let mut total = 0u64;
        for indexed in indexed_utxos {
            let Some(utxo) = live_treasury_utxo(client, &indexed)? else {
                continue;
            };
            if utxo.asset() != policy_asset || utxo.amount() != indexed.amount {
                continue;
            }
            total = total
                .checked_add(utxo.amount())
                .ok_or_else(|| VotingExecutionError::Invalid("Treasury input overflow".into()))?;
            selected.push(utxo);
            if total >= self.transaction_fee_sats {
                return Ok(selected);
            }
        }
        Err(VotingExecutionError::Invalid(
            "Treasury cannot cover the voting transaction fee".into(),
        ))
    }

    fn client(&self) -> Result<Client, VotingExecutionError> {
        let mut url = Url::parse(&self.elements_rpc.url)?;
        url.path_segments_mut()
            .map_err(|_| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
            .pop_if_empty()
            .push("wallet")
            .push(&self.elements_rpc.wallet);
        Ok(Client::new(
            url.as_str(),
            Auth::UserPass(
                self.elements_rpc.username.clone(),
                self.elements_rpc.password.clone(),
            ),
        )?)
    }
}

fn require_retryable(stored: &StoredVotingRequest) -> Result<(), VotingExecutionError> {
    if stored.execution_confirmed {
        return Err(VotingExecutionError::AlreadyExecuted);
    }
    if stored.execution_txid.is_some() {
        return Err(VotingExecutionError::AlreadyExecuting);
    }
    if stored.approved_at_block_height.is_none() {
        return Err(VotingExecutionError::NotApproved);
    }
    Ok(())
}

fn require_approved_or_executing(
    stored: &StoredVotingRequest,
    transaction: &[u8],
) -> Result<(), VotingExecutionError> {
    if stored.execution_confirmed {
        return Err(VotingExecutionError::AlreadyExecuted);
    }
    if stored.execution_txid.is_some() {
        return Err(VotingExecutionError::AlreadyExecuting);
    }
    if stored.approved_at_block_height.is_none() {
        return Err(VotingExecutionError::NotApproved);
    }
    if stored.execution_started && stored.execution_transaction.as_deref() != Some(transaction) {
        return Err(VotingExecutionError::AlreadyExecuting);
    }
    Ok(())
}

fn decode_operation(
    stored: &StoredVotingRequest,
    current_members: &BTreeSet<[u8; 32]>,
) -> Result<ReshapeOperation, VotingExecutionError> {
    let message: NodeMessage = postcard::from_bytes(&stored.message)?;
    let request: crate::NetworkVoteRequest = message.decode_payload()?;
    match NetworkVoteKind::from_id(request.kind) {
        Some(NetworkVoteKind::MergeStormEyes) => {
            let merge: MergeStormEyes = postcard::from_bytes(&request.payload)?;
            let count = u8::try_from(merge.utxos_to_merge.len()).map_err(|_| {
                VotingExecutionError::Invalid("too many Storm Eyes to merge".into())
            })?;
            if !(2..=MAX_RESHAPE_COUNT as u8).contains(&count) {
                return Err(VotingExecutionError::Invalid(
                    "a merge requires two or three Storm Eye UTXOs".into(),
                ));
            }
            Ok(ReshapeOperation::Merge(merge.utxos_to_merge))
        }
        Some(NetworkVoteKind::SplitStormEye) => {
            let split: SplitStormEye = postcard::from_bytes(&request.payload)?;
            let count = u8::try_from(split.number_of_splits)
                .map_err(|_| VotingExecutionError::Invalid("too many Storm Eye splits".into()))?;
            if !(2..=MAX_RESHAPE_COUNT as u8).contains(&count) {
                return Err(VotingExecutionError::Invalid(
                    "a Storm Eye must be split into two or three outputs".into(),
                ));
            }
            Ok(ReshapeOperation::Split(split.utxo_to_split, count))
        }
        Some(NetworkVoteKind::UpdateNetworkMembers) => {
            let update: UpdateNetworkMembers = postcard::from_bytes(&request.payload)?;
            let mut members = current_members.clone();
            for member in update.to_remove {
                if !members.remove(&member) {
                    return Err(VotingExecutionError::Invalid(
                        "member update removes a non-member".into(),
                    ));
                }
            }
            for member in update.to_accept {
                if !members.insert(member) {
                    return Err(VotingExecutionError::Invalid(
                        "member update accepts an existing member".into(),
                    ));
                }
            }
            let members = members.into_iter().collect::<Vec<_>>();
            let new_root = StormTree::new(members.clone())
                .map_err(super::signing::SigningError::from)?
                .root();
            Ok(ReshapeOperation::UpdateMembers { members, new_root })
        }
        None => Err(VotingExecutionError::Invalid("unknown voting kind".into())),
    }
}

fn storm_eye_reservations(
    votes: &[StoredVotingRequest],
) -> Result<BTreeMap<StormEyeUtxo, StormEyeReservation>, VotingExecutionError> {
    let mut reservations = BTreeMap::new();
    for vote in votes.iter().filter(|vote| !vote.execution_confirmed) {
        let message: NodeMessage = postcard::from_bytes(&vote.message)?;
        let request: crate::NetworkVoteRequest = message.decode_payload()?;
        if NetworkVoteKind::from_id(request.kind) == Some(NetworkVoteKind::UpdateNetworkMembers) {
            continue;
        }
        let operation = decode_operation(vote, &BTreeSet::new())?;
        let state = if vote.execution_started {
            StormEyeState::Executing
        } else {
            StormEyeState::Proposed
        };
        let outpoints = match operation {
            ReshapeOperation::Merge(outpoints) => outpoints,
            ReshapeOperation::Split(outpoint, _) => vec![outpoint],
            ReshapeOperation::UpdateMembers { .. } => unreachable!("handled above"),
        };
        for outpoint in outpoints {
            let reservation = reservations
                .entry(outpoint)
                .or_insert_with(|| StormEyeReservation {
                    state,
                    voting_request_hashes: Vec::new(),
                });
            if state == StormEyeState::Executing {
                reservation.state = state;
            }
            if !reservation
                .voting_request_hashes
                .contains(&vote.message_hash)
            {
                reservation.voting_request_hashes.push(vote.message_hash);
            }
        }
    }
    Ok(reservations)
}

#[derive(Deserialize)]
struct ScanResult {
    unspents: Vec<ScannedUtxo>,
}

#[derive(Deserialize)]
struct ScannedUtxo {
    txid: String,
    vout: u32,
    height: Option<u64>,
}

#[derive(Deserialize)]
struct RawTransactionInfo {
    #[serde(default)]
    confirmations: u64,
}

fn operation_utxos(
    client: &Client,
    storm_eye: &NetworkAsset,
    operation: &ReshapeOperation,
) -> Result<Vec<UTXO>, VotingExecutionError> {
    if matches!(operation, ReshapeOperation::UpdateMembers { .. }) {
        return scan_storm_eye_utxos(client, storm_eye);
    }
    let outpoints = match operation {
        ReshapeOperation::Merge(outpoints) => outpoints.as_slice(),
        ReshapeOperation::Split(outpoint, _) => std::slice::from_ref(outpoint),
        ReshapeOperation::UpdateMembers { .. } => unreachable!("handled above"),
    };
    let expected_asset = asset_id(storm_eye.asset_id)?;
    outpoints
        .iter()
        .map(|outpoint| {
            let utxo = get_explicit_outpoint(
                client,
                Txid::from_byte_array(outpoint.txid),
                outpoint.output_index,
            )?;
            if utxo.asset() != expected_asset
                || utxo.txout.script_pubkey.as_bytes() != storm_eye.contract_script
            {
                return Err(VotingExecutionError::Invalid(
                    "voting request references a non-Storm-Eye UTXO".into(),
                ));
            }
            Ok(utxo)
        })
        .collect()
}

fn scan_storm_eye_utxos(
    client: &Client,
    storm_eye: &NetworkAsset,
) -> Result<Vec<UTXO>, VotingExecutionError> {
    let descriptor = format!("raw({})", hex::encode(&storm_eye.contract_script));
    let scan: ScanResult = client.call(
        "scantxoutset",
        &["start".into(), serde_json::json!([descriptor])],
    )?;
    let expected_asset = asset_id(storm_eye.asset_id)?;
    let mut utxos = scan
        .unspents
        .into_iter()
        .map(|unspent| {
            let txid = Txid::from_str(&unspent.txid)
                .map_err(|_| VotingExecutionError::Invalid("invalid Storm Eye txid".into()))?;
            let utxo = get_explicit_outpoint(client, txid, unspent.vout)?;
            if utxo.asset() != expected_asset
                || utxo.txout.script_pubkey.as_bytes() != storm_eye.contract_script
            {
                return Err(VotingExecutionError::Invalid(
                    "Storm Eye scan returned an invalid UTXO".into(),
                ));
            }
            Ok(utxo)
        })
        .collect::<Result<Vec<_>, _>>()?;
    utxos.sort_unstable_by_key(|utxo| (utxo.outpoint.txid.to_byte_array(), utxo.outpoint.vout));
    if utxos.is_empty() {
        return Err(VotingExecutionError::Invalid(
            "network has no live Storm Eye UTXOs to migrate".into(),
        ));
    }
    Ok(utxos)
}

fn live_treasury_utxo(
    client: &Client,
    indexed: &TreasuryUtxo,
) -> Result<Option<UTXO>, VotingExecutionError> {
    Ok(get_optional_explicit_outpoint(
        client,
        Txid::from_byte_array(indexed.txid),
        indexed.output_index,
    )?)
}

fn verify_voting_amounts(
    transaction: &simplex::simplicityhl::elements::Transaction,
    spent_utxos: &[TxOut],
) -> Result<(), VotingExecutionError> {
    let mut verifiable = transaction.clone();
    verifiable.output.retain(|output| {
        output.value.explicit() != Some(0) || !output.script_pubkey.is_provably_unspendable()
    });
    verifiable
        .verify_tx_amt_proofs(&Secp256k1::new(), spent_utxos)
        .map_err(|error| {
            VotingExecutionError::Invalid(format!(
                "failed to verify voting transaction amounts: {error}"
            ))
        })
}

fn build_transaction(
    proposer: [u8; 32],
    operation: ReshapeOperation,
    storm_eye: NetworkAsset,
    storm_eye_utxos: Vec<UTXO>,
    treasury_utxos: Vec<UTXO>,
    network: SimplicityNetwork,
    transaction_fee_sats: u64,
) -> Result<PreparedVotingExecution, VotingExecutionError> {
    let contract_data = contract_data(&storm_eye)?;
    let auth_program = storm_eye_program(&storm_eye)?;
    let storm_eye_inputs = storm_eye_utxos.len();
    let storm_eye_amount = storm_eye_utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount())
            .ok_or_else(|| VotingExecutionError::Invalid("Storm Eye amount overflow".into()))
    })?;
    let treasury_amount = treasury_utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount())
            .ok_or_else(|| VotingExecutionError::Invalid("Treasury amount overflow".into()))
    })?;
    let treasury_change = treasury_amount
        .checked_sub(transaction_fee_sats)
        .ok_or_else(|| VotingExecutionError::Invalid("Treasury cannot cover the fee".into()))?;

    let mut transaction = FinalTransaction::new();
    for (output_index, utxo) in storm_eye_utxos.iter().enumerate() {
        transaction.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(auth_program.as_ref().clone()),
                Box::new(placeholder_witness(
                    &contract_data,
                    &operation,
                    output_index as u32,
                )),
            ),
            RequiredSignature::witness_tagged("PATH", ["Left", "1", "0"], STORM_EYE_TAG),
        );
    }

    let treasury = TreasuryProgram::new(&TreasuryArguments {
        storm_eye_asset_id: storm_eye.asset_id,
    });
    for utxo in &treasury_utxos {
        transaction.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(treasury.as_ref().clone()),
                Box::new(TreasuryWitness {
                    storm_eye_input_index: 0,
                }),
            ),
            RequiredSignature::None,
        );
    }

    let storm_eye_asset = asset_id(storm_eye.asset_id)?;
    let storm_eye_script = Script::from(storm_eye.contract_script.clone());
    match &operation {
        ReshapeOperation::Merge(_) => transaction.add_output(PartialOutput::new(
            storm_eye_script,
            storm_eye_amount,
            storm_eye_asset,
        )),
        ReshapeOperation::Split(_, count) => {
            if storm_eye_amount < u64::from(*count) {
                return Err(VotingExecutionError::Invalid(
                    "Storm Eye amount is too small for the requested split".into(),
                ));
            }
            let base = storm_eye_amount / u64::from(*count);
            let remainder = storm_eye_amount % u64::from(*count);
            for index in 0..*count {
                transaction.add_output(PartialOutput::new(
                    storm_eye_script.clone(),
                    base + u64::from(index < remainder as u8),
                    storm_eye_asset,
                ));
            }
        }
        ReshapeOperation::UpdateMembers { members, new_root } => {
            let destination_script = migrated_storm_eye_script(&storm_eye, *new_root, &network)?;
            for utxo in &storm_eye_utxos {
                transaction.add_output(PartialOutput::new(
                    destination_script.clone(),
                    utxo.amount(),
                    storm_eye_asset,
                ));
            }
            transaction.add_output(PartialOutput::new(
                migrated_members_script(members, proposer)?,
                0,
                network.policy_asset(),
            ));
        }
    }

    let policy_asset = network.policy_asset();
    if treasury_change > 0 {
        transaction.add_output(PartialOutput::new(
            treasury.get_script_pubkey(&network),
            treasury_change,
            policy_asset,
        ));
    }
    if !matches!(operation, ReshapeOperation::UpdateMembers { .. }) {
        transaction.add_output(PartialOutput::new(member_script(proposer), 0, policy_asset));
    }
    transaction.add_output(PartialOutput::new(
        Script::new(),
        transaction_fee_sats,
        policy_asset,
    ));

    let spent_utxos = storm_eye_utxos
        .iter()
        .chain(&treasury_utxos)
        .map(|utxo| utxo.txout.clone())
        .collect();
    let (pset, _) = transaction.extract_pst();
    let request = ExecuteVotingRequest {
        tx: encode::serialize(&pset),
        final_tx: None,
        signing_hashes: signing_hashes(&pset, &storm_eye, &network, storm_eye_inputs)?,
        signing_storm_tree_branch: contract_data.storm_tree_root,
        proposer_public_key: proposer,
    };

    Ok(PreparedVotingExecution {
        request,
        transaction,
        pset,
        spent_utxos,
        storm_eye_inputs,
        operation,
        network,
        storm_eye,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_layout(
    client: &Client,
    pset: &PartiallySignedTransaction,
    request_signing_hashes: &[[u8; 32]],
    proposer: [u8; 32],
    operation: &ReshapeOperation,
    storm_eye: &NetworkAsset,
    network: &SimplicityNetwork,
    transaction_fee_sats: u64,
    indexed_treasury: &[TreasuryUtxo],
    allow_spent_inputs: bool,
) -> Result<(), VotingExecutionError> {
    let scanned_update_utxos = if matches!(operation, ReshapeOperation::UpdateMembers { .. }) {
        match scan_storm_eye_utxos(client, storm_eye) {
            Ok(utxos) => Some(utxos),
            Err(VotingExecutionError::Invalid(message))
                if allow_spent_inputs
                    && message == "network has no live Storm Eye UTXOs to migrate" =>
            {
                Some(Vec::new())
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let update_outpoints = scanned_update_utxos
        .as_ref()
        .map(|utxos| {
            utxos
                .iter()
                .map(|utxo| StormEyeUtxo {
                    txid: utxo.outpoint.txid.to_byte_array(),
                    output_index: utxo.outpoint.vout,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let transaction_update_outpoints =
        if allow_spent_inputs && matches!(operation, ReshapeOperation::UpdateMembers { .. }) {
            pset.inputs()
                .iter()
                .take_while(|input| {
                    input.witness_utxo.as_ref().is_some_and(|output| {
                        output.script_pubkey.as_bytes() == storm_eye.contract_script
                    })
                })
                .map(|input| StormEyeUtxo {
                    txid: input.previous_txid.to_byte_array(),
                    output_index: input.previous_output_index,
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
    let expected_outpoints = match operation {
        ReshapeOperation::Merge(outpoints) => outpoints.as_slice(),
        ReshapeOperation::Split(outpoint, _) => std::slice::from_ref(outpoint),
        ReshapeOperation::UpdateMembers { .. }
            if allow_spent_inputs && update_outpoints.is_empty() =>
        {
            transaction_update_outpoints.as_slice()
        }
        ReshapeOperation::UpdateMembers { .. } => update_outpoints.as_slice(),
    };
    let storm_count = expected_outpoints.len();
    if storm_count == 0 {
        return Err(VotingExecutionError::Invalid(
            "voting transaction has no Storm Eye input".into(),
        ));
    }
    if pset.inputs().len() <= storm_count {
        return Err(VotingExecutionError::Invalid(
            "voting transaction has no Treasury fee input".into(),
        ));
    }
    let storm_asset = asset_id(storm_eye.asset_id)?;
    let mut storm_total = 0u64;
    for (index, expected) in expected_outpoints.iter().enumerate() {
        let input = pset.inputs().get(index).ok_or_else(|| {
            VotingExecutionError::Invalid("voting transaction is missing a Storm Eye input".into())
        })?;
        if input.previous_txid.to_byte_array() != expected.txid
            || input.previous_output_index != expected.output_index
        {
            return Err(VotingExecutionError::Invalid(
                "Storm Eye inputs do not match the approved vote".into(),
            ));
        }
        let witness = witness_utxo(pset, index)?;
        let previous = voting_input(
            client,
            input.previous_txid,
            input.previous_output_index,
            allow_spent_inputs,
        )?;
        if witness != &previous
            || previous.asset.explicit() != Some(storm_asset)
            || previous.script_pubkey.as_bytes() != storm_eye.contract_script
        {
            return Err(VotingExecutionError::Invalid(
                "Storm Eye input does not match the live approved UTXO".into(),
            ));
        }
        storm_total = storm_total
            .checked_add(previous.value.explicit().ok_or_else(|| {
                VotingExecutionError::Invalid("Storm Eye input value must be explicit".into())
            })?)
            .ok_or_else(|| VotingExecutionError::Invalid("Storm Eye amount overflow".into()))?;
    }

    let treasury = TreasuryProgram::new(&TreasuryArguments {
        storm_eye_asset_id: storm_eye.asset_id,
    });
    let treasury_script = treasury.get_script_pubkey(network);
    let policy_asset = network.policy_asset();
    let mut treasury_total = 0u64;
    for index in storm_count..pset.inputs().len() {
        let input = &pset.inputs()[index];
        if !indexed_treasury.iter().any(|utxo| {
            utxo.txid == input.previous_txid.to_byte_array()
                && utxo.output_index == input.previous_output_index
        }) {
            return Err(VotingExecutionError::Invalid(
                "voting transaction uses an unindexed Treasury input".into(),
            ));
        }
        let witness = witness_utxo(pset, index)?;
        let previous = voting_input(
            client,
            input.previous_txid,
            input.previous_output_index,
            allow_spent_inputs,
        )?;
        if witness != &previous
            || previous.asset.explicit() != Some(policy_asset)
            || previous.script_pubkey != treasury_script
        {
            return Err(VotingExecutionError::Invalid(
                "Treasury fee input does not match the live UTXO".into(),
            ));
        }
        treasury_total = treasury_total
            .checked_add(previous.value.explicit().ok_or_else(|| {
                VotingExecutionError::Invalid("Treasury input value must be explicit".into())
            })?)
            .ok_or_else(|| VotingExecutionError::Invalid("Treasury amount overflow".into()))?;
    }

    let split_count = match operation {
        ReshapeOperation::Merge(_) => 1,
        ReshapeOperation::Split(_, count) => usize::from(*count),
        ReshapeOperation::UpdateMembers { .. } => storm_count,
    };
    if pset.outputs().len() < split_count + 2 {
        return Err(VotingExecutionError::Invalid(
            "voting transaction outputs are incomplete".into(),
        ));
    }
    let expected_base = storm_total / split_count as u64;
    let expected_remainder = storm_total % split_count as u64;
    let destination_script = match operation {
        ReshapeOperation::UpdateMembers { new_root, .. } => {
            migrated_storm_eye_script(storm_eye, *new_root, network)?
        }
        _ => Script::from(storm_eye.contract_script.clone()),
    };
    for (index, output) in pset.outputs().iter().take(split_count).enumerate() {
        let expected = match operation {
            ReshapeOperation::UpdateMembers { .. } => voting_input(
                client,
                Txid::from_byte_array(expected_outpoints[index].txid),
                expected_outpoints[index].output_index,
                allow_spent_inputs,
            )?
            .value
            .explicit()
            .ok_or_else(|| {
                VotingExecutionError::Invalid("Storm Eye input value must be explicit".into())
            })?,
            _ => expected_base + u64::from(index < expected_remainder as usize),
        };
        if !is_fully_explicit_output(output)
            || output.asset != Some(storm_asset)
            || output.amount != Some(expected)
            || output.script_pubkey != destination_script
        {
            return Err(VotingExecutionError::Invalid(
                "Storm Eye outputs do not match the approved reshape".into(),
            ));
        }
    }

    let mut marker_count = 0usize;
    let mut members_marker_count = 0usize;
    let mut fee_count = 0usize;
    let mut treasury_return = 0u64;
    for output in pset.outputs().iter().skip(split_count) {
        if !is_fully_explicit_output(output) || output.asset != Some(policy_asset) {
            return Err(VotingExecutionError::Invalid(
                "voting fee outputs must be explicit LBTC".into(),
            ));
        }
        let amount = output.amount.ok_or_else(|| {
            VotingExecutionError::Invalid("voting output amount is missing".into())
        })?;
        if output.script_pubkey == treasury_script {
            treasury_return = treasury_return
                .checked_add(amount)
                .ok_or_else(|| VotingExecutionError::Invalid("Treasury change overflow".into()))?;
        } else if output.script_pubkey == member_script(proposer) && amount == 0 {
            marker_count += 1;
        } else if matches!(operation, ReshapeOperation::UpdateMembers { .. })
            && amount == 0
            && migrated_members_script(
                match operation {
                    ReshapeOperation::UpdateMembers { members, .. } => members,
                    _ => unreachable!(),
                },
                proposer,
            )? == output.script_pubkey
        {
            marker_count += 1;
            members_marker_count += 1;
        } else if output.script_pubkey.is_empty() && amount == transaction_fee_sats {
            fee_count += 1;
        } else {
            return Err(VotingExecutionError::Invalid(
                "voting transaction contains an unexpected output".into(),
            ));
        }
    }
    let expected_members_markers =
        usize::from(matches!(operation, ReshapeOperation::UpdateMembers { .. }));
    if marker_count != 1
        || members_marker_count != expected_members_markers
        || fee_count != 1
        || treasury_total.checked_sub(treasury_return) != Some(transaction_fee_sats)
    {
        return Err(VotingExecutionError::Invalid(
            "voting transaction fee accounting is invalid".into(),
        ));
    }
    if signing_hashes(pset, storm_eye, network, storm_count)? != request_signing_hashes {
        return Err(VotingExecutionError::Invalid(
            "voting execution signing hashes mismatch".into(),
        ));
    }
    Ok(())
}

fn voting_input(
    client: &Client,
    txid: Txid,
    output_index: u32,
    allow_spent: bool,
) -> Result<TxOut, VotingExecutionError> {
    if let Some(utxo) = get_optional_explicit_outpoint(client, txid, output_index)? {
        return Ok(utxo.txout);
    }
    if !allow_spent {
        return Err(VotingExecutionError::Invalid(
            "required voting input is unavailable".into(),
        ));
    }

    let encoded: String = client.call(
        "getrawtransaction",
        &[txid.to_string().into(), false.into()],
    )?;
    let transaction: simplex::simplicityhl::elements::Transaction =
        encode::deserialize(&hex::decode(encoded).map_err(|_| {
            VotingExecutionError::Invalid("invalid previous voting transaction encoding".into())
        })?)?;
    transaction
        .output
        .get(output_index as usize)
        .cloned()
        .ok_or_else(|| {
            VotingExecutionError::Invalid("previous voting transaction output is missing".into())
        })
}

fn placeholder_witness(
    data: &StormEyeContractData,
    operation: &ReshapeOperation,
    output_index: u32,
) -> AuthWitness {
    let kind = match operation {
        ReshapeOperation::Split(_, count) => Either::Right(Either::Right(Either::Left(*count))),
        ReshapeOperation::Merge(outpoints) => {
            Either::Right(Either::Right(Either::Right(outpoints.len() as u8)))
        }
        ReshapeOperation::UpdateMembers { new_root, .. } => {
            Either::Right(Either::Left(Either::Left((*new_root, output_index))))
        }
    };
    AuthWitness {
        path: Either::Left((
            (data.storm_tree_root, data.rescue_height),
            (
                [0; 64],
                data.storm_tree_root,
                std::array::from_fn(|_| Either::Left(())),
            ),
            kind,
        )),
    }
}

fn verified_signatures(
    prepared: &PreparedVotingExecution,
    signing: &SigningResult,
    proof: &StormTreeProof,
) -> Result<Vec<[u8; 64]>, VotingExecutionError> {
    if !has_signature_per_input(
        signing.signatures.len(),
        prepared.request.signing_hashes.len(),
        prepared.storm_eye_inputs,
    ) {
        return Err(VotingExecutionError::Invalid(
            "incorrect number of Storm Eye signatures".into(),
        ));
    }
    let branch_key = XOnlyPublicKey::from_slice(&signing.signing_storm_tree_branch)
        .map_err(|_| VotingExecutionError::Invalid("invalid Storm Eye signing branch".into()))?;
    for (signature, signing_hash) in signing
        .signatures
        .iter()
        .zip(&prepared.request.signing_hashes)
    {
        Secp256k1::verification_only()
            .verify_schnorr(
                &Signature::from_slice(signature).map_err(|_| {
                    VotingExecutionError::Invalid("invalid Storm Eye signature".into())
                })?,
                &Message::from_digest_slice(signing_hash).expect("the signing hash has 32 bytes"),
                &branch_key,
            )
            .map_err(|_| {
                VotingExecutionError::Invalid("Storm Eye signature verification failed".into())
            })?;
    }
    let data = contract_data(&prepared.storm_eye)?;
    if !storm_tree::StormTree::verify_branch(
        &data.storm_tree_root,
        &signing.signing_storm_tree_branch,
        proof,
    ) {
        return Err(VotingExecutionError::Invalid(
            "signing branch is not included in the Storm Eye root".into(),
        ));
    }
    Ok(signing.signatures.clone())
}

fn has_signature_per_input(
    signature_count: usize,
    signing_hash_count: usize,
    input_count: usize,
) -> bool {
    signature_count == signing_hash_count && signature_count == input_count
}

fn reshape_witness(
    data: &StormEyeContractData,
    signing: &SigningResult,
    proof: &StormTreeProof,
    operation: &ReshapeOperation,
    signature: [u8; 64],
    output_index: u32,
) -> Result<AuthWitness, VotingExecutionError> {
    let kind = match operation {
        ReshapeOperation::Split(_, count) => Either::Right(Either::Right(Either::Left(*count))),
        ReshapeOperation::Merge(outpoints) => {
            Either::Right(Either::Right(Either::Right(outpoints.len() as u8)))
        }
        ReshapeOperation::UpdateMembers { new_root, .. } => {
            Either::Right(Either::Left(Either::Left((*new_root, output_index))))
        }
    };
    Ok(AuthWitness {
        path: Either::Left((
            (data.storm_tree_root, data.rescue_height),
            (
                signature,
                signing.signing_storm_tree_branch,
                pack_proof(proof)?,
            ),
            kind,
        )),
    })
}

fn migrated_storm_eye_script(
    storm_eye: &NetworkAsset,
    new_root: [u8; 32],
    network: &SimplicityNetwork,
) -> Result<Script, VotingExecutionError> {
    Ok(Script::from(
        migrated_storm_eye(storm_eye, new_root, network)?.contract_script,
    ))
}

fn migrated_storm_eye(
    storm_eye: &NetworkAsset,
    new_root: [u8; 32],
    network: &SimplicityNetwork,
) -> Result<NetworkAsset, VotingExecutionError> {
    let mut migrated = storm_eye.clone();
    let mut data = contract_data(storm_eye)?;
    data.storm_tree_root = new_root;
    migrated.contract_data = Some(postcard::to_stdvec(&data)?);
    migrated.contract_script = storm_eye_program(&migrated)?
        .get_script_pubkey(network)
        .into_bytes();
    Ok(migrated)
}

fn contract_data(storm_eye: &NetworkAsset) -> Result<StormEyeContractData, VotingExecutionError> {
    postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
        VotingExecutionError::Invalid("Storm Eye contract data is missing".into())
    })?)
    .map_err(Into::into)
}

fn signing_hashes(
    pset: &PartiallySignedTransaction,
    storm_eye: &NetworkAsset,
    network: &SimplicityNetwork,
    input_count: usize,
) -> Result<Vec<[u8; 32]>, VotingExecutionError> {
    let program = storm_eye_program(storm_eye)?;
    (0..input_count)
        .map(|input_index| {
            let env = program.as_ref().get_env(pset, input_index, network)?;
            Ok(SigMessage::Tagged(STORM_EYE_TAG.to_string())
                .digest(env.c_tx_env().sighash_all().to_byte_array()))
        })
        .collect()
}

fn network(client: &Client) -> Result<SimplicityNetwork, VotingExecutionError> {
    #[derive(serde::Deserialize)]
    struct ChainInfo {
        chain: String,
    }
    #[derive(serde::Deserialize)]
    struct SidechainInfo {
        pegged_asset: String,
    }

    let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
    match chain.chain.as_str() {
        "liquidv1" => Ok(SimplicityNetwork::Liquid),
        "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elementsregtest" => {
            let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
            let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
            Ok(SimplicityNetwork::ElementsCustom {
                policy_asset: AssetId::from_str(&sidechain.pegged_asset).map_err(|_| {
                    VotingExecutionError::Invalid("invalid regtest policy asset".into())
                })?,
                genesis_hash: BlockHash::from_str(&genesis_hash).map_err(|_| {
                    VotingExecutionError::Invalid("invalid regtest genesis hash".into())
                })?,
            })
        }
        _ => Err(VotingExecutionError::Invalid(format!(
            "unsupported Elements chain '{}'",
            chain.chain
        ))),
    }
}

#[cfg(test)]
mod inventory_tests {
    use super::*;
    use crate::NodeMessageKind;
    use secp256k1::{PublicKey, SecretKey};
    use simplex::simplicityhl::elements::{
        BlockHash, LockTime, OutPoint, Transaction, TxIn, confidential,
    };

    #[test]
    fn executing_votes_override_proposed_reservations() {
        let shared = StormEyeUtxo {
            txid: [1; 32],
            output_index: 2,
        };
        let proposed = stored_reshape([3; 32], shared, false, None);
        let executing = stored_reshape([4; 32], shared, true, None);
        let broadcast = stored_reshape([5; 32], shared, true, Some([6; 32]));
        let executed = stored_reshape([7; 32], shared, false, Some([8; 32]));

        let reservations =
            storm_eye_reservations(&[proposed, executing, broadcast, executed]).unwrap();
        let reservation = reservations.get(&shared).unwrap();

        assert_eq!(reservation.state, StormEyeState::Executing);
        assert_eq!(
            reservation.voting_request_hashes,
            vec![[3; 32], [4; 32], [5; 32]]
        );
    }

    #[test]
    fn interrupted_execution_remains_retryable() {
        let mut executing = stored_member_update([8; 32], [9; 32]);
        executing.execution_started = true;
        executing.execution_transaction = Some(vec![1, 2, 3]);

        assert!(require_retryable(&executing).is_ok());
        assert!(matches!(
            require_approved_or_executing(&executing, &[4, 5, 6]),
            Err(VotingExecutionError::AlreadyExecuting)
        ));
    }

    #[test]
    fn verifies_amounts_with_zero_value_member_marker() {
        let asset = AssetId::from_byte_array([8; 32]);
        let spent_utxo = TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(1_000),
            script_pubkey: Script::from(vec![0x51]),
            ..Default::default()
        };
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(1_000),
                    script_pubkey: Script::new(),
                    ..Default::default()
                },
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(0),
                    script_pubkey: member_script([7; 32]),
                    ..Default::default()
                },
            ],
        };

        verify_voting_amounts(&transaction, &[spent_utxo]).unwrap();
    }

    #[test]
    fn requires_one_signature_and_hash_per_storm_eye_input() {
        assert!(has_signature_per_input(1, 1, 1));
        assert!(has_signature_per_input(2, 2, 2));
        assert!(!has_signature_per_input(1, 1, 2));
        assert!(!has_signature_per_input(2, 1, 2));
    }

    #[test]
    fn member_update_derives_target_root_and_root_update_witness() {
        let member = |byte| {
            PublicKey::from_secret_key(&SecretKey::from_secret_bytes([byte; 32]).unwrap())
                .x_only_public_key()
                .0
                .serialize()
        };
        let current = [member(1), member(2), member(3)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let target = [member(1), member(3), member(4)]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let stored = stored_member_update(member(4), member(2));

        let operation = decode_operation(&stored, &current).unwrap();
        let expected_root = StormTree::new(target.clone()).unwrap().root();
        assert!(matches!(
            &operation,
            ReshapeOperation::UpdateMembers { members, new_root }
                if members == &target && *new_root == expected_root
        ));

        let witness = placeholder_witness(
            &StormEyeContractData {
                storm_tree_root: [8; 32],
                rescue_height: 42,
                rescue_output_script_hash: [9; 32],
            },
            &operation,
            2,
        );
        assert!(matches!(
            witness.path,
            Either::Left((
                (old_root, rescue_height),
                _,
                Either::Right(Either::Left(Either::Left((root, 2))))
            )) if old_root == [8; 32] && rescue_height == 42 && root == expected_root
        ));
    }

    #[test]
    fn member_update_migrates_every_storm_eye_to_the_new_root() {
        let member = |byte| {
            PublicKey::from_secret_key(&SecretKey::from_secret_bytes([byte; 32]).unwrap())
                .x_only_public_key()
                .0
                .serialize()
        };
        let members = [member(1), member(2), member(3)];
        let new_root = StormTree::new(members.to_vec()).unwrap().root();
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset: AssetId::from_byte_array([10; 32]),
            genesis_hash: BlockHash::from_byte_array([11; 32]),
        };
        let mut storm_eye = NetworkAsset {
            kind: STORM_EYE_KIND.to_string(),
            name: "Storm Eye".to_string(),
            asset_id: [12; 32],
            reissuance_token_id: None,
            entropy: None,
            issuance_txid: [13; 32],
            contract_script: Vec::new(),
            contract_data: Some(
                postcard::to_stdvec(&StormEyeContractData {
                    storm_tree_root: [14; 32],
                    rescue_height: 42,
                    rescue_output_script_hash: [15; 32],
                })
                .unwrap(),
            ),
            supply: 10_000,
            created_at_block: 1,
        };
        storm_eye.contract_script = storm_eye_program(&storm_eye)
            .unwrap()
            .get_script_pubkey(&network)
            .into_bytes();
        let storm_asset = AssetId::from_byte_array(storm_eye.asset_id);
        let old_script = Script::from(storm_eye.contract_script.clone());
        let storm_utxo = |byte, output_index, amount| UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([byte; 32]), output_index),
            txout: TxOut {
                asset: confidential::Asset::Explicit(storm_asset),
                value: confidential::Value::Explicit(amount),
                script_pubkey: old_script.clone(),
                ..Default::default()
            },
            secrets: None,
        };
        let treasury = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        });
        let treasury_utxo = UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([16; 32]), 0),
            txout: TxOut {
                asset: confidential::Asset::Explicit(network.policy_asset()),
                value: confidential::Value::Explicit(2_000),
                script_pubkey: treasury.get_script_pubkey(&network),
                ..Default::default()
            },
            secrets: None,
        };

        let prepared = build_transaction(
            [17; 32],
            ReshapeOperation::UpdateMembers {
                members: members.to_vec(),
                new_root,
            },
            storm_eye.clone(),
            vec![storm_utxo(18, 0, 4_000), storm_utxo(19, 1, 6_000)],
            vec![treasury_utxo],
            network,
            500,
        )
        .unwrap();
        let destination = migrated_storm_eye_script(&storm_eye, new_root, &network).unwrap();

        assert_eq!(prepared.storm_eye_inputs, 2);
        assert_eq!(prepared.pset.outputs()[0].amount, Some(4_000));
        assert_eq!(prepared.pset.outputs()[1].amount, Some(6_000));
        assert_eq!(prepared.pset.outputs()[0].script_pubkey, destination);
        assert_eq!(prepared.pset.outputs()[1].script_pubkey, destination);
        assert_eq!(
            prepared
                .pset
                .outputs()
                .iter()
                .filter(|output| {
                    !output.script_pubkey.is_empty()
                        && output.script_pubkey.is_provably_unspendable()
                })
                .count(),
            1
        );
        assert!(prepared.pset.outputs().iter().any(|output| {
            output.amount == Some(0)
                && output.script_pubkey == migrated_members_script(&members, [17; 32]).unwrap()
        }));
    }

    fn stored_reshape(
        message_hash: [u8; 32],
        outpoint: StormEyeUtxo,
        execution_started: bool,
        execution_txid: Option<[u8; 32]>,
    ) -> StoredVotingRequest {
        let request = crate::NetworkVoteRequest::new(
            NetworkVoteKind::SplitStormEye,
            &SplitStormEye {
                utxo_to_split: outpoint,
                number_of_splits: 2,
            },
        )
        .unwrap();
        let message =
            NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request).unwrap();

        StoredVotingRequest {
            message_hash,
            message: postcard::to_allocvec(&message).unwrap(),
            proposer_public_key: Some([7; 32]),
            block_height: 1,
            approved_at_block_height: None,
            execution_started,
            execution_transaction: execution_started.then(Vec::new),
            execution_request: None,
            execution_txid,
            execution_confirmed: execution_txid.is_some() && !execution_started,
            approvals: Vec::new(),
        }
    }

    fn stored_member_update(accepted: [u8; 32], removed: [u8; 32]) -> StoredVotingRequest {
        let request = crate::NetworkVoteRequest::new(
            NetworkVoteKind::UpdateNetworkMembers,
            &UpdateNetworkMembers {
                to_accept: vec![accepted],
                to_remove: vec![removed],
            },
        )
        .unwrap();
        let message =
            NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request).unwrap();

        StoredVotingRequest {
            message_hash: [6; 32],
            message: postcard::to_allocvec(&message).unwrap(),
            proposer_public_key: Some([7; 32]),
            block_height: 1,
            approved_at_block_height: Some(2),
            execution_started: false,
            execution_transaction: None,
            execution_request: None,
            execution_txid: None,
            execution_confirmed: false,
            approvals: Vec::new(),
        }
    }
}
