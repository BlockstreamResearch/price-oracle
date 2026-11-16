//! Governance votes, their execution and member migration.

use crate::high_storm::*;

impl HighStorm {
    pub(crate) async fn restore_member_migration(&self) -> Result<(), VotingError> {
        self.state
            .voting()
            .restore_member_migration(&self.storm.handle())
            .await
    }

    pub async fn create_voting_request(
        &self,
        request: NetworkVoteRequest,
        block_height: u64,
    ) -> Result<[u8; 32], VotingError> {
        self.state.set_block_height(block_height);
        self.state
            .voting()
            .create(&self.storm.handle(), request, block_height)
            .await
    }

    pub async fn approve_voting_request(
        &self,
        request_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(), VotingError> {
        self.state.set_block_height(block_height);
        self.state
            .voting()
            .approve(&self.storm.handle(), request_hash, block_height)
            .await
    }

    pub async fn voting_request(
        &self,
        request_hash: [u8; 32],
    ) -> Result<Option<VotingRequest>, VotingError> {
        self.state.voting().get(request_hash).await
    }

    pub async fn voting_requests(&self) -> Result<Vec<VotingRequest>, VotingError> {
        self.state.voting().list().await
    }

    pub async fn synchronize_voting_requests(&self) -> Result<(), VotingError> {
        self.state.voting().synchronize(&self.storm.handle()).await
    }

    pub async fn remove_expired_voting_requests(
        &self,
        block_height: u64,
    ) -> Result<u64, VotingError> {
        self.state.set_block_height(block_height);
        self.state.voting().remove_expired(block_height).await
    }

    pub async fn reconcile_voting_executions(&self) -> Result<usize, VotingExecutionError> {
        self.handle().reconcile_voting_executions().await
    }
}

impl HighStormHandle {
    pub async fn member_migration_request(&self) -> Option<[u8; 32]> {
        self.state.member_migration_request().await
    }

    pub async fn member_migration_ready(&self) -> bool {
        self.storm.member_migration_ready().await
    }

    pub(crate) async fn open_voting_kinds(&self) -> Result<Vec<&'static str>, VotingError> {
        self.state.voting().unconfirmed_kinds().await
    }

    pub async fn create_voting_request(
        &self,
        request: NetworkVoteRequest,
    ) -> Result<[u8; 32], VotingError> {
        self.state
            .voting()
            .create(&self.storm, request, self.state.block_height())
            .await
    }

    pub async fn approve_voting_request(&self, request_hash: [u8; 32]) -> Result<(), VotingError> {
        self.state
            .voting()
            .approve(&self.storm, request_hash, self.state.block_height())
            .await
    }

    pub async fn execute_voting_request(
        &self,
        request_hash: [u8; 32],
    ) -> Result<[u8; 32], VotingExecutionError> {
        if self.is_transaction_production_blocked() {
            return Err(VotingExecutionError::Invalid(
                "transaction production is paused for chain recovery or member migration".into(),
            ));
        }
        self.spawn_voting_execution(request_hash)?
            .await
            .map_err(|error| {
                VotingExecutionError::Invalid(format!("voting execution task failed: {error}"))
            })?
    }

    fn spawn_voting_execution(
        &self,
        request_hash: [u8; 32],
    ) -> Result<tokio::task::JoinHandle<Result<[u8; 32], VotingExecutionError>>, VotingExecutionError>
    {
        let attempt = self
            .state
            .begin_voting_execution(request_hash)
            .ok_or(VotingExecutionError::AlreadyExecuting)?;
        let handle = self.clone();
        Ok(tokio::spawn(async move {
            let _attempt = attempt;
            let result = handle.execute_voting_request_inner(request_hash).await;
            monitoring::record_voting_execution(match &result {
                Ok(_) => "broadcast",
                Err(VotingExecutionError::MemberMigrationNotReady) => "migration_not_ready",
                Err(_) => "failed",
            });
            if let Err(error) = &result {
                tracing::warn!(request_hash = %hex::encode(request_hash), %error, "voting execution attempt failed");
            }
            result
        }))
    }

    async fn execute_voting_request_inner(
        &self,
        request_hash: [u8; 32],
    ) -> Result<[u8; 32], VotingExecutionError> {
        let peers = self.peers().await;
        let current_members = voting_member_keys(&peers)?;
        let local = leader::local_public_key(&peers).ok_or_else(|| {
            VotingExecutionError::Invalid("local network member is missing".into())
        })?;
        handler::authorize_voting_executor(&current_members, local)?;

        let vote = self
            .state
            .voting()
            .get(request_hash)
            .await
            .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
            .ok_or_else(|| VotingExecutionError::UnknownRequest(hex::encode(request_hash)))?;
        if let Some(target_members) = member_migration_target(&vote.request, &current_members)? {
            self.state
                .ensure_member_migration(&self.storm, request_hash, target_members)
                .await
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
            if !self.storm.member_migration_ready().await {
                return Err(VotingExecutionError::MemberMigrationNotReady);
            }
        }
        let mut request = self
            .state
            .voting_execution()
            .prepare(request_hash, &current_members)
            .await?;
        let chain_tip = self
            .state
            .indexer()
            .chain_tip()
            .await
            .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
        request.chain_tip = Some(chain_tip);
        let proposer = request.proposer_public_key;

        self.state
            .voting_execution()
            .begin(
                request_hash,
                &request,
                self.state.block_height(),
                &current_members,
            )
            .await?;
        let signing = match self
            .state
            .signing()
            .sign_execute_voting_request(
                &self.storm,
                request_hash,
                request.tx.clone(),
                request.signing_hashes.clone(),
                proposer,
                chain_tip,
            )
            .await
        {
            Ok(signing) => signing,
            Err(error) => return Err(error.into()),
        };
        let proof = match self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await
        {
            Ok(proof) => proof,
            Err(error) => return Err(error.into()),
        };
        let mut prepared = match self
            .state
            .voting_execution()
            .prepare_finalization(request_hash, &request, &current_members)
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                let message = error.to_string();
                return Err(VotingExecutionError::Invalid(message));
            }
        };
        prepared.request.chain_tip = Some(chain_tip);
        let (txid, notification) = match self
            .state
            .voting_execution()
            .finalize(prepared, signing, proof)
        {
            Ok(finalized) => finalized,
            Err(error) => {
                let message = error.to_string();
                drop(error);
                return Err(VotingExecutionError::Invalid(message));
            }
        };
        self.state
            .voting_execution()
            .record_broadcast(request_hash, txid, &notification)
            .await?;
        self.state
            .voting_execution()
            .broadcast(txid, &notification)?;
        if let Err(error) = self
            .announce_voting_execution(request_hash, &notification)
            .await
        {
            tracing::warn!(%error, "failed to announce executed voting request");
        }
        Ok(txid)
    }

    async fn activate_member_migration(
        &self,
        request_hash: [u8; 32],
        txid: [u8; 32],
        block_height: u64,
        block_hash: [u8; 32],
        current_members: &BTreeSet<[u8; 32]>,
    ) -> Result<(), VotingExecutionError> {
        activate_member_migration_state(
            &self.state,
            &self.storm,
            request_hash,
            txid,
            block_height,
            block_hash,
            current_members,
        )
        .await
    }

    pub async fn reconcile_voting_executions(&self) -> Result<usize, VotingExecutionError> {
        let mut confirmed = 0;
        if let Some(request_hash) = self.state.member_migration_request().await
            && self
                .state
                .voting()
                .get(request_hash)
                .await
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
                .is_some_and(|request| request.status == VotingStatus::Executed)
        {
            finish_member_migration_state(&self.state, &self.storm).await?;
        }

        for (request_hash, txid, request) in
            self.state.voting_execution().pending_broadcasts().await?
        {
            let current_members = voting_member_keys(&self.peers().await)?;
            let vote = self
                .state
                .voting()
                .get(request_hash)
                .await
                .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?
                .ok_or_else(|| VotingExecutionError::UnknownRequest(hex::encode(request_hash)))?;
            let is_member_migration =
                member_migration_target(&vote.request, &current_members)?.is_some();
            let Some(inclusion) = self
                .state
                .voting_execution()
                .transaction_confirmation(txid)?
            else {
                if is_member_migration {
                    self.state
                        .set_spending_paused(false)
                        .await
                        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
                }
                self.state
                    .voting_execution()
                    .mark_orphaned(request_hash, txid)
                    .await?;
                self.state.voting_execution().broadcast(txid, &request)?;
                if let Err(error) = self.announce_voting_execution(request_hash, &request).await {
                    tracing::warn!(%error, "failed to reannounce voting execution");
                }
                continue;
            };
            if is_member_migration {
                self.state
                    .set_spending_paused(true)
                    .await
                    .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
            }
            let included_at = inclusion.block_height;
            self.state
                .voting_execution()
                .mark_included(request_hash, txid, included_at, inclusion.block_hash)
                .await?;
            if !self
                .state
                .voting_execution()
                .is_final(inclusion.confirmations)
            {
                // Peers that missed the first notice can still record it before finality.
                if let Err(error) = self.announce_voting_execution(request_hash, &request).await {
                    tracing::warn!(%error, "failed to reannounce voting execution");
                }
                continue;
            }

            if is_member_migration {
                let canonical_hash = self
                    .state
                    .indexer()
                    .hash_at(included_at)
                    .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
                if canonical_hash != inclusion.block_hash {
                    self.state
                        .set_spending_paused(false)
                        .await
                        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
                    self.state
                        .voting_execution()
                        .mark_orphaned(request_hash, txid)
                        .await?;
                    continue;
                }
                self.activate_member_migration(
                    request_hash,
                    txid,
                    included_at,
                    inclusion.block_hash,
                    &current_members,
                )
                .await?;
            } else {
                self.state
                    .voting_execution()
                    .confirm(request_hash, txid)
                    .await?;
            }
            monitoring::record_voting_execution("confirmed");
            confirmed += 1;
        }

        let local = leader::local_public_key(&self.peers().await)
            .and_then(|key| PublicKey::from_slice(&key).ok())
            .map(|key| key.x_only_public_key().0.serialize());
        for (request_hash, proposer) in self.state.voting_execution().unfinished_attempts().await? {
            if Some(proposer) != local {
                continue;
            }
            match self.spawn_voting_execution(request_hash) {
                Ok(task) => drop(task),
                Err(VotingExecutionError::AlreadyExecuting) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(confirmed)
    }

    async fn announce_voting_execution(
        &self,
        request_hash: [u8; 32],
        notification: &ExecuteVotingRequest,
    ) -> Result<(), SigningError> {
        announce(
            &self.storm,
            NodeMessageKind::ExecuteVotingRequest,
            Some(request_hash),
            notification,
            "invalid voting notification recipient",
        )
        .await
    }

    pub async fn voting_request(
        &self,
        request_hash: [u8; 32],
    ) -> Result<Option<VotingRequest>, VotingError> {
        self.state.voting().get(request_hash).await
    }

    pub async fn voting_requests(&self) -> Result<Vec<VotingRequest>, VotingError> {
        self.state.voting().list().await
    }
}

async fn activate_member_migration_state(
    state: &NetworkState,
    storm: &StormHandle,
    request_hash: [u8; 32],
    txid: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
    current_members: &BTreeSet<[u8; 32]>,
) -> Result<(), VotingExecutionError> {
    let _voting_guard = state.voting().lock_operations().await;
    let Some(asset) = state
        .voting_execution()
        .member_migration_asset(request_hash, current_members)
        .await?
    else {
        return Ok(());
    };
    let peers = storm
        .member_migration_peers()
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    let contract_data = asset.contract_data.as_deref().ok_or_else(|| {
        VotingExecutionError::Invalid("migrated Storm Eye contract data is missing".into())
    })?;
    state
        .network_store()
        .apply_member_migration(
            &peers,
            state.coordinator_public_key(),
            &asset.kind,
            &asset.contract_script,
            contract_data,
            crate::db::network::ConfirmedVotingExecution {
                request_hash,
                txid,
                block_height,
                block_hash,
            },
        )
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    finish_member_migration_state(state, storm).await
}

async fn finish_member_migration_state(
    state: &NetworkState,
    storm: &StormHandle,
) -> Result<(), VotingExecutionError> {
    let peers = storm
        .member_migration_peers()
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    state.signing().refresh_members(&peers).await?;
    storm
        .activate_member_migration()
        .await
        .map_err(|error| VotingExecutionError::Invalid(error.to_string()))?;
    state.complete_member_migration().await;
    state.migration_finalized();

    if let Err(error) = state.assets().announce_pending(storm).await {
        tracing::warn!(%error, "failed to announce migrated network assets");
    }
    Ok(())
}
