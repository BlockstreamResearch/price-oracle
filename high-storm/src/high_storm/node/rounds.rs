//! Issuance and burn rounds the node coordinates or leads.

use crate::high_storm::*;

impl HighStorm {
    pub async fn sign_execute_user_requests(
        &self,
        tx: Vec<u8>,
        signing_hash: [u8; 32],
        price_hash: Option<[u8; 32]>,
        external_requests: Vec<ExternalRequests>,
    ) -> Result<SigningResult, SigningError> {
        if self.is_transaction_production_blocked() {
            return Err(SigningError::InvalidMessage(
                "transaction production is paused for chain recovery or member migration".into(),
            ));
        }
        let chain_tip = self
            .state
            .indexer()
            .chain_tip()
            .await
            .map_err(|error| SigningError::InvalidMessage(error.to_string()))?;
        self.state
            .signing()
            .sign_execute_user_requests(
                &self.storm,
                move |_| Ok((tx.clone(), signing_hash)),
                price_hash,
                external_requests,
                chain_tip,
            )
            .await
    }

    pub async fn process_user_requests(
        &self,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<usize, user_requests::UserRequestError> {
        if self.is_transaction_production_blocked() {
            return Err(user_requests::UserRequestError::Invalid(
                "transaction production is paused for chain recovery or member migration".into(),
            ));
        }
        if !self.is_coordinator().await {
            return Ok(0);
        }
        // Counted once this node coordinates the round, preparation included.
        let issued = self
            .coordinate_issuance_round(storm_eye_lane, max_transaction_weight)
            .await;
        if let Some(outcome) = round_outcome(&issued) {
            monitoring::record_issuance_round(outcome);
        }
        issued
    }

    async fn coordinate_issuance_round(
        &self,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<usize, user_requests::UserRequestError> {
        let mut prepared = match self
            .state
            .user_requests()
            .prepare_round(
                self.state.block_height(),
                storm_eye_lane,
                max_transaction_weight,
            )
            .await?
        {
            Some(prepared) => prepared,
            None => return Ok(0),
        };
        let chain_tip = self
            .state
            .indexer()
            .chain_tip()
            .await
            .map_err(|error| user_requests::UserRequestError::Invalid(error.to_string()))?;
        prepared.request.chain_tip = Some(chain_tip);
        let instructed = self
            .state
            .user_requests()
            .validate_execute(&prepared.request)
            .await?;
        let round = prepared.transaction.clone();
        let signing = self
            .state
            .signing()
            .sign_execute_user_requests(
                &self.storm,
                move |branch| {
                    round
                        .for_branch(branch)
                        .map(|(pset, signing_hash)| {
                            (
                                simplex::simplicityhl::elements::encode::serialize(&pset),
                                signing_hash,
                            )
                        })
                        .map_err(|error| SigningError::InvalidMessage(error.to_string()))
                },
                instructed.as_ref().map(prices::price_hash),
                prepared.request.external_requests.clone(),
                chain_tip,
            )
            .await
            .map_err(user_requests::UserRequestError::Signing)?;
        let proof = self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await
            .map_err(user_requests::UserRequestError::Signing)?;

        self.state
            .user_requests()
            .finalize_and_broadcast(prepared, signing, proof)
            .await
    }

    pub async fn burn_expired_utxos(
        &self,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<usize, BurningError> {
        if self.is_transaction_production_blocked() {
            return Err(BurningError::Invalid(
                "transaction production is paused for chain recovery or member migration".into(),
            ));
        }
        let block_height = self.state.block_height();
        let released = self
            .state
            .burning()
            .release_vanished_burns(block_height)
            .await?;
        if released > 0 {
            tracing::info!(
                released,
                "returned items whose burning transaction vanished to the burn queue"
            );
        }
        let reconciled = self.state.burning().reconcile_mempool(block_height).await?;
        if reconciled > 0 {
            tracing::info!(
                reconciled,
                "recovered in-flight Tick burns from the mempool"
            );
        }

        let peers = self.peers().await;
        if !leader::is_local_leader(&peers, block_height) {
            return Ok(0);
        }
        // Counted once this node leads the round, preparation included.
        let burned = self
            .lead_burn_round(block_height, storm_eye_lane, max_transaction_weight)
            .await;
        if let Some(outcome) = round_outcome(&burned) {
            monitoring::record_burn_round(outcome);
        }
        burned
    }

    async fn lead_burn_round(
        &self,
        block_height: u64,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<usize, BurningError> {
        let mut prepared = match self
            .state
            .burning()
            .prepare_round(block_height, storm_eye_lane, max_transaction_weight)
            .await?
        {
            Some(prepared) => prepared,
            None => return Ok(0),
        };
        let chain_tip = self
            .state
            .indexer()
            .chain_tip()
            .await
            .map_err(|error| BurningError::Invalid(error.to_string()))?;
        if chain_tip.height != block_height {
            return Err(BurningError::Invalid(
                "burn does not target the indexed chain tip".into(),
            ));
        }
        prepared.request.chain_tip = Some(chain_tip);
        self.state
            .burning()
            .validate_request(&prepared.request)
            .await?;
        let signing = self
            .state
            .signing()
            .sign_burn_expired_utxos(
                &self.storm,
                prepared.request.tx.clone(),
                prepared.request.signing_hash,
                block_height,
                chain_tip,
            )
            .await?;
        let proof = self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await?;
        let notification = self
            .state
            .burning()
            .finalize_and_broadcast(prepared, signing, proof, block_height)
            .await?;
        let count = notification.utxos.len();
        if let Err(error) = self.announce_burn(&notification).await {
            tracing::warn!(%error, "failed to announce broadcast Tick burn");
        }

        Ok(count)
    }

    async fn announce_burn(&self, notification: &ExpiredUtxosBurned) -> Result<(), SigningError> {
        announce(
            &self.storm.handle(),
            NodeMessageKind::ExpiredUtxosBurned,
            None,
            notification,
            "invalid burn notification recipient",
        )
        .await
    }

    pub async fn reconcile_user_requests(&self) -> Result<usize, user_requests::UserRequestError> {
        if !self.is_coordinator().await {
            return Ok(0);
        }

        self.state.user_requests().reconcile_confirmations().await
    }

    pub async fn storm_eye_utxo_count(&self) -> Result<usize, user_requests::UserRequestError> {
        self.state.user_requests().storm_eye_utxo_count().await
    }
}
