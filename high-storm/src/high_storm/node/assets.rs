//! Network assets: issuance at start-up, announcements and Storm Eye renewal.

use crate::high_storm::*;

impl HighStorm {
    pub async fn announce_protocol_settings(&self) -> Result<(), SigningError> {
        announce(
            &self.storm.handle(),
            NodeMessageKind::ProtocolSettings,
            None,
            &self.state.protocol_settings(),
            "invalid protocol settings recipient",
        )
        .await
    }

    pub async fn reconcile_storm_eye_renewal(&self) -> Result<bool, RenewalError> {
        let confirmed = self.state.renewal().reconcile().await?;
        if confirmed {
            monitoring::record_storm_eye_renewal(RenewalOutcome::Confirmed);
        }
        if !confirmed
            && self.is_coordinator().await
            && let Some(request) = self.state.renewal().pending_request().await?
        {
            renewal::announce(&self.storm.handle(), &request).await?;
        }
        Ok(confirmed)
    }

    pub async fn renew_storm_eye_timelock(&self) -> Result<Option<[u8; 32]>, RenewalError> {
        if self.is_transaction_production_blocked() {
            return Err(RenewalError::Invalid(
                "transaction production is paused for chain recovery or member migration".into(),
            ));
        }
        if !self.is_coordinator().await {
            return Ok(None);
        }
        let block_height = self.state.block_height();
        let Some(storm_eye) = self.state.renewal().due_storm_eye(block_height).await? else {
            return Ok(None);
        };
        // Every failure from here on counts, preparation included: a due renewal
        // that keeps failing, for example for want of Treasury funds, needs an
        // operator before the rescue height arrives.
        let renewed = self.renew_due_storm_eye(storm_eye, block_height).await;
        monitoring::record_storm_eye_renewal(if renewed.is_ok() {
            RenewalOutcome::Broadcast
        } else {
            RenewalOutcome::Failed
        });
        renewed.map(Some)
    }

    async fn renew_due_storm_eye(
        &self,
        storm_eye: NetworkAsset,
        block_height: u64,
    ) -> Result<[u8; 32], RenewalError> {
        let mut prepared = self
            .state
            .renewal()
            .prepare(block_height, storm_eye)
            .await?;
        let chain_tip = self
            .state
            .indexer()
            .chain_tip()
            .await
            .map_err(|error| RenewalError::Invalid(error.to_string()))?;
        if chain_tip.height != block_height {
            return Err(RenewalError::Invalid(
                "renewal does not target the indexed chain tip".into(),
            ));
        }
        prepared.request.chain_tip = Some(chain_tip);
        let request = prepared.request.clone();
        self.state.renewal().validate_request(&request).await?;
        let signing = self
            .state
            .signing()
            .sign_renew_storm_utxos(&self.storm.handle(), &request)
            .await?;
        let proof = self
            .state
            .signing()
            .storm_tree_proof(&signing.signing_storm_tree_branch)
            .await?;
        let notification = self.state.renewal().finalize(prepared, signing, proof)?;
        let txid = self
            .state
            .renewal()
            .record_and_broadcast(&notification)
            .await?;
        if let Err(error) = renewal::announce(&self.storm.handle(), &notification).await {
            tracing::warn!(%error, "failed to announce Storm Eye timelock renewal");
        }

        Ok(txid)
    }

    pub async fn announce_network_assets(&self) -> Result<(), AssetError> {
        self.state
            .assets()
            .announce_pending(&self.storm.handle())
            .await
    }

    pub async fn initialize_storm_eye(
        &self,
        config: &crate::config::ElementsRpcConfig,
    ) -> Result<Option<NetworkAsset>, AssetError> {
        if !self.is_coordinator().await {
            return Ok(None);
        }

        let storm_tree_root = self.state.signing().storm_tree_root().await?;
        let initial_members = state::x_only_keys(self.peers().await);
        self.state
            .assets()
            .initialize_storm_eye(
                &self.storm.handle(),
                config,
                storm_tree_root,
                initial_members,
            )
            .await
            .map(Some)
    }

    pub async fn initialize_tick_asset(
        &self,
        config: &crate::config::ElementsRpcConfig,
    ) -> Result<Option<NetworkAsset>, AssetError> {
        if !self.is_coordinator().await {
            return Ok(None);
        }

        let storm_eye = self
            .state
            .assets()
            .storm_eye()
            .await?
            .ok_or_else(|| AssetError::Conflict("Storm Eye is not initialized".to_string()))?;
        self.state
            .assets()
            .initialize_tick_asset(&self.storm.handle(), config, storm_eye.asset_id)
            .await
            .map(Some)
    }

    /// The asset a `signed-price-data` request is issued in. Issued beside the
    /// Tick, since a priced round mints one of these instead of a Tick.
    pub async fn initialize_oracle_verifier_asset(
        &self,
        config: &crate::config::ElementsRpcConfig,
    ) -> Result<Option<NetworkAsset>, AssetError> {
        if !self.is_coordinator().await {
            return Ok(None);
        }

        let storm_eye = self
            .state
            .assets()
            .storm_eye()
            .await?
            .ok_or_else(|| AssetError::Conflict("Storm Eye is not initialized".to_string()))?;
        self.state
            .assets()
            .initialize_oracle_verifier_asset(&self.storm.handle(), config, storm_eye.asset_id)
            .await
            .map(Some)
    }

    pub async fn network_asset(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().get(kind).await
    }

    pub async fn storm_eye_asset(&self) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().storm_eye().await
    }
}

impl HighStormHandle {
    /// The height from which anyone may spend the Storm Eye UTXOs, once the
    /// Storm Eye exists.
    pub(crate) async fn storm_eye_rescue_height(&self) -> Result<Option<u32>, RenewalError> {
        self.state.renewal().rescue_height().await
    }

    pub async fn storm_eye_utxos(
        &self,
    ) -> Result<Vec<StormEyeInventoryItem>, VotingExecutionError> {
        self.state
            .voting_execution()
            .storm_eye_utxos(self.state.block_height())
            .await
    }

    pub async fn network_asset(&self, kind: &str) -> Result<Option<NetworkAsset>, AssetError> {
        self.state.assets().get(kind).await
    }
}
