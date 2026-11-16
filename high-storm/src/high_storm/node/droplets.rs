//! Droplets: exchanges the node leads and the operator view of its balance.

use crate::high_storm::*;

impl HighStorm {
    pub async fn exchange_droplets(
        &self,
        tx: Vec<u8>,
        signing_hash: [u8; 32],
        block_height: u64,
    ) -> Result<[u8; 32], DropletsError> {
        if self.is_transaction_production_blocked() {
            return Err(DropletsError::Invalid(
                "transaction production is paused for chain recovery or member migration".into(),
            ));
        }
        let chain_tip = self
            .state
            .indexer()
            .chain_tip()
            .await
            .map_err(|error| DropletsError::Invalid(error.to_string()))?;
        if chain_tip.height != block_height {
            return Err(DropletsError::Invalid(
                "Droplets exchange does not target the indexed chain tip".into(),
            ));
        }
        self.state.set_block_height(block_height);
        let peers = self.peers().await;
        let local = leader::local_public_key(&peers);
        let current = leader::leader_for_height(&peers, block_height);
        if local.is_none() || local != current {
            return Err(DropletsError::Invalid(
                "only the current network leader may exchange Droplets".into(),
            ));
        }
        let local = local.expect("local leader was checked");
        let exchange = self
            .state
            .droplets()
            .validate_transaction(&tx, signing_hash, local)
            .await?;
        self.state
            .droplets()
            .lock_exchange(&exchange, block_height, &tx)
            .await?;

        let request = ExchangeRewards {
            tx: tx.clone(),
            final_tx: None,
            signing_hash,
            signing_storm_tree_branch: [0; 32],
            block_height,
            chain_tip: Some(chain_tip),
        };
        match self
            .state
            .signing()
            .sign_exchange_rewards(&self.storm, tx, signing_hash, block_height, chain_tip)
            .await
        {
            Ok(signing) => {
                let proof = self
                    .state
                    .signing()
                    .storm_tree_proof(&signing.signing_storm_tree_branch)
                    .await?;
                let request = ExchangeRewards {
                    signing_storm_tree_branch: signing.signing_storm_tree_branch,
                    ..request
                };
                let (txid, final_tx) = self
                    .state
                    .droplets()
                    .finalize_and_broadcast(&request, signing, proof, &exchange)
                    .await?;
                let notification = ExchangeRewards {
                    final_tx: Some(final_tx),
                    ..request
                };
                if let Err(error) = self.announce_exchange(&notification).await {
                    tracing::warn!(%error, "failed to announce broadcast Droplets exchange");
                }

                Ok(txid)
            }
            Err(error) => {
                self.state
                    .droplets()
                    .unlock_exchange(exchange.member, block_height)
                    .await?;
                Err(error.into())
            }
        }
    }

    pub async fn process_droplet_exchange_request(
        &self,
    ) -> Result<Option<[u8; 32]>, DropletsError> {
        if self.is_transaction_production_blocked() {
            return Ok(None);
        }
        let peers = self.peers().await;
        if !leader::is_local_leader(&peers, self.state.block_height()) {
            return Ok(None);
        }
        let Some(local) = leader::local_public_key(&peers) else {
            return Ok(None);
        };
        let member = droplets::local_member_key(&local)?;
        let Some(request) = self.state.droplets().state(member).await?.1 else {
            return Ok(None);
        };
        if request.status != "pending" {
            return Ok(None);
        }

        let exchanged = self
            .exchange_droplets(
                request.transaction.clone(),
                request.signing_hash,
                self.state.block_height(),
            )
            .await;
        monitoring::record_droplets_exchange(match &exchanged {
            Ok(_) => "broadcast",
            Err(error) if error.is_retryable() => "retry",
            Err(_) => "failed",
        });
        match exchanged {
            Ok(txid) => {
                self.state
                    .droplets()
                    .complete_request(&request, txid)
                    .await?;
                Ok(Some(txid))
            }
            Err(error) if error.is_retryable() => Err(error),
            Err(error) => {
                self.state
                    .droplets()
                    .fail_request(&request, &error.to_string())
                    .await?;
                Err(error)
            }
        }
    }

    async fn announce_exchange(&self, notification: &ExchangeRewards) -> Result<(), SigningError> {
        announce(
            &self.storm.handle(),
            NodeMessageKind::ExchangeRewards,
            None,
            notification,
            "invalid exchange notification recipient",
        )
        .await
    }
}

impl HighStormHandle {
    /// The x-only key this node holds Droplets under.
    async fn local_droplet_member(&self) -> Result<[u8; 32], DropletsError> {
        let local = leader::local_public_key(&self.peers().await)
            .ok_or_else(|| DropletsError::Invalid("local network member is missing".into()))?;
        droplets::local_member_key(&local)
    }

    pub(crate) async fn droplet_state(
        &self,
    ) -> Result<
        (
            Option<crate::db::droplet::DropletBalance>,
            Option<crate::db::droplet::DropletExchangeRequest>,
        ),
        DropletsError,
    > {
        let member = self.local_droplet_member().await?;
        self.state.droplets().state(member).await
    }

    pub(crate) async fn droplet_history(
        &self,
    ) -> Result<Vec<crate::db::droplet::DropletExchangeRequest>, DropletsError> {
        let member = self.local_droplet_member().await?;
        self.state.droplets().history(member).await
    }

    pub(crate) fn droplet_exchange_fee_sats(&self) -> u64 {
        self.state.droplets().transaction_fee_sats()
    }

    pub(crate) async fn queue_droplet_exchange(
        &self,
        amount: u64,
        destination: &str,
    ) -> Result<crate::db::droplet::DropletExchangeRequest, DropletsError> {
        let local = leader::local_public_key(&self.peers().await)
            .ok_or_else(|| DropletsError::Invalid("local network member is missing".into()))?;
        self.state
            .droplets()
            .prepare_and_queue_exchange(amount, destination, local, self.state.block_height())
            .await
    }
}
