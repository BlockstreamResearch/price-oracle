use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use secp256k1_zkp::PublicKey;
use storm::Storm;

use super::{
    HighStormDependencies, assets::Assets, burning::Burning, droplets::Droplets, indexer::Indexer,
    signing::Signing, user_requests::UserRequestProcessor, voting::Voting,
};

/// Cloneable higher-level state shared by HighStorm message handlers.
#[derive(Clone)]
pub(crate) struct NetworkState {
    coordinator_public_key: [u8; 33],
    signing: Signing,
    voting: Voting,
    assets: Assets,
    burning: Burning,
    droplets: Droplets,
    indexer: Indexer,
    user_requests: UserRequestProcessor,
    block_height: Arc<AtomicU64>,
}

impl NetworkState {
    pub(crate) async fn new(
        storm: &Storm,
        secret_key: [u8; 32],
        coordinator_public_key: [u8; 33],
        dependencies: HighStormDependencies,
    ) -> Self {
        let HighStormDependencies {
            voting_store,
            network_assets,
            monitored_utxos,
            droplets,
            user_requests,
            elements_rpc,
            protocol_config,
        } = dependencies;

        let initial_members = storm
            .peers()
            .await
            .into_iter()
            .map(|peer| {
                PublicKey::from_slice(&peer.compressed_public_key)
                    .expect("Storm peers contain validated public keys")
                    .x_only_public_key()
                    .0
                    .serialize()
            })
            .collect();

        Self {
            coordinator_public_key,
            signing: Signing::new(storm, secret_key, coordinator_public_key).await,
            voting: Voting::new(secret_key, voting_store),
            assets: Assets::new(network_assets.clone()),
            burning: Burning::new(
                monitored_utxos.clone(),
                network_assets.clone(),
                elements_rpc.clone(),
                protocol_config.clone(),
            ),
            droplets: Droplets::new(
                droplets.clone(),
                network_assets.clone(),
                elements_rpc.clone(),
                protocol_config.exchange_transaction_fee_sats,
            ),
            indexer: Indexer::new(
                monitored_utxos.clone(),
                droplets,
                network_assets.clone(),
                elements_rpc.clone(),
                &protocol_config,
                initial_members,
            ),
            user_requests: UserRequestProcessor::new(
                user_requests,
                monitored_utxos,
                network_assets,
                elements_rpc,
                protocol_config,
            ),
            block_height: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn coordinator_public_key(&self) -> [u8; 33] {
        self.coordinator_public_key
    }

    pub(crate) fn signing(&self) -> &Signing {
        &self.signing
    }

    pub(crate) fn voting(&self) -> &Voting {
        &self.voting
    }

    pub(crate) fn assets(&self) -> &Assets {
        &self.assets
    }

    pub(crate) fn burning(&self) -> &Burning {
        &self.burning
    }

    pub(crate) fn droplets(&self) -> &Droplets {
        &self.droplets
    }

    pub(crate) fn indexer(&self) -> &Indexer {
        &self.indexer
    }

    pub(crate) fn user_requests(&self) -> &UserRequestProcessor {
        &self.user_requests
    }

    pub(crate) fn block_height(&self) -> u64 {
        self.block_height.load(Ordering::Relaxed)
    }

    pub(crate) fn set_block_height(&self, block_height: u64) {
        self.block_height.store(block_height, Ordering::Relaxed);
    }
}
