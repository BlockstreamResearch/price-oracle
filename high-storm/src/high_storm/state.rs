use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use storm::Storm;

use crate::db::voting::VotingStore;

use super::{signing::Signing, voting::Voting};

/// Cloneable higher-level state shared by HighStorm message handlers.
#[derive(Clone)]
pub(crate) struct NetworkState {
    coordinator_public_key: [u8; 33],
    signing: Signing,
    voting: Voting,
    block_height: Arc<AtomicU64>,
}

impl NetworkState {
    pub(crate) async fn new(
        storm: &Storm,
        secret_key: [u8; 32],
        coordinator_public_key: [u8; 33],
        voting_store: VotingStore,
    ) -> Self {
        Self {
            coordinator_public_key,
            signing: Signing::new(storm, secret_key).await,
            voting: Voting::new(secret_key, voting_store),
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

    pub(crate) fn block_height(&self) -> u64 {
        self.block_height.load(Ordering::Relaxed)
    }

    pub(crate) fn set_block_height(&self, block_height: u64) {
        self.block_height.store(block_height, Ordering::Relaxed);
    }
}
