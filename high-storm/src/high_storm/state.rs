use storm::Storm;

use super::signing::Signing;

/// Cloneable higher-level state shared by HighStorm message handlers.
#[derive(Clone)]
pub(crate) struct NetworkState {
    coordinator_public_key: [u8; 33],
    signing: Signing,
}

impl NetworkState {
    pub(crate) async fn new(
        storm: &Storm,
        secret_key: [u8; 32],
        coordinator_public_key: [u8; 33],
    ) -> Self {
        Self {
            coordinator_public_key,
            signing: Signing::new(storm, secret_key).await,
        }
    }

    pub(crate) fn coordinator_public_key(&self) -> [u8; 33] {
        self.coordinator_public_key
    }

    pub(crate) fn signing(&self) -> &Signing {
        &self.signing
    }
}
