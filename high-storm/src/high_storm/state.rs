use storm::Storm;

use super::signing::Signing;

/// Cloneable higher-level state shared by HighStorm message handlers.
#[derive(Clone)]
pub(crate) struct NetworkState {
    signing: Signing,
}

impl NetworkState {
    pub(crate) async fn new(storm: &Storm, secret_key: [u8; 32]) -> Self {
        Self {
            signing: Signing::new(storm, secret_key).await,
        }
    }

    pub(crate) fn signing(&self) -> &Signing {
        &self.signing
    }
}
