use std::{
    ops::{Deref, DerefMut},
    time::Duration,
};

use storm::Storm;
use storm_tree::NodePublicKey;

mod handler;
mod message;
mod signing;
mod state;

pub use message::{NodeMessage, NodeMessageKind, TestNodeMessage};
pub use signing::{SigningError, SigningResult};
use state::NetworkState;

/// A long-lived Oracle Network node and its higher-level protocol state.
pub struct HighStorm {
    storm: Storm,
    state: NetworkState,
}

impl HighStorm {
    pub(crate) async fn new(storm: Storm, secret_key: [u8; 32]) -> Self {
        let state = NetworkState::new(&storm, secret_key).await;
        let handler_state = state.clone();
        storm
            .register_custom_handler(move |message, context| {
                let state = handler_state.clone();
                async move {
                    if let Err(error) = handler::handle(state, message, context).await {
                        tracing::warn!(%error, "failed to handle high-storm NodeMessage");
                    }
                }
            })
            .await;
        Self { storm, state }
    }

    /// Signs one or more dummy message hashes using an active Storm Tree branch.
    pub async fn sign_test(
        &self,
        message_hashes: Vec<[u8; 32]>,
    ) -> Result<SigningResult, SigningError> {
        self.state
            .signing()
            .sign_test(&self.storm, message_hashes)
            .await
    }

    /// Runs a temporary signing request with controls used by disconnect tests.
    pub async fn sign_test_with_delay(
        &self,
        message_hashes: Vec<[u8; 32]>,
        attempt_timeout: Duration,
        delayed_signer: NodePublicKey,
        delay: Duration,
    ) -> Result<SigningResult, SigningError> {
        self.state
            .signing()
            .sign_test_with_delay(
                &self.storm,
                message_hashes,
                attempt_timeout,
                delayed_signer,
                delay,
            )
            .await
    }

    /// Returns the signer subset HighStorm would currently choose.
    pub async fn selected_signers(&self) -> Result<Vec<NodePublicKey>, SigningError> {
        self.state.signing().selected_signers(&self.storm).await
    }
}

impl Deref for HighStorm {
    type Target = Storm;

    fn deref(&self) -> &Self::Target {
        &self.storm
    }
}

impl DerefMut for HighStorm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.storm
    }
}
