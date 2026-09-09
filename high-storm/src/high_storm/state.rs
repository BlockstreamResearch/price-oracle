use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
};

use secp256k1_zkp::PublicKey;
use storm::Storm;
use tokio::sync::Mutex;

use super::{
    HighStormDependencies, assets::Assets, burning::Burning, droplets::Droplets, indexer::Indexer,
    signing::Signing, user_requests::UserRequestProcessor, voting::Voting,
    voting_execution::VotingExecution,
};

/// Cloneable higher-level state shared by HighStorm message handlers.
#[derive(Clone)]
pub(crate) struct NetworkState {
    network_store: crate::db::network::NetworkStore,
    coordinator_public_key: [u8; 33],
    signing: Signing,
    voting: Voting,
    voting_execution: VotingExecution,
    assets: Assets,
    burning: Burning,
    droplets: Droplets,
    indexer: Indexer,
    user_requests: UserRequestProcessor,
    block_height: Arc<AtomicU64>,
    member_migration: Arc<Mutex<Option<MemberMigrationAttempt>>>,
    voting_execution_attempts: VotingExecutionAttempts,
}

#[derive(Clone, Default)]
struct VotingExecutionAttempts {
    active: Arc<StdMutex<BTreeSet<[u8; 32]>>>,
}

pub(crate) struct VotingExecutionAttempt {
    attempts: Arc<StdMutex<BTreeSet<[u8; 32]>>>,
    request_hash: [u8; 32],
}

impl VotingExecutionAttempts {
    fn begin(&self, request_hash: [u8; 32]) -> Option<VotingExecutionAttempt> {
        let mut attempts = self
            .active
            .lock()
            .expect("voting execution attempts lock is not poisoned");
        attempts
            .insert(request_hash)
            .then(|| VotingExecutionAttempt {
                attempts: self.active.clone(),
                request_hash,
            })
    }
}

impl Drop for VotingExecutionAttempt {
    fn drop(&mut self) {
        self.attempts
            .lock()
            .expect("voting execution attempts lock is not poisoned")
            .remove(&self.request_hash);
    }
}

#[derive(Clone, Copy)]
struct MemberMigrationAttempt {
    request_hash: [u8; 32],
    started_at_block: u64,
}

pub(crate) const MEMBER_MIGRATION_TIMEOUT_BLOCKS: u64 = 5;

impl NetworkState {
    pub(crate) async fn new(
        storm: &Storm,
        secret_key: [u8; 32],
        coordinator_public_key: [u8; 33],
        dependencies: HighStormDependencies,
    ) -> Self {
        let HighStormDependencies {
            network_store,
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
            network_store,
            coordinator_public_key,
            signing: Signing::new(storm, secret_key, coordinator_public_key).await,
            voting: Voting::new(secret_key, coordinator_public_key, voting_store.clone()),
            voting_execution: VotingExecution::new(
                voting_store,
                droplets.clone(),
                network_assets.clone(),
                elements_rpc.clone(),
                protocol_config.exchange_transaction_fee_sats,
            ),
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
            member_migration: Arc::new(Mutex::new(None)),
            voting_execution_attempts: VotingExecutionAttempts::default(),
        }
    }

    pub(crate) fn coordinator_public_key(&self) -> [u8; 33] {
        self.coordinator_public_key
    }

    pub(crate) fn network_store(&self) -> &crate::db::network::NetworkStore {
        &self.network_store
    }

    pub(crate) fn signing(&self) -> &Signing {
        &self.signing
    }

    pub(crate) fn voting(&self) -> &Voting {
        &self.voting
    }

    pub(crate) fn voting_execution(&self) -> &VotingExecution {
        &self.voting_execution
    }

    pub(crate) fn begin_voting_execution(
        &self,
        request_hash: [u8; 32],
    ) -> Option<VotingExecutionAttempt> {
        self.voting_execution_attempts.begin(request_hash)
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

    pub(crate) async fn ensure_member_migration(
        &self,
        storm: &storm::StormHandle,
        request_hash: [u8; 32],
        target_members: std::collections::BTreeSet<[u8; 32]>,
    ) -> Result<(), storm::Error> {
        let block_height = self.block_height();
        let mut attempt = self.member_migration.lock().await;
        if let Some(current) = *attempt {
            if current.request_hash != request_hash {
                return Err(storm::Error::MigrationAlreadyStaged);
            }
            if block_height.saturating_sub(current.started_at_block)
                >= MEMBER_MIGRATION_TIMEOUT_BLOCKS
            {
                storm.cancel_member_migration().await;
                *attempt = None;
            }
        }
        if attempt.is_none() {
            storm.cancel_member_migration().await;
            *attempt = Some(MemberMigrationAttempt {
                request_hash,
                started_at_block: block_height,
            });
        }
        drop(attempt);

        storm.begin_member_migration(target_members).await
    }

    pub(crate) async fn complete_member_migration(&self) {
        *self.member_migration.lock().await = None;
    }

    pub(crate) async fn member_migration_request(&self) -> Option<[u8; 32]> {
        self.member_migration
            .lock()
            .await
            .map(|attempt| attempt.request_hash)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use secp256k1_zkp::{Secp256k1, SecretKey};
    use storm::{Peer, Storm};

    use crate::{
        config::{ElementsRpcConfig, ProtocolConfig},
        db::Database,
        high_storm::HighStormDependencies,
    };

    use super::{NetworkState, VotingExecutionAttempts};

    #[test]
    fn voting_execution_attempts_are_exclusive_and_released_on_drop() {
        let attempts = VotingExecutionAttempts::default();
        let request_hash = [1; 32];

        let attempt = attempts.begin(request_hash).unwrap();
        assert!(attempts.begin(request_hash).is_none());

        drop(attempt);
        assert!(attempts.begin(request_hash).is_some());
    }

    #[tokio::test]
    async fn execution_replaces_opportunistic_member_migration_staging() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let secp = Secp256k1::new();
        let local_secret = SecretKey::from_slice(&[21; 32]).unwrap();
        let local_public = local_secret.public_key(&secp).serialize();
        let first_public = SecretKey::from_slice(&[22; 32])
            .unwrap()
            .public_key(&secp)
            .serialize();
        let second_public = SecretKey::from_slice(&[23; 32])
            .unwrap()
            .public_key(&secp)
            .serialize();
        let storm = Storm::from_peers(
            local_secret,
            vec![
                Peer::new(local_public),
                Peer::new(first_public),
                Peer::new(second_public),
            ],
        );
        let state = NetworkState::new(
            &storm,
            local_secret.secret_bytes(),
            local_public,
            HighStormDependencies::new(
                database.network(),
                database.voting(),
                database.network_assets(),
                database.monitored_utxos(),
                database.droplets(),
                database.user_requests(),
                ElementsRpcConfig {
                    url: "http://127.0.0.1:18884".to_string(),
                    username: "unused".to_string(),
                    password: "unused".to_string(),
                    wallet: "unused".to_string(),
                },
                ProtocolConfig {
                    operational_fee_sats: 1_000,
                    tick_burn_reserve_sats: 1_000,
                    issuance_transaction_fee_sats: 1_000,
                    burn_transaction_fee_sats: 500,
                    exchange_transaction_fee_sats: 500,
                    tick_lifetime_blocks: 60,
                },
            ),
        )
        .await;
        let first_target: BTreeSet<[u8; 32]> = [local_public, first_public]
            .into_iter()
            .map(|key| key[1..].try_into().unwrap())
            .collect();
        let second_target: BTreeSet<[u8; 32]> = [local_public, second_public]
            .into_iter()
            .map(|key| key[1..].try_into().unwrap())
            .collect();

        storm.begin_member_migration(first_target).await.unwrap();
        state
            .ensure_member_migration(&storm.handle(), [1; 32], second_target.clone())
            .await
            .unwrap();

        assert_eq!(state.member_migration_request().await, Some([1; 32]));
        assert!(matches!(
            state
                .ensure_member_migration(&storm.handle(), [2; 32], second_target)
                .await,
            Err(storm::Error::MigrationAlreadyStaged)
        ));
    }
}
