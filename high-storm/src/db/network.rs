use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use secp256k1_zkp::{Parity, PublicKey};
use sqlx::{AnyPool, Row};
use storm::{Peer, PeerStatus};

use super::{
    chain::ChainStore, droplet::DropletStore, monitored_utxo::MonitoredUtxoStore,
    network_asset::NetworkAssetStore, price_attestation::PriceAttestationStore,
    price_source::FrozenPriceSourceStore, user_request::UserRequestStore, voting::VotingStore,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("network has not been initialized")]
    NotInitialized,
    #[error("invalid persisted peer status: {0}")]
    InvalidStatus(String),
    #[error("persisted public key is invalid: {0}")]
    InvalidPublicKey(String),
    #[error("peer timestamp exceeds the database integer range")]
    TimestampOutOfRange,
    #[error("active network asset was not updated during member migration")]
    MigrationAssetNotUpdated,
    #[error("voting execution was not confirmed during member migration")]
    MigrationExecutionNotUpdated,
    #[error("member migration contains duplicate x-only identity: {0}")]
    DuplicateMemberIdentity(String),
}

#[derive(Clone)]
pub struct NetworkStore {
    pool: AnyPool,
}

pub(crate) struct ConfirmedVotingExecution {
    pub(crate) request_hash: [u8; 32],
    pub(crate) txid: [u8; 32],
    pub(crate) block_height: u64,
    pub(crate) block_hash: [u8; 32],
}

impl NetworkStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub(crate) fn voting(&self) -> VotingStore {
        VotingStore::new(self.pool.clone())
    }

    pub(crate) fn chain(&self) -> ChainStore {
        ChainStore::new(self.pool.clone())
    }

    pub(crate) fn droplets(&self) -> DropletStore {
        DropletStore::new(self.pool.clone())
    }

    pub(crate) fn network_assets(&self) -> NetworkAssetStore {
        NetworkAssetStore::new(self.pool.clone())
    }

    pub(crate) fn monitored_utxos(&self) -> MonitoredUtxoStore {
        MonitoredUtxoStore::new(self.pool.clone())
    }

    pub(crate) fn price_attestations(&self) -> PriceAttestationStore {
        PriceAttestationStore::new(self.pool.clone())
    }

    pub(crate) fn frozen_price_sources(&self) -> FrozenPriceSourceStore {
        FrozenPriceSourceStore::new(self.pool.clone())
    }

    pub(crate) fn user_requests(&self) -> UserRequestStore {
        UserRequestStore::new(self.pool.clone())
    }

    pub async fn save(
        &self,
        peers: &[Peer],
        coordinator_public_key: [u8; 33],
    ) -> Result<(), Error> {
        tracing::debug!(peer_count = peers.len(), "persisting network state");

        let mut transaction = self.pool.begin().await?;
        reset_network_state(&mut transaction, coordinator_public_key).await?;

        for (position, peer) in peers.iter().enumerate() {
            insert_peer(&mut transaction, position, peer, peer_last_seen(peer)?).await?;
        }

        transaction.commit().await?;
        tracing::debug!(peer_count = peers.len(), "network state persisted");
        Ok(())
    }

    pub async fn update_runtime(&self, peers: &[Peer]) -> Result<(), Error> {
        let mut transaction = self.pool.begin().await?;

        for peer in peers {
            let last_seen = peer_last_seen(peer)?;

            sqlx::query(
                "UPDATE network_peers SET \
					socket_address = $1, last_seen = $2, status = $3, discovery = $4 \
				 WHERE public_key = $5",
            )
            .bind(&peer.socket_address)
            .bind(last_seen)
            .bind(status_name(peer.status))
            .bind(i64::from(peer.discovery))
            .bind(hex::encode(peer.compressed_public_key))
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        tracing::trace!(peer_count = peers.len(), "runtime network state updated");

        Ok(())
    }

    pub(crate) async fn apply_member_migration(
        &self,
        peers: &[Peer],
        coordinator_public_key: [u8; 33],
        asset_kind: &str,
        contract_script: &[u8],
        contract_data: &[u8],
        execution: ConfirmedVotingExecution,
    ) -> Result<(), Error> {
        validate_unique_member_identities(peers)?;

        let mut transaction = self.pool.begin().await?;
        let previous_coordinator: String =
            sqlx::query_scalar("SELECT coordinator_public_key FROM network_state WHERE id = 1")
                .fetch_one(&mut *transaction)
                .await?;
        let previous_asset = sqlx::query(
            "SELECT contract_script, contract_data FROM network_assets \
             WHERE kind = $1 AND status = 'active'",
        )
        .bind(asset_kind)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(Error::MigrationAssetNotUpdated)?;
        let previous_script: Vec<u8> = previous_asset.try_get("contract_script")?;
        let previous_data: Option<Vec<u8>> = previous_asset.try_get("contract_data")?;
        sqlx::query(
            "INSERT INTO network_member_migrations (request_hash, execution_txid, block_height, \
             block_hash, asset_kind, previous_script, previous_data, next_script, next_data, \
             previous_coordinator_public_key, next_coordinator_public_key) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(execution.request_hash.to_vec())
        .bind(execution.txid.to_vec())
        .bind(i64::try_from(execution.block_height).map_err(|_| Error::TimestampOutOfRange)?)
        .bind(execution.block_hash.to_vec())
        .bind(asset_kind)
        .bind(&previous_script)
        .bind(&previous_data)
        .bind(contract_script)
        .bind(contract_data)
        .bind(&previous_coordinator)
        .bind(hex::encode(coordinator_public_key))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO network_member_migration_peers \
             (request_hash, snapshot_kind, peer_order, public_key, socket_address, last_seen, status, discovery) \
             SELECT $1, 'previous', peer_order, public_key, socket_address, last_seen, status, discovery \
             FROM network_peers",
        )
        .bind(execution.request_hash.to_vec())
        .execute(&mut *transaction)
        .await?;
        reset_network_state(&mut transaction, coordinator_public_key).await?;
        for (position, peer) in peers.iter().enumerate() {
            let last_seen = peer_last_seen(peer)?;
            insert_peer(&mut transaction, position, peer, last_seen).await?;
            sqlx::query(
                "INSERT INTO network_member_migration_peers \
                 (request_hash, snapshot_kind, peer_order, public_key, socket_address, last_seen, status, discovery) \
                 VALUES ($1, 'next', $2, $3, $4, $5, $6, $7)",
            )
            .bind(execution.request_hash.to_vec())
            .bind(i64::try_from(position).map_err(|_| Error::TimestampOutOfRange)?)
            .bind(hex::encode(peer.compressed_public_key))
            .bind(&peer.socket_address)
            .bind(last_seen)
            .bind(status_name(peer.status))
            .bind(i64::from(peer.discovery))
            .execute(&mut *transaction)
            .await?;
        }
        let asset_updated = sqlx::query(
            "UPDATE network_assets
             SET contract_script = $1, contract_data = $2
             WHERE kind = $3 AND status = 'active'",
        )
        .bind(contract_script)
        .bind(contract_data)
        .bind(asset_kind)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if !asset_updated {
            return Err(Error::MigrationAssetNotUpdated);
        }
        let execution_updated = sqlx::query(
            "UPDATE voting_requests SET execution_started = 0, execution_confirmed = 1
             WHERE message_hash = $1 AND execution_txid = $2
             AND execution_request IS NOT NULL AND execution_confirmed = 0",
        )
        .bind(execution.request_hash.to_vec())
        .bind(execution.txid.to_vec())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if !execution_updated {
            return Err(Error::MigrationExecutionNotUpdated);
        }
        sqlx::query(
            "DELETE FROM voting_approvals WHERE voting_request_hash IN (
                SELECT message_hash FROM voting_requests WHERE execution_confirmed = 0
            )",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM voting_requests WHERE execution_confirmed = 0")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE chain_recovery_state SET migration_paused = 0 WHERE id = 1")
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn load(&self) -> Result<Vec<Peer>, Error> {
        tracing::debug!("loading network state");
        let initialized = sqlx::query("SELECT id FROM network_state WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        if initialized.is_none() {
            return Err(Error::NotInitialized);
        }

        let rows = sqlx::query(
            "SELECT public_key, socket_address, last_seen, status, discovery \
			 FROM network_peers ORDER BY peer_order",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let encoded_key: String = row.try_get("public_key")?;
                let key = hex::decode(&encoded_key)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| Error::InvalidPublicKey(encoded_key.clone()))?;
                let status: String = row.try_get("status")?;
                let last_seen: Option<i64> = row.try_get("last_seen")?;
                let discovery: i64 = row.try_get("discovery")?;
                Ok(Peer {
                    compressed_public_key: key,
                    socket_address: row.try_get("socket_address")?,
                    last_seen: last_seen.map(|value| value as u64),
                    status: parse_status(status)?,
                    discovery: discovery != 0,
                })
            })
            .collect()
    }

    pub async fn load_coordinator_public_key(&self) -> Result<[u8; 33], Error> {
        let row = sqlx::query("SELECT coordinator_public_key FROM network_state WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::NotInitialized)?;
        let encoded_key: String = row.try_get("coordinator_public_key")?;

        hex::decode(&encoded_key)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(Error::InvalidPublicKey(encoded_key))
    }
}

fn validate_unique_member_identities(peers: &[Peer]) -> Result<(), Error> {
    let mut identities = HashSet::with_capacity(peers.len());
    for peer in peers {
        let public_key = PublicKey::from_slice(&peer.compressed_public_key)
            .map_err(|_| Error::InvalidPublicKey(hex::encode(peer.compressed_public_key)))?;
        let canonical_identity = public_key
            .x_only_public_key()
            .0
            .public_key(Parity::Even)
            .serialize();
        if !identities.insert(canonical_identity) {
            return Err(Error::DuplicateMemberIdentity(hex::encode(
                &canonical_identity[1..],
            )));
        }
    }

    Ok(())
}

/// Empties `network_peers` and rewrites the single `network_state` row.
async fn reset_network_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Any>,
    coordinator_public_key: [u8; 33],
) -> Result<(), Error> {
    sqlx::query("DELETE FROM network_peers")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM network_state")
        .execute(&mut **transaction)
        .await?;

    let initialized_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    sqlx::query(
        "INSERT INTO network_state (id, initialized_at, coordinator_public_key) \
         VALUES (1, $1, $2)",
    )
    .bind(i64::try_from(initialized_at).map_err(|_| Error::TimestampOutOfRange)?)
    .bind(hex::encode(coordinator_public_key))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_peer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Any>,
    position: usize,
    peer: &Peer,
    last_seen: Option<i64>,
) -> Result<(), Error> {
    sqlx::query(
        "INSERT INTO network_peers (\
            peer_order, public_key, socket_address, last_seen, status, discovery\
        ) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(i64::try_from(position).map_err(|_| Error::TimestampOutOfRange)?)
    .bind(hex::encode(peer.compressed_public_key))
    .bind(&peer.socket_address)
    .bind(last_seen)
    .bind(status_name(peer.status))
    .bind(i64::from(peer.discovery))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn peer_last_seen(peer: &Peer) -> Result<Option<i64>, Error> {
    peer.last_seen
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::TimestampOutOfRange)
}

fn status_name(status: PeerStatus) -> &'static str {
    match status {
        PeerStatus::Controlled => "controlled",
        PeerStatus::Active => "active",
        PeerStatus::Inactive => "inactive",
        PeerStatus::Banned => "banned",
    }
}

fn parse_status(status: String) -> Result<PeerStatus, Error> {
    match status.as_str() {
        "controlled" => Ok(PeerStatus::Controlled),
        "active" => Ok(PeerStatus::Active),
        "inactive" => Ok(PeerStatus::Inactive),
        "banned" => Ok(PeerStatus::Banned),
        _ => Err(Error::InvalidStatus(status)),
    }
}

#[cfg(test)]
mod tests;
