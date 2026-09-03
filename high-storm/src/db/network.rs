use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{AnyPool, Row};
use storm::{Peer, PeerStatus};

use super::{
    network_asset::NetworkAssetStore, user_request::UserRequestStore, voting::VotingStore,
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
}

#[derive(Clone)]
pub struct NetworkStore {
    pool: AnyPool,
}

impl NetworkStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub(crate) fn voting(&self) -> VotingStore {
        VotingStore::new(self.pool.clone())
    }

    pub(crate) fn network_assets(&self) -> NetworkAssetStore {
        NetworkAssetStore::new(self.pool.clone())
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
        sqlx::query("DELETE FROM network_peers")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM network_state")
            .execute(&mut *transaction)
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
        .execute(&mut *transaction)
        .await?;

        for (position, peer) in peers.iter().enumerate() {
            let last_seen = peer
                .last_seen
                .map(i64::try_from)
                .transpose()
                .map_err(|_| Error::TimestampOutOfRange)?;

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
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        tracing::debug!(peer_count = peers.len(), "network state persisted");
        Ok(())
    }

    pub async fn update_runtime(&self, peers: &[Peer]) -> Result<(), Error> {
        let mut transaction = self.pool.begin().await?;

        for peer in peers {
            let last_seen = peer
                .last_seen
                .map(i64::try_from)
                .transpose()
                .map_err(|_| Error::TimestampOutOfRange)?;

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
