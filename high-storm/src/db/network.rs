use std::{
    collections::HashSet,
    time::{SystemTime, UNIX_EPOCH},
};

use secp256k1_zkp::{Parity, PublicKey};
use sqlx::{AnyPool, Row};
use storm::{Peer, PeerStatus};

use super::{
    droplet::DropletStore, monitored_utxo::MonitoredUtxoStore, network_asset::NetworkAssetStore,
    user_request::UserRequestStore, voting::VotingStore,
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
}

impl NetworkStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub(crate) fn voting(&self) -> VotingStore {
        VotingStore::new(self.pool.clone())
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
                "INSERT INTO network_peers (
                    peer_order, public_key, socket_address, last_seen, status, discovery
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
mod tests {
    use secp256k1_zkp::{Secp256k1, SecretKey};

    use crate::{
        NetworkAsset,
        db::{Database, network_asset::STORM_EYE_KIND},
    };

    use super::*;

    #[tokio::test]
    async fn member_migration_persists_peers_and_contract_atomically() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network();
        let old_peer = Peer::new([2; 33]);
        let new_peer = Peer::new(
            SecretKey::from_slice(&[3; 32])
                .unwrap()
                .public_key(&Secp256k1::new())
                .serialize(),
        );
        let request_hash = [7; 32];
        let proposer = [8; 32];
        let transaction = [9];
        let execution_request = [10];
        let execution_txid = [11; 32];
        let stale_request_hash = [12; 32];
        let removed_member = [13; 32];
        store
            .save(std::slice::from_ref(&old_peer), [2; 33])
            .await
            .unwrap();
        let votes = database.voting();
        votes
            .insert_request(request_hash, &[12], proposer, 1)
            .await
            .unwrap();
        votes
            .insert_approval(request_hash, proposer, &[13], 2, 1)
            .await
            .unwrap();
        votes
            .record_broadcast(
                request_hash,
                proposer,
                &transaction,
                &execution_request,
                execution_txid,
            )
            .await
            .unwrap();
        votes
            .insert_request(stale_request_hash, &[14], removed_member, 2)
            .await
            .unwrap();
        votes
            .insert_approval(stale_request_hash, removed_member, &[15], 3, 1)
            .await
            .unwrap();

        assert!(matches!(
            store
                .apply_member_migration(
                    std::slice::from_ref(&new_peer),
                    [2; 33],
                    STORM_EYE_KIND,
                    &[0x52],
                    &[9; 32],
                    ConfirmedVotingExecution {
                        request_hash,
                        txid: execution_txid,
                    },
                )
                .await
                .unwrap_err(),
            Error::MigrationAssetNotUpdated
        ));
        assert_eq!(store.load().await.unwrap(), vec![old_peer.clone()]);
        assert!(
            !votes
                .get(request_hash)
                .await
                .unwrap()
                .unwrap()
                .execution_confirmed
        );
        assert!(votes.get(stale_request_hash).await.unwrap().is_some());
        assert_eq!(votes.approval_count(stale_request_hash).await.unwrap(), 1);

        database
            .network_assets()
            .insert_active(&NetworkAsset {
                kind: STORM_EYE_KIND.to_string(),
                name: "Storm Eye".to_string(),
                asset_id: [4; 32],
                reissuance_token_id: None,
                entropy: None,
                issuance_txid: [5; 32],
                contract_script: vec![0x51],
                contract_data: Some(vec![6; 32]),
                supply: 10_000,
                created_at_block: 1,
            })
            .await
            .unwrap();

        assert!(matches!(
            store
                .apply_member_migration(
                    std::slice::from_ref(&new_peer),
                    [2; 33],
                    STORM_EYE_KIND,
                    &[0x52],
                    &[9; 32],
                    ConfirmedVotingExecution {
                        request_hash,
                        txid: [12; 32],
                    },
                )
                .await
                .unwrap_err(),
            Error::MigrationExecutionNotUpdated
        ));
        assert_eq!(store.load().await.unwrap(), vec![old_peer]);
        let unchanged_asset = database
            .network_assets()
            .get(STORM_EYE_KIND)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged_asset.contract_script, vec![0x51]);
        assert_eq!(unchanged_asset.contract_data, Some(vec![6; 32]));
        assert!(votes.get(stale_request_hash).await.unwrap().is_some());
        assert_eq!(votes.approval_count(stale_request_hash).await.unwrap(), 1);

        store
            .apply_member_migration(
                std::slice::from_ref(&new_peer),
                [2; 33],
                STORM_EYE_KIND,
                &[0x52],
                &[9; 32],
                ConfirmedVotingExecution {
                    request_hash,
                    txid: execution_txid,
                },
            )
            .await
            .unwrap();
        assert_eq!(store.load().await.unwrap(), vec![new_peer]);
        assert!(
            votes
                .get(request_hash)
                .await
                .unwrap()
                .unwrap()
                .execution_confirmed
        );
        assert!(votes.get(stale_request_hash).await.unwrap().is_none());
        assert_eq!(votes.approval_count(stale_request_hash).await.unwrap(), 0);
        let asset = database
            .network_assets()
            .get(STORM_EYE_KIND)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(asset.contract_script, vec![0x52]);
        assert_eq!(asset.contract_data, Some(vec![9; 32]));
    }

    #[tokio::test]
    async fn member_migration_rejects_duplicate_x_only_identities_before_persistence() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network();
        let secp = Secp256k1::new();
        let old_public_key = SecretKey::from_slice(&[2; 32])
            .unwrap()
            .public_key(&secp)
            .serialize();
        let old_peer = Peer::new(old_public_key);
        store
            .save(std::slice::from_ref(&old_peer), old_public_key)
            .await
            .unwrap();

        let member_public_key = SecretKey::from_slice(&[3; 32])
            .unwrap()
            .public_key(&secp)
            .serialize();
        let mut opposite_parity = member_public_key;
        opposite_parity[0] = if opposite_parity[0] == 2 { 3 } else { 2 };
        let error = store
            .apply_member_migration(
                &[Peer::new(member_public_key), Peer::new(opposite_parity)],
                old_public_key,
                STORM_EYE_KIND,
                &[0x52],
                &[9; 32],
                ConfirmedVotingExecution {
                    request_hash: [7; 32],
                    txid: [11; 32],
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(error, Error::DuplicateMemberIdentity(_)));
        assert_eq!(store.load().await.unwrap(), vec![old_peer]);
    }
}
