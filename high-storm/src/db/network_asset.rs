use sqlx::{AnyPool, Error, Row};

use crate::NetworkAsset;

pub const STORM_EYE_KIND: &str = "storm-eye";
pub const TICK_ASSET_KIND: &str = "tick-asset";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingNetworkAsset {
    pub asset: NetworkAsset,
    pub issuance_tx: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingStormEyeRenewal {
    pub txid: [u8; 32],
    pub request: Vec<u8>,
    pub contract_script: Vec<u8>,
    pub contract_data: Vec<u8>,
    pub block_height: u64,
}

#[derive(Clone)]
pub struct NetworkAssetStore {
    pool: AnyPool,
}

impl NetworkAssetStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn insert_pending(&self, pending: &PendingNetworkAsset) -> Result<bool, Error> {
        let asset = &pending.asset;
        let result = sqlx::query(
            "INSERT INTO network_assets (
                kind, name, asset_id, reissuance_token_id, entropy, issuance_txid,
                     issuance_tx, contract_script, contract_data, supply, created_at_block, status
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending')
             ON CONFLICT (kind) DO NOTHING",
        )
        .bind(&asset.kind)
        .bind(&asset.name)
        .bind(asset.asset_id.to_vec())
        .bind(asset.reissuance_token_id.map(|value| value.to_vec()))
        .bind(asset.entropy.map(|value| value.to_vec()))
        .bind(asset.issuance_txid.to_vec())
        .bind(&pending.issuance_tx)
        .bind(&asset.contract_script)
        .bind(&asset.contract_data)
        .bind(i64::try_from(asset.supply).map_err(|error| Error::Encode(Box::new(error)))?)
        .bind(
            i64::try_from(asset.created_at_block)
                .map_err(|error| Error::Encode(Box::new(error)))?,
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn insert_active(&self, asset: &NetworkAsset) -> Result<bool, Error> {
        let result = sqlx::query(
            "INSERT INTO network_assets (
                kind, name, asset_id, reissuance_token_id, entropy, issuance_txid,
                     issuance_tx, contract_script, contract_data, supply, created_at_block, status
                 ) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, 'active')
             ON CONFLICT (kind) DO NOTHING",
        )
        .bind(&asset.kind)
        .bind(&asset.name)
        .bind(asset.asset_id.to_vec())
        .bind(asset.reissuance_token_id.map(|value| value.to_vec()))
        .bind(asset.entropy.map(|value| value.to_vec()))
        .bind(asset.issuance_txid.to_vec())
        .bind(&asset.contract_script)
        .bind(&asset.contract_data)
        .bind(i64::try_from(asset.supply).map_err(|error| Error::Encode(Box::new(error)))?)
        .bind(
            i64::try_from(asset.created_at_block)
                .map_err(|error| Error::Encode(Box::new(error)))?,
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn activate(&self, kind: &str) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE network_assets
             SET status = 'active', issuance_tx = NULL
             WHERE kind = $1 AND status = 'pending'",
        )
        .bind(kind)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn record_storm_eye_renewal(
        &self,
        renewal: &PendingStormEyeRenewal,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "INSERT INTO storm_eye_renewals (
                id, txid, request, contract_script, contract_data, block_height
             ) VALUES (1, $1, $2, $3, $4, $5)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(renewal.txid.to_vec())
        .bind(&renewal.request)
        .bind(&renewal.contract_script)
        .bind(&renewal.contract_data)
        .bind(i64::try_from(renewal.block_height).map_err(|error| Error::Encode(Box::new(error)))?)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn pending_storm_eye_renewal(&self) -> Result<Option<PendingStormEyeRenewal>, Error> {
        sqlx::query(
            "SELECT txid, request, contract_script, contract_data, block_height
             FROM storm_eye_renewals WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            Ok(PendingStormEyeRenewal {
                txid: decode_array(row.try_get("txid")?)?,
                request: row.try_get("request")?,
                contract_script: row.try_get("contract_script")?,
                contract_data: row.try_get("contract_data")?,
                block_height: u64::try_from(row.try_get::<i64, _>("block_height")?)
                    .map_err(|error| Error::Decode(Box::new(error)))?,
            })
        })
        .transpose()
    }

    pub async fn confirm_storm_eye_renewal(&self, txid: [u8; 32]) -> Result<bool, Error> {
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE network_assets
             SET contract_script = renewal.contract_script,
                 contract_data = renewal.contract_data
             FROM storm_eye_renewals AS renewal
             WHERE network_assets.kind = 'storm-eye'
               AND network_assets.status = 'active'
               AND renewal.id = 1 AND renewal.txid = $1",
        )
        .bind(txid.to_vec())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated != 1 {
            transaction.rollback().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM storm_eye_renewals WHERE id = 1 AND txid = $1")
            .bind(txid.to_vec())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(true)
    }

    pub async fn index_storm_eye_renewal(
        &self,
        current: &NetworkAsset,
        renewed: &NetworkAsset,
    ) -> Result<bool, Error> {
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE network_assets
             SET contract_script = $1, contract_data = $2
             WHERE kind = 'storm-eye' AND status = 'active'
                             AND contract_script = $3
                             AND ((contract_data IS NULL AND $4 IS NULL) OR contract_data = $5)",
        )
        .bind(&renewed.contract_script)
        .bind(&renewed.contract_data)
        .bind(&current.contract_script)
        .bind(&current.contract_data)
        .bind(&current.contract_data)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated != 1 {
            transaction.rollback().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM storm_eye_renewals")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(true)
    }

    pub async fn get(&self, kind: &str) -> Result<Option<NetworkAsset>, Error> {
        sqlx::query(
            "SELECT kind, name, asset_id, reissuance_token_id, entropy, issuance_txid,
                    contract_script, contract_data, supply, created_at_block
             FROM network_assets WHERE kind = $1 AND status = 'active'",
        )
        .bind(kind)
        .fetch_optional(&self.pool)
        .await?
        .map(decode_asset)
        .transpose()
    }

    pub async fn pending_for_peer(
        &self,
        peer_public_key: &[u8; 33],
    ) -> Result<Vec<NetworkAsset>, Error> {
        sqlx::query(
            "SELECT kind, name, asset_id, reissuance_token_id, entropy, issuance_txid,
                    contract_script, contract_data, supply, created_at_block
             FROM network_assets AS asset
             WHERE status = 'active' AND NOT EXISTS (
                 SELECT 1 FROM network_asset_announcements AS announcement
                 WHERE announcement.kind = asset.kind
                   AND announcement.peer_public_key = $1
             )
             ORDER BY kind",
        )
        .bind(peer_public_key.to_vec())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_asset)
        .collect()
    }

    pub async fn mark_announced_to(
        &self,
        kinds: &[String],
        peer_public_key: &[u8; 33],
    ) -> Result<(), Error> {
        let mut transaction = self.pool.begin().await?;

        for kind in kinds {
            sqlx::query(
                "INSERT INTO network_asset_announcements (kind, peer_public_key)
                 VALUES ($1, $2)
                 ON CONFLICT (kind, peer_public_key) DO NOTHING",
            )
            .bind(kind)
            .bind(peer_public_key.to_vec())
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await
    }

    pub async fn get_pending(&self, kind: &str) -> Result<Option<PendingNetworkAsset>, Error> {
        sqlx::query(
            "SELECT kind, name, asset_id, reissuance_token_id, entropy, issuance_txid,
                    issuance_tx, contract_script, contract_data, supply, created_at_block
             FROM network_assets WHERE kind = $1 AND status = 'pending'",
        )
        .bind(kind)
        .fetch_optional(&self.pool)
        .await?
        .map(|row| {
            let issuance_tx = row.try_get("issuance_tx")?;
            Ok(PendingNetworkAsset {
                asset: decode_asset(row)?,
                issuance_tx,
            })
        })
        .transpose()
    }

    pub async fn list(&self) -> Result<Vec<NetworkAsset>, Error> {
        sqlx::query(
            "SELECT kind, name, asset_id, reissuance_token_id, entropy, issuance_txid,
                    contract_script, contract_data, supply, created_at_block
             FROM network_assets WHERE status = 'active' ORDER BY kind",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_asset)
        .collect()
    }
}

fn decode_asset(row: sqlx::any::AnyRow) -> Result<NetworkAsset, Error> {
    Ok(NetworkAsset {
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        asset_id: decode_array(row.try_get("asset_id")?)?,
        reissuance_token_id: row
            .try_get::<Option<Vec<u8>>, _>("reissuance_token_id")?
            .map(decode_array)
            .transpose()?,
        entropy: row
            .try_get::<Option<Vec<u8>>, _>("entropy")?
            .map(decode_array)
            .transpose()?,
        issuance_txid: decode_array(row.try_get("issuance_txid")?)?,
        contract_script: row.try_get("contract_script")?,
        contract_data: row.try_get("contract_data")?,
        supply: decode_u64(row.try_get("supply")?)?,
        created_at_block: decode_u64(row.try_get("created_at_block")?)?,
    })
}

fn decode_array(bytes: Vec<u8>) -> Result<[u8; 32], Error> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        Error::Decode(format!("expected 32 bytes, got {}", bytes.len()).into())
    })
}

fn decode_u64(value: i64) -> Result<u64, Error> {
    u64::try_from(value).map_err(|error| Error::Decode(error.into()))
}

#[cfg(test)]
mod tests {
    use crate::db::Database;

    use super::*;

    fn pending_asset() -> PendingNetworkAsset {
        PendingNetworkAsset {
            asset: NetworkAsset {
                kind: STORM_EYE_KIND.to_string(),
                name: "Storm Eye".to_string(),
                asset_id: [1; 32],
                reissuance_token_id: None,
                entropy: None,
                issuance_txid: [2; 32],
                contract_script: vec![0x51],
                contract_data: None,
                supply: 10_000,
                created_at_block: 42,
            },
            issuance_tx: vec![3; 64],
        }
    }

    #[tokio::test]
    async fn persists_one_immutable_asset_and_activates_it() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network_assets();
        let pending = pending_asset();

        assert!(store.insert_pending(&pending).await.unwrap());
        assert!(!store.insert_pending(&pending).await.unwrap());
        assert_eq!(
            store.get_pending(STORM_EYE_KIND).await.unwrap(),
            Some(pending.clone())
        );
        assert!(store.get(STORM_EYE_KIND).await.unwrap().is_none());

        assert!(store.activate(STORM_EYE_KIND).await.unwrap());
        assert!(!store.activate(STORM_EYE_KIND).await.unwrap());
        assert_eq!(
            store.get(STORM_EYE_KIND).await.unwrap(),
            Some(pending.asset)
        );
        assert!(store.get_pending(STORM_EYE_KIND).await.unwrap().is_none());

        let peer_public_key = [7; 33];
        let pending = store.pending_for_peer(&peer_public_key).await.unwrap();
        assert_eq!(pending.len(), 1);
        store
            .mark_announced_to(&[STORM_EYE_KIND.to_string()], &peer_public_key)
            .await
            .unwrap();
        assert!(
            store
                .pending_for_peer(&peer_public_key)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.pending_for_peer(&[8; 33]).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn confirms_one_pending_storm_eye_renewal_atomically() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network_assets();
        let pending = pending_asset();
        store.insert_active(&pending.asset).await.unwrap();
        let renewal = PendingStormEyeRenewal {
            txid: [4; 32],
            request: vec![5; 64],
            contract_script: vec![0x52],
            contract_data: vec![6; 64],
            block_height: 43_200,
        };

        assert!(store.record_storm_eye_renewal(&renewal).await.unwrap());
        assert!(!store.record_storm_eye_renewal(&renewal).await.unwrap());
        assert_eq!(
            store.pending_storm_eye_renewal().await.unwrap(),
            Some(renewal)
        );
        assert!(!store.confirm_storm_eye_renewal([7; 32]).await.unwrap());
        assert!(store.confirm_storm_eye_renewal([4; 32]).await.unwrap());
        assert!(store.pending_storm_eye_renewal().await.unwrap().is_none());

        let active = store.get(STORM_EYE_KIND).await.unwrap().unwrap();
        assert_eq!(active.contract_script, vec![0x52]);
        assert_eq!(active.contract_data, Some(vec![6; 64]));
    }

    #[tokio::test]
    async fn indexes_storm_eye_renewal_without_pending_announcement() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network_assets();
        let current = pending_asset().asset;
        let mut renewed = current.clone();
        renewed.contract_script = vec![0x52];
        renewed.contract_data = Some(vec![6; 64]);
        store.insert_active(&current).await.unwrap();

        assert!(
            store
                .index_storm_eye_renewal(&current, &renewed)
                .await
                .unwrap()
        );
        assert!(
            !store
                .index_storm_eye_renewal(&current, &renewed)
                .await
                .unwrap()
        );
        assert_eq!(store.get(STORM_EYE_KIND).await.unwrap(), Some(renewed));
    }

    #[tokio::test]
    async fn indexed_storm_eye_renewal_clears_pending_announcement() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network_assets();
        let current = pending_asset().asset;
        let mut renewed = current.clone();
        renewed.contract_script = vec![0x52];
        renewed.contract_data = Some(vec![6; 64]);
        store.insert_active(&current).await.unwrap();
        store
            .record_storm_eye_renewal(&PendingStormEyeRenewal {
                txid: [4; 32],
                request: vec![5; 64],
                contract_script: renewed.contract_script.clone(),
                contract_data: renewed.contract_data.clone().unwrap(),
                block_height: 43_200,
            })
            .await
            .unwrap();

        assert!(
            store
                .index_storm_eye_renewal(&current, &renewed)
                .await
                .unwrap()
        );
        assert!(store.pending_storm_eye_renewal().await.unwrap().is_none());
        assert_eq!(store.get(STORM_EYE_KIND).await.unwrap(), Some(renewed));
    }
}
