use sqlx::{AnyPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredUserRequest {
    pub request_hash: [u8; 32],
    pub request: Vec<u8>,
    pub block_height: u64,
    pub status: String,
    pub payload: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct FeeUtxo {
    pub txid: [u8; 32],
    pub output_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertPendingResult {
    Inserted,
    RequestExists,
    FeeUtxoReserved(FeeUtxo),
}

#[derive(Clone)]
pub struct UserRequestStore {
    pool: AnyPool,
}

impl UserRequestStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn insert_pending(
        &self,
        request_hash: [u8; 32],
        request: &[u8],
        block_height: u64,
        fee_utxos: &[FeeUtxo],
    ) -> Result<InsertPendingResult, Error> {
        let block_height = i64::try_from(block_height)
            .map_err(|error| Error::Sqlx(sqlx::Error::Encode(Box::new(error))))?;
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO network_user_requests \
             (request_hash, request, block_height, status) \
             VALUES ($1, $2, $3, 'pending') \
             ON CONFLICT (request_hash) DO NOTHING",
        )
        .bind(request_hash.to_vec())
        .bind(request)
        .bind(block_height)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(InsertPendingResult::RequestExists);
        }

        for fee_utxo in fee_utxos {
            let result = sqlx::query(
                "INSERT INTO network_user_request_fee_utxos \
                 (txid, output_index, request_hash) VALUES ($1, $2, $3) \
                 ON CONFLICT (txid, output_index) DO NOTHING",
            )
            .bind(fee_utxo.txid.to_vec())
            .bind(i64::from(fee_utxo.output_index))
            .bind(request_hash.to_vec())
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() == 0 {
                transaction.rollback().await?;
                return Ok(InsertPendingResult::FeeUtxoReserved(fee_utxo.clone()));
            }
        }

        transaction.commit().await?;
        Ok(InsertPendingResult::Inserted)
    }

    pub async fn list_pending(&self, limit: u32) -> Result<Vec<StoredUserRequest>, Error> {
        sqlx::query(
            "SELECT request_hash, request, block_height, status, payload \
             FROM network_user_requests WHERE status = 'pending' \
             ORDER BY block_height, request_hash LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_request)
        .collect()
    }

    pub async fn list_processing(&self) -> Result<Vec<StoredUserRequest>, Error> {
        sqlx::query(
            "SELECT request_hash, request, block_height, status, payload \
             FROM network_user_requests WHERE status = 'processing' \
             ORDER BY block_height, request_hash",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_request)
        .collect()
    }

    pub async fn mark_processing(
        &self,
        request_hash: [u8; 32],
        payload: &[u8],
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'processing', payload = $2 \
             WHERE request_hash = $1 AND status = 'pending'",
        )
        .bind(request_hash.to_vec())
        .bind(payload)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_executed(&self, request_hash: [u8; 32]) -> Result<bool, Error> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'executed' \
             WHERE request_hash = $1 AND status = 'processing'",
        )
        .bind(request_hash.to_vec())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM network_user_request_fee_utxos WHERE request_hash = $1")
            .bind(request_hash.to_vec())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(true)
    }

    pub async fn mark_failed(&self, request_hash: [u8; 32], reason: &[u8]) -> Result<bool, Error> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'failed', payload = $2 \
             WHERE request_hash = $1 AND status = 'pending'",
        )
        .bind(request_hash.to_vec())
        .bind(reason)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }

        sqlx::query("DELETE FROM network_user_request_fee_utxos WHERE request_hash = $1")
            .bind(request_hash.to_vec())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(true)
    }

    pub async fn get(&self, request_hash: [u8; 32]) -> Result<Option<StoredUserRequest>, Error> {
        let Some(row) = sqlx::query(
            "SELECT request_hash, request, block_height, status, payload \
             FROM network_user_requests WHERE request_hash = $1",
        )
        .bind(request_hash.to_vec())
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(decode_request(row)?))
    }
}

fn decode_request(row: sqlx::any::AnyRow) -> Result<StoredUserRequest, Error> {
    let stored_hash: Vec<u8> = row.try_get("request_hash")?;
    let block_height: i64 = row.try_get("block_height")?;
    Ok(StoredUserRequest {
        request_hash: stored_hash
            .try_into()
            .map_err(|_| Error::Sqlx(sqlx::Error::Decode("invalid request hash length".into())))?,
        request: row.try_get("request")?,
        block_height: u64::try_from(block_height)
            .map_err(|error| Error::Sqlx(sqlx::Error::Decode(Box::new(error))))?,
        status: row.try_get("status")?,
        payload: row.try_get("payload")?,
    })
}

#[cfg(test)]
mod tests {
    use crate::db::{Database, user_request::InsertPendingResult};

    use super::FeeUtxo;

    #[tokio::test]
    async fn inserts_pending_request_once() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.user_requests();
        let hash = [7; 32];
        let fee_utxo = FeeUtxo {
            txid: [8; 32],
            output_index: 3,
        };

        assert_eq!(
            store
                .insert_pending(hash, b"request", 42, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::Inserted
        );
        assert_eq!(
            store
                .insert_pending(hash, b"changed", 43, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::RequestExists
        );

        let stored = store.get(hash).await.unwrap().unwrap();
        assert_eq!(stored.request_hash, hash);
        assert_eq!(stored.request, b"request");
        assert_eq!(stored.block_height, 42);
        assert_eq!(stored.status, "pending");
        assert_eq!(stored.payload, None);
    }

    #[tokio::test]
    async fn reserves_fee_utxos_through_processing_and_releases_after_execution() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.user_requests();
        let fee_utxo = FeeUtxo {
            txid: [8; 32],
            output_index: 3,
        };

        assert_eq!(
            store
                .insert_pending([1; 32], b"first", 42, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::Inserted
        );
        assert_eq!(store.list_pending(10).await.unwrap().len(), 1);
        assert!(store.mark_processing([1; 32], b"result").await.unwrap());
        assert!(store.list_pending(10).await.unwrap().is_empty());
        assert_eq!(
            store
                .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::FeeUtxoReserved(fee_utxo.clone())
        );

        assert!(store.mark_executed([1; 32]).await.unwrap());
        assert_eq!(
            store
                .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::Inserted
        );
    }

    #[tokio::test]
    async fn failing_pending_request_releases_fee_utxos() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.user_requests();
        let fee_utxo = FeeUtxo {
            txid: [8; 32],
            output_index: 3,
        };

        assert_eq!(
            store
                .insert_pending([1; 32], b"first", 42, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::Inserted
        );
        assert!(
            store
                .mark_failed([1; 32], b"input unavailable")
                .await
                .unwrap()
        );
        let failed = store.get([1; 32]).await.unwrap().unwrap();
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.payload.as_deref(), Some(&b"input unavailable"[..]));
        assert!(store.list_pending(10).await.unwrap().is_empty());
        assert_eq!(
            store
                .insert_pending([2; 32], b"second", 43, std::slice::from_ref(&fee_utxo))
                .await
                .unwrap(),
            InsertPendingResult::Inserted
        );
    }
}
