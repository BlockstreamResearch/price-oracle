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
    pub execution_tx: Option<Vec<u8>>,
    pub included_at_block: Option<u64>,
    pub included_block_hash: Option<[u8; 32]>,
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
            "SELECT request_hash, request, block_height, status, payload, execution_tx, \
                    included_at_block, included_block_hash \
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

    /// Pending requests in issuance order, resuming after the one `after`
    /// names. A round walks the queue in pages so that a request it cannot
    /// issue yet costs one row of the scan instead of a place in the round.
    pub async fn list_pending_after(
        &self,
        limit: u32,
        after: Option<(u64, [u8; 32])>,
    ) -> Result<Vec<StoredUserRequest>, Error> {
        // No cursor scans from the start: heights are never negative, so the
        // sentinel leaves every row past it. Written as two comparisons rather
        // than a row value, and without casts, to stay portable across the
        // backends behind `Any`.
        let (height, hash) = match after {
            Some((height, hash)) => (
                i64::try_from(height)
                    .map_err(|error| Error::Sqlx(sqlx::Error::Encode(Box::new(error))))?,
                hash.to_vec(),
            ),
            None => (-1, Vec::new()),
        };

        sqlx::query(
            "SELECT request_hash, request, block_height, status, payload, execution_tx, \
                    included_at_block, included_block_hash \
             FROM network_user_requests WHERE status = 'pending' \
               AND (block_height > $2 \
                    OR (block_height = $2 AND request_hash > $3)) \
             ORDER BY block_height, request_hash LIMIT $1",
        )
        .bind(i64::from(limit))
        .bind(height)
        .bind(hash)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_request)
        .collect()
    }

    pub async fn list_processing(&self) -> Result<Vec<StoredUserRequest>, Error> {
        sqlx::query(
            "SELECT request_hash, request, block_height, status, payload, execution_tx, \
                    included_at_block, included_block_hash \
                 FROM network_user_requests WHERE status IN ('processing', 'included') \
             ORDER BY block_height, request_hash",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_request)
        .collect()
    }

    pub async fn observe_processing(
        &self,
        request_hash: [u8; 32],
        request: &[u8],
        block_height: u64,
        payload: &[u8],
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO network_user_requests \
             (request_hash, request, block_height, status, payload) \
             VALUES ($1, $2, $3, 'processing', $4) \
             ON CONFLICT (request_hash) DO NOTHING",
        )
        .bind(request_hash.to_vec())
        .bind(request)
        .bind(
            i64::try_from(block_height)
                .map_err(|error| Error::Sqlx(sqlx::Error::Encode(Box::new(error))))?,
        )
        .bind(payload)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_processing(
        &self,
        request_hash: [u8; 32],
        payload: &[u8],
        execution_tx: &[u8],
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'processing', payload = $2, execution_tx = $3 \
             WHERE request_hash = $1 AND status = 'pending'",
        )
        .bind(request_hash.to_vec())
        .bind(payload)
        .bind(execution_tx)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_included(
        &self,
        request_hash: [u8; 32],
        block_height: u64,
        block_hash: [u8; 32],
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'included', included_at_block = $2, \
             included_block_hash = $3 WHERE request_hash = $1 \
             AND status IN ('processing', 'included')",
        )
        .bind(request_hash.to_vec())
        .bind(
            i64::try_from(block_height)
                .map_err(|error| Error::Sqlx(sqlx::Error::Encode(Box::new(error))))?,
        )
        .bind(block_hash.to_vec())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_orphaned(&self, request_hash: [u8; 32]) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'processing', included_at_block = NULL, \
             included_block_hash = NULL WHERE request_hash = $1 AND status = 'included'",
        )
        .bind(request_hash.to_vec())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_executed(&self, request_hash: [u8; 32]) -> Result<bool, Error> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE network_user_requests SET status = 'executed' \
             WHERE request_hash = $1 AND status = 'included'",
        )
        .bind(request_hash.to_vec())
        .execute(&mut *transaction)
        .await?;
        release_fee_utxos(transaction, result.rows_affected(), request_hash).await
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
        release_fee_utxos(transaction, result.rows_affected(), request_hash).await
    }

    pub async fn count_by_status(&self) -> Result<Vec<(String, u64)>, Error> {
        sqlx::query("SELECT status, COUNT(*) AS count FROM network_user_requests GROUP BY status")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get("status")?,
                    decode_height(row.try_get("count")?)?,
                ))
            })
            .collect()
    }

    /// The height at which the oldest request not yet in a block was submitted.
    pub async fn oldest_open_block_height(&self) -> Result<Option<u64>, Error> {
        sqlx::query(
            "SELECT MIN(block_height) AS height FROM network_user_requests \
             WHERE status IN ('pending', 'processing')",
        )
        .fetch_one(&self.pool)
        .await?
        .try_get::<Option<i64>, _>("height")?
        .map(decode_height)
        .transpose()
    }

    pub async fn get(&self, request_hash: [u8; 32]) -> Result<Option<StoredUserRequest>, Error> {
        let Some(row) = sqlx::query(
            "SELECT request_hash, request, block_height, status, payload, execution_tx, \
                    included_at_block, included_block_hash \
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

/// Finishes a status change: when it updated a row, drops the request's fee
/// UTXOs and commits; otherwise rolls back.
async fn release_fee_utxos(
    mut transaction: sqlx::Transaction<'_, sqlx::Any>,
    rows_affected: u64,
    request_hash: [u8; 32],
) -> Result<bool, Error> {
    if rows_affected == 0 {
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
        execution_tx: row.try_get("execution_tx")?,
        included_at_block: row
            .try_get::<Option<i64>, _>("included_at_block")?
            .map(u64::try_from)
            .transpose()
            .map_err(|error| Error::Sqlx(sqlx::Error::Decode(Box::new(error))))?,
        included_block_hash: row
            .try_get::<Option<Vec<u8>>, _>("included_block_hash")?
            .map(|value| {
                value.try_into().map_err(|_| {
                    Error::Sqlx(sqlx::Error::Decode("invalid block hash length".into()))
                })
            })
            .transpose()?,
    })
}

fn decode_height(value: i64) -> Result<u64, Error> {
    u64::try_from(value).map_err(|error| Error::Sqlx(sqlx::Error::Decode(Box::new(error))))
}

#[cfg(test)]
mod tests;
