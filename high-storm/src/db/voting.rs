use sqlx::{AnyPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("voting execution state was not updated")]
    ExecutionStateNotUpdated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredApproval {
    pub public_key: [u8; 32],
    pub message: Vec<u8>,
    pub block_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredVotingRequest {
    pub message_hash: [u8; 32],
    pub message: Vec<u8>,
    pub proposer_public_key: Option<[u8; 32]>,
    pub block_height: u64,
    pub approved_at_block_height: Option<u64>,
    pub execution_started: bool,
    pub execution_transaction: Option<Vec<u8>>,
    pub execution_txid: Option<[u8; 32]>,
    pub approvals: Vec<StoredApproval>,
}

#[derive(Clone)]
pub struct VotingStore {
    pool: AnyPool,
}

impl VotingStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn insert_request(
        &self,
        message_hash: [u8; 32],
        message: &[u8],
        proposer_public_key: [u8; 32],
        block_height: u64,
    ) -> Result<bool, Error> {
        self.insert_synchronized_request(
            message_hash,
            message,
            Some(proposer_public_key),
            block_height,
        )
        .await
    }

    pub async fn insert_synchronized_request(
        &self,
        message_hash: [u8; 32],
        message: &[u8],
        proposer_public_key: Option<[u8; 32]>,
        block_height: u64,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "INSERT INTO voting_requests \
             (message_hash, message, proposer_public_key, block_height) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (message_hash) DO NOTHING",
        )
        .bind(message_hash.to_vec())
        .bind(message)
        .bind(proposer_public_key.map(|key| key.to_vec()))
        .bind(height_to_i64(block_height)?)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn insert_approval(
        &self,
        request_hash: [u8; 32],
        public_key: [u8; 32],
        message: &[u8],
        block_height: u64,
        required_approvals: usize,
    ) -> Result<bool, Error> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "INSERT INTO voting_approvals \
             (voting_request_hash, public_key, message, block_height) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (voting_request_hash, public_key) DO NOTHING",
        )
        .bind(request_hash.to_vec())
        .bind(public_key.to_vec())
        .bind(message)
        .bind(height_to_i64(block_height)?)
        .execute(&mut *transaction)
        .await?;
        let inserted = result.rows_affected() == 1;

        if inserted {
            let approval_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM voting_approvals WHERE voting_request_hash = $1",
            )
            .bind(request_hash.to_vec())
            .fetch_one(&mut *transaction)
            .await?;
            let reaches_approval = approval_count as usize >= required_approvals;
            if reaches_approval {
                sqlx::query(
                    "UPDATE voting_requests SET approved_at_block_height = $1 \
                 WHERE message_hash = $2 AND approved_at_block_height IS NULL",
                )
                .bind(height_to_i64(block_height)?)
                .bind(request_hash.to_vec())
                .execute(&mut *transaction)
                .await?;
            }
        }

        transaction.commit().await?;
        Ok(inserted)
    }

    pub async fn approval_count(&self, request_hash: [u8; 32]) -> Result<usize, Error> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM voting_approvals WHERE voting_request_hash = $1",
        )
        .bind(request_hash.to_vec())
        .fetch_one(&self.pool)
        .await?;
        Ok(count as usize)
    }

    pub async fn get(&self, message_hash: [u8; 32]) -> Result<Option<StoredVotingRequest>, Error> {
        let Some(row) = sqlx::query(
            "SELECT message_hash, message, proposer_public_key, block_height, \
             approved_at_block_height, execution_started, execution_transaction, execution_txid \
             FROM voting_requests WHERE message_hash = $1",
        )
        .bind(message_hash.to_vec())
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };

        Ok(Some(self.request_from_row(row).await?))
    }

    pub async fn list(&self) -> Result<Vec<StoredVotingRequest>, Error> {
        let rows = sqlx::query(
            "SELECT message_hash, message, proposer_public_key, block_height, \
             approved_at_block_height, execution_started, execution_transaction, execution_txid \
             FROM voting_requests ORDER BY block_height, message_hash",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut requests = Vec::with_capacity(rows.len());
        for row in rows {
            requests.push(self.request_from_row(row).await?);
        }
        Ok(requests)
    }

    pub async fn start_execution(
        &self,
        message_hash: [u8; 32],
        transaction: &[u8],
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "UPDATE voting_requests SET execution_started = 1, execution_transaction = $1 \
             WHERE message_hash = $2 AND approved_at_block_height IS NOT NULL \
             AND execution_started = 0 AND execution_txid IS NULL",
        )
        .bind(transaction)
        .bind(message_hash.to_vec())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn cancel_execution(&self, message_hash: [u8; 32]) -> Result<(), Error> {
        let updated = sqlx::query(
            "UPDATE voting_requests SET execution_started = 0, execution_transaction = NULL \
             WHERE message_hash = $1 AND execution_txid IS NULL",
        )
        .bind(message_hash.to_vec())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(Error::ExecutionStateNotUpdated);
        }
        Ok(())
    }

    pub async fn complete_execution(
        &self,
        message_hash: [u8; 32],
        proposer_public_key: [u8; 32],
        txid: [u8; 32],
    ) -> Result<(), Error> {
        let updated = sqlx::query(
            "UPDATE voting_requests SET execution_started = 0, execution_transaction = NULL, \
             proposer_public_key = COALESCE(proposer_public_key, $1), execution_txid = $2 \
             WHERE message_hash = $3 AND approved_at_block_height IS NOT NULL \
             AND (proposer_public_key IS NULL OR proposer_public_key = $1) \
             AND (execution_txid IS NULL OR execution_txid = $2)",
        )
        .bind(proposer_public_key.to_vec())
        .bind(txid.to_vec())
        .bind(message_hash.to_vec())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(Error::ExecutionStateNotUpdated);
        }
        Ok(())
    }

    pub async fn delete_expired(
        &self,
        current_block_height: u64,
        timeout_blocks: u64,
    ) -> Result<u64, Error> {
        let current = height_to_i64(current_block_height)?;
        let timeout = height_to_i64(timeout_blocks)?;
        let result = sqlx::query(
            "DELETE FROM voting_requests WHERE \
             (approved_at_block_height IS NULL AND block_height + $1 <= $2) OR \
             (approved_at_block_height IS NOT NULL AND approved_at_block_height + $1 <= $2)",
        )
        .bind(timeout)
        .bind(current)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "DELETE FROM voting_approvals WHERE NOT EXISTS (\
             SELECT 1 FROM voting_requests \
             WHERE voting_requests.message_hash = voting_approvals.voting_request_hash)",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn request_from_row(&self, row: sqlx::any::AnyRow) -> Result<StoredVotingRequest, Error> {
        let hash = bytes_to_array(row.try_get("message_hash")?)?;
        let approval_rows = sqlx::query(
            "SELECT public_key, message, block_height FROM voting_approvals \
             WHERE voting_request_hash = $1 ORDER BY block_height, public_key",
        )
        .bind(hash.to_vec())
        .fetch_all(&self.pool)
        .await?;
        let approvals = approval_rows
            .into_iter()
            .map(|approval| {
                Ok(StoredApproval {
                    public_key: bytes_to_array(approval.try_get("public_key")?)?,
                    message: approval.try_get("message")?,
                    block_height: i64_to_height(approval.try_get("block_height")?)?,
                })
            })
            .collect::<Result<_, Error>>()?;

        Ok(StoredVotingRequest {
            message_hash: hash,
            message: row.try_get("message")?,
            proposer_public_key: row
                .try_get::<Option<Vec<u8>>, _>("proposer_public_key")?
                .map(bytes_to_array)
                .transpose()?,
            block_height: i64_to_height(row.try_get("block_height")?)?,
            approved_at_block_height: row
                .try_get::<Option<i64>, _>("approved_at_block_height")?
                .map(i64_to_height)
                .transpose()?,
            execution_started: row.try_get::<i64, _>("execution_started")? != 0,
            execution_transaction: row.try_get("execution_transaction")?,
            execution_txid: row
                .try_get::<Option<Vec<u8>>, _>("execution_txid")?
                .map(bytes_to_array)
                .transpose()?,
            approvals,
        })
    }
}

fn height_to_i64(height: u64) -> Result<i64, Error> {
    i64::try_from(height).map_err(|error| Error::Sqlx(sqlx::Error::Encode(Box::new(error))))
}

fn i64_to_height(height: i64) -> Result<u64, Error> {
    u64::try_from(height).map_err(|error| Error::Sqlx(sqlx::Error::Decode(Box::new(error))))
}

fn bytes_to_array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Sqlx(sqlx::Error::Decode("invalid byte array length".into())))
}

#[cfg(test)]
mod tests {
    use crate::db::Database;

    #[tokio::test]
    async fn persists_voting_execution_lifecycle() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.voting();
        let request_hash = [1; 32];
        let proposer = [2; 32];
        let transaction = [3, 4, 5];
        let txid = [6; 32];

        assert!(
            store
                .insert_request(request_hash, &[7], proposer, 10)
                .await
                .unwrap()
        );
        assert!(
            store
                .insert_approval(request_hash, [8; 32], &[9], 11, 1)
                .await
                .unwrap()
        );
        assert!(
            store
                .start_execution(request_hash, &transaction)
                .await
                .unwrap()
        );
        assert!(
            !store
                .start_execution(request_hash, &transaction)
                .await
                .unwrap()
        );

        let executing = store.get(request_hash).await.unwrap().unwrap();
        assert!(executing.execution_started);
        assert_eq!(executing.execution_transaction, Some(transaction.to_vec()));

        assert!(
            store
                .complete_execution(request_hash, [9; 32], txid)
                .await
                .is_err()
        );
        store
            .complete_execution(request_hash, proposer, txid)
            .await
            .unwrap();
        let executed = store.get(request_hash).await.unwrap().unwrap();
        assert!(!executed.execution_started);
        assert_eq!(executed.execution_transaction, None);
        assert_eq!(executed.execution_txid, Some(txid));
        assert!(
            store
                .complete_execution(request_hash, proposer, txid)
                .await
                .is_ok()
        );
        assert!(
            store
                .complete_execution([0; 32], proposer, txid)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn completion_populates_an_unknown_synchronized_proposer() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.voting();
        let request_hash = [10; 32];
        let proposer = [12; 32];
        let txid = [13; 32];

        assert!(
            store
                .insert_synchronized_request(request_hash, &[11], None, 12)
                .await
                .unwrap()
        );
        assert!(
            store
                .insert_approval(request_hash, [14; 32], &[15], 13, 1)
                .await
                .unwrap()
        );
        store
            .complete_execution(request_hash, proposer, txid)
            .await
            .unwrap();
        let completed = store.get(request_hash).await.unwrap().unwrap();
        assert_eq!(completed.proposer_public_key, Some(proposer));
        assert_eq!(completed.execution_txid, Some(txid));
    }
}
