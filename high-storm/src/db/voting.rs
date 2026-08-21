use sqlx::{AnyPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
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
    pub block_height: u64,
    pub approved_at_block_height: Option<u64>,
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
        block_height: u64,
    ) -> Result<bool, Error> {
        let result = sqlx::query(
            "INSERT INTO voting_requests (message_hash, message, block_height) \
             VALUES ($1, $2, $3) ON CONFLICT (message_hash) DO NOTHING",
        )
        .bind(message_hash.to_vec())
        .bind(message)
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
            "SELECT message_hash, message, block_height, approved_at_block_height \
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
            "SELECT message_hash, message, block_height, approved_at_block_height \
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
            block_height: i64_to_height(row.try_get("block_height")?)?,
            approved_at_block_height: row
                .try_get::<Option<i64>, _>("approved_at_block_height")?
                .map(i64_to_height)
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
