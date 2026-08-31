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
    ) -> Result<bool, Error> {
        let block_height = i64::try_from(block_height)
            .map_err(|error| Error::Sqlx(sqlx::Error::Encode(Box::new(error))))?;
        let result = sqlx::query(
            "INSERT INTO network_user_requests \
             (request_hash, request, block_height, status) \
             VALUES ($1, $2, $3, 'pending') \
             ON CONFLICT (request_hash) DO NOTHING",
        )
        .bind(request_hash.to_vec())
        .bind(request)
        .bind(block_height)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
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
        let stored_hash: Vec<u8> = row.try_get("request_hash")?;
        let block_height: i64 = row.try_get("block_height")?;
        Ok(Some(StoredUserRequest {
            request_hash: stored_hash.try_into().map_err(|_| {
                Error::Sqlx(sqlx::Error::Decode("invalid request hash length".into()))
            })?,
            request: row.try_get("request")?,
            block_height: u64::try_from(block_height)
                .map_err(|error| Error::Sqlx(sqlx::Error::Decode(Box::new(error))))?,
            status: row.try_get("status")?,
            payload: row.try_get("payload")?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Database;

    #[tokio::test]
    async fn inserts_pending_request_once() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.user_requests();
        let hash = [7; 32];

        assert!(store.insert_pending(hash, b"request", 42).await.unwrap());
        assert!(!store.insert_pending(hash, b"changed", 43).await.unwrap());

        let stored = store.get(hash).await.unwrap().unwrap();
        assert_eq!(stored.request_hash, hash);
        assert_eq!(stored.request, b"request");
        assert_eq!(stored.block_height, 42);
        assert_eq!(stored.status, "pending");
        assert_eq!(stored.payload, None);
    }
}
