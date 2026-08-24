use sqlx::{AnyPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("persisted node operator public key has an invalid length")]
    InvalidPublicKey,
}

#[derive(Clone)]
pub struct NodeOperatorStore {
    pool: AnyPool,
}

impl NodeOperatorStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn add(&self, public_key: [u8; 33]) -> Result<bool, Error> {
        let result = sqlx::query(
            "INSERT INTO node_operators (public_key) VALUES ($1) \
             ON CONFLICT (public_key) DO NOTHING",
        )
        .bind(public_key.to_vec())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn remove(&self, public_key: [u8; 33]) -> Result<bool, Error> {
        let result = sqlx::query("DELETE FROM node_operators WHERE public_key = $1")
            .bind(public_key.to_vec())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn list(&self) -> Result<Vec<[u8; 33]>, Error> {
        sqlx::query("SELECT public_key FROM node_operators ORDER BY public_key")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|row| {
                row.try_get::<Vec<u8>, _>("public_key")?
                    .try_into()
                    .map_err(|_| Error::InvalidPublicKey)
            })
            .collect()
    }
}
