use price_feed::FeedId;
use sqlx::{AnyPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("value {0} does not fit in the database integer type")]
    OutOfRange(u64),
}

/// The sources this node's operator froze, which a restart freezes again.
#[derive(Clone)]
pub struct FrozenPriceSourceStore {
    pool: AnyPool,
}

impl FrozenPriceSourceStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// Freezing a frozen source keeps the time it was first frozen at.
    pub async fn freeze(&self, feed: FeedId, source: &str, frozen_at: u64) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO frozen_price_sources (feed_id, source, frozen_at) VALUES ($1, $2, $3) \
             ON CONFLICT (feed_id, source) DO NOTHING",
        )
        .bind(i64::from(feed))
        .bind(source)
        .bind(to_i64(frozen_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn unfreeze(&self, feed: FeedId, source: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM frozen_price_sources WHERE feed_id = $1 AND source = $2")
            .bind(i64::from(feed))
            .bind(source)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// When the source was frozen, `None` while it is not.
    pub async fn frozen_at(&self, feed: FeedId, source: &str) -> Result<Option<u64>, Error> {
        let row = sqlx::query(
            "SELECT frozen_at FROM frozen_price_sources WHERE feed_id = $1 AND source = $2",
        )
        .bind(i64::from(feed))
        .bind(source)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .map(|row| row.try_get::<i64, _>("frozen_at"))
            .transpose()?
            .map(|frozen_at| frozen_at as u64))
    }
}

fn to_i64(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::OutOfRange(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    const NOW: u64 = 1_700_000_000;
    const LBTC_USD: FeedId = 0;
    const USDT_USD: FeedId = 1;

    async fn store() -> FrozenPriceSourceStore {
        Database::connect("sqlite::memory:", 1)
            .await
            .unwrap()
            .frozen_price_sources()
    }

    #[tokio::test]
    async fn holds_a_freeze_until_it_is_lifted() {
        let store = store().await;
        assert_eq!(store.frozen_at(LBTC_USD, "coingecko").await.unwrap(), None);

        store.freeze(LBTC_USD, "coingecko", NOW).await.unwrap();
        assert_eq!(
            store.frozen_at(LBTC_USD, "coingecko").await.unwrap(),
            Some(NOW)
        );

        store.unfreeze(LBTC_USD, "coingecko").await.unwrap();
        assert_eq!(store.frozen_at(LBTC_USD, "coingecko").await.unwrap(), None);
    }

    #[tokio::test]
    async fn freezes_one_source_of_one_feed_only() {
        let store = store().await;
        store.freeze(LBTC_USD, "coingecko", NOW).await.unwrap();

        assert_eq!(store.frozen_at(LBTC_USD, "kraken").await.unwrap(), None);
        assert_eq!(store.frozen_at(USDT_USD, "coingecko").await.unwrap(), None);
    }

    #[tokio::test]
    async fn keeps_the_time_a_source_was_first_frozen() {
        let store = store().await;
        store.freeze(LBTC_USD, "coingecko", NOW).await.unwrap();
        store.freeze(LBTC_USD, "coingecko", NOW + 60).await.unwrap();

        assert_eq!(
            store.frozen_at(LBTC_USD, "coingecko").await.unwrap(),
            Some(NOW)
        );
    }

    #[tokio::test]
    async fn unfreezing_a_source_that_is_not_frozen_changes_nothing() {
        let store = store().await;

        store.unfreeze(LBTC_USD, "coingecko").await.unwrap();

        assert_eq!(store.frozen_at(LBTC_USD, "coingecko").await.unwrap(), None);
    }
}
