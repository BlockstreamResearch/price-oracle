use price_feed::{FeedId, PriceFeedData};

use crate::high_storm::PriceAttestation;
use sqlx::{AnyPool, Row};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("value {0} does not fit in the database integer type")]
    OutOfRange(u64),
    #[error("stored attestation public key is not 32 bytes")]
    MalformedPublicKey,
}

#[derive(Clone)]
pub struct PriceAttestationStore {
    pool: AnyPool,
}

impl PriceAttestationStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    /// The `received_at` `attester` last attested for `feed`.
    pub async fn last_attested(
        &self,
        attester: [u8; 32],
        feed: FeedId,
    ) -> Result<Option<u64>, Error> {
        let stamp: Option<i64> = sqlx::query_scalar(
            "SELECT received_at FROM price_attestations \
             WHERE public_key = $1 AND feed_id = $2",
        )
        .bind(attester.to_vec())
        .bind(i64::from(feed))
        .fetch_optional(&self.pool)
        .await?;
        Ok(stamp.map(|stamp| stamp as u64))
    }

    /// False when `received_at` is not strictly greater than the one held.
    pub async fn store_latest(&self, attestation: &PriceAttestation) -> Result<bool, Error> {
        let feed = &attestation.feed;
        let result = sqlx::query(
            "INSERT INTO price_attestations \
             (public_key, feed_id, price, decimals, received_at, valid_until, signature) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (public_key, feed_id) DO UPDATE SET \
             price = $3, decimals = $4, received_at = $5, valid_until = $6, signature = $7 \
             WHERE price_attestations.received_at < $5",
        )
        .bind(attestation.public_key.to_vec())
        .bind(i64::from(feed.feed_id))
        .bind(to_i64(feed.price)?)
        .bind(i64::from(feed.decimals))
        .bind(to_i64(feed.received_at)?)
        .bind(to_i64(feed.valid_until)?)
        .bind(attestation.signature.clone())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn attestations_for(&self, feed: FeedId) -> Result<Vec<PriceAttestation>, Error> {
        let rows = sqlx::query(
            "SELECT public_key, price, decimals, received_at, valid_until, signature \
             FROM price_attestations WHERE feed_id = $1 ORDER BY public_key",
        )
        .bind(i64::from(feed))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let public_key: Vec<u8> = row.try_get("public_key")?;
                Ok(PriceAttestation {
                    public_key: public_key
                        .try_into()
                        .map_err(|_| Error::MalformedPublicKey)?,
                    feed: PriceFeedData {
                        feed_id: feed,
                        price: row.try_get::<i64, _>("price")? as u64,
                        decimals: row.try_get::<i64, _>("decimals")? as u32,
                        received_at: row.try_get::<i64, _>("received_at")? as u64,
                        valid_until: row.try_get::<i64, _>("valid_until")? as u64,
                    },
                    signature: row.try_get("signature")?,
                })
            })
            .collect()
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

    async fn store() -> PriceAttestationStore {
        Database::connect("sqlite::memory:", 1)
            .await
            .unwrap()
            .price_attestations()
    }

    fn attestation(node: u8, price: u64, received_at: u64) -> PriceAttestation {
        PriceAttestation {
            public_key: [node; 32],
            feed: PriceFeedData {
                feed_id: LBTC_USD,
                price,
                decimals: 8,
                received_at,
                valid_until: received_at + 60,
            },
            signature: vec![node; 64],
        }
    }

    #[tokio::test]
    async fn keeps_only_the_latest_attestation_of_a_node() {
        let store = store().await;

        assert!(store.store_latest(&attestation(1, 100, NOW)).await.unwrap());
        assert!(
            store
                .store_latest(&attestation(1, 400, NOW + 1))
                .await
                .unwrap()
        );

        let held = store.attestations_for(LBTC_USD).await.unwrap();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].feed.price, 400);
    }

    #[tokio::test]
    async fn drops_an_attestation_that_is_not_strictly_newer() {
        let store = store().await;
        store.store_latest(&attestation(1, 100, NOW)).await.unwrap();

        // Equal and older both fail the strictly-greater rule.
        assert!(!store.store_latest(&attestation(1, 400, NOW)).await.unwrap());
        assert!(
            !store
                .store_latest(&attestation(1, 700, NOW - 1))
                .await
                .unwrap()
        );

        let held = store.attestations_for(LBTC_USD).await.unwrap();
        assert_eq!(held[0].feed.price, 100);
    }

    #[tokio::test]
    async fn holds_one_attestation_per_node_for_the_same_feed() {
        let store = store().await;
        store.store_latest(&attestation(1, 100, NOW)).await.unwrap();
        store.store_latest(&attestation(2, 300, NOW)).await.unwrap();

        let held = store.attestations_for(LBTC_USD).await.unwrap();

        assert_eq!(held.len(), 2);
        assert_eq!(held[0].public_key, [1; 32]);
        assert_eq!(held[1].public_key, [2; 32]);
    }

    #[tokio::test]
    async fn reads_back_the_stamp_a_node_last_attested() {
        let store = store().await;
        let own = [1; 32];

        assert_eq!(store.last_attested(own, LBTC_USD).await.unwrap(), None);

        // A node holds its own attestation like any other, and reads it back on
        // restart to decide whether an observation is new.
        store.store_latest(&attestation(1, 100, NOW)).await.unwrap();

        assert_eq!(store.last_attested(own, LBTC_USD).await.unwrap(), Some(NOW));
    }

    #[tokio::test]
    async fn reads_back_only_its_own_attested_stamp() {
        let store = store().await;
        store.store_latest(&attestation(1, 100, NOW)).await.unwrap();
        store
            .store_latest(&attestation(2, 300, NOW + 5))
            .await
            .unwrap();

        assert_eq!(
            store.last_attested([1; 32], LBTC_USD).await.unwrap(),
            Some(NOW)
        );
        assert_eq!(
            store.last_attested([2; 32], LBTC_USD).await.unwrap(),
            Some(NOW + 5)
        );
        assert_eq!(store.last_attested([3; 32], LBTC_USD).await.unwrap(), None);
    }
}
