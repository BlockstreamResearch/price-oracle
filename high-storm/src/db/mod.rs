pub mod chain;
pub mod droplet;
pub mod monitored_utxo;
pub mod network;
pub mod network_asset;
pub mod node_operator;
pub mod price_attestation;
pub mod user_request;
pub mod voting;

use node_operator::NodeOperatorStore;
use sqlx::{AnyPool, any::AnyPoolOptions};

use chain::ChainStore;
use droplet::DropletStore;
use monitored_utxo::MonitoredUtxoStore;
use network::NetworkStore;
use network_asset::NetworkAssetStore;
use price_attestation::PriceAttestationStore;
use user_request::UserRequestStore;
use voting::VotingStore;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database operation failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

#[derive(Clone)]
pub struct Database {
    pool: AnyPool,
}

impl Database {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, Error> {
        sqlx::any::install_default_drivers();
        tracing::debug!(max_connections, "connecting to database");
        let pool = AnyPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        MIGRATOR.run(&pool).await?;
        tracing::debug!("database migrations are current");
        Ok(Self { pool })
    }

    pub fn network(&self) -> NetworkStore {
        NetworkStore::new(self.pool.clone())
    }

    pub fn chain(&self) -> ChainStore {
        ChainStore::new(self.pool.clone())
    }

    pub fn droplets(&self) -> DropletStore {
        DropletStore::new(self.pool.clone())
    }

    pub fn network_assets(&self) -> NetworkAssetStore {
        NetworkAssetStore::new(self.pool.clone())
    }

    pub fn monitored_utxos(&self) -> MonitoredUtxoStore {
        MonitoredUtxoStore::new(self.pool.clone())
    }

    pub fn node_operators(&self) -> NodeOperatorStore {
        NodeOperatorStore::new(self.pool.clone())
    }

    pub fn price_attestations(&self) -> PriceAttestationStore {
        PriceAttestationStore::new(self.pool.clone())
    }

    pub fn user_requests(&self) -> UserRequestStore {
        UserRequestStore::new(self.pool.clone())
    }

    pub fn voting(&self) -> VotingStore {
        VotingStore::new(self.pool.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    async fn upgrade_populated_ledger(url: &str) {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .unwrap();
        let previous = sqlx::migrate::Migrator {
            migrations: Cow::Owned(
                MIGRATOR
                    .iter()
                    .filter(|migration| migration.version < 25)
                    .cloned()
                    .collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        previous.run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO droplets (xonly_pubkey, amount, block_height, exchange_locked, last_tx) \
             VALUES ($1, 12000, 10, 1, $2)",
        )
        .bind(vec![7u8; 32])
        .bind(vec![8u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE chain_recovery_state SET recovering = 1, fork_height = 9 WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO canonical_blocks (block_height, block_hash, parent_hash) VALUES (10, $1, $2)",
        )
        .bind(vec![10u8; 32])
        .bind(vec![9u8; 32])
        .execute(&pool)
        .await
        .unwrap();

        MIGRATOR.run(&pool).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let database = Database { pool: pool.clone() };
        let droplets = database.droplets();
        let balance = droplets.balance([7; 32]).await.unwrap().unwrap();
        assert_eq!(balance.amount, 12_000);
        assert_eq!(balance.block_height, 10);
        assert!(balance.exchange_locked);
        assert_eq!(balance.last_tx, Some(vec![8; 32]));
        assert_eq!(droplets.ledger_halt().await.unwrap(), None);
        let recovery = database.chain().recovery_state().await.unwrap();
        assert!(recovery.recovering);
        assert_eq!(recovery.fork_height, Some(9));
        assert_eq!(database.chain().tip().await.unwrap().unwrap().height, 10);
        let deficit: i64 =
            sqlx::query_scalar("SELECT deficit FROM droplets WHERE xonly_pubkey = $1")
                .bind(vec![7u8; 32])
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(deficit, 0);
        assert!(
            sqlx::query("UPDATE droplets SET deficit = -1")
                .execute(&pool)
                .await
                .is_err()
        );

        sqlx::query("UPDATE droplets SET deficit = 400")
            .execute(&pool)
            .await
            .unwrap();
        droplets.credit([7; 32], 250, 11).await.unwrap();
        assert_eq!(
            droplets.balance([7; 32]).await.unwrap().unwrap().amount,
            12_000
        );
        droplets.credit([7; 32], 250, 12).await.unwrap();
        let balance = droplets.balance([7; 32]).await.unwrap().unwrap();
        assert_eq!(balance.amount, 12_100);
        assert!(balance.exchange_locked);
        assert_eq!(balance.last_tx, Some(vec![8; 32]));
        let deficit: i64 =
            sqlx::query_scalar("SELECT deficit FROM droplets WHERE xonly_pubkey = $1")
                .bind(vec![7u8; 32])
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(deficit, 0);

        let mut transaction = pool.begin().await.unwrap();
        DropletStore::halt_ledger_in(&mut transaction, 12, "upgrade test")
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        assert_eq!(
            droplets.ledger_halt().await.unwrap(),
            Some((12, "upgrade test".into()))
        );
        database.chain().reset_projections().await.unwrap();
        assert_eq!(droplets.ledger_halt().await.unwrap(), None);
        pool.close().await;
    }

    #[tokio::test]
    async fn sqlite_upgrades_a_populated_ledger_without_losing_locks() {
        upgrade_populated_ledger("sqlite::memory:").await;
    }

    #[tokio::test]
    #[ignore = "requires an empty dedicated database in TEST_POSTGRES_MIGRATION_URL"]
    async fn postgres_upgrades_a_populated_ledger_without_losing_locks() {
        let url = std::env::var("TEST_POSTGRES_MIGRATION_URL")
            .expect("TEST_POSTGRES_MIGRATION_URL must name an empty dedicated test database");
        upgrade_populated_ledger(&url).await;
    }
}
