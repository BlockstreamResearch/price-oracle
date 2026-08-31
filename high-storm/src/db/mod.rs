pub mod network;
pub mod node_operator;
pub mod user_request;
pub mod voting;

use node_operator::NodeOperatorStore;
use sqlx::{AnyPool, any::AnyPoolOptions};

use network::NetworkStore;
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

    pub fn node_operators(&self) -> NodeOperatorStore {
        NodeOperatorStore::new(self.pool.clone())
    }

    pub fn user_requests(&self) -> UserRequestStore {
        UserRequestStore::new(self.pool.clone())
    }

    pub fn voting(&self) -> VotingStore {
        VotingStore::new(self.pool.clone())
    }
}
