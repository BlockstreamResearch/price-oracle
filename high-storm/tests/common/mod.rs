use std::{
    net::TcpListener,
    path::{Path, PathBuf},
};

use high_storm::{
    config::{Config, DbConfig, ElementsRpcConfig, ProtocolConfig, ServiceConfig, SignerConfig},
    db::{Database, network::NetworkStore, network_asset::NetworkAssetStore},
};
use secp256k1_zkp::{Secp256k1, SecretKey};

pub struct TestNode {
    pub config: Config,
    pub public_key: String,
    pub store: NetworkStore,
    #[allow(dead_code)]
    pub assets: NetworkAssetStore,
    _database_file: TemporaryDatabase,
}

struct TemporaryDatabase(PathBuf);

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(sidecar_path(&self.0, "-shm"));
        let _ = std::fs::remove_file(sidecar_path(&self.0, "-wal"));
    }
}

impl TestNode {
    pub async fn new(key_byte: u8) -> Self {
        let secret = SecretKey::from_slice(&[key_byte; 32]).unwrap();
        let public_key = secret.public_key(&Secp256k1::new()).serialize();
        let port = available_port();

        let config = Config {
            service: ServiceConfig {
                port,
                ipc_path: std::env::temp_dir().join(format!("high-storm-{port}.sock")),
                external_api_address: "127.0.0.1:0".parse().unwrap(),
                signer: SignerConfig {
                    private_key: hex::encode(secret.secret_bytes()),
                },
                elements_rpc: ElementsRpcConfig {
                    url: "http://127.0.0.1:18884".to_string(),
                    username: "unused".to_string(),
                    password: "unused".to_string(),
                    wallet: "unused".to_string(),
                },
                protocol: ProtocolConfig {
                    operational_fee_sats: 1_000,
                    tick_burn_reserve_sats: 1_000,
                    issuance_transaction_fee_sats: 1_000,
                    burn_transaction_fee_sats: 500,
                    exchange_transaction_fee_sats: 500,
                    tick_lifetime_blocks: 60,
                },
                db: DbConfig {
                    url: "unused".to_string(),
                    username: "unused".to_string(),
                    password: "unused".to_string(),
                    database: "unused".to_string(),
                    max_connections: 1,
                },
            },
        };

        let database_path = std::env::temp_dir().join(format!("high-storm-{port}.sqlite"));
        let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
        let database = Database::connect(&database_url, 1).await.unwrap();
        let store = database.network();
        let assets = database.network_assets();

        Self {
            config,
            public_key: hex::encode(public_key),
            store,
            assets,
            _database_file: TemporaryDatabase(database_path),
        }
    }

    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.config.service.port)
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_owned();
    path.push(suffix);
    path.into()
}

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
