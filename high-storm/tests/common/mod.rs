use std::net::TcpListener;

use high_storm::{
    config::{Config, DbConfig, ServiceConfig, SignerConfig},
    db::{Database, network::NetworkStore},
};
use secp256k1_zkp::{Secp256k1, SecretKey};

pub struct TestNode {
    pub config: Config,
    pub public_key: String,
    pub store: NetworkStore,
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
                db: DbConfig {
                    url: "unused".to_string(),
                    username: "unused".to_string(),
                    password: "unused".to_string(),
                    database: "unused".to_string(),
                    max_connections: 1,
                },
            },
        };

        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.network();

        Self {
            config,
            public_key: hex::encode(public_key),
            store,
        }
    }

    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.config.service.port)
    }
}

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
