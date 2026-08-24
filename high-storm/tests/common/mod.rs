#![allow(dead_code)]

use std::net::TcpListener;
use std::time::Duration;

use high_storm::{
    HighStorm, initialize_host, initialize_join,
    config::{Config, DbConfig, ServiceConfig, SignerConfig},
    db::{Database, network::NetworkStore},
};
use secp256k1::PublicKey;
use secp256k1_zkp::{Secp256k1, SecretKey};
use storm::PeerStatus;
use storm_tree::NodePublicKey;
use tokio::time::timeout;

/// How long node startup and peer-state changes are given before a test gives up.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(15);

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
                rest_address: "127.0.0.1:0".parse().unwrap(),
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

/// A running network of `count` nodes: node 0 hosts discovery, the rest join it.
pub struct TestNetwork {
    pub definitions: Vec<TestNode>,
    pub nodes: Vec<HighStorm>,
}

impl TestNetwork {
    /// # Panics
    /// Panics on fewer than three nodes, or if the network does not finish discovery.
    pub async fn start(count: usize) -> Self {
        assert!(count >= 3, "a Storm Tree needs at least three nodes");

        let mut definitions = Vec::with_capacity(count);
        for index in 0..count {
            // Secrets [1;32], [2;32], ... — the same keys as high-storm/compose.yml and
            // storm-tree's walkthrough test, so all three build an identical Storm Tree.
            definitions.push(TestNode::new(1 + index as u8).await);
        }

        let host_config = definitions[0].config.clone();
        let host_store = definitions[0].store.clone();
        let members: Vec<String> = definitions[1..]
            .iter()
            .map(|node| node.public_key.clone())
            .collect();
        let host =
            tokio::spawn(async move { initialize_host(&host_config, &host_store, &members).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let host_key = definitions[0].public_key.clone();
        let host_address = definitions[0].address();

        let joining: Vec<_> = definitions[1..]
            .iter()
            .map(|node| {
                let config = node.config.clone();
                let store = node.store.clone();
                let host_key = host_key.clone();
                let host_address = host_address.clone();
                tokio::spawn(async move {
                    initialize_join(&config, &store, &host_key, &host_address).await
                })
            })
            .collect();

        let mut nodes = vec![
            timeout(SETTLE_TIMEOUT, host)
                .await
                .expect("host initialization timed out")
                .expect("host task failed")
                .expect("host initialization failed"),
        ];
        for (index, task) in joining.into_iter().enumerate() {
            nodes.push(
                timeout(SETTLE_TIMEOUT, task)
                    .await
                    .unwrap_or_else(|_| panic!("node {} initialization timed out", index + 1))
                    .expect("join task failed")
                    .expect("join initialization failed"),
            );
        }

        let network = Self { definitions, nodes };
        network.wait_for_all_connections().await;

        network
    }

    /// The x-only node keys, in the form `StormTree::new` expects.
    pub fn node_keys(&self) -> Vec<NodePublicKey> {
        self.definitions
            .iter()
            .map(|node| xonly_key(&node.public_key))
            .collect()
    }

    /// The x-only key of one node, by index.
    pub fn node_key(&self, index: usize) -> NodePublicKey {
        xonly_key(&self.definitions[index].public_key)
    }

    /// A, B, C, ... for a node's position in the lexicographically sorted network — the
    /// same labels storm-tree's walkthrough test prints.
    pub fn label(&self, key: &NodePublicKey) -> String {
        let mut sorted = self.node_keys();
        sorted.sort_unstable();
        match sorted.iter().position(|candidate| candidate == key) {
            Some(index) if index < 26 => char::from(b'A' + index as u8).to_string(),
            Some(index) => format!("N{index}"),
            None => "?".to_string(),
        }
    }

    pub async fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown().await;
        }
    }

    /// Blocks until no node still sees an inactive peer.
    pub async fn wait_for_all_connections(&self) {
        timeout(SETTLE_TIMEOUT, async {
            loop {
                let mut connected = true;
                for node in &self.nodes {
                    if node
                        .peers()
                        .await
                        .iter()
                        .any(|peer| peer.status == PeerStatus::Inactive)
                    {
                        connected = false;
                        break;
                    }
                }
                if connected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("nodes did not establish all connections");
    }

    /// Blocks until `observer` sees `peer` in `status`.
    pub async fn wait_for_peer_status(
        &self,
        observer: usize,
        peer: NodePublicKey,
        status: PeerStatus,
    ) {
        timeout(SETTLE_TIMEOUT, async {
            loop {
                let matches = self.nodes[observer].peers().await.iter().any(|candidate| {
                    xonly_bytes(candidate.compressed_public_key) == peer
                        && candidate.status == status
                });
                if matches {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("peer status did not change");
    }
}

/// Converts a hex-encoded compressed public key to its x-only form.
///
/// # Panics
/// Panics if the input is not a valid 33-byte compressed key.
pub fn xonly_key(encoded: &str) -> NodePublicKey {
    let bytes: [u8; 33] = hex::decode(encoded)
        .expect("test node keys are hex")
        .try_into()
        .expect("compressed public key is 33 bytes");

    xonly_bytes(bytes)
}

/// # Panics
/// Panics if the bytes are not a valid compressed public key.
pub fn xonly_bytes(compressed: [u8; 33]) -> NodePublicKey {
    PublicKey::from_slice(&compressed)
        .expect("valid compressed public key")
        .x_only_public_key()
        .0
        .serialize()
}

fn available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
