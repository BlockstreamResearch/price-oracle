use std::{
    collections::HashSet,
    error::Error,
    io,
    path::{Path, PathBuf},
};

use secp256k1_zkp::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use storm::{Peer, PeerStatus};

pub type BoxError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub private_key: String,
    pub listen_address: String,
    pub peers_file: PathBuf,
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default)]
    pub public_keys: Vec<String>,
    pub discoverer: Option<ConfiguredPeer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredPeer {
    pub public_key: String,
    pub socket_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SavedPeers {
    peers: Vec<SavedPeer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SavedPeer {
    public_key: String,
    socket_address: Option<String>,
    last_seen: Option<u64>,
    status: SavedPeerStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SavedPeerStatus {
    Controlled,
    Active,
    Inactive,
    Banned,
}

fn default_domain() -> String {
    "basic.message".to_string()
}

impl NodeConfig {
    pub async fn load(path: &Path) -> Result<Self, BoxError> {
        let contents = tokio::fs::read_to_string(path).await?;
        Ok(toml::from_str(&contents)?)
    }

    pub fn secret_key(&self) -> Result<SecretKey, BoxError> {
        let bytes = decode_hex::<32>(&self.private_key, "private_key")?;
        Ok(SecretKey::from_slice(&bytes)?)
    }

    pub fn discovery_peers(&self, local_public_key: [u8; 33]) -> Result<Vec<Peer>, BoxError> {
        if self.public_keys.is_empty() {
            return Err(invalid_data(
                "discovery mode requires at least one public_keys entry",
            ));
        }

        let mut seen = HashSet::new();
        let mut peers = Vec::new();
        for key in &self.public_keys {
            let public_key = parse_public_key(key)?;
            if public_key != local_public_key && seen.insert(public_key) {
                peers.push(Peer::new(public_key));
            }
        }
        Ok(peers)
    }

    pub fn discoverer_peer(&self) -> Result<Peer, BoxError> {
        let configured = self
            .discoverer
            .as_ref()
            .ok_or_else(|| invalid_data("discoverable mode requires a [discoverer] section"))?;
        let mut peer = Peer::new(parse_public_key(&configured.public_key)?);
        peer.socket_address = Some(configured.socket_address.clone());
        Ok(peer)
    }
}

pub async fn load_peers(path: &Path) -> Result<Vec<Peer>, BoxError> {
    let contents = tokio::fs::read_to_string(path).await?;
    let saved: SavedPeers = toml::from_str(&contents)?;
    saved.peers.into_iter().map(Peer::try_from).collect()
}

pub async fn save_peers(path: &Path, peers: &[Peer]) -> Result<(), BoxError> {
    let saved = SavedPeers {
        peers: peers.iter().map(SavedPeer::from).collect(),
    };
    let contents = toml::to_string_pretty(&saved)?;
    let temporary = path.with_extension("tmp");

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&temporary, contents).await?;
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

pub fn parse_public_key(value: &str) -> Result<[u8; 33], BoxError> {
    let bytes = decode_hex::<33>(value, "public key")?;
    PublicKey::from_slice(&bytes)?;
    Ok(bytes)
}

fn decode_hex<const LENGTH: usize>(value: &str, name: &str) -> Result<[u8; LENGTH], BoxError> {
    let bytes =
        hex::decode(value).map_err(|error| invalid_data(format!("invalid {name}: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        invalid_data(format!(
            "invalid {name} length: expected {LENGTH} bytes, got {}",
            bytes.len()
        ))
    })
}

fn invalid_data(message: impl Into<String>) -> BoxError {
    Box::new(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

impl From<&Peer> for SavedPeer {
    fn from(peer: &Peer) -> Self {
        Self {
            public_key: hex::encode(peer.compressed_public_key),
            socket_address: peer.socket_address.clone(),
            last_seen: peer.last_seen,
            status: peer.status.into(),
        }
    }
}

impl TryFrom<SavedPeer> for Peer {
    type Error = BoxError;

    fn try_from(peer: SavedPeer) -> Result<Self, Self::Error> {
        Ok(Self {
            compressed_public_key: parse_public_key(&peer.public_key)?,
            socket_address: peer.socket_address,
            last_seen: peer.last_seen,
            status: peer.status.into(),
            discovery: false,
        })
    }
}

impl From<PeerStatus> for SavedPeerStatus {
    fn from(status: PeerStatus) -> Self {
        match status {
            PeerStatus::Controlled => Self::Controlled,
            PeerStatus::Active => Self::Active,
            PeerStatus::Inactive => Self::Inactive,
            PeerStatus::Banned => Self::Banned,
        }
    }
}

impl From<SavedPeerStatus> for PeerStatus {
    fn from(status: SavedPeerStatus) -> Self {
        match status {
            SavedPeerStatus::Controlled => Self::Controlled,
            SavedPeerStatus::Active => Self::Active,
            SavedPeerStatus::Inactive => Self::Inactive,
            SavedPeerStatus::Banned => Self::Banned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1_zkp::Secp256k1;

    #[test]
    fn config_rejects_unknown_fields() {
        let error = toml::from_str::<NodeConfig>(
            r#"
private_key = "00"
listen_address = "127.0.0.1:9000"
peers_file = "peers.toml"
typo = true
"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn saved_peer_round_trip_preserves_ban() {
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = secret_key.public_key(&Secp256k1::new()).serialize();
        let mut peer = Peer::new(public_key);
        peer.status = PeerStatus::Banned;
        let encoded = toml::to_string(&SavedPeers {
            peers: vec![SavedPeer::from(&peer)],
        })
        .unwrap();
        let decoded: SavedPeers = toml::from_str(&encoded).unwrap();
        let restored = Peer::try_from(decoded.peers.into_iter().next().unwrap()).unwrap();

        assert_eq!(restored.status, PeerStatus::Banned);
        assert_eq!(restored.compressed_public_key, peer.compressed_public_key);
    }

    #[test]
    fn shipped_configs_have_valid_keys() {
        let discovery: NodeConfig =
            toml::from_str(include_str!("../config/discovery.toml")).unwrap();
        let secret_key = discovery.secret_key().unwrap();
        let local_public_key = secret_key.public_key(&Secp256k1::new()).serialize();
        assert_eq!(
            discovery.discovery_peers(local_public_key).unwrap().len(),
            2
        );

        let discoverable: NodeConfig =
            toml::from_str(include_str!("../config/discoverable.toml")).unwrap();
        discoverable.secret_key().unwrap();
        discoverable.discoverer_peer().unwrap();

        let third: NodeConfig =
            toml::from_str(include_str!("../config/discoverable-third.toml")).unwrap();
        let third_public_key = third
            .secret_key()
            .unwrap()
            .public_key(&Secp256k1::new())
            .serialize();
        assert_eq!(
            hex::encode(third_public_key),
            "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
        );
        third.discoverer_peer().unwrap();

        let restored: NodeConfig = toml::from_str(include_str!("../config/restored.toml")).unwrap();
        restored.secret_key().unwrap();
    }
}
