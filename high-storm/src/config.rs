use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read config file: {0}")]
    Io(std::io::Error),
    #[error("failed to parse config file: {0}")]
    Toml(toml::de::Error),
    #[error("invalid database configuration: {0}")]
    Database(String),
}

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub service: ServiceConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfig {
    pub port: u16,
    #[serde(default = "default_ipc_path")]
    pub ipc_path: PathBuf,
    #[serde(default = "default_external_api_address")]
    pub external_api_address: SocketAddr,
    pub signer: SignerConfig,
    pub elements_rpc: ElementsRpcConfig,
    pub db: DbConfig,
}

fn default_ipc_path() -> PathBuf {
    "/tmp/high-storm.sock".into()
}

fn default_external_api_address() -> SocketAddr {
    "127.0.0.1:9001"
        .parse()
        .expect("the default external API address is valid")
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignerConfig {
    pub private_key: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ElementsRpcConfig {
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DbConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    pub database: String,
    pub max_connections: u32,
}

impl Config {
    pub fn from_file(path: PathBuf) -> Result<Self, Error> {
        let contents = std::fs::read_to_string(path).map_err(Error::Io)?;
        let config: Config = toml::from_str(&contents).map_err(Error::Toml)?;

        Ok(config)
    }

    pub fn database_url(&self) -> Result<String, Error> {
        let db = &self.service.db;
        let mut url = Url::parse(&format!("postgres://{}/{}", db.url, db.database))
            .map_err(|error| Error::Database(error.to_string()))?;
        url.set_username(&db.username)
            .map_err(|_| Error::Database("invalid database username".to_string()))?;
        url.set_password(Some(&db.password))
            .map_err(|_| Error::Database("invalid database password".to_string()))?;
        Ok(url.to_string())
    }
}
