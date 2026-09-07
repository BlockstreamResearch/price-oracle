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
    #[serde(alias = "user_requests")]
    pub protocol: ProtocolConfig,
    pub db: DbConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProtocolConfig {
    pub operational_fee_sats: u64,
    pub tick_burn_reserve_sats: u64,
    pub issuance_transaction_fee_sats: u64,
    #[serde(default = "default_burn_transaction_fee_sats")]
    pub burn_transaction_fee_sats: u64,
    #[serde(default = "default_exchange_transaction_fee_sats")]
    pub exchange_transaction_fee_sats: u64,
    #[serde(default = "default_tick_lifetime_blocks")]
    pub tick_lifetime_blocks: u64,
}

fn default_burn_transaction_fee_sats() -> u64 {
    500
}

fn default_exchange_transaction_fee_sats() -> u64 {
    500
}

fn default_tick_lifetime_blocks() -> u64 {
    60
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
    #[serde(default = "default_elements_wallet")]
    pub wallet: String,
}

fn default_elements_wallet() -> String {
    "funded-key".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_protocol_section(section: &str) -> String {
        format!(
            r#"
[service]
port = 9000

[service.signer]
private_key = "{private_key}"

[service.elements_rpc]
url = "http://127.0.0.1:18884"
username = "user"
password = "password"

[service.{section}]
operational_fee_sats = 1000
tick_burn_reserve_sats = 1000
issuance_transaction_fee_sats = 1000

[service.db]
url = "localhost:5432"
username = "user"
password = "password"
database = "high-storm"
max_connections = 5
"#,
            private_key = "01".repeat(32),
        )
    }

    #[test]
    fn parses_protocol_section() {
        let config: Config = toml::from_str(&config_with_protocol_section("protocol")).unwrap();

        assert_eq!(config.service.protocol.operational_fee_sats, 1000);
    }

    #[test]
    fn accepts_legacy_user_requests_section() {
        let config: Config =
            toml::from_str(&config_with_protocol_section("user_requests")).unwrap();

        assert_eq!(config.service.protocol.operational_fee_sats, 1000);
    }
}
