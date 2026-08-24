#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Ipc(#[from] high_storm::ipc::Error),
    #[error("invalid secp256k1 public key '{0}'")]
    InvalidPublicKey(String),
    #[error("high-storm rejected the command: {0}")]
    Rejected(String),
}
