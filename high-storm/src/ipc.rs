use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use secp256k1_zkp::PublicKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use crate::db::node_operator::NodeOperatorStore;

const MAX_FRAME_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NodeOperatorCommand {
    Add { public_key: String },
    Remove { public_key: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NodeOperatorResponse {
    Added,
    AlreadyExists,
    Removed,
    NotFound,
    Error(String),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IPC I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("IPC message encoding failed: {0}")]
    Codec(#[from] postcard::Error),
    #[error("IPC message exceeds the {MAX_FRAME_SIZE}-byte limit")]
    FrameTooLarge,
    #[error("another high-storm process is listening on '{0}'")]
    SocketInUse(PathBuf),
}

pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
    owner_uid: u32,
    operators: NodeOperatorStore,
}

impl IpcServer {
    pub async fn bind(
        socket_path: impl Into<PathBuf>,
        operators: NodeOperatorStore,
    ) -> Result<Self, Error> {
        let socket_path = socket_path.into();
        prepare_socket_path(&socket_path).await?;
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        let owner_uid = std::fs::symlink_metadata(&socket_path)?.uid();
        tracing::info!(path = %socket_path.display(), "operator IPC listener started");
        Ok(Self {
            listener,
            socket_path,
            owner_uid,
            operators,
        })
    }

    pub async fn run(self) -> Result<(), Error> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let peer_uid = match stream.peer_cred() {
                Ok(credentials) => credentials.uid(),
                Err(error) => {
                    tracing::warn!(%error, "rejected operator IPC connection without credentials");
                    continue;
                }
            };
            if !is_authorized_peer(self.owner_uid, peer_uid) {
                tracing::warn!(peer_uid, "rejected unauthorized operator IPC connection");
                continue;
            }
            let operators = self.operators.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_connection(stream, operators).await {
                    tracing::warn!(%error, "operator IPC command failed");
                }
            });
        }
    }
}

fn is_authorized_peer(owner_uid: u32, peer_uid: u32) -> bool {
    peer_uid == owner_uid || peer_uid == 0
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, path = %self.socket_path.display(), "failed to remove IPC socket");
        }
    }
}

pub async fn send_command(
    socket_path: impl AsRef<Path>,
    command: &NodeOperatorCommand,
) -> Result<NodeOperatorResponse, Error> {
    let mut stream = UnixStream::connect(socket_path).await?;
    write_frame(&mut stream, command).await?;
    read_frame(&mut stream).await
}

async fn prepare_socket_path(socket_path: &Path) -> Result<(), Error> {
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let Ok(metadata) = tokio::fs::symlink_metadata(socket_path).await else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "IPC path '{}' exists and is not a socket",
                socket_path.display()
            ),
        )
        .into());
    }
    if UnixStream::connect(socket_path).await.is_ok() {
        return Err(Error::SocketInUse(socket_path.to_path_buf()));
    }
    tokio::fs::remove_file(socket_path).await?;
    Ok(())
}

async fn handle_connection(
    mut stream: UnixStream,
    operators: NodeOperatorStore,
) -> Result<(), Error> {
    let command = read_frame(&mut stream).await?;
    let response = execute_command(&operators, command).await;
    write_frame(&mut stream, &response).await
}

async fn execute_command(
    operators: &NodeOperatorStore,
    command: NodeOperatorCommand,
) -> NodeOperatorResponse {
    let (encoded_key, add) = match command {
        NodeOperatorCommand::Add { public_key } => (public_key, true),
        NodeOperatorCommand::Remove { public_key } => (public_key, false),
    };
    let public_key = match parse_public_key(&encoded_key) {
        Ok(public_key) => public_key,
        Err(message) => return NodeOperatorResponse::Error(message),
    };
    if add {
        match operators.add(public_key).await {
            Ok(true) => NodeOperatorResponse::Added,
            Ok(false) => NodeOperatorResponse::AlreadyExists,
            Err(error) => NodeOperatorResponse::Error(error.to_string()),
        }
    } else {
        match operators.remove(public_key).await {
            Ok(true) => NodeOperatorResponse::Removed,
            Ok(false) => NodeOperatorResponse::NotFound,
            Err(error) => NodeOperatorResponse::Error(error.to_string()),
        }
    }
}

fn parse_public_key(encoded: &str) -> Result<[u8; 33], String> {
    let bytes = hex::decode(encoded).map_err(|_| format!("invalid public key '{encoded}'"))?;
    PublicKey::from_slice(&bytes)
        .map(|public_key| public_key.serialize())
        .map_err(|_| format!("invalid public key '{encoded}'"))
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, message: &T) -> Result<(), Error> {
    let payload = postcard::to_stdvec(message)?;
    let length = u32::try_from(payload.len()).map_err(|_| Error::FrameTooLarge)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(Error::FrameTooLarge);
    }
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, Error> {
    let mut length = [0; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(Error::FrameTooLarge);
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    Ok(postcard::from_bytes(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::is_authorized_peer;

    #[test]
    fn authorizes_only_the_socket_owner_and_root() {
        assert!(is_authorized_peer(1000, 1000));
        assert!(is_authorized_peer(1000, 0));
        assert!(!is_authorized_peer(1000, 1001));
    }
}
