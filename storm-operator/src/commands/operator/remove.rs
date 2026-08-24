use std::path::Path;

use clap::Args;
use high_storm::ipc::{NodeOperatorCommand, NodeOperatorResponse, send_command};

use super::public_key::parse_public_key;
use crate::error::Error;

#[derive(Args)]
pub struct RemoveCommand {
    #[arg(value_name = "HEX_PUBLIC_KEY")]
    pub public_key: String,
}

impl RemoveCommand {
    pub(super) async fn execute(self, socket: &Path) -> Result<NodeOperatorResponse, Error> {
        let public_key = parse_public_key(&self.public_key)?;
        Ok(send_command(socket, &NodeOperatorCommand::Remove { public_key }).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_an_invalid_key_before_ipc() {
        let error = RemoveCommand {
            public_key: "invalid".to_string(),
        }
        .execute(Path::new("/not/a/storm/socket"))
        .await
        .unwrap_err();

        assert!(matches!(error, Error::InvalidPublicKey(_)));
    }
}
