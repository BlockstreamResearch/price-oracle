mod add;
mod public_key;
mod remove;

use std::path::Path;

pub use add::AddCommand;
use clap::{Args, Subcommand};
use high_storm::ipc::NodeOperatorResponse;
pub use remove::RemoveCommand;

use crate::error::Error;

#[derive(Args)]
pub struct OperatorCommand {
    #[command(subcommand)]
    pub command: OperatorSubcommand,
}

#[derive(Subcommand)]
pub enum OperatorSubcommand {
    /// Add a node operator by hex-encoded secp256k1 public key.
    Add(AddCommand),
    /// Remove a node operator by hex-encoded secp256k1 public key.
    Remove(RemoveCommand),
}

impl OperatorCommand {
    pub async fn execute(self, socket: &Path) -> Result<NodeOperatorResponse, Error> {
        match self.command {
            OperatorSubcommand::Add(command) => command.execute(socket).await,
            OperatorSubcommand::Remove(command) => command.execute(socket).await,
        }
    }
}
