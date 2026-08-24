mod operator;
mod output;

use std::path::Path;

use clap::Subcommand;
use high_storm::ipc::NodeOperatorResponse;
pub use operator::OperatorCommand;
#[cfg(test)]
pub use operator::OperatorSubcommand;
pub use output::CommandOutput;

use crate::error::Error;

#[derive(Subcommand)]
pub enum Command {
    /// Manage node operators.
    Operator(OperatorCommand),
}

impl Command {
    pub async fn execute(self, socket: &Path) -> Result<CommandOutput, Error> {
        let response = match self {
            Self::Operator(command) => command.execute(socket).await?,
        };
        response.try_into()
    }
}

impl TryFrom<NodeOperatorResponse> for CommandOutput {
    type Error = Error;

    fn try_from(response: NodeOperatorResponse) -> Result<Self, Self::Error> {
        match response {
            NodeOperatorResponse::Added => Ok(Self::new("node operator added")),
            NodeOperatorResponse::AlreadyExists => Ok(Self::new("node operator already exists")),
            NodeOperatorResponse::Removed => Ok(Self::new("node operator removed")),
            NodeOperatorResponse::NotFound => Ok(Self::new("node operator was not found")),
            NodeOperatorResponse::Error(message) => Err(Error::Rejected(message)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_successful_responses_to_output() {
        let output = CommandOutput::try_from(NodeOperatorResponse::Added).unwrap();

        assert_eq!(output.to_string(), "node operator added");
    }

    #[test]
    fn converts_server_errors_to_command_errors() {
        let error =
            CommandOutput::try_from(NodeOperatorResponse::Error("denied".to_string())).unwrap_err();

        assert_eq!(error.to_string(), "high-storm rejected the command: denied");
    }
}
