use std::path::PathBuf;

use clap::Parser;

use crate::commands::Command;

#[derive(Parser)]
#[command(name = "storm-operator")]
#[command(about = "Manage a running high-storm node")]
pub struct Cli {
    /// Path to the high-storm IPC socket.
    #[arg(long, default_value = "/tmp/high-storm.sock")]
    pub socket: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::OperatorSubcommand;

    #[test]
    fn parses_add_command() {
        let cli = Cli::try_parse_from([
            "storm-operator",
            "--socket",
            "/tmp/node.sock",
            "operator",
            "add",
            "public-key",
        ])
        .unwrap();

        assert_eq!(cli.socket, PathBuf::from("/tmp/node.sock"));
        assert!(matches!(
            cli.command,
            Command::Operator(operator)
                if matches!(&operator.command, OperatorSubcommand::Add(command) if command.public_key == "public-key")
        ));
    }

    #[test]
    fn parses_remove_command() {
        let cli =
            Cli::try_parse_from(["storm-operator", "operator", "remove", "public-key"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Operator(operator)
                if matches!(&operator.command, OperatorSubcommand::Remove(command) if command.public_key == "public-key")
        ));
    }
}
