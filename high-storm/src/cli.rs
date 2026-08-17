use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "high-storm")]
#[command(about = "High Storm", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start a previously initialized node.
    Run(ConfigArgs),
    /// Create and persist this node's initial network state.
    Initialize {
        #[command(subcommand)]
        command: InitializeCommands,
    },
}

#[derive(Subcommand)]
pub enum InitializeCommands {
    /// Coordinate discovery for the complete set of network members.
    Host(HostArgs),
    /// Join a network through its discovery node.
    Join(JoinArgs),
}

#[derive(Args)]
pub struct ConfigArgs {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,
}

#[derive(Args)]
pub struct HostArgs {
    #[command(flatten)]
    pub common: ConfigArgs,
    /// Compressed secp256k1 public key of another network member. Repeat for every member.
    #[arg(long = "public-key", required = true)]
    pub public_keys: Vec<String>,
}

#[derive(Args)]
pub struct JoinArgs {
    #[command(flatten)]
    pub common: ConfigArgs,
    /// Compressed secp256k1 public key of the discovery node.
    #[arg(long)]
    pub discovery_public_key: String,
    /// Reachable TCP socket address of the discovery node.
    #[arg(long)]
    pub discovery_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_member_keys() {
        let cli = Cli::try_parse_from([
            "high-storm",
            "initialize",
            "host",
            "--public-key",
            "key-one",
            "--public-key",
            "key-two",
        ])
        .unwrap();

        let Commands::Initialize {
            command: InitializeCommands::Host(args),
        } = cli.command
        else {
            panic!("expected initialize host");
        };
        assert_eq!(args.public_keys, ["key-one", "key-two"]);
    }

    #[test]
    fn parses_join_discovery_node() {
        let cli = Cli::try_parse_from([
            "high-storm",
            "initialize",
            "join",
            "--discovery-public-key",
            "key",
            "--discovery-address",
            "127.0.0.1:9000",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Commands::Initialize {
                command: InitializeCommands::Join(_)
            }
        ));
    }
}
