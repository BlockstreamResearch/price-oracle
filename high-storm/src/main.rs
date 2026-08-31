use clap::Parser;
use high_storm::{
    HighStorm,
    cli::{Cli, Commands, InitializeCommands},
    config::Config,
    db::{Database, network::NetworkStore},
    external_api::ExternalApiServer,
    ipc::IpcServer,
};
use tokio::time::{Duration, Instant, MissedTickBehavior};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,high_storm=debug,storm=debug,sqlx=warn")),
        )
        .init();

    let cli = Cli::parse();

    let (config_path, action) = match cli.command {
        Commands::Run(args) => (args.config, Action::Run),
        Commands::Initialize {
            command: InitializeCommands::Host(args),
        } => (args.common.config, Action::Host(args.public_keys)),
        Commands::Initialize {
            command: InitializeCommands::Join(args),
        } => (
            args.common.config,
            Action::Join(args.discovery_public_key, args.discovery_address),
        ),
    };
    tracing::info!(
        command = action.name(),
        config = %config_path.display(),
        "starting high-storm"
    );
    let config = Config::from_file(config_path)?;
    tracing::debug!(
        listen_port = config.service.port,
        elements_rpc = %config.service.elements_rpc.url,
        database_host = %config.service.db.url,
        database = %config.service.db.database,
        "configuration loaded"
    );
    let database =
        Database::connect(&config.database_url()?, config.service.db.max_connections).await?;
    let store = database.network();
    tracing::info!("database is ready");
    let storm = match action {
        Action::Run => high_storm::start_initialized(&config, &store).await?,
        Action::Host(public_keys) => {
            high_storm::initialize_host(&config, &store, &public_keys).await?
        }
        Action::Join(public_key, address) => {
            high_storm::initialize_join(&config, &store, &public_key, &address).await?
        }
    };
    let external_api = ExternalApiServer::bind(
        config.service.external_api_address,
        storm.handle(),
        database.node_operators(),
    )
    .await?;
    tracing::info!(address = %external_api.local_addr()?, "external API is listening");
    let ipc = IpcServer::bind(&config.service.ipc_path, database.node_operators()).await?;
    run_until_shutdown(storm, &store, ipc, external_api).await?;

    Ok(())
}

enum Action {
    Run,
    Host(Vec<String>),
    Join(String, String),
}

impl Action {
    fn name(&self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Host(_) => "initialize host",
            Self::Join(_, _) => "initialize join",
        }
    }
}

async fn run_until_shutdown(
    mut storm: HighStorm,
    store: &NetworkStore,
    ipc: IpcServer,
    external_api: ExternalApiServer,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reconnect = tokio::time::interval(Duration::from_secs(3));
    reconnect.set_missed_tick_behavior(MissedTickBehavior::Skip);
    reconnect.tick().await;
    let mut persist_runtime = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    persist_runtime.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let ipc_task = tokio::spawn(ipc.run());
    tokio::pin!(ipc_task);
    let external_api_task = tokio::spawn(external_api.run());
    tokio::pin!(external_api_task);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                break;
            },
            _ = reconnect.tick() => {
                if let Err(error) = storm.start(None).await {
                    tracing::warn!(%error, "peer reconnection pass failed");
                }
            }
            _ = persist_runtime.tick() => {
                let peers = storm.peers().await;
                if let Err(error) = store.update_runtime(&peers).await {
                    tracing::warn!(%error, "failed to persist current peer state");
                }
            }
            result = &mut ipc_task => {
                result??;
                return Err("operator IPC listener stopped unexpectedly".into());
            }
            result = &mut external_api_task => {
                result??;
                return Err("external API listener stopped unexpectedly".into());
            }
        }
    }
    ipc_task.abort();
    let _ = ipc_task.await;
    external_api_task.abort();
    let _ = external_api_task.await;
    let peers = storm.peers().await;
    tracing::info!(
        peer_count = peers.len(),
        "saving network state before shutdown"
    );
    store.save(&peers, storm.coordinator_public_key()).await?;
    storm.shutdown().await;
    tracing::info!("high-storm stopped");
    Ok(())
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler should install");
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.expect("Ctrl-C handler should remain available");
        }
        _ = terminate.recv() => {}
    }
}
