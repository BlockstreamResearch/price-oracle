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

const LIQUID_BLOCK_FINALIZATION_TIME: Duration = Duration::from_secs(60);
const MAX_LIQUID_TRANSACTION_WEIGHT: u64 = 400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockRoundSchedule {
    storm_eye_count: usize,
    coordinator_rounds: usize,
    leader_rounds: usize,
}

impl BlockRoundSchedule {
    fn new(storm_eye_count: usize) -> Option<Self> {
        let coordinator_rounds = storm_eye_count / 2;
        let leader_rounds = storm_eye_count - coordinator_rounds;
        (storm_eye_count > 0).then_some(Self {
            storm_eye_count,
            coordinator_rounds,
            leader_rounds,
        })
    }

    fn issuance_offset(self, lane: usize) -> Option<Duration> {
        (lane < self.coordinator_rounds).then(|| {
            let interval =
                LIQUID_BLOCK_FINALIZATION_TIME.as_secs() / self.coordinator_rounds as u64;
            Duration::from_secs(interval * lane as u64)
        })
    }

    fn burning_offset(self, lane: usize) -> Option<Duration> {
        (lane < self.leader_rounds).then(|| {
            let interval =
                LIQUID_BLOCK_FINALIZATION_TIME.as_secs() / (self.leader_rounds + 1) as u64;
            Duration::from_secs(interval * (lane + 1) as u64)
        })
    }

    fn max_transaction_weight(self) -> u64 {
        MAX_LIQUID_TRANSACTION_WEIGHT / self.storm_eye_count as u64
    }
}

fn idle_round_deadline() -> Instant {
    Instant::now() + Duration::from_secs(365 * 24 * 60 * 60)
}

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

    if let Some(storm_eye) = storm
        .initialize_storm_eye(&config.service.elements_rpc)
        .await?
    {
        tracing::info!(
            asset_id = %hex::encode(storm_eye.asset_id),
            issuance_txid = %hex::encode(storm_eye.issuance_txid),
            "Storm Eye asset is initialized"
        );
    }

    if let Some(tick_asset) = storm
        .initialize_tick_asset(&config.service.elements_rpc)
        .await?
    {
        tracing::info!(
            asset_id = %hex::encode(tick_asset.asset_id),
            reissuance_token_id = %tick_asset.reissuance_token_id.map(hex::encode).unwrap_or_default(),
            issuance_txid = %hex::encode(tick_asset.issuance_txid),
            "Tick asset is initialized"
        );
    }

    let external_api = ExternalApiServer::bind(
        config.service.external_api_address,
        storm.handle(),
        &database,
        &config.service.elements_rpc,
        &config.service.protocol,
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

    let mut index_blocks = tokio::time::interval(Duration::from_secs(10));
    index_blocks.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut persist_runtime = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    persist_runtime.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut round_schedule = None;
    let mut round_started_at = Instant::now();
    let mut issuance_lane = 0usize;
    let mut burning_lane = 0usize;
    let issuance_round = tokio::time::sleep_until(idle_round_deadline());
    tokio::pin!(issuance_round);
    let burning_round = tokio::time::sleep_until(idle_round_deadline());
    tokio::pin!(burning_round);

    let mut reconcile_requests = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(10),
        Duration::from_secs(10),
    );
    reconcile_requests.set_missed_tick_behavior(MissedTickBehavior::Skip);

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
                if !storm.is_local_member().await {
                    tracing::info!("local signer was removed from the network; shutting down");
                    break;
                }

                if let Err(error) = storm.start(None).await {
                    tracing::warn!(%error, "peer reconnection pass failed");
                }

                if storm.is_coordinator().await
                    && let Err(error) = storm.announce_network_assets().await {
                        tracing::warn!(%error, "network asset announcement pass failed");
                }
            }
            _ = index_blocks.tick() => {
                let indexed = storm.index_blocks().await;
                match &indexed {
                    Ok(0) => {}
                    Ok(block_count) => {
                        tracing::info!(block_count, "indexed confirmed blocks");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to index confirmed blocks");
                    }
                }
                if indexed.as_ref().is_ok_and(|block_count| *block_count > 0) {
                    match storm.storm_eye_utxo_count().await {
                        Ok(storm_eye_count) => {
                            round_schedule = BlockRoundSchedule::new(storm_eye_count);
                            round_started_at = Instant::now();
                            issuance_lane = 0;
                            burning_lane = 0;
                            issuance_round.as_mut().reset(
                                round_schedule
                                    .and_then(|schedule| schedule.issuance_offset(0))
                                    .map_or_else(idle_round_deadline, |offset| round_started_at + offset),
                            );
                            burning_round.as_mut().reset(
                                round_schedule
                                    .and_then(|schedule| schedule.burning_offset(0))
                                    .map_or_else(idle_round_deadline, |offset| round_started_at + offset),
                            );
                            if let Some(schedule) = round_schedule {
                                tracing::debug!(
                                    storm_eye_count,
                                    coordinator_rounds = schedule.coordinator_rounds,
                                    leader_rounds = schedule.leader_rounds,
                                    max_transaction_weight = schedule.max_transaction_weight(),
                                    "scheduled Storm Eye rounds for indexed Liquid block"
                                );
                            }
                        }
                        Err(error) => {
                            round_schedule = None;
                            issuance_round.as_mut().reset(idle_round_deadline());
                            burning_round.as_mut().reset(idle_round_deadline());
                            tracing::warn!(%error, "failed to schedule Storm Eye rounds");
                        }
                    }
                }
                if indexed.as_ref().is_ok_and(|block_count| *block_count > 0) {
                    match storm.process_droplet_exchange_request().await {
                        Ok(Some(txid)) => {
                            tracing::info!(txid = %hex::encode(txid), "broadcast queued Droplets exchange");
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::warn!(%error, "queued Droplets exchange failed");
                        }
                    }
                }
            }
            _ = persist_runtime.tick() => {
                let peers = storm.peers().await;
                if let Err(error) = store.update_runtime(&peers).await {
                    tracing::warn!(%error, "failed to persist current peer state");
                }
            }
            _ = &mut issuance_round => {
                let Some(schedule) = round_schedule else {
                    issuance_round.as_mut().reset(idle_round_deadline());
                    continue;
                };
                let lane = issuance_lane;
                issuance_lane += 1;
                issuance_round.as_mut().reset(
                    schedule
                        .issuance_offset(issuance_lane)
                        .map_or_else(idle_round_deadline, |offset| round_started_at + offset),
                );
                match storm
                    .process_user_requests(lane, schedule.max_transaction_weight() as usize)
                    .await
                {
                    Ok(0) => {}
                    Ok(request_count) => {
                        tracing::info!(request_count, lane, "broadcast Tick issuance transaction");
                    }
                    Err(error) => {
                        tracing::warn!(%error, lane, "user request issuance round failed");
                    }
                }
            }
            _ = &mut burning_round => {
                let Some(schedule) = round_schedule else {
                    burning_round.as_mut().reset(idle_round_deadline());
                    continue;
                };
                let lane = burning_lane;
                burning_lane += 1;
                burning_round.as_mut().reset(
                    schedule
                        .burning_offset(burning_lane)
                        .map_or_else(idle_round_deadline, |offset| round_started_at + offset),
                );
                match storm
                    .burn_expired_utxos(lane, schedule.max_transaction_weight() as usize)
                    .await
                {
                    Ok(0) => {}
                    Ok(utxo_count) => {
                        tracing::info!(utxo_count, lane, "broadcast expired Tick burn transaction");
                    }
                    Err(error) => {
                        tracing::warn!(%error, lane, "expired Tick burning round failed");
                    }
                }
            }
            _ = reconcile_requests.tick() => {
                if let Err(error) = storm.synchronize_voting_requests().await {
                    tracing::warn!(%error, "failed to synchronize voting requests");
                }
                match storm.reconcile_voting_executions().await {
                    Ok(0) => {}
                    Ok(request_count) => {
                        tracing::info!(request_count, "confirmed executed voting requests");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to reconcile voting execution confirmations");
                    }
                }
                match storm.reconcile_user_requests().await {
                    Ok(0) => {}
                    Ok(request_count) => {
                        tracing::info!(request_count, "confirmed executed user requests");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "failed to reconcile user request confirmations");
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_six_storm_eyes_across_one_liquid_block() {
        let schedule = BlockRoundSchedule::new(6).unwrap();

        assert_eq!(schedule.coordinator_rounds, 3);
        assert_eq!(schedule.leader_rounds, 3);
        assert_eq!(schedule.issuance_offset(0), Some(Duration::from_secs(0)));
        assert_eq!(schedule.issuance_offset(1), Some(Duration::from_secs(20)));
        assert_eq!(schedule.issuance_offset(2), Some(Duration::from_secs(40)));
        assert_eq!(schedule.issuance_offset(3), None);
        assert_eq!(schedule.burning_offset(0), Some(Duration::from_secs(15)));
        assert_eq!(schedule.burning_offset(1), Some(Duration::from_secs(30)));
        assert_eq!(schedule.burning_offset(2), Some(Duration::from_secs(45)));
        assert_eq!(schedule.burning_offset(3), None);
        assert_eq!(schedule.max_transaction_weight(), 66_666);
    }

    #[test]
    fn recalculates_rounds_when_storm_eye_count_changes() {
        let schedule = BlockRoundSchedule::new(8).unwrap();

        assert_eq!(schedule.coordinator_rounds, 4);
        assert_eq!(schedule.leader_rounds, 4);
        assert_eq!(schedule.issuance_offset(3), Some(Duration::from_secs(45)));
        assert_eq!(schedule.burning_offset(3), Some(Duration::from_secs(48)));
        assert_eq!(schedule.max_transaction_weight(), 50_000);
    }

    #[test]
    fn assigns_an_odd_storm_eye_remainder_to_leader_rounds() {
        let schedule = BlockRoundSchedule::new(7).unwrap();

        assert_eq!(schedule.coordinator_rounds, 3);
        assert_eq!(schedule.leader_rounds, 4);
        assert_eq!(schedule.issuance_offset(2), Some(Duration::from_secs(40)));
        assert_eq!(schedule.burning_offset(3), Some(Duration::from_secs(48)));
        assert_eq!(schedule.max_transaction_weight(), 57_142);
    }
}
