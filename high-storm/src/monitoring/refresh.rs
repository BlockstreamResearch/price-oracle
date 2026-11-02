use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use metrics::{gauge, histogram};
use storm::{Peer, PeerStatus};
use storm_tree::StormTree;
use tokio::time::{Instant, MissedTickBehavior};

use super::{flag, names, record_build_info};
use crate::{HighStormHandle, db::Database};

const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const DATABASE_PING_TIMEOUT: Duration = Duration::from_secs(2);

/// An arm of the main loop's `select!`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopTask {
    Reconnect,
    IndexBlocks,
    PersistRuntime,
    IssuanceRound,
    BurningRound,
    ReconcileRequests,
    PriceAttestation,
}

impl LoopTask {
    const ALL: [Self; 7] = [
        Self::Reconnect,
        Self::IndexBlocks,
        Self::PersistRuntime,
        Self::IssuanceRound,
        Self::BurningRound,
        Self::ReconcileRequests,
        Self::PriceAttestation,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Reconnect => "reconnect",
            Self::IndexBlocks => "index_blocks",
            Self::PersistRuntime => "persist_runtime",
            Self::IssuanceRound => "issuance_round",
            Self::BurningRound => "burning_round",
            Self::ReconcileRequests => "reconcile_requests",
            Self::PriceAttestation => "price_attestation",
        }
    }
}

/// When each arm last started, in Unix seconds; 0 until it first runs. They are
/// published by the refresh task rather than the loop, so a stuck loop keeps
/// reporting its old stamp instead of dropping out as an idle gauge.
static LOOP_TICKS: [AtomicU64; LoopTask::ALL.len()] =
    [const { AtomicU64::new(0) }; LoopTask::ALL.len()];

pub fn record_loop_tick(task: LoopTask) {
    LOOP_TICKS[task as usize].store(unix_now(), Ordering::Relaxed);
}

/// Gauges set where something happens rather than read by this task. Their
/// last values are republished on every refresh, so they never go idle.
static RETAINED: Mutex<BTreeMap<&'static str, f64>> = Mutex::new(BTreeMap::new());

pub(super) fn set_retained(name: &'static str, value: f64) {
    gauge!(name).set(value);
    RETAINED
        .lock()
        .expect("retained gauges lock poisoned")
        .insert(name, value);
}

fn record_retained() {
    let retained = RETAINED.lock().expect("retained gauges lock poisoned");
    for (&name, &value) in retained.iter() {
        gauge!(name).set(value);
    }
}

/// Republishes the node's gauges until the process exits.
pub fn spawn_refresh(node: HighStormHandle, database: Database) {
    tokio::spawn(async move {
        let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            refresh.tick().await;
            record_build_info();
            record_loop_ticks();
            record_retained();
            record_node(&NodeSnapshot::read(&node).await);
            super::prices::record_prices(&node).await;
            record_database(&database).await;
        }
    });
}

fn record_loop_ticks() {
    for task in LoopTask::ALL {
        let tick = LOOP_TICKS[task as usize].load(Ordering::Relaxed);
        if tick > 0 {
            gauge!(names::LOOP_LAST_TICK, "task" => task.as_str()).set(tick as f64);
        }
    }
}

struct NodeSnapshot {
    peers: Vec<Peer>,
    connected: BTreeSet<[u8; 33]>,
    coordinator: [u8; 33],
    is_member: bool,
    is_leader: bool,
    block_height: u64,
    is_recovering: bool,
    is_spending_paused: bool,
}

impl NodeSnapshot {
    async fn read(node: &HighStormHandle) -> Self {
        Self {
            peers: node.peers().await,
            connected: node.connected_peer_keys().await,
            coordinator: node.coordinator_public_key(),
            is_member: node.is_local_member().await,
            is_leader: node.is_leader().await,
            block_height: node.block_height(),
            is_recovering: node.is_recovering(),
            is_spending_paused: node.is_spending_paused(),
        }
    }

    /// Whether signing can use this member now: the same rule it applies when
    /// it picks a Storm Tree branch.
    fn can_sign(&self, peer: &Peer) -> bool {
        peer.status == PeerStatus::Controlled
            || (peer.status == PeerStatus::Active
                && self.connected.contains(&peer.compressed_public_key))
    }
}

fn record_node(node: &NodeSnapshot) {
    let local = node
        .peers
        .iter()
        .find(|peer| peer.status == PeerStatus::Controlled)
        .map(|peer| peer.compressed_public_key);
    let members = node.peers.len();
    let signers = node.peers.iter().filter(|peer| node.can_sign(peer)).count();
    let coordinator_connected = node
        .peers
        .iter()
        .any(|peer| peer.compressed_public_key == node.coordinator && node.can_sign(peer));

    gauge!(names::IS_MEMBER).set(flag(node.is_member));
    gauge!(names::IS_COORDINATOR).set(flag(local == Some(node.coordinator)));
    gauge!(names::IS_LEADER).set(flag(node.is_leader));
    gauge!(names::BLOCK_HEIGHT).set(node.block_height as f64);
    gauge!(names::MEMBERS_TOTAL).set(members as f64);
    gauge!(names::SIGNING_THRESHOLD).set(StormTree::minimum_threshold(members) as f64);
    gauge!(names::CONNECTED_MEMBERS).set(signers as f64);
    gauge!(names::COORDINATOR_CONNECTED).set(flag(coordinator_connected));
    gauge!(names::CHAIN_RECOVERING).set(flag(node.is_recovering));
    gauge!(names::SPENDING_PAUSED).set(flag(node.is_spending_paused));

    for peer in node
        .peers
        .iter()
        .filter(|peer| peer.status != PeerStatus::Controlled)
    {
        let label = hex::encode(peer.compressed_public_key);
        if let Some(last_seen) = peer.last_seen {
            gauge!(names::PEER_LAST_SEEN, "peer" => label.clone()).set(last_seen as f64);
        }
        gauge!(names::PEER_CONNECTED, "peer" => label).set(flag(node.can_sign(peer)));
    }
}

async fn record_database(database: &Database) {
    let started = Instant::now();
    let reachable = matches!(
        tokio::time::timeout(DATABASE_PING_TIMEOUT, database.ping()).await,
        Ok(Ok(()))
    );
    if reachable {
        histogram!(names::DB_PING_DURATION).record(started.elapsed().as_secs_f64());
    }
    gauge!(names::DB_UP).set(flag(reachable));

    let pool = database.pool_connections();
    gauge!(names::DB_POOL_CONNECTIONS, "state" => "idle").set(pool.idle as f64);
    gauge!(names::DB_POOL_CONNECTIONS, "state" => "used").set(pool.used as f64);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use metrics_exporter_prometheus::PrometheusRecorder;

    use super::*;
    use crate::monitoring::builder;

    fn recorder() -> PrometheusRecorder {
        builder().unwrap().build_recorder()
    }

    fn peer(byte: u8, status: PeerStatus) -> Peer {
        let mut peer = Peer::new([byte; 33]);
        peer.status = status;
        peer
    }

    fn label(byte: u8) -> String {
        hex::encode([byte; 33])
    }

    #[test]
    fn indexes_every_task_by_its_position() {
        for (index, task) in LoopTask::ALL.into_iter().enumerate() {
            assert_eq!(task as usize, index);
        }
    }

    #[test]
    fn publishes_only_the_tasks_that_ran() {
        let recorder = recorder();
        record_loop_tick(LoopTask::IndexBlocks);

        metrics::with_local_recorder(&recorder, record_loop_ticks);

        let rendered = recorder.handle().render();
        assert!(
            rendered.contains("high_storm_loop_last_tick_timestamp_seconds{task=\"index_blocks\"}")
        );
        assert!(!rendered.contains("task=\"burning_round\""));
    }

    #[test]
    fn republishes_retained_gauges_from_memory() {
        let first = recorder();
        metrics::with_local_recorder(&first, || {
            set_retained("high_storm_test_retained", 7.0);
        });
        let second = recorder();

        metrics::with_local_recorder(&second, record_retained);

        assert!(
            second
                .handle()
                .render()
                .contains("high_storm_test_retained 7")
        );
    }

    #[test]
    fn counts_the_members_signing_can_use() {
        let mut seen = peer(2, PeerStatus::Active);
        seen.last_seen = Some(1_700_000_000);
        let snapshot = NodeSnapshot {
            peers: vec![
                peer(1, PeerStatus::Controlled),
                seen,
                peer(3, PeerStatus::Active),
                // A connection alone is not enough while the peer is inactive.
                peer(4, PeerStatus::Inactive),
            ],
            connected: BTreeSet::from([[2; 33], [4; 33]]),
            coordinator: [3; 33],
            is_member: true,
            is_leader: false,
            block_height: 42,
            is_recovering: true,
            is_spending_paused: true,
        };
        let recorder = recorder();

        metrics::with_local_recorder(&recorder, || record_node(&snapshot));

        let rendered = recorder.handle().render();
        for line in [
            "high_storm_is_member 1".to_string(),
            "high_storm_is_coordinator 0".to_string(),
            "high_storm_is_leader 0".to_string(),
            "high_storm_block_height 42".to_string(),
            "high_storm_members_total 4".to_string(),
            "high_storm_signing_threshold 3".to_string(),
            "high_storm_connected_members 2".to_string(),
            "high_storm_coordinator_connected 0".to_string(),
            "high_storm_chain_recovering 1".to_string(),
            "high_storm_spending_paused 1".to_string(),
            format!("storm_peer_connected{{peer=\"{}\"}} 1", label(2)),
            format!("storm_peer_connected{{peer=\"{}\"}} 0", label(3)),
            format!("storm_peer_connected{{peer=\"{}\"}} 0", label(4)),
            format!(
                "storm_peer_last_seen_timestamp_seconds{{peer=\"{}\"}} 1700000000",
                label(2)
            ),
        ] {
            assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
        }
        assert!(
            !rendered.contains(&label(1)),
            "the local node is not a peer"
        );
    }

    #[test]
    fn reports_a_connected_coordinator() {
        let snapshot = NodeSnapshot {
            peers: vec![peer(1, PeerStatus::Controlled), peer(2, PeerStatus::Active)],
            connected: BTreeSet::from([[2; 33]]),
            coordinator: [2; 33],
            is_member: true,
            is_leader: true,
            block_height: 0,
            is_recovering: false,
            is_spending_paused: false,
        };
        let recorder = recorder();

        metrics::with_local_recorder(&recorder, || record_node(&snapshot));

        assert!(
            recorder
                .handle()
                .render()
                .contains("high_storm_coordinator_connected 1")
        );
    }

    #[tokio::test]
    async fn reports_a_reachable_database() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let recorder = recorder();

        {
            let _local = metrics::set_default_local_recorder(&recorder);
            record_database(&database).await;
        }

        let rendered = recorder.handle().render();
        assert!(rendered.contains("high_storm_db_up 1"));
        assert!(rendered.contains("high_storm_db_ping_duration_seconds_count 1"));
        // The probe's connection returns to the pool in the background, so it
        // may still count as used; either way the pool holds that one connection.
        let connections = |state: &str| -> f64 {
            let prefix = format!("high_storm_db_pool_connections{{state=\"{state}\"}} ");
            rendered
                .lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .expect("pool connections are reported by state")
                .parse()
                .unwrap()
        };
        assert_eq!(connections("idle") + connections("used"), 1.0);
    }
}
