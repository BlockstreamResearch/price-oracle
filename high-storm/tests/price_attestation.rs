mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use high_storm::{
    HighStorm, PriceAttestation, initialize_host, initialize_join, start_initialized,
};
use price_feed::{FeedId, SourceObservation};
use secp256k1::{PublicKey, SecretKey};
use storm::PeerStatus;
use tokio::time::timeout;

use common::TestNode;

const LBTC_USD: FeedId = 0;
const USDT_USD: FeedId = 1;
const LBTC_USDT: FeedId = 4;
static PRICE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestNetwork {
    _test_guard: tokio::sync::MutexGuard<'static, ()>,
    definitions: [TestNode; 3],
    nodes: [HighStorm; 3],
}

impl TestNetwork {
    async fn start() -> Self {
        let test_guard = PRICE_TEST_LOCK.lock().await;
        let first = TestNode::new(31).await;
        let second = TestNode::new(32).await;
        let third = TestNode::new(33).await;

        let host_config = first.config.clone();
        let host_store = first.store.clone();
        let members = vec![second.public_key.clone(), third.public_key.clone()];
        let host =
            tokio::spawn(async move { initialize_host(&host_config, &host_store, &members).await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        let host_address = first.address();
        let (second_node, third_node) = tokio::join!(
            initialize_join(
                &second.config,
                &second.store,
                &first.public_key,
                &host_address,
            ),
            initialize_join(
                &third.config,
                &third.store,
                &first.public_key,
                &host_address,
            ),
        );

        let nodes = [
            timeout(Duration::from_secs(5), host)
                .await
                .expect("host initialization timed out")
                .expect("host task failed")
                .expect("host initialization failed"),
            second_node.expect("second node initialization failed"),
            third_node.expect("third node initialization failed"),
        ];

        wait_for_all_connections(&nodes).await;

        Self {
            _test_guard: test_guard,
            definitions: [first, second, third],
            nodes,
        }
    }

    async fn shutdown(&mut self) {
        for node in &mut self.nodes {
            node.shutdown().await;
        }
    }

    /// Stops the first node and starts it again from its store, a round later.
    async fn restart_first(&mut self) {
        self.nodes[0].shutdown().await;
        wait_for_peer_status(&self.nodes[1], xonly_key(31), PeerStatus::Inactive).await;
        self.nodes[0] = start_initialized(&self.definitions[0].config, &self.definitions[0].store)
            .await
            .unwrap();
        self.nodes[0].start(None).await.unwrap();
        wait_for_all_connections(&self.nodes).await;
        next_round().await;
    }
}

#[tokio::test]
async fn attests_a_price_every_peer_accepts() {
    let mut network = TestNetwork::start().await;
    observe(&network.nodes[0], 100).await;

    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);

    // Its own attestation is stored alongside the peers' copies.
    for node in &network.nodes {
        let held = wait_for_attestation(node).await;
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].public_key, xonly_key(31));
        assert_eq!(held[0].feed.feed_id, LBTC_USD);
        assert_eq!(held[0].feed.price, 100);
    }

    network.shutdown().await;
}

#[tokio::test]
async fn keeps_one_attestation_per_node_across_rounds() {
    let mut network = TestNetwork::start().await;

    observe(&network.nodes[0], 100).await;
    network.nodes[0].attest_prices().await.unwrap();
    wait_for_attestation(&network.nodes[1]).await;

    next_round().await;
    observe(&network.nodes[0], 400).await;
    network.nodes[0].attest_prices().await.unwrap();

    // The second round replaces the first rather than accumulating.
    let held = wait_for_price(&network.nodes[1], LBTC_USD, 400).await;
    assert_eq!(held.len(), 1);

    network.shutdown().await;
}

#[tokio::test]
async fn does_not_reattest_an_unchanged_price() {
    let mut network = TestNetwork::start().await;

    observe(&network.nodes[0], 100).await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);
    wait_for_attestation(&network.nodes[1]).await;

    // A round carries only the feeds that produced a new observation, so a
    // round with none broadcasts nothing.
    next_round().await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 0);

    network.shutdown().await;
}

#[tokio::test]
async fn two_nodes_attesting_the_same_feed_are_held_separately() {
    let mut network = TestNetwork::start().await;

    observe(&network.nodes[0], 100).await;
    observe(&network.nodes[1], 300).await;
    network.nodes[0].attest_prices().await.unwrap();
    network.nodes[1].attest_prices().await.unwrap();

    let held = timeout(Duration::from_secs(5), async {
        loop {
            let held = attestations(&network.nodes[2]).await;
            if held.len() == 2 {
                return held;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both attestations did not arrive");

    let mut prices: Vec<u64> = held.iter().map(|held| held.feed.price).collect();
    prices.sort_unstable();
    assert_eq!(prices, [100, 300]);

    network.shutdown().await;
}

#[tokio::test]
async fn does_not_reattest_the_same_observation_after_restart() {
    let mut network = TestNetwork::start().await;
    let observation = observation(100);

    network.nodes[0]
        .handle()
        .record_price_observation(LBTC_USD, 0, observation)
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);
    wait_for_attestation(&network.nodes[1]).await;

    network.restart_first().await;

    // The observation it already attested is not attested again.
    network.nodes[0]
        .handle()
        .record_price_observation(LBTC_USD, 0, observation)
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 0);

    // A strictly newer one is what releases it.
    network.nodes[0]
        .handle()
        .record_price_observation(LBTC_USD, 0, observation_at(400, now() + 1))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);

    network.shutdown().await;
}

#[tokio::test]
async fn attests_a_cross_pair_once_both_its_legs_are_observed() {
    let mut network = TestNetwork::start().await;
    let node = network.nodes[0].handle();

    // LBTC at $60,000 alone leaves LBTC/USDt unavailable.
    node.record_price_observation(LBTC_USD, 0, observation(6_000_000_000_000))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);

    node.record_price_observation(USDT_USD, 0, observation(80_000_000))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 2);
    let held = wait_for_feed(&network.nodes[1], LBTC_USDT).await;
    assert_eq!(held[0].public_key, xonly_key(31));
    assert_eq!(held[0].feed.price, 7_500_000_000_000);
    assert_eq!(held[0].feed.decimals, 8);

    // While neither leg moves, it is not recomputed or attested again.
    next_round().await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 0);

    network.shutdown().await;
}

#[tokio::test]
async fn does_not_reattest_a_cross_pair_rebuilt_after_restart() {
    let mut network = TestNetwork::start().await;
    let legs = [
        (LBTC_USD, observation(6_000_000_000_000)),
        (USDT_USD, observation(80_000_000)),
    ];

    for (feed, leg) in legs {
        let node = network.nodes[0].handle();
        node.record_price_observation(feed, 0, leg).await;
    }
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 3);
    wait_for_feed(&network.nodes[1], LBTC_USDT).await;

    network.restart_first().await;

    // The same legs rebuild the same pair, no newer than they are.
    for (feed, leg) in legs {
        let node = network.nodes[0].handle();
        node.record_price_observation(feed, 0, leg).await;
    }
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 0);

    // A newer leg releases the pair along with itself.
    network.nodes[0]
        .handle()
        .record_price_observation(USDT_USD, 0, observation_at(75_000_000, now() + 1))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 2);

    network.shutdown().await;
}

#[tokio::test]
async fn attests_a_cross_pair_whose_legs_change_within_one_second() {
    let mut network = TestNetwork::start().await;
    let node = network.nodes[0].handle();
    node.record_price_observation(LBTC_USD, 0, observation(6_000_000_000_000))
        .await;
    node.record_price_observation(USDT_USD, 0, observation(80_000_000))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 3);

    // Both legs move within a second, and each attests on its own.
    let at = now() + 1;
    node.record_price_observation(LBTC_USD, 0, observation_at(6_400_000_000_000, at))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 2);
    node.record_price_observation(USDT_USD, 0, observation_at(100_000_000, at))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 2);

    // Peers replace the pair priced from one new leg with the one from both.
    let held = wait_for_price(&network.nodes[1], LBTC_USDT, 6_400_000_000_000).await;
    assert_eq!(held[0].feed.received_at, at + 1);

    network.shutdown().await;
}

#[tokio::test]
async fn attests_a_feed_whose_second_source_reports_in_the_same_second() {
    let mut network = TestNetwork::start().await;
    let node = network.nodes[0].handle();
    let at = now() + 1;

    node.record_price_observation(LBTC_USD, 0, observation_at(100, at))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);

    // A feed is stamped from its earliest observation, so a second source
    // reporting in the same second moves the median but not the stamp.
    node.record_price_observation(LBTC_USD, 1, observation_at(300, at))
        .await;
    assert_eq!(network.nodes[0].attest_prices().await.unwrap(), 1);

    let held = wait_for_price(&network.nodes[1], LBTC_USD, 200).await;
    assert_eq!(held[0].feed.received_at, at + 1);

    network.shutdown().await;
}

/// A node attests once per `POLLING_INTERVAL`, so consecutive rounds never
/// share a `received_at`. One second is enough to reproduce that here.
async fn next_round() {
    tokio::time::sleep(Duration::from_millis(1_100)).await;
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn observation(price: u64) -> SourceObservation {
    observation_at(price, now())
}

fn observation_at(price: u64, at: u64) -> SourceObservation {
    SourceObservation::new(price, 8, at, at)
}

async fn observe(node: &HighStorm, price: u64) {
    node.handle()
        .record_price_observation(LBTC_USD, 0, observation(price))
        .await
}

async fn attestations(node: &HighStorm) -> Vec<PriceAttestation> {
    node.handle().price_attestations(LBTC_USD).await.unwrap()
}

fn xonly_key(key_byte: u8) -> [u8; 32] {
    let secret = SecretKey::from_secret_bytes([key_byte; 32]).unwrap();
    PublicKey::from_secret_key(&secret)
        .x_only_public_key()
        .0
        .serialize()
}

async fn wait_for_attestation(node: &HighStorm) -> Vec<PriceAttestation> {
    wait_for_feed(node, LBTC_USD).await
}

async fn wait_for_feed(node: &HighStorm, feed: FeedId) -> Vec<PriceAttestation> {
    timeout(Duration::from_secs(5), async {
        loop {
            let held = node.handle().price_attestations(feed).await.unwrap();
            if !held.is_empty() {
                return held;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("attestation did not propagate")
}

async fn wait_for_price(node: &HighStorm, feed: FeedId, price: u64) -> Vec<PriceAttestation> {
    timeout(Duration::from_secs(5), async {
        loop {
            let held = node.handle().price_attestations(feed).await.unwrap();
            if held.iter().any(|held| held.feed.price == price) {
                return held;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("updated attestation did not propagate")
}

async fn wait_for_peer_status(node: &HighStorm, peer: [u8; 32], status: PeerStatus) {
    timeout(Duration::from_secs(5), async {
        loop {
            let matches = node.peers().await.iter().any(|candidate| {
                PublicKey::from_slice(&candidate.compressed_public_key)
                    .unwrap()
                    .x_only_public_key()
                    .0
                    .serialize()
                    == peer
                    && candidate.status == status
            });
            if matches {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer status did not change");
}

async fn wait_for_all_connections(nodes: &[HighStorm; 3]) {
    timeout(Duration::from_secs(5), async {
        loop {
            let mut connected = true;
            for node in nodes {
                connected &= node
                    .peers()
                    .await
                    .iter()
                    .all(|peer| peer.status != PeerStatus::Inactive);
            }
            if connected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("nodes did not connect");
}
