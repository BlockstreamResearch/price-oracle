use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
    time::Duration,
};

use metrics::{counter, gauge, histogram};
use price_feed::{
    ConnectionError, FeedDefinition, FeedId, FeedKind, FeedRegistry, PriceFeedData,
    RejectionReason, SourceObservation, SourceState, cross,
};
use storm::{Peer, PeerStatus};

use super::{flag, names, refresh::unix_now};
use crate::{
    HighStormHandle,
    high_storm::{PollOutcome, PriceAttestation, PriceHealth, SourceHealth},
};

/// A poller `sources::spawn` started for one feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolledSource {
    feed: FeedId,
    source: usize,
    name: &'static str,
}

static POLLED: Mutex<Vec<PolledSource>> = Mutex::new(Vec::new());

/// The last change each source observed, in basis points. A source observes at
/// most once a minute, so the refresh republishes these.
static CHANGES: Mutex<BTreeMap<(FeedId, &'static str), u64>> = Mutex::new(BTreeMap::new());

/// Price gauges cover only the feeds registered here and the Cross pairs they
/// price, so a feed no source quotes never reads as down.
pub fn register_price_source(feed: FeedId, source: usize, name: &'static str) {
    let polled = PolledSource { feed, source, name };
    let mut registered = POLLED.lock().expect("polled price sources lock poisoned");
    if !registered.contains(&polled) {
        registered.push(polled);
    }
}

pub(super) async fn record_prices(node: &HighStormHandle) {
    let polled = POLLED
        .lock()
        .expect("polled price sources lock poisoned")
        .clone();
    if polled.is_empty() {
        return;
    }
    let feeds = priced_feeds(&FeedRegistry::default(), &polled);
    let sources = polled
        .iter()
        .map(|polled| (polled.feed, polled.source))
        .collect::<Vec<_>>();
    let ids = feeds
        .iter()
        .map(|definition| definition.id)
        .collect::<Vec<_>>();
    let health = node.price_health(&sources, &ids).await;
    record_price_health(&feeds, &polled, &health);
    record_price_changes();
}

pub(crate) fn record_price_poll(feed: FeedId, source: &'static str, outcome: PollOutcome) {
    counter!(
        names::PRICE_POLLS,
        "feed" => feed_symbol(feed),
        "source" => source,
        "outcome" => outcome.as_str(),
    )
    .increment(1);
}

pub(crate) fn record_price_poll_duration(source: &'static str, took: Duration) {
    histogram!(names::PRICE_POLL_DURATION, "source" => source).record(took.as_secs_f64());
}

/// The source could not be reached or read.
pub(crate) fn record_price_poll_error(source: &'static str, error: ConnectionError) {
    record_price_poll_failure(
        source,
        match error {
            ConnectionError::RequestFailure => "request_failure",
            ConnectionError::MalformedResponse => "malformed",
            ConnectionError::RateLimited => "rate_limited",
            ConnectionError::Unauthorized => "unauthorized",
        },
    );
}

/// The source answered, but its observation failed validation.
pub(crate) fn record_price_poll_rejection(source: &'static str, reason: RejectionReason) {
    record_price_poll_failure(
        source,
        match reason {
            RejectionReason::InvalidPrice => "invalid_price",
            RejectionReason::Expired => "expired",
            RejectionReason::ClockSkewExceeded => "clock_skew",
            RejectionReason::StaleObservation => "stale",
        },
    );
}

fn record_price_poll_failure(source: &'static str, reason: &'static str) {
    counter!(names::PRICE_POLL_FAILURES, "source" => source, "reason" => reason).increment(1);
}

/// Between two observations of the same source; skipped when they are not
/// quoted at the same decimals or the previous price is 0.
pub(crate) fn record_price_change(
    feed: FeedId,
    source: &'static str,
    previous: &SourceObservation,
    current: &SourceObservation,
) {
    let Some(change) = change_bps(previous, current) else {
        return;
    };
    CHANGES
        .lock()
        .expect("price changes lock poisoned")
        .insert((feed, source), change);
    set_price_change(feed, source, change);
}

fn record_price_changes() {
    let changes = CHANGES.lock().expect("price changes lock poisoned").clone();
    for ((feed, source), change) in changes {
        set_price_change(feed, source, change);
    }
}

fn set_price_change(feed: FeedId, source: &'static str, change: u64) {
    gauge!(names::PRICE_CHANGE, "feed" => feed_symbol(feed), "source" => source).set(change as f64);
}

fn change_bps(previous: &SourceObservation, current: &SourceObservation) -> Option<u64> {
    if previous.decimals != current.decimals {
        return None;
    }
    difference_bps(previous.price, current.price)
}

/// How far `other` is from `reference`, in basis points of `reference`.
fn difference_bps(reference: u64, other: u64) -> Option<u64> {
    if reference == 0 {
        return None;
    }
    let difference = u128::from(reference.abs_diff(other)) * 10_000 / u128::from(reference);
    Some(u64::try_from(difference).unwrap_or(u64::MAX))
}

pub(crate) fn record_price_attestation_rejected(peer: [u8; 33], reason: &'static str) {
    counter!(
        names::PRICE_ATTESTATIONS_REJECTED,
        "peer" => hex::encode(peer),
        "reason" => reason,
    )
    .increment(1);
}

/// Read from the latest attestation each member stored per feed, so a peer
/// that stops attesting keeps its last timestamp instead of dropping out, and
/// a removed member drops out.
pub(super) async fn record_peer_attestations(node: &HighStormHandle) {
    let members = remote_members(&node.peers().await);
    let registry = FeedRegistry::default();
    let ids = registry
        .feeds()
        .map(|definition| definition.id)
        .collect::<Vec<_>>();
    let own = node.price_health(&[], &ids).await.values;
    let now = unix_now();
    for definition in registry.feeds() {
        let attestations = match node.price_attestations(definition.id).await {
            Ok(attestations) => attestations,
            Err(error) => {
                super::health::record_task_error(super::health::MonitoringTask::DbGauges);
                tracing::debug!(%error, "could not read peer price attestations");
                return;
            }
        };
        let own = own
            .iter()
            .find(|(feed, _)| *feed == definition.id)
            .and_then(|(_, value)| *value);
        record_feed_attestations(&feed_label(definition), &members, &attestations, own, now);
    }
}

/// Remote members by their x-only key, mapped to the transport key the `peer`
/// label shows.
fn remote_members(peers: &[Peer]) -> BTreeMap<[u8; 32], [u8; 33]> {
    peers
        .iter()
        .filter(|peer| peer.status != PeerStatus::Controlled)
        .filter_map(|peer| {
            let key = secp256k1::PublicKey::from_slice(&peer.compressed_public_key).ok()?;
            Some((
                key.x_only_public_key().0.serialize(),
                peer.compressed_public_key,
            ))
        })
        .collect()
}

/// The deviation is reported only while the peer's price is still valid and
/// this node has its own; otherwise it reads NaN, which no threshold matches,
/// rather than keeping a stale value until it goes idle.
fn record_feed_attestations(
    feed: &str,
    members: &BTreeMap<[u8; 32], [u8; 33]>,
    attestations: &[PriceAttestation],
    own: Option<PriceFeedData>,
    now: u64,
) {
    for attestation in attestations {
        let Some(peer) = members.get(&attestation.public_key) else {
            continue;
        };
        let peer = hex::encode(peer);
        gauge!(
            names::PRICE_PEER_ATTESTATION,
            "feed" => feed.to_owned(),
            "peer" => peer.clone(),
        )
        .set(attestation.feed.received_at as f64);
        let deviation = own
            .filter(|own| {
                own.decimals == attestation.feed.decimals && now <= attestation.feed.valid_until
            })
            .and_then(|own| difference_bps(own.price, attestation.feed.price));
        gauge!(names::PRICE_PEER_DEVIATION, "feed" => feed.to_owned(), "peer" => peer)
            .set(deviation.map_or(f64::NAN, |deviation| deviation as f64));
    }
}

/// Direct feeds a source is polled for, and the Cross pairs with a route made
/// only of those.
fn priced_feeds(registry: &FeedRegistry, polled: &[PolledSource]) -> Vec<FeedDefinition> {
    let direct = polled
        .iter()
        .map(|polled| polled.feed)
        .collect::<BTreeSet<_>>();
    registry
        .feeds()
        .filter(|definition| match definition.kind {
            FeedKind::Direct => direct.contains(&definition.id),
            FeedKind::Cross => cross::candidates(registry, definition).is_ok_and(|routes| {
                routes
                    .iter()
                    .any(|route| route.iter().all(|leg| direct.contains(&leg.feed)))
            }),
        })
        .copied()
        .collect()
}

fn record_price_health(feeds: &[FeedDefinition], polled: &[PolledSource], health: &PriceHealth) {
    let label = |feed: FeedId| {
        feeds
            .iter()
            .find(|definition| definition.id == feed)
            .map(feed_label)
    };

    for (feed, value) in &health.values {
        let Some(feed) = label(*feed) else {
            continue;
        };
        gauge!(names::PRICE_FEED_AVAILABLE, "feed" => feed.clone()).set(flag(value.is_some()));
        if let Some(value) = value {
            gauge!(names::PRICE_FEED_RECEIVED, "feed" => feed.clone())
                .set(value.received_at as f64);
            gauge!(names::PRICE_FEED_VALID_UNTIL, "feed" => feed).set(value.valid_until as f64);
        }
    }

    for definition in feeds
        .iter()
        .filter(|definition| definition.kind == FeedKind::Direct)
    {
        let active = health
            .sources
            .iter()
            .filter(|source| source.feed == definition.id && source.state == SourceState::Active)
            .count();
        gauge!(names::PRICE_FEED_ACTIVE_SOURCES, "feed" => feed_label(definition))
            .set(active as f64);
    }

    for source in &health.sources {
        let name = polled
            .iter()
            .find(|polled| polled.feed == source.feed && polled.source == source.source)
            .map(|polled| polled.name);
        if let (Some(feed), Some(name)) = (label(source.feed), name) {
            record_source(&feed, name, source);
        }
    }
}

fn record_source(feed: &str, name: &'static str, source: &SourceHealth) {
    for state in [
        SourceState::Active,
        SourceState::Dropped,
        SourceState::Frozen,
    ] {
        gauge!(
            names::PRICE_SOURCE_STATE,
            "feed" => feed.to_owned(),
            "source" => name,
            "state" => state_label(state),
        )
        .set(flag(source.state == state));
    }
    if let Some(observed_at) = source.observed_at {
        gauge!(
            names::PRICE_SOURCE_LAST_OBSERVED,
            "feed" => feed.to_owned(),
            "source" => name,
        )
        .set(observed_at as f64);
    }
}

fn feed_label(definition: &FeedDefinition) -> String {
    format!("{}/{}", definition.base.symbol(), definition.quote.symbol())
}

fn feed_symbol(feed: FeedId) -> String {
    FeedRegistry::default()
        .get(feed)
        .map_or_else(|| feed.to_string(), feed_label)
}

fn state_label(state: SourceState) -> &'static str {
    match state {
        SourceState::Active => "active",
        SourceState::Dropped => "dropped",
        SourceState::Frozen => "frozen",
    }
}

#[cfg(test)]
mod tests {
    use price_feed::PriceFeedData;

    use super::*;
    use crate::monitoring::builder;

    const LBTC_USD: FeedId = 0;
    const USDT_USD: FeedId = 1;
    const LBTC_USDT: FeedId = 4;
    const USDC_USD: FeedId = 7;

    fn coingecko(feed: FeedId) -> PolledSource {
        PolledSource {
            feed,
            source: 0,
            name: "coingecko",
        }
    }

    #[test]
    fn measures_a_change_only_between_comparable_prices() {
        let at = |price, decimals| SourceObservation::new(price, decimals, 0, 0);

        assert_eq!(change_bps(&at(10_000, 8), &at(8_900, 8)), Some(1_100));
        assert_eq!(change_bps(&at(10_000, 8), &at(10_000, 8)), Some(0));
        assert_eq!(change_bps(&at(10_000, 8), &at(9_000, 6)), None);
        assert_eq!(change_bps(&at(0, 8), &at(9_000, 8)), None);
    }

    #[test]
    fn reports_each_members_latest_attestation() {
        let attestation = |key: u8, price, valid_until| PriceAttestation {
            feed: PriceFeedData {
                feed_id: LBTC_USD,
                price,
                decimals: 8,
                received_at: 1_700_000_000,
                valid_until,
            },
            signature: Vec::new(),
            public_key: [key; 32],
        };
        let members = BTreeMap::from([([2; 32], [2; 33]), ([3; 32], [3; 33])]);
        let own = PriceFeedData {
            feed_id: LBTC_USD,
            price: 10_000,
            decimals: 8,
            received_at: 1_700_000_000,
            valid_until: 1_700_000_100,
        };
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_feed_attestations(
                "LBTC/USD",
                &members,
                &[
                    attestation(2, 10_250, 1_700_000_100),
                    // Expired, so only its timestamp is reported.
                    attestation(3, 20_000, 1_700_000_010),
                    // Its own, or a node that is no longer a member.
                    attestation(1, 10_000, 1_700_000_100),
                ],
                Some(own),
                1_700_000_050,
            );
        });

        let rendered = recorder.handle().render();
        let (second, third) = (hex::encode([2; 33]), hex::encode([3; 33]));
        for line in [
            format!(
                "high_storm_price_peer_attestation_timestamp_seconds{{feed=\"LBTC/USD\",peer=\"{second}\"}} 1700000000"
            ),
            format!(
                "high_storm_price_peer_attestation_timestamp_seconds{{feed=\"LBTC/USD\",peer=\"{third}\"}} 1700000000"
            ),
            format!(
                "high_storm_price_peer_deviation_bps{{feed=\"LBTC/USD\",peer=\"{second}\"}} 250"
            ),
        ] {
            assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
        }
        assert!(rendered.contains(&format!(
            "high_storm_price_peer_deviation_bps{{feed=\"LBTC/USD\",peer=\"{third}\"}} NaN"
        )));
        assert!(!rendered.contains(&hex::encode([1; 33])));
    }

    #[test]
    fn tells_a_refused_api_key_from_an_unreachable_source() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_price_poll_error("keyed", ConnectionError::Unauthorized);
            record_price_poll_error("keyed", ConnectionError::RequestFailure);
        });

        let rendered = recorder.handle().render();
        for reason in ["unauthorized", "request_failure"] {
            assert!(rendered.contains(&format!(
                "high_storm_price_poll_failures_total{{source=\"keyed\",reason=\"{reason}\"}} 1"
            )));
        }
    }

    #[test]
    fn republishes_the_last_change() {
        let at = |price| SourceObservation::new(price, 8, 0, 0);
        let first = builder().unwrap().build_recorder();
        metrics::with_local_recorder(&first, || {
            record_price_change(USDC_USD, "republished", &at(10_000), &at(10_050));
        });
        let second = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&second, record_price_changes);

        assert!(
            second.handle().render().contains(
                r#"high_storm_price_change_bps{feed="USDC/USD",source="republished"} 50"#
            )
        );
    }

    #[test]
    fn covers_only_the_feeds_a_source_can_price() {
        let polled = [
            coingecko(LBTC_USD),
            coingecko(USDT_USD),
            coingecko(USDC_USD),
        ];

        let feeds = priced_feeds(&FeedRegistry::default(), &polled);

        // No source quotes EURX or DePix, so neither they nor their Cross pairs count.
        assert_eq!(
            feeds
                .iter()
                .map(|definition| definition.id)
                .collect::<Vec<_>>(),
            vec![LBTC_USD, USDT_USD, LBTC_USDT, USDC_USD]
        );
    }

    #[test]
    fn records_feed_and_source_health() {
        let polled = [coingecko(LBTC_USD), coingecko(USDT_USD)];
        let feeds = priced_feeds(&FeedRegistry::default(), &polled);
        let health = PriceHealth {
            sources: vec![
                SourceHealth {
                    feed: LBTC_USD,
                    source: 0,
                    state: SourceState::Active,
                    observed_at: Some(1_700_000_000),
                },
                SourceHealth {
                    feed: USDT_USD,
                    source: 0,
                    state: SourceState::Dropped,
                    observed_at: None,
                },
            ],
            values: vec![
                (
                    LBTC_USD,
                    Some(PriceFeedData {
                        feed_id: LBTC_USD,
                        price: 100,
                        decimals: 8,
                        received_at: 1_700_000_001,
                        valid_until: 1_700_000_301,
                    }),
                ),
                (USDT_USD, None),
                (LBTC_USDT, None),
            ],
        };
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            record_price_health(&feeds, &polled, &health);
        });

        let rendered = recorder.handle().render();
        for line in [
            r#"high_storm_price_feed_available{feed="LBTC/USD"} 1"#,
            r#"high_storm_price_feed_available{feed="USDT/USD"} 0"#,
            r#"high_storm_price_feed_available{feed="LBTC/USDT"} 0"#,
            r#"high_storm_price_feed_received_timestamp_seconds{feed="LBTC/USD"} 1700000001"#,
            r#"high_storm_price_feed_valid_until_timestamp_seconds{feed="LBTC/USD"} 1700000301"#,
            r#"high_storm_price_feed_active_sources{feed="LBTC/USD"} 1"#,
            r#"high_storm_price_feed_active_sources{feed="USDT/USD"} 0"#,
            r#"high_storm_price_source_state{feed="LBTC/USD",source="coingecko",state="active"} 1"#,
            r#"high_storm_price_source_state{feed="USDT/USD",source="coingecko",state="dropped"} 1"#,
            r#"high_storm_price_source_state{feed="USDT/USD",source="coingecko",state="active"} 0"#,
            r#"high_storm_price_source_last_observed_timestamp_seconds{feed="LBTC/USD",source="coingecko"} 1700000000"#,
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
        assert!(!rendered.contains(r#"active_sources{feed="LBTC/USDT"}"#));
    }
}
