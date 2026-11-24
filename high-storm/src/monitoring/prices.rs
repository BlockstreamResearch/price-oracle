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
mod tests;
