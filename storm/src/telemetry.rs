//! Metrics recorded through the [`metrics`] facade. Nothing is recorded unless
//! the embedding process installs a recorder.

use std::sync::atomic::{AtomicUsize, Ordering};

use metrics::{counter, gauge};

use crate::{Error, StormState};

/// Declares a constant per metric name and `describe`, which registers the
/// help text of each metric, in table order.
macro_rules! metrics {
    ($($describe:ident $name:ident = $metric:literal, $help:literal;)*) => {
        $(const $name: &str = $metric;)*

        /// Describes Storm's metrics to the installed recorder.
        pub fn describe() {
            $(metrics::$describe!($name, $help);)*
        }
    };
}

metrics! {
    describe_counter PEER_CONNECTIONS = "storm_peer_connections_total",
        "Connections established with a peer, by direction.";
    describe_counter PEER_DISCONNECTIONS = "storm_peer_disconnections_total",
        "Established peer connections that ended, by reason.";
    describe_counter HANDSHAKES_REJECTED = "storm_handshakes_rejected_total",
        "Connections rejected during the handshake or when claiming the peer's slot, by direction and reason.";
    describe_gauge INBOUND_CONNECTIONS_ACTIVE = "storm_inbound_connections_active",
        "Inbound connections open, handshakes included; the listener stops accepting at 128.";
    describe_counter DNS_RESOLUTION_FAILURES = "storm_dns_resolution_failures_total",
        "Failed lookups of a peer's DNS address.";
    describe_counter MESSAGES_REJECTED = "storm_messages_rejected_total",
        "Messages from a peer that were dropped, by reason.";
    describe_counter OUTBOUND_QUEUE_FULL = "storm_outbound_queue_full_total",
        "Messages not queued for a peer because it is not draining its queue.";
    describe_counter CONNECTION_TIMEOUTS = "storm_connection_timeouts_total",
        "Connection operations that timed out, by stage: connect, handshake, write or idle.";
    describe_gauge PEER_PROTOCOL_VERSION = "storm_peer_protocol_version",
        "Storm protocol version of the peer's latest message.";
}

/// Accepted inbound connections, each holding one of the listener's permits.
static INBOUND_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// Publishes Storm's gauges again, so a recorder that drops gauges left
/// unchanged for a while keeps reporting them.
pub fn record_gauges() {
    gauge!(INBOUND_CONNECTIONS_ACTIVE).set(INBOUND_CONNECTIONS.load(Ordering::Relaxed) as f64);
}

/// The `peer` label: the key of a member or a staged migration peer, and
/// `unregistered` for anyone else, whose made-up keys must not add series.
pub(crate) fn peer_label(state: &StormState, peer: &[u8; 33]) -> String {
    let known = state
        .peers
        .iter()
        .chain(&state.migration_peers)
        .any(|known| known.compressed_public_key == *peer);
    if known {
        hex::encode(peer)
    } else {
        "unregistered".into()
    }
}

pub(crate) fn record_connection(peer: String, direction: Direction) {
    counter!(PEER_CONNECTIONS, "peer" => peer, "direction" => direction.as_str()).increment(1);
}

/// A connection that ends without an error was closed by this node.
pub(crate) fn record_disconnection(peer: String, result: &Result<(), Error>) {
    let reason = result
        .as_ref()
        .err()
        .map_or("closed_locally", Error::metric_reason);
    counter!(PEER_DISCONNECTIONS, "peer" => peer, "reason" => reason).increment(1);
}

/// No peer label: the key is not authenticated yet, or not a member.
pub(crate) fn record_handshake_rejected(direction: Direction, error: &Error) {
    counter!(
        HANDSHAKES_REJECTED,
        "direction" => direction.as_str(),
        "reason" => error.metric_reason()
    )
    .increment(1);
}

pub(crate) fn record_dns_failure(peer: [u8; 33]) {
    counter!(DNS_RESOLUTION_FAILURES, "peer" => hex::encode(peer)).increment(1);
}

pub(crate) fn record_message_rejected(peer: String, reason: &'static str) {
    counter!(MESSAGES_REJECTED, "peer" => peer, "reason" => reason).increment(1);
}

pub(crate) fn record_outbound_queue_full(peer: String) {
    counter!(OUTBOUND_QUEUE_FULL, "peer" => peer).increment(1);
}

/// Counts a timeout at `stage` (`connect`, `handshake`, `write` or `idle`) and
/// returns its error.
pub(crate) fn timed_out(stage: &'static str, during: &'static str) -> Error {
    counter!(CONNECTION_TIMEOUTS, "stage" => stage).increment(1);
    Error::ConnectionTimeout(during)
}

pub(crate) fn set_peer_protocol_version(peer: [u8; 33], version: u32) {
    gauge!(PEER_PROTOCOL_VERSION, "peer" => hex::encode(peer)).set(f64::from(version));
}

/// Counts an accepted inbound connection until it is dropped.
pub(crate) struct InboundConnection(());

impl InboundConnection {
    pub(crate) fn open() -> Self {
        INBOUND_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        record_gauges();
        Self(())
    }
}

impl Drop for InboundConnection {
    fn drop(&mut self) {
        INBOUND_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        record_gauges();
    }
}
