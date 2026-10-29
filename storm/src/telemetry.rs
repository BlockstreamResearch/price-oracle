//! Metrics recorded through the [`metrics`] facade. Nothing is recorded unless
//! the embedding process installs a recorder.

use std::sync::atomic::{AtomicUsize, Ordering};

use metrics::{counter, describe_counter, describe_gauge, gauge};

use crate::Error;

const PEER_CONNECTIONS: &str = "storm_peer_connections_total";
const PEER_DISCONNECTIONS: &str = "storm_peer_disconnections_total";
const HANDSHAKES_REJECTED: &str = "storm_handshakes_rejected_total";
const INBOUND_CONNECTIONS_ACTIVE: &str = "storm_inbound_connections_active";
const DNS_RESOLUTION_FAILURES: &str = "storm_dns_resolution_failures_total";

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

/// Describes Storm's metrics to the installed recorder.
pub fn describe() {
    describe_counter!(
        PEER_CONNECTIONS,
        "Connections established with a peer, by direction."
    );
    describe_counter!(
        PEER_DISCONNECTIONS,
        "Established peer connections that ended, by reason."
    );
    describe_counter!(
        HANDSHAKES_REJECTED,
        "Connections rejected during the handshake or when claiming the peer's slot, by direction and reason."
    );
    describe_gauge!(
        INBOUND_CONNECTIONS_ACTIVE,
        "Inbound connections open, handshakes included; the listener stops accepting at 128."
    );
    describe_counter!(
        DNS_RESOLUTION_FAILURES,
        "Failed lookups of a peer's DNS address."
    );
}

/// Publishes Storm's gauges again, so a recorder that drops gauges left
/// unchanged for a while keeps reporting them.
pub fn record_gauges() {
    gauge!(INBOUND_CONNECTIONS_ACTIVE).set(INBOUND_CONNECTIONS.load(Ordering::Relaxed) as f64);
}

pub(crate) fn record_connection(peer: [u8; 33], direction: Direction) {
    counter!(PEER_CONNECTIONS, "peer" => hex::encode(peer), "direction" => direction.as_str())
        .increment(1);
}

/// A connection that ends without an error was closed by this node.
pub(crate) fn record_disconnection(peer: [u8; 33], result: &Result<(), Error>) {
    let reason = result
        .as_ref()
        .err()
        .map_or("closed_locally", Error::metric_reason);
    counter!(PEER_DISCONNECTIONS, "peer" => hex::encode(peer), "reason" => reason).increment(1);
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
