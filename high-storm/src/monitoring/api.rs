use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use axum::http::{Method, StatusCode};
use metrics::{counter, gauge, histogram};

use super::{names, refresh::set_retained};

/// Accepted external API connections, each holding one of the listener's slots.
static API_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// `reason` is `global` or `per_client`.
pub(crate) fn record_api_connection_rejected(reason: &'static str) {
    counter!(names::API_CONNECTIONS_REJECTED, "reason" => reason).increment(1);
}

/// `reason` is `client_inflight`, `body_read_limit`, `too_large`,
/// `body_invalid`, `body_timeout` or `busy`.
pub(crate) fn record_api_request_rejected(reason: &'static str) {
    counter!(names::API_REQUESTS_REJECTED, "reason" => reason).increment(1);
}

/// `route` is the matched route template, never the raw path.
pub(crate) fn record_api_request(
    route: String,
    method: &Method,
    status: StatusCode,
    took: Duration,
) {
    histogram!(names::API_REQUEST_DURATION, "route" => route.clone()).record(took.as_secs_f64());
    counter!(
        names::API_REQUESTS,
        "route" => route,
        "method" => method_label(method),
        "status" => status.as_u16().to_string(),
    )
    .increment(1);
}

pub(crate) fn record_operator_auth_failure(reason: &'static str) {
    counter!(names::OPERATOR_AUTH_FAILURES, "reason" => reason).increment(1);
}

/// `reason` is `not_coordinator`, `payload`, `signature`, `fee_utxo` or
/// `conflict`.
pub(crate) fn record_user_request_rejected(reason: &'static str) {
    counter!(names::USER_REQUESTS_REJECTED, "reason" => reason).increment(1);
}

/// `reason` is `no_credentials` or `uid`.
pub(crate) fn record_ipc_rejected(reason: &'static str) {
    counter!(names::IPC_REJECTED, "reason" => reason).increment(1);
}

/// `action` is `add` or `remove`.
pub(crate) fn record_operator_change(action: &'static str) {
    counter!(names::OPERATOR_CHANGES, "action" => action).increment(1);
}

pub(super) fn set_operators(count: u64) {
    set_retained(names::OPERATORS, count as f64);
}

pub(super) fn record_api_gauges() {
    gauge!(names::API_CONNECTIONS_ACTIVE).set(API_CONNECTIONS.load(Ordering::Relaxed) as f64);
}

/// Counts an accepted external API connection until it is dropped.
pub(crate) struct ApiConnection(());

impl ApiConnection {
    pub(crate) fn open() -> Self {
        API_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        record_api_gauges();
        Self(())
    }
}

impl Drop for ApiConnection {
    fn drop(&mut self) {
        API_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        record_api_gauges();
    }
}

/// A client picks the method, so anything unusual shares one label.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_connections_operators_and_refused_ipc() {
        let recorder = crate::monitoring::builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || {
            let _open = ApiConnection::open();
            set_operators(2);
            record_ipc_rejected("uid");
        });

        let rendered = recorder.handle().render();
        // Other tests open connections too, so only the gauge's presence is fixed.
        assert!(rendered.contains("high_storm_api_connections_active "));
        assert!(rendered.contains("high_storm_operators 2"));
        assert!(rendered.contains(r#"high_storm_ipc_rejected_total{reason="uid"} 1"#));
    }

    #[test]
    fn labels_only_standard_methods() {
        assert_eq!(method_label(&Method::POST), "POST");
        assert_eq!(method_label(&Method::from_bytes(b"BREW").unwrap()), "other");
    }
}
