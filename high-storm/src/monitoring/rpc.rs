use std::{fmt, time::Instant};

use bitcoincore_rpc::{
    Auth, Client,
    jsonrpc::{self, Request, Response, Transport, simple_http::SimpleHttpTransport},
};
use metrics::{counter, histogram};

use super::names;

/// An Elements RPC client like `Client::new` builds, whose calls are timed and
/// counted by method. `broadcasts` names the transactions it sends, the `kind`
/// of every `sendrawtransaction` it carries.
pub(crate) fn elements_client(
    url: &str,
    auth: Auth,
    broadcasts: &'static str,
) -> bitcoincore_rpc::Result<Client> {
    let (user, pass) = auth.get_user_pass()?;
    let mut builder = SimpleHttpTransport::builder()
        .url(url)
        .map_err(|error| bitcoincore_rpc::Error::JsonRpc(error.into()))?;
    if let Some(user) = user {
        builder = builder.auth(user, pass);
    }
    Ok(Client::from_jsonrpc(jsonrpc::Client::with_transport(
        Instrumented {
            transport: builder.build(),
            broadcasts,
        },
    )))
}

struct Instrumented {
    transport: SimpleHttpTransport,
    broadcasts: &'static str,
}

impl Transport for Instrumented {
    fn send_request(&self, request: Request) -> Result<Response, jsonrpc::Error> {
        let method = request.method.to_owned();
        let started = Instant::now();
        let response = self.transport.send_request(request);
        record_call(&method, started, &response);
        if method == "sendrawtransaction" {
            record_broadcast(self.broadcasts, &response);
        }
        response
    }

    fn send_batch(&self, requests: &[Request]) -> Result<Vec<Response>, jsonrpc::Error> {
        self.transport.send_batch(requests)
    }

    fn fmt_target(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.transport.fmt_target(formatter)
    }
}

/// `transport` when Elements did not answer, so alerts can tell it apart from
/// an error Elements answered with, which some calls expect.
fn record_call(method: &str, started: Instant, response: &Result<Response, jsonrpc::Error>) {
    histogram!(names::ELEMENTS_RPC_DURATION, "method" => method.to_owned())
        .record(started.elapsed().as_secs_f64());
    let reason = match response {
        Ok(response) if response.error.is_none() => return,
        Ok(_) => "rpc",
        Err(_) => "transport",
    };
    counter!(names::ELEMENTS_RPC_ERRORS, "method" => method.to_owned(), "reason" => reason)
        .increment(1);
}

/// `outcome` is `accepted`, already in the mempool included; `inputs_spent`
/// when an input is missing or spent, which is also what resending an already
/// confirmed transaction gets; `rejected` for any other refusal; or `failed`
/// to reach Elements.
fn record_broadcast(kind: &'static str, response: &Result<Response, jsonrpc::Error>) {
    let outcome = match response {
        Ok(response) => response
            .error
            .as_ref()
            .map_or("accepted", broadcast_refusal),
        Err(_) => "failed",
    };
    counter!(names::TX_BROADCASTS, "kind" => kind, "outcome" => outcome).increment(1);
}

/// -27 is `RPC_VERIFY_ALREADY_IN_CHAIN`.
fn broadcast_refusal(error: &jsonrpc::error::RpcError) -> &'static str {
    if error.message.contains("txn-already-in-mempool")
        || error.message.contains("txn-already-known")
    {
        "accepted"
    } else if error.code == -27 || error.message.contains("bad-txns-inputs-missingorspent") {
        "inputs_spent"
    } else {
        "rejected"
    }
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::RpcApi;
    use serde_json::{Value, json};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn times_calls_and_counts_errors_and_broadcasts_by_kind() {
        let elements = axum::Router::new().route(
            "/",
            axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
                axum::Json(match request["params"][0].as_str() {
                    Some("rejected") => json!({
                        "id": request["id"],
                        "result": null,
                        "error": {"code": -26, "message": "min relay fee not met"},
                    }),
                    // What Elements answered live when a confirmed transaction was resent.
                    Some("confirmed") => json!({
                        "id": request["id"],
                        "result": null,
                        "error": {"code": -25, "message": "bad-txns-inputs-missingorspent"},
                    }),
                    _ => json!({"id": request["id"], "result": "txid", "error": null}),
                })
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, elements).await.unwrap() });
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();

        let rendered = tokio::task::spawn_blocking(move || {
            metrics::with_local_recorder(&recorder, || {
                let client =
                    elements_client(&format!("http://{address}"), Auth::None, "burn").unwrap();
                client
                    .call::<String>("sendrawtransaction", &["accepted".into()])
                    .unwrap();
                client
                    .call::<String>("sendrawtransaction", &["rejected".into()])
                    .unwrap_err();
                client
                    .call::<String>("sendrawtransaction", &["confirmed".into()])
                    .unwrap_err();
                elements_client(&format!("http://{closed}"), Auth::None, "burn")
                    .unwrap()
                    .call::<u64>("getblockcount", &[])
                    .unwrap_err();
            });
            recorder.handle().render()
        })
        .await
        .unwrap();

        for line in [
            r#"high_storm_tx_broadcast_total{kind="burn",outcome="accepted"} 1"#,
            r#"high_storm_tx_broadcast_total{kind="burn",outcome="rejected"} 1"#,
            r#"high_storm_tx_broadcast_total{kind="burn",outcome="inputs_spent"} 1"#,
            r#"high_storm_elements_rpc_errors_total{method="sendrawtransaction",reason="rpc"} 2"#,
            r#"high_storm_elements_rpc_errors_total{method="getblockcount",reason="transport"} 1"#,
            r#"high_storm_elements_rpc_duration_seconds_count{method="sendrawtransaction"} 3"#,
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
    }
}
