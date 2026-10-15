use std::time::{SystemTime, UNIX_EPOCH};

use ::secp256k1::{Keypair as SchnorrKeypair, SecretKey as SchnorrSecretKey, schnorr};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use bitcoin::{
    Address, Network, PrivateKey,
    hashes::Hash,
    secp256k1::{self, Message},
    sign_message::signed_msg_hash,
};
use http_body_util::BodyExt;
use price_feed::{FeedId, SourceObservation};
use secp256k1_zkp::{Secp256k1, SecretKey};
use simplex::simplicityhl::elements::AssetId;
use storm::{Peer, Storm};
use tower::ServiceExt;

use crate::{
    HighStorm, NetworkAsset,
    db::{
        Database,
        monitored_utxo::{IndexedBlock, MonitoredUtxo},
        network_asset::{ORACLE_VERIFIER_KIND, STORM_EYE_KIND, TICK_ASSET_KIND},
    },
};

use super::{
    API_BODY_READ_TIMEOUT, API_REQUEST_TIMEOUT, ApiClientAddress, ClientLimits, LimitedListener,
    MAX_API_BODY_BYTES, MAX_API_BODY_READS, MAX_API_CONCURRENCY, MAX_API_REQUESTS_PER_CLIENT,
    fee_utxo::FeeUtxoValidator,
    operators::{AuthService, auth::AuthNetwork},
    router,
    users::{NetworkUserRequests, UserRequest, UserRequestHeader, signing_hash},
    with_request_limits,
};

#[tokio::test]
async fn rejects_fee_checks_on_non_coordinator_nodes() {
    let elsewhere = SecretKey::from_slice(&[22; 32])
        .unwrap()
        .public_key(&Secp256k1::new())
        .serialize();
    let (app, ..) = node_setup_with_coordinator(elsewhere).await;
    let response = app
        .oneshot(json_request(
            "/users/check-fee-utxos",
            serde_json::json!({"fee_utxos": [format!("{}:0", hex::encode([9; 32]))]}),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_json(response).await["error"],
        "this node is not the coordinator"
    );
}

#[tokio::test]
async fn rejects_oversized_api_bodies_without_a_content_length() {
    let (app, _, _) = setup().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/users/check-fee-utxos")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(" ".repeat(MAX_API_BODY_BYTES + 1)))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(start_paused = true)]
async fn times_out_stalled_api_requests() {
    let app = with_request_limits(Router::new().route(
        "/",
        axum::routing::get(|| async {
            std::future::pending::<()>().await;
            StatusCode::OK
        }),
    ));
    let started = tokio::time::Instant::now();
    let response = app.oneshot(get_request("/")).await.unwrap();

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert_eq!(started.elapsed(), API_REQUEST_TIMEOUT);
}

#[tokio::test]
async fn stalled_uploads_do_not_take_execution_slots() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (entered, mut arrivals) = tokio::sync::mpsc::channel(MAX_API_BODY_READS + 1);
    let app = with_request_limits(
        Router::new().route(
            "/",
            axum::routing::get(|| async { StatusCode::OK })
                .post(|_: axum::body::Bytes| async { StatusCode::OK }),
        ),
    )
    .layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let entered = entered.clone();
            async move {
                if request.method() == axum::http::Method::POST {
                    entered.send(()).await.unwrap();
                }
                next.run(request).await
            }
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut uploads = Vec::new();
    for _ in 0..MAX_API_BODY_READS {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        uploads.push(stream);
    }
    for _ in 0..MAX_API_BODY_READS {
        tokio::time::timeout(std::time::Duration::from_secs(1), arrivals.recv())
            .await
            .unwrap()
            .unwrap();
    }

    let mut overflow = tokio::net::TcpStream::connect(address).await.unwrap();
    overflow.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        overflow.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");

    let mut healthy = tokio::net::TcpStream::connect(address).await.unwrap();
    healthy
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        healthy.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    drop(uploads);
    server.abort();
}

#[tokio::test]
async fn times_out_trickled_bodies_and_releases_capacity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let app = with_request_limits(Router::new().route(
        "/",
        axum::routing::post(|_: axum::body::Bytes| async { StatusCode::OK }),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            LimitedListener::new(listener),
            app.into_make_service_with_connect_info::<ApiClientAddress>(),
        )
        .await
        .unwrap();
    });
    let mut upload = tokio::net::TcpStream::connect(address).await.unwrap();
    let started = tokio::time::Instant::now();
    upload.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
    let (mut reader, mut writer) = upload.into_split();
    let trickle = tokio::spawn(async move {
        let mut ticks = tokio::time::interval(std::time::Duration::from_millis(500));
        loop {
            ticks.tick().await;
            if writer.write_all(b"1\r\nx\r\n").await.is_err() {
                break;
            }
        }
    });
    let mut response = String::new();
    let read = tokio::time::timeout(
        API_BODY_READ_TIMEOUT * 2,
        reader.read_to_string(&mut response),
    )
    .await
    .unwrap();
    if let Err(error) = &read {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    }
    assert!(
        response.starts_with("HTTP/1.1 408") || (response.is_empty() && read.is_err()),
        "{response}"
    );
    assert!(started.elapsed() >= API_BODY_READ_TIMEOUT);
    assert!(started.elapsed() < API_BODY_READ_TIMEOUT * 2);
    trickle.abort();

    let mut complete = tokio::net::TcpStream::connect(address).await.unwrap();
    complete.write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nConnection: close\r\n\r\ncomplete").await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        complete.read_to_string(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    server.abort();
}

#[tokio::test(start_paused = true)]
async fn isolates_request_limits_by_socket_ip_and_releases_client_capacity() {
    let (entered, mut arrivals) = tokio::sync::mpsc::channel(MAX_API_REQUESTS_PER_CLIENT + 1);
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let gate = release.clone();
    let app = with_request_limits(Router::new().route("/", axum::routing::get(move |axum::extract::ConnectInfo(ApiClientAddress(address)): axum::extract::ConnectInfo<ApiClientAddress>| {
        let entered = entered.clone();
        let gate = gate.clone();
        async move {
            entered.send(()).await.unwrap();
            if address.ip() == "192.0.2.1".parse::<std::net::IpAddr>().unwrap() {
                gate.acquire().await.unwrap().forget();
            }
            StatusCode::OK
        }
    })));
    let client_request = |address: &str| {
        let mut request = get_request("/");
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(ApiClientAddress(
                address.parse().unwrap(),
            )));
        request
    };
    let mut requests = Vec::new();
    for _ in 0..MAX_API_REQUESTS_PER_CLIENT {
        let app = app.clone();
        let request = client_request("192.0.2.1:1000");
        requests.push(tokio::spawn(
            async move { app.oneshot(request).await.unwrap() },
        ));
    }
    for _ in 0..MAX_API_REQUESTS_PER_CLIENT {
        arrivals.recv().await.unwrap();
    }

    let mut spoofed = client_request("192.0.2.1:2000");
    spoofed
        .headers_mut()
        .insert("x-forwarded-for", "192.0.2.2".parse().unwrap());
    spoofed
        .headers_mut()
        .insert("forwarded", "for=192.0.2.2".parse().unwrap());
    let response = app.clone().oneshot(spoofed).await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    assert_eq!(
        app.clone()
            .oneshot(client_request("192.0.2.2:1000"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    release.add_permits(MAX_API_REQUESTS_PER_CLIENT);
    for request in requests {
        assert_eq!(request.await.unwrap().status(), StatusCode::OK);
    }
    release.add_permits(1);
    assert_eq!(
        app.oneshot(client_request("192.0.2.1:3000"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[test]
fn client_limit_state_is_bounded_and_normalizes_mapped_addresses() {
    let limits = ClientLimits::new(1);
    let permit = limits.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
    assert!(
        limits
            .try_acquire("::ffff:192.0.2.1".parse().unwrap())
            .is_err()
    );
    for index in 0..10_000u32 {
        let address = std::net::IpAddr::V4(std::net::Ipv4Addr::from(index));
        drop(limits.try_acquire(address).unwrap());
    }
    assert!(limits.clients.lock().unwrap().len() <= 2);
    drop(permit);
    assert!(limits.try_acquire("192.0.2.1".parse().unwrap()).is_ok());
}

#[tokio::test]
async fn limits_connections_before_headers_and_recovers_after_disconnect() {
    use axum::serve::Listener;
    use tokio::io::AsyncReadExt;

    for (global_limit, client_limit) in [(1, 2), (2, 1)] {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let mut listener = LimitedListener {
            connections: std::sync::Arc::new(tokio::sync::Semaphore::new(global_limit)),
            clients: ClientLimits::new(client_limit),
            ..LimitedListener::new(tcp)
        };
        let first = tokio::net::TcpStream::connect(address).await.unwrap();
        let (accepted, _) = listener.accept().await;
        let mut rejected = tokio::net::TcpStream::connect(address).await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });
        let mut buffer = [0; 1];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            rejected.read(&mut buffer),
        )
        .await
        .unwrap();
        assert!(
            matches!(read, Ok(0)) || read.is_err(),
            "unexpected connection response: {read:?}"
        );

        drop(accepted);
        drop(first);
        let replacement = tokio::net::TcpStream::connect(address).await.unwrap();
        let (accepted, _) = tokio::time::timeout(std::time::Duration::from_secs(1), accept)
            .await
            .unwrap()
            .unwrap();
        drop(accepted);
        drop(replacement);
    }
}

#[tokio::test(start_paused = true)]
async fn sheds_api_overload_across_router_clones_and_releases_capacity() {
    let (entered, mut arrivals) = tokio::sync::mpsc::channel(MAX_API_CONCURRENCY);
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let gate = release.clone();
    let app = with_request_limits(Router::new().route(
        "/",
        axum::routing::get(move || {
            let entered = entered.clone();
            let gate = gate.clone();
            async move {
                entered.send(()).await.unwrap();
                gate.acquire().await.unwrap().forget();
                StatusCode::OK
            }
        }),
    ));
    let mut requests = Vec::new();
    for _ in 0..MAX_API_CONCURRENCY {
        let app = app.clone();
        requests.push(tokio::spawn(async move {
            app.oneshot(get_request("/")).await.unwrap()
        }));
    }
    for _ in 0..MAX_API_CONCURRENCY {
        arrivals.recv().await.unwrap();
    }

    let rejected = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        app.clone().oneshot(get_request("/")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);

    release.add_permits(MAX_API_CONCURRENCY);
    for request in requests {
        assert_eq!(request.await.unwrap().status(), StatusCode::OK);
    }
    release.add_permits(1);
    assert_eq!(
        app.oneshot(get_request("/")).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn permits_browser_preflight_requests() {
    let (app, _, _) = setup().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/users/account/505f234a81fe3af88625ebda259dbaec44c72b181e2f64735f8b8ec8d7cf7377")
                .header(header::ORIGIN, "http://127.0.0.1:5173")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

#[tokio::test]
async fn authenticates_operator_reads_with_a_real_bip322_signature() {
    let (app, private_key, public_key) = setup().await;

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/voting")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let challenge = app
        .clone()
        .oneshot(json_request(
            "/operators/auth/challenge",
            serde_json::json!({"public_key": public_key}),
        ))
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge: serde_json::Value = response_json(challenge).await;
    let message = challenge["message"].as_str().unwrap();
    let signature = sign(&private_key, message);

    let token = app
        .clone()
        .oneshot(json_request(
            "/operators/auth/token",
            serde_json::json!({
                "public_key": public_key,
                "message": message,
                "signature": signature,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    let token: serde_json::Value = response_json(token).await;

    let voting = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/voting")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", token["token"].as_str().unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(voting.status(), StatusCode::OK);
    assert_eq!(response_json(voting).await, serde_json::json!([]));

    let authorization = format!("Bearer {}", token["token"].as_str().unwrap());
    let network = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/state")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(network.status(), StatusCode::OK);
    let network = response_json(network).await;
    assert_eq!(network["total_peers"], 1);
    assert_eq!(network["online_peers"], 1);
    assert_eq!(network["is_coordinator"], true);
    assert_xonly_public_key(&network["local_public_key"]);
    assert_xonly_public_key(&network["coordinator_public_key"]);

    let peers = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/state/peers")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(peers.status(), StatusCode::OK);
    let peers = response_json(peers).await;
    assert_eq!(peers.as_array().unwrap().len(), 1);
    assert_eq!(peers[0]["status"], "controlled");
    assert_eq!(peers[0]["is_local"], true);
    assert_eq!(peers[0]["is_leader"], true);
    assert_xonly_public_key(&peers[0]["public_key"]);

    let droplets = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/droplets")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(droplets.status(), StatusCode::OK);
    assert_eq!(
        response_json(droplets).await,
        serde_json::json!({
            "amount": 0,
            "exchange_fee_sats": 500,
            "exchange_locked": false,
            "block_height": 0,
            "next_leader_block": 0,
            "request": null,
            "history": [],
        })
    );

    let users = app
        .oneshot(
            Request::builder()
                .uri("/users/pending")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(users.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn authenticates_operator_reads_with_a_humid_signature() {
    let (app, private_key, _) = setup().await;
    let public_key = hex::encode(
        private_key
            .public_key(&secp256k1::Secp256k1::new())
            .inner
            .serialize(),
    );
    let scheme = "bitcoin-signed-message-ecdsa-v1";

    let config = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/auth/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(config.status(), StatusCode::OK);
    let config = response_json(config).await;
    assert_eq!(config["network"], "elementsregtest");
    assert_eq!(config["caip2_chain_id"], serde_json::Value::Null);
    assert_eq!(config["signature_scheme"], scheme);
    assert_eq!(config["identity_derivation"]["branch"], 0);
    assert_eq!(config["identity_derivation"]["index"], 0);

    let challenge = app
        .clone()
        .oneshot(json_request(
            "/operators/auth/challenge",
            serde_json::json!({
                "public_key": public_key,
                "signature_scheme": scheme,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge = response_json(challenge).await;
    assert_eq!(challenge["signature_scheme"], scheme);
    let message = challenge["message"].as_str().unwrap();
    let signature = sign_humid(&private_key, message);

    let token = app
        .clone()
        .oneshot(json_request(
            "/operators/auth/token",
            serde_json::json!({
                "public_key": public_key,
                "signature_scheme": scheme,
                "message": message,
                "signature": signature,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::OK);
    let token = response_json(token).await;

    let voting = app
        .oneshot(
            Request::builder()
                .uri("/operators/voting")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", token["token"].as_str().unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(voting.status(), StatusCode::OK);
}

fn assert_xonly_public_key(value: &serde_json::Value) {
    let encoded = value.as_str().expect("public key must be a string");
    let bytes: [u8; 32] = hex::decode(encoded)
        .expect("public key must be hexadecimal")
        .try_into()
        .expect("public key must contain exactly 32 bytes");
    secp256k1::XOnlyPublicKey::from_slice(&bytes)
        .expect("public key must be a valid x-only secp256k1 key");
}

#[tokio::test]
async fn creates_and_approves_voting_with_signed_requests() {
    let (app, private_key, public_key) = setup().await;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let proposal = serde_json::json!({
        "kind": "split_storm_eye",
        "utxo_to_split": {
            "txid": hex::encode([7; 32]),
            "output_index": 1
        },
        "number_of_splits": 2
    });
    let create = app
        .clone()
        .oneshot(signed_request(
            &private_key,
            &public_key,
            "/operators/voting",
            timestamp,
            "create-voting",
            proposal,
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let created: serde_json::Value = response_json(create).await;
    let hash = created["message_hash"].as_str().unwrap();
    let approval_path = format!("/operators/voting/{hash}/approve");

    let approve = app
        .clone()
        .oneshot(signed_request(
            &private_key,
            &public_key,
            &approval_path,
            timestamp,
            "approve-voting",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(approve.status(), StatusCode::NO_CONTENT);

    let repeated_approve = app
        .oneshot(signed_request(
            &private_key,
            &public_key,
            &approval_path,
            timestamp,
            "approve-voting-retry",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(repeated_approve.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn rejects_invalid_droplets_exchange_fields_before_registration() {
    let (app, private_key, public_key) = setup().await;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let response = app
        .oneshot(signed_request(
            &private_key,
            &public_key,
            "/operators/droplets/exchange",
            timestamp,
            "exchange-droplets",
            serde_json::json!({
                "amount": 0,
                "address": "not-an-address",
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({"error": "invalid Droplets exchange: exchange amount must be positive"})
    );
}

#[tokio::test]
async fn rejects_malformed_droplets_destination_before_registration() {
    let (app, private_key, public_key) = setup().await;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let response = app
        .oneshot(signed_request(
            &private_key,
            &public_key,
            "/operators/droplets/exchange",
            timestamp,
            "exchange-droplets-address",
            serde_json::json!({
                "amount": 1,
                "address": "not-an-address",
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({"error": "invalid Droplets exchange: invalid destination address"})
    );
}

#[tokio::test]
async fn registers_tick_requests_and_returns_pending_status() {
    let (app, _, _) = setup().await;
    let request = signed_user_request("tick-utxo", "signature-auth");

    let created = app.clone().oneshot(user_request(&request)).await.unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = response_json(created).await;
    let request_hash = created["request_hash"].as_str().unwrap();
    assert_eq!(request_hash.len(), 64);

    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/users/requests/{request_hash}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        response_json(status).await,
        serde_json::json!({"status": "pending", "payload": null})
    );

    let duplicate = app.oneshot(user_request(&request)).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn classifies_fee_utxos_reserved_for_burning() {
    let (app, _, _, database) = setup_with_database().await;
    database
        .monitored_utxos()
        .apply_block(
            "burning-v1",
            &IndexedBlock {
                height: 10,
                hash: [10; 32],
            },
            &[MonitoredUtxo {
                txid: [1; 32],
                output_index: 2,
                asset_kind: TICK_ASSET_KIND.to_string(),
                amount: 1,
                script_pubkey: vec![0x51],
                auth_method: "signature-auth".to_string(),
                auth_data: vec![2; 32],
                account_owner_pubkey: [3; 32],
                internal_key: None,
                burning_fee_txid: [4; 32],
                burning_fee_output_index: 5,
                block_height: 10,
                status: "active".to_string(),
                status_block_height: 10,
                burn_txid: None,
            }],
            &[],
            60,
        )
        .await
        .unwrap();
    let usable_first = format!("{}:1", hex::encode([6; 32]));
    let reserved = format!("{}:5", hex::encode([4; 32]));
    let usable_second = format!("{}:7", hex::encode([8; 32]));

    let response = app
        .oneshot(json_request(
            "/users/check-fee-utxos",
            serde_json::json!({
                "fee_utxos": [&usable_first, &reserved, &usable_second],
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        serde_json::json!({
            "reserved": [reserved],
            "usable": [usable_first, usable_second],
        })
    );
}

#[tokio::test]
async fn derives_oracle_account_from_the_active_storm_eye() {
    let (app, _, public_key) = setup().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/users/account/{public_key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let account = response_json(response).await;
    assert_eq!(account["network"], "elementsregtest");
    let mut storm_eye_asset_id = [1; 32];
    storm_eye_asset_id[0] = 2;
    let mut tick_asset_id = [3; 32];
    tick_asset_id[0] = 4;
    assert_eq!(
        account["storm_eye_asset_id"],
        AssetId::from_byte_array(storm_eye_asset_id).to_string()
    );
    assert_eq!(
        account["tick_asset_id"],
        AssetId::from_byte_array(tick_asset_id).to_string()
    );
    assert_eq!(
        account["oracle_verifier_asset_id"],
        AssetId::from_byte_array(ORACLE_VERIFIER_ASSET_ID).to_string()
    );
    assert!(
        account["tick_script_pubkey"]
            .as_str()
            .unwrap()
            .starts_with("5120")
    );
    assert!(account["address"].as_str().unwrap().starts_with("ert1p"));
    assert!(
        account["script_pubkey"]
            .as_str()
            .unwrap()
            .starts_with("5120")
    );
}

#[tokio::test]
async fn rejects_unsupported_or_invalid_user_requests() {
    let (app, _, _) = setup().await;

    // A request issued at a price has to name the feed.
    let price = signed_user_request("signed-price-data", "signature-auth");
    let response = app.clone().oneshot(user_request(&price)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let invalid_auth = signed_user_request("tick-utxo", "unknown-auth");
    let response = app
        .clone()
        .oneshot(user_request(&invalid_auth))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut invalid_signature = signed_user_request("tick-utxo", "signature-auth");
    invalid_signature.header.signature = hex::encode([0; 64]);
    let response = app
        .clone()
        .oneshot(user_request(&invalid_signature))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/users/requests/{}", hex::encode([9; 32])))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lists_every_price_feed_with_its_symbols() {
    let (app, _node, ..) = node_setup().await;

    let response = app.oneshot(get_request("/price-feeds")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let feeds = response_json(response).await;
    assert_eq!(feeds.as_array().unwrap().len(), 8);
    assert_eq!(
        feeds[0],
        serde_json::json!({
            "id": 0, "symbol": "LBTC/USD", "base": "LBTC", "quote": "USD",
            "decimals": 8, "kind": "direct",
        })
    );
    // A Cross pair is listed like any other feed.
    assert_eq!(
        feeds[4],
        serde_json::json!({
            "id": 4, "symbol": "LBTC/USDT", "base": "LBTC", "quote": "USDT",
            "decimals": 8, "kind": "cross",
        })
    );
}

#[tokio::test]
async fn serves_the_rate_it_attested_for_a_feed() {
    let (app, node, ..) = node_setup().await;

    let unknown = app
        .clone()
        .oneshot(get_request("/price-feeds/99"))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    // An id that is not a number is answered in this API's error shape.
    let malformed = app
        .clone()
        .oneshot(get_request("/price-feeds/abc"))
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(malformed).await["error"],
        "invalid price feed id 'abc'"
    );

    // A feed the node has not attested yet has no rate to read.
    let unattested = app
        .clone()
        .oneshot(get_request("/price-feeds/0"))
        .await
        .unwrap();
    assert_eq!(unattested.status(), StatusCode::SERVICE_UNAVAILABLE);

    let at = now();
    node.handle()
        .record_price_observation(
            LBTC_USD,
            0,
            SourceObservation::new(9_876_543_210, 8, at, at),
        )
        .await;
    assert_eq!(node.attest_prices().await.unwrap(), 1);

    let response = app.oneshot(get_request("/price-feeds/0")).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // A cache must not answer with a price the node would no longer serve.
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let rate = response_json(response).await;
    assert_eq!(rate["main"]["feed"]["feed_id"], 0);
    assert_eq!(rate["main"]["feed"]["price"], 9_876_543_210u64);
    assert_eq!(rate["main"]["feed"]["decimals"], 8);
    assert_eq!(rate["main"]["feed"]["received_at"], at);
    assert!(rate["main"]["feed"]["valid_until"].as_u64().unwrap() > at);
    assert_eq!(rate["main"]["public_key"], hex::encode(attester_key()));
    assert_eq!(rate["main"]["signature"].as_str().unwrap().len(), 128);
    // The only member is the coordinator itself, so nothing stands beside it.
    assert_eq!(rate["auxiliary"], serde_json::json!([]));
}

#[tokio::test]
async fn lets_an_operator_freeze_and_unfreeze_a_price_source() {
    let (app, node, private_key, public_key, _) = node_setup().await;
    node.handle()
        .register_price_source(LBTC_USD, 0, "coingecko")
        .await
        .unwrap();

    let unauthorized = app
        .clone()
        .oneshot(get_request("/operators/price-sources"))
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorization = bearer(&app, &private_key, &public_key).await;
    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/price-sources")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert_eq!(listed["is_coordinator"], true);
    // Direct feeds only: a Cross pair has no sources of its own.
    assert_eq!(listed["feeds"].as_array().unwrap().len(), 5);
    assert_eq!(listed["feeds"][0]["symbol"], "LBTC/USD");
    assert_eq!(
        listed["feeds"][0]["sources"],
        serde_json::json!([{
            "name": "coingecko",
            "state": "active",
            "failures": 0,
            "retry_at": null,
            "frozen_at": null,
            "observation": null,
        }])
    );

    let timestamp = now();
    let frozen = app
        .clone()
        .oneshot(signed_request(
            &private_key,
            &public_key,
            "/operators/price-sources/freeze",
            timestamp,
            "freeze-coingecko",
            serde_json::json!({"feed_id": LBTC_USD, "source": "coingecko"}),
        ))
        .await
        .unwrap();
    assert_eq!(frozen.status(), StatusCode::OK);
    let frozen = response_json(frozen).await;
    assert_eq!(frozen["feeds"][0]["sources"][0]["state"], "frozen");
    assert!(frozen["feeds"][0]["sources"][0]["frozen_at"].is_u64());
    assert_eq!(frozen["feeds"][0]["available"], false);

    let unfrozen = app
        .clone()
        .oneshot(signed_request(
            &private_key,
            &public_key,
            "/operators/price-sources/unfreeze",
            timestamp,
            "unfreeze-coingecko",
            serde_json::json!({"feed_id": LBTC_USD, "source": "coingecko"}),
        ))
        .await
        .unwrap();
    assert_eq!(unfrozen.status(), StatusCode::OK);
    let unfrozen = response_json(unfrozen).await;
    assert_eq!(unfrozen["feeds"][0]["sources"][0]["state"], "active");
    assert_eq!(
        unfrozen["feeds"][0]["sources"][0]["frozen_at"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn refuses_to_freeze_a_source_a_feed_does_not_have() {
    let (app, node, private_key, public_key, _) = node_setup().await;
    node.handle()
        .register_price_source(LBTC_USD, 0, "coingecko")
        .await
        .unwrap();
    let timestamp = now();

    for (nonce, feed, source, status) in [
        ("unknown-feed", 99, "coingecko", StatusCode::NOT_FOUND),
        ("unknown-source", LBTC_USD, "kraken", StatusCode::NOT_FOUND),
        (
            "cross-pair",
            LBTC_USDT,
            "coingecko",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(signed_request(
                &private_key,
                &public_key,
                "/operators/price-sources/freeze",
                timestamp,
                nonce,
                serde_json::json!({"feed_id": feed, "source": source}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{nonce}");
    }

    // An unfreeze signature does not freeze: each write is signed for its path.
    let payload = serde_json::json!({"feed_id": LBTC_USD, "source": "coingecko"});
    let nonce = "signed-for-unfreeze";
    let message = AuthService::write_message(
        "POST",
        "/operators/price-sources/unfreeze",
        timestamp,
        nonce,
        &payload,
    )
    .unwrap();
    let replayed = app
        .oneshot(json_request(
            "/operators/price-sources/freeze",
            serde_json::json!({
                "public_key": public_key,
                "timestamp": timestamp,
                "nonce": nonce,
                "signature": sign(&private_key, &message),
                "payload": payload,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    let listed = node.handle().price_sources().await.unwrap();
    assert_eq!(
        listed[0].sources[0].status.state,
        price_feed::SourceState::Active
    );
}

/// A bearer token for an operator read.
async fn bearer(app: &Router, private_key: &PrivateKey, public_key: &str) -> String {
    let challenge = app
        .clone()
        .oneshot(json_request(
            "/operators/auth/challenge",
            serde_json::json!({"public_key": public_key}),
        ))
        .await
        .unwrap();
    let challenge = response_json(challenge).await;
    let message = challenge["message"].as_str().unwrap();
    let token = app
        .clone()
        .oneshot(json_request(
            "/operators/auth/token",
            serde_json::json!({
                "public_key": public_key,
                "message": message,
                "signature": sign(private_key, message),
            }),
        ))
        .await
        .unwrap();
    let token = response_json(token).await;
    format!("Bearer {}", token["token"].as_str().unwrap())
}

#[tokio::test]
async fn registers_a_request_issued_at_a_feed_it_prices() {
    let (app, _, _) = setup().await;

    let response = app
        .clone()
        .oneshot(user_request(&signed_price_request(LBTC_USDT)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let unknown = app
        .clone()
        .oneshot(user_request(&signed_price_request(99)))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    let named = signed_batch(&[("tick-utxo", "signature-auth", Some(LBTC_USDT))]);
    let response = app.clone().oneshot(user_request(&named)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let two_feeds = signed_batch(&[
        ("signed-price-data", "signature-auth", Some(LBTC_USDT)),
        ("signed-price-data", "signature-auth", Some(LBTC_USD)),
    ]);
    let response = app.oneshot(user_request(&two_feeds)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn serves_no_price_from_a_node_that_is_not_the_coordinator() {
    let elsewhere = SecretKey::from_slice(&[22; 32])
        .unwrap()
        .public_key(&Secp256k1::new())
        .serialize();
    let (app, _node, ..) = node_setup_with_coordinator(elsewhere).await;

    for path in ["/price-feeds", "/price-feeds/0"] {
        let response = app.clone().oneshot(get_request(path)).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

const NODE_KEY: [u8; 32] = [21; 32];
const LBTC_USD: FeedId = 0;
const LBTC_USDT: FeedId = 4;

fn node_public_key() -> [u8; 33] {
    SecretKey::from_slice(&NODE_KEY)
        .unwrap()
        .public_key(&Secp256k1::new())
        .serialize()
}

/// The same key, which the node signs its attestations with.
fn attester_key() -> [u8; 32] {
    SchnorrKeypair::from_secret_key(&SchnorrSecretKey::from_secret_bytes(NODE_KEY).unwrap())
        .x_only_public_key()
        .0
        .serialize()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn setup() -> (Router, PrivateKey, String) {
    let (app, private_key, public_key, _) = setup_with_database().await;

    (app, private_key, public_key)
}

async fn setup_with_database() -> (Router, PrivateKey, String, Database) {
    let (app, _, private_key, public_key, database) = node_setup().await;

    (app, private_key, public_key, database)
}

const ORACLE_VERIFIER_ASSET_ID: [u8; 32] = [11; 32];

/// Keeps the node, for the tests that drive it before they read it.
async fn node_setup() -> (Router, HighStorm, PrivateKey, String, Database) {
    node_setup_with_coordinator(node_public_key()).await
}

/// Naming another node as the coordinator leaves this one serving nothing.
async fn node_setup_with_coordinator(
    coordinator_public_key: [u8; 33],
) -> (Router, HighStorm, PrivateKey, String, Database) {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let operators = database.node_operators();
    let mut storm_eye_asset_id = [1; 32];
    storm_eye_asset_id[0] = 2;
    let mut tick_asset_id = [3; 32];
    tick_asset_id[0] = 4;
    database
        .network_assets()
        .insert_active(&NetworkAsset {
            kind: STORM_EYE_KIND.to_string(),
            name: "Storm Eye".to_string(),
            asset_id: storm_eye_asset_id,
            reissuance_token_id: None,
            entropy: None,
            issuance_txid: [2; 32],
            contract_script: vec![0x51],
            contract_data: None,
            supply: 10_000,
            created_at_block: 1,
        })
        .await
        .unwrap();
    database
        .network_assets()
        .insert_active(&NetworkAsset {
            kind: TICK_ASSET_KIND.to_string(),
            name: "Tick".to_string(),
            asset_id: tick_asset_id,
            reissuance_token_id: Some([4; 32]),
            entropy: Some([5; 32]),
            issuance_txid: [6; 32],
            contract_script: vec![0x51],
            contract_data: None,
            supply: 1,
            created_at_block: 1,
        })
        .await
        .unwrap();
    database
        .network_assets()
        .insert_active(&NetworkAsset {
            kind: ORACLE_VERIFIER_KIND.to_string(),
            name: "Oracle Verifier".to_string(),
            asset_id: ORACLE_VERIFIER_ASSET_ID,
            reissuance_token_id: Some([7; 32]),
            entropy: Some([8; 32]),
            issuance_txid: [9; 32],
            contract_script: vec![0x51],
            contract_data: None,
            supply: 0,
            created_at_block: 1,
        })
        .await
        .unwrap();

    let operator_secret = secp256k1::SecretKey::from_slice(&[42; 32]).unwrap();
    let operator_private_key = PrivateKey::new(operator_secret, Network::Regtest);
    let compressed_operator_public_key = operator_private_key
        .public_key(&secp256k1::Secp256k1::new())
        .inner
        .serialize();
    let operator_public_key = secp256k1::PublicKey::from_slice(&compressed_operator_public_key)
        .unwrap()
        .x_only_public_key()
        .0
        .serialize();
    operators.add(compressed_operator_public_key).await.unwrap();

    let node_secret = SecretKey::from_slice(&NODE_KEY).unwrap();
    let storm = Storm::from_peers(node_secret, vec![Peer::new(node_public_key())]);
    let node = HighStorm::new(
        storm,
        node_secret.secret_bytes(),
        coordinator_public_key,
        crate::high_storm::HighStormDependencies::new(
            database.network(),
            database.voting(),
            database.network_assets(),
            database.monitored_utxos(),
            database.droplets(),
            database.user_requests(),
            database.price_attestations(),
            crate::config::ElementsRpcConfig {
                url: "http://127.0.0.1:18884".to_string(),
                username: "unused".to_string(),
                password: "unused".to_string(),
                wallet: "unused".to_string(),
            },
            crate::config::ProtocolConfig {
                operational_fee_sats: 1_000,
                tick_burn_reserve_sats: 1_000,
                issuance_transaction_fee_sats: 1_000,
                burn_transaction_fee_sats: 500,
                exchange_transaction_fee_sats: 500,
                tick_lifetime_blocks: 60,
                finality_confirmations: 2,
            },
        ),
    )
    .await;

    let app = router(
        node.handle(),
        operators,
        database.user_requests(),
        FeeUtxoValidator::allow_all(database.monitored_utxos()),
        AuthNetwork::ElementsRegtest,
    );

    (
        app,
        node,
        operator_private_key,
        hex::encode(operator_public_key),
        database,
    )
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn json_request(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn signed_request(
    private_key: &PrivateKey,
    public_key: &str,
    path: &str,
    timestamp: u64,
    nonce: &str,
    payload: serde_json::Value,
) -> Request<Body> {
    let message = AuthService::write_message("POST", path, timestamp, nonce, &payload).unwrap();
    json_request(
        path,
        serde_json::json!({
            "public_key": public_key,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": sign(private_key, &message),
            "payload": payload,
        }),
    )
}

fn signed_user_request(kind: &str, auth_kind: &str) -> NetworkUserRequests {
    signed_batch(&[(kind, auth_kind, None)])
}

fn signed_price_request(feed: FeedId) -> NetworkUserRequests {
    signed_batch(&[("signed-price-data", "signature-auth", Some(feed))])
}

/// A batch of `(kind, authentication method, feed it is issued at)`.
fn signed_batch(requests: &[(&str, &str, Option<FeedId>)]) -> NetworkUserRequests {
    let secret_key = SchnorrSecretKey::from_secret_bytes([31; 32]).unwrap();
    let keypair = SchnorrKeypair::from_secret_key(&secret_key);
    let public_key = keypair.x_only_public_key().0.serialize();
    let requests = requests
        .iter()
        .map(|(kind, auth_kind, feed)| {
            let mut payload = serde_json::json!({
                "utxo_auth_method": {
                    "kind": auth_kind,
                    "auth_data": hex::encode(public_key),
                }
            });
            if let Some(feed) = feed {
                payload["price_feed_id"] = serde_json::json!(feed);
            }
            UserRequest {
                kind: kind.to_string(),
                payload: payload.to_string(),
            }
        })
        .collect();
    let mut request = NetworkUserRequests {
        header: UserRequestHeader {
            signature: String::new(),
            public_key: hex::encode(public_key),
            fee_utxos: vec![format!("{}:3", hex::encode([8; 32]))],
            signature_scheme: None,
            signing_public_key: None,
        },
        requests,
    };
    request.header.signature =
        hex::encode(schnorr::sign(&signing_hash(&request), &keypair).to_byte_array());
    request
}

#[test]
fn humid_user_request_verification_binds_request_and_owner() {
    let private_key = PrivateKey::new(
        secp256k1::SecretKey::from_slice(&[31; 32]).unwrap(),
        Network::Regtest,
    );
    let mut request = signed_user_request("tick-utxo", "scriptPubKey-auth");
    request.header.signature_scheme = Some(super::users::HUMID_USER_SIGNATURE_SCHEME.into());
    request.header.signing_public_key = Some(hex::encode(
        private_key
            .public_key(&secp256k1::Secp256k1::new())
            .inner
            .serialize(),
    ));
    request.header.signature = sign_humid(
        &private_key,
        &super::users::humid_signing_message(&request)
            .map_err(|error| error.message)
            .unwrap(),
    );
    let verify = |value: &NetworkUserRequests| {
        super::users::validate_encoded_request(&serde_json::to_vec(value).unwrap())
    };
    assert!(verify(&request).is_ok());
    let mut changed = request.clone();
    changed.header.fee_utxos[0] = format!("{}:4", hex::encode([8; 32]));
    assert!(verify(&changed).is_err());
    let mut changed = request.clone();
    changed.requests[0].payload = changed.requests[0]
        .payload
        .replace("scriptPubKey-auth", "asset-id-auth");
    assert!(verify(&changed).is_err());
    let mut changed = request.clone();
    changed.header.signing_public_key = Some(hex::encode(
        PrivateKey::new(
            secp256k1::SecretKey::from_slice(&[32; 32]).unwrap(),
            Network::Regtest,
        )
        .public_key(&secp256k1::Secp256k1::new())
        .inner
        .serialize(),
    ));
    assert!(verify(&changed).is_err());
    let mut changed = request.clone();
    changed.header.signature_scheme = Some("unsupported".into());
    assert!(verify(&changed).is_err());
    let mut changed = request.clone();
    changed.header.signature_scheme = None;
    assert!(verify(&changed).is_err());
    assert!(verify(&signed_user_request("tick-utxo", "signature-auth")).is_ok());
}

fn user_request(request: &NetworkUserRequests) -> Request<Body> {
    json_request("/users/requests", serde_json::to_value(request).unwrap())
}

async fn response_json(response: Response) -> serde_json::Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn sign(private_key: &PrivateKey, message: &str) -> String {
    let public_key = private_key
        .public_key(&secp256k1::Secp256k1::new())
        .inner
        .x_only_public_key()
        .0;
    bip322::sign_simple_encoded(
        &Address::p2tr(
            &secp256k1::Secp256k1::new(),
            public_key,
            None,
            Network::Regtest,
        )
        .to_string(),
        message,
        &[private_key.to_wif()],
        None,
    )
    .unwrap()
}

fn sign_humid(private_key: &PrivateKey, message: &str) -> String {
    let message = Message::from_digest(signed_msg_hash(message).to_byte_array());
    let signature =
        secp256k1::Secp256k1::signing_only().sign_ecdsa_recoverable(&message, &private_key.inner);
    let (recovery_id, compact) = signature.serialize_compact();
    let mut encoded = Vec::from(compact);
    encoded.push(recovery_id.to_i32() as u8);
    hex::encode(encoded)
}
