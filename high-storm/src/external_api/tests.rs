use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey, address::KnownHrp, secp256k1};
use http_body_util::BodyExt;
use secp256k1_zkp::{Secp256k1, SecretKey};
use storm::{Peer, Storm};
use tower::ServiceExt;

use crate::{HighStorm, db::Database};

use super::{operators::AuthService, router};

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

    let peers = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/operators/state/peers")
                .header(header::AUTHORIZATION, authorization)
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

    let users = app
        .oneshot(
            Request::builder()
                .uri("/users/pending")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(users.status(), StatusCode::NOT_IMPLEMENTED);
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
}

async fn setup() -> (Router, PrivateKey, String) {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let operators = database.node_operators();
    let operator_secret = secp256k1::SecretKey::from_slice(&[42; 32]).unwrap();
    let operator_private_key = PrivateKey::new(operator_secret, Network::Bitcoin);
    let operator_public_key = operator_private_key
        .public_key(&secp256k1::Secp256k1::new())
        .inner
        .serialize();
    operators.add(operator_public_key).await.unwrap();

    let node_secret = SecretKey::from_slice(&[21; 32]).unwrap();
    let node_public_key = node_secret.public_key(&Secp256k1::new()).serialize();
    let storm = Storm::from_peers(node_secret, vec![Peer::new(node_public_key)]);
    let node = HighStorm::new(
        storm,
        node_secret.secret_bytes(),
        node_public_key,
        database.voting(),
    )
    .await;
    (
        router(node.handle(), operators),
        operator_private_key,
        hex::encode(operator_public_key),
    )
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

async fn response_json(response: Response) -> serde_json::Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

fn sign(private_key: &PrivateKey, message: &str) -> String {
    let public_key =
        CompressedPublicKey::from_private_key(&secp256k1::Secp256k1::new(), private_key).unwrap();
    bip322::sign_simple_encoded(
        &Address::p2wpkh(&public_key, KnownHrp::Mainnet).to_string(),
        message,
        &[private_key.to_wif()],
        None,
    )
    .unwrap()
}
