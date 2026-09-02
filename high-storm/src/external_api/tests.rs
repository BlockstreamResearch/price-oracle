use ::secp256k1::{Keypair as SchnorrKeypair, SecretKey as SchnorrSecretKey, schnorr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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

use crate::{HighStorm, NetworkAsset, db::Database};

use super::{
    fee_utxo::{AcceptAllFeeUtxos, Error as FeeUtxoError, FeeUtxoValidator},
    operators::AuthService,
    router_with_fee_utxo_validator,
    users::{NetworkUserRequests, UserRequest, UserRequestHeader, signing_hash},
};

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
    assert_eq!(users.status(), StatusCode::NOT_FOUND);
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
async fn rejects_fee_utxos_reserved_by_another_user_request() {
    let (app, _, _) = setup().await;
    let first = signed_user_request("tick-utxo", "signature-auth");
    let mut second = first.clone();
    second.requests[0].payload.push(' ');
    sign_user_request(&mut second);

    let created = app.clone().oneshot(user_request(&first)).await.unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);

    let conflict = app.oneshot(user_request(&second)).await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        response_json(conflict).await,
        serde_json::json!({
            "error": format!(
                "fee UTXO '{}:3' is reserved by another user request",
                hex::encode([8; 32])
            )
        })
    );
}

#[tokio::test]
async fn validates_fee_utxos_before_storing_the_request() {
    let (app, _, _) = setup_with_fee_utxo_validator(Arc::new(RejectFeeUtxosOnce {
        rejected: AtomicBool::new(false),
    }))
    .await;
    let request = signed_user_request("tick-utxo", "signature-auth");

    let invalid = app.clone().oneshot(user_request(&request)).await.unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(invalid).await,
        serde_json::json!({
            "error": format!(
                "fee UTXO '{}:3' does not exist or is already spent",
                hex::encode([8; 32])
            )
        })
    );

    let created = app.oneshot(user_request(&request)).await.unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn rejects_unsupported_or_invalid_user_requests() {
    let (app, _, _) = setup().await;

    let price = signed_user_request("signed-price-data", "signature-auth");
    let response = app.clone().oneshot(user_request(&price)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

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

async fn setup() -> (Router, PrivateKey, String) {
    setup_with_fee_utxo_validator(Arc::new(AcceptAllFeeUtxos)).await
}

async fn setup_with_fee_utxo_validator(
    fee_utxo_validator: Arc<dyn FeeUtxoValidator>,
) -> (Router, PrivateKey, String) {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let operators = database.node_operators();
    database
        .network_assets()
        .insert_active(&NetworkAsset {
            kind: "storm-eye".to_string(),
            name: "Storm Eye".to_string(),
            asset_id: [1; 32],
            reissuance_token_id: None,
            entropy: None,
            issuance_txid: [2; 32],
            contract_script: vec![0x51],
            supply: 10_000,
            created_at_block: 1,
        })
        .await
        .unwrap();

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
        database.network_assets(),
    )
    .await;

    (
        router_with_fee_utxo_validator(
            node.handle(),
            operators,
            database.user_requests(),
            fee_utxo_validator,
        ),
        operator_private_key,
        hex::encode(operator_public_key),
    )
}

struct RejectFeeUtxosOnce {
    rejected: AtomicBool,
}

impl FeeUtxoValidator for RejectFeeUtxosOnce {
    fn validate(
        &self,
        fee_utxos: &[crate::db::user_request::FeeUtxo],
        _account_owner_pubkey: [u8; 32],
        _storm_eye_asset_id: [u8; 32],
    ) -> Result<(), FeeUtxoError> {
        if !self.rejected.swap(true, Ordering::SeqCst) {
            let fee_utxo = &fee_utxos[0];
            return Err(FeeUtxoError::Missing(format!(
                "{}:{}",
                hex::encode(fee_utxo.txid),
                fee_utxo.output_index
            )));
        }

        Ok(())
    }
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
    let secret_key = SchnorrSecretKey::from_secret_bytes([31; 32]).unwrap();
    let keypair = SchnorrKeypair::from_secret_key(&secret_key);
    let public_key = keypair.x_only_public_key().0.serialize();
    let payload = serde_json::json!({
        "utxo_auth_method": {
            "kind": auth_kind,
            "auth_data": hex::encode(public_key),
        }
    })
    .to_string();
    let mut request = NetworkUserRequests {
        header: UserRequestHeader {
            signature: String::new(),
            public_key: hex::encode(public_key),
            fee_utxos: vec![format!("{}:3", hex::encode([8; 32]))],
        },
        requests: vec![UserRequest {
            kind: kind.to_string(),
            payload,
        }],
    };
    request.header.signature =
        hex::encode(schnorr::sign(&signing_hash(&request), &keypair).to_byte_array());
    request
}

fn sign_user_request(request: &mut NetworkUserRequests) {
    let secret_key = SchnorrSecretKey::from_secret_bytes([31; 32]).unwrap();
    let keypair = SchnorrKeypair::from_secret_key(&secret_key);
    request.header.signature =
        hex::encode(schnorr::sign(&signing_hash(request), &keypair).to_byte_array());
}

fn user_request(request: &NetworkUserRequests) -> Request<Body> {
    json_request("/users/requests", serde_json::to_value(request).unwrap())
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
