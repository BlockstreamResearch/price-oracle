use ::secp256k1::{Keypair as SchnorrKeypair, SecretKey as SchnorrSecretKey, schnorr};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use bitcoin::{Address, Network, PrivateKey, secp256k1};
use http_body_util::BodyExt;
use secp256k1_zkp::{Secp256k1, SecretKey};
use simplex::simplicityhl::elements::AssetId;
use storm::{Peer, Storm};
use tower::ServiceExt;

use crate::{
    HighStorm, NetworkAsset,
    db::{
        Database,
        network_asset::{STORM_EYE_KIND, TICK_ASSET_KIND},
    },
};

use super::{
    fee_utxo::FeeUtxoValidator,
    operators::{AuthService, auth::AuthNetwork},
    router,
    users::{NetworkUserRequests, UserRequest, UserRequestHeader, signing_hash},
};

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

    let node_secret = SecretKey::from_slice(&[21; 32]).unwrap();
    let node_public_key = node_secret.public_key(&Secp256k1::new()).serialize();
    let storm = Storm::from_peers(node_secret, vec![Peer::new(node_public_key)]);
    let node = HighStorm::new(
        storm,
        node_secret.secret_bytes(),
        node_public_key,
        crate::high_storm::HighStormDependencies::new(
            database.network(),
            database.voting(),
            database.network_assets(),
            database.monitored_utxos(),
            database.droplets(),
            database.user_requests(),
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
            },
        ),
    )
    .await;

    (
        router(
            node.handle(),
            operators,
            database.user_requests(),
            FeeUtxoValidator::allow_all(database.monitored_utxos()),
            AuthNetwork::ElementsRegtest,
        ),
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
