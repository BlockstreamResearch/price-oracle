use bitcoin::{
    Network, PrivateKey,
    secp256k1::{self, Secp256k1},
};

use crate::{
    db::Database,
    external_api::tests::{sign, sign_humid},
};

use super::*;

#[test]
fn signed_writes_display_the_full_canonical_payload_for_both_schemes() {
    let payload = canonical_json(&serde_json::json!({"b": 2, "a": 1})).unwrap();

    for scheme in [SignatureScheme::Bip322V1, SignatureScheme::HumidEcdsaV1] {
        let message = write_message(scheme, "post", "/operators/voting", 123, "nonce", &payload);

        assert_eq!(
            message,
            format!(
                "high-storm:operator-write:v3\nSignature scheme: {}\nMethod: POST\nPath: /operators/voting\nTimestamp (Unix seconds): 123\nNonce: nonce\nPayload SHA-256: 43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777\n\nPayload JSON:\n{{\n  \"a\": 1,\n  \"b\": 2\n}}",
                scheme.as_str()
            )
        );
    }
}

#[tokio::test]
async fn rejects_changed_display_fields_and_hash_only_signatures() {
    let (auth, private_key, xonly_public_key) = setup().await;
    let payload = canonical_json(&serde_json::json!({
        "amount": 100,
        "withdrawal_address": "operator-destination"
    }))
    .unwrap();

    for scheme in [SignatureScheme::Bip322V1, SignatureScheme::HumidEcdsaV1] {
        let public_key = match scheme {
            SignatureScheme::Bip322V1 => xonly_public_key.clone(),
            SignatureScheme::HumidEcdsaV1 => {
                hex::encode(private_key.public_key(&Secp256k1::new()).inner.serialize())
            }
        };
        let message = write_message(
            scheme,
            "POST",
            "/operators/droplets/exchange",
            1_000,
            "nonce",
            &payload,
        );
        let hash_only = match scheme {
            SignatureScheme::Bip322V1 => format!(
                "high-storm:operator-write:v1\nPOST\n/operators/droplets/exchange\n1000\nnonce\n{}",
                hex::encode(Sha256::digest(&payload))
            ),
            SignatureScheme::HumidEcdsaV1 => format!(
                "high-storm:operator-write:v2\n{}\nPOST\n/operators/droplets/exchange\n1000\nnonce\n{}",
                scheme.as_str(),
                hex::encode(Sha256::digest(&payload))
            ),
        };

        for altered in [
            message.replace("operator-destination", "attacker-destination"),
            message.replace("\"amount\": 100", "\"amount\": 999"),
            hash_only,
        ] {
            let signature = match scheme {
                SignatureScheme::Bip322V1 => sign(&private_key, &altered),
                SignatureScheme::HumidEcdsaV1 => sign_humid(&private_key, &altered),
            };

            assert!(matches!(
                auth.verify_write_for_scheme_at(
                    &public_key,
                    1_000,
                    "nonce",
                    &signature,
                    scheme,
                    "POST",
                    "/operators/droplets/exchange",
                    &payload,
                    1_000,
                )
                .await,
                Err(AuthError::InvalidSignature)
            ));
        }
    }
}

#[tokio::test]
async fn exchanges_a_real_bip322_proof_for_a_one_time_token() {
    let (auth, private_key, public_key) = setup().await;
    let challenge = auth.issue_challenge_at(&public_key, 1_000).await.unwrap();
    assert_eq!(challenge.network, AuthNetwork::ElementsRegtest);
    let signature = sign(&private_key, &challenge.message);

    let access = auth
        .exchange_token_at(&public_key, &challenge.message, &signature, 1_001)
        .await
        .unwrap();
    assert_eq!(
        auth.authenticate_token_at(&access.token, 1_002)
            .await
            .unwrap(),
        public_key
    );
    assert!(matches!(
        auth.exchange_token_at(&public_key, &challenge.message, &signature, 1_003)
            .await,
        Err(AuthError::InvalidChallenge)
    ));
}

#[tokio::test]
async fn exchanges_a_humid_ecdsa_proof_and_verifies_a_write() {
    let (auth, private_key, _) = setup().await;
    let public_key = hex::encode(private_key.public_key(&Secp256k1::new()).inner.serialize());
    let scheme = SignatureScheme::HumidEcdsaV1;
    let challenge = auth
        .issue_challenge_for_scheme_at(&public_key, scheme, 1_000)
        .await
        .unwrap();
    assert_eq!(challenge.signature_scheme, HUMID_ECDSA_SCHEME);
    assert!(
        challenge
            .message
            .starts_with("high-storm:operator-auth:v2\nbitcoin-signed-message-ecdsa-v1\n")
    );

    let signature = sign_humid(&private_key, &challenge.message);
    let access = auth
        .exchange_token_for_scheme_at(&public_key, &challenge.message, &signature, scheme, 1_001)
        .await
        .unwrap();
    assert_eq!(
        auth.authenticate_token_at(&access.token, 1_002)
            .await
            .unwrap(),
        public_key
    );

    let payload = serde_json::json!({"kind": "split_storm_eye"});
    let encoded = serde_json::to_vec(&payload).unwrap();
    let message = write_message(
        scheme,
        "POST",
        "/operators/voting",
        1_002,
        "humid-nonce",
        &encoded,
    );
    let signature = sign_humid(&private_key, &message);

    auth.verify_write_for_scheme_at(
        &public_key,
        1_002,
        "humid-nonce",
        &signature,
        scheme,
        "POST",
        "/operators/voting",
        &encoded,
        1_002,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_compressed_operator_public_keys() {
    let (auth, private_key, _) = setup().await;
    let compressed_public_key = private_key
        .public_key(&secp256k1::Secp256k1::new())
        .inner
        .serialize();

    assert!(matches!(
        auth.issue_challenge_at(&hex::encode(compressed_public_key), 1_000)
            .await,
        Err(AuthError::InvalidPublicKey)
    ));
}

#[tokio::test]
async fn reuses_one_live_challenge_per_operator() {
    let (auth, _, public_key) = setup().await;

    let first = auth.issue_challenge_at(&public_key, 1_000).await.unwrap();
    let repeated = auth.issue_challenge_at(&public_key, 1_001).await.unwrap();
    assert_eq!(repeated.message, first.message);
    assert_eq!(repeated.expires_at, first.expires_at);
    assert_eq!(auth.state.lock().await.challenges.len(), 1);

    let replacement = auth.issue_challenge_at(&public_key, 1_300).await.unwrap();
    assert_ne!(replacement.message, first.message);
    assert_eq!(auth.state.lock().await.challenges.len(), 1);
}

#[tokio::test]
async fn rejects_replayed_signed_writes() {
    let (auth, private_key, public_key) = setup().await;
    let payload = serde_json::json!({"kind": "split_storm_eye"});
    let message =
        AuthService::write_message("POST", "/operators/voting", 1_000, "unique-nonce", &payload)
            .unwrap();
    let signature = sign(&private_key, &message);
    let encoded = serde_json::to_vec(&payload).unwrap();

    auth.verify_write_at(
        &public_key,
        1_000,
        "unique-nonce",
        &signature,
        "POST",
        "/operators/voting",
        &encoded,
        1_000,
    )
    .await
    .unwrap();
    assert!(matches!(
        auth.verify_write_at(
            &public_key,
            1_000,
            "unique-nonce",
            &signature,
            "POST",
            "/operators/voting",
            &encoded,
            1_300,
        )
        .await,
        Err(AuthError::ReplayedNonce)
    ));
}

#[tokio::test]
async fn retains_nonces_for_future_skewed_request_lifetime() {
    let (auth, private_key, public_key) = setup().await;
    let payload = serde_json::json!({"kind": "split_storm_eye"});
    let message = AuthService::write_message(
        "POST",
        "/operators/voting",
        1_300,
        "future-skewed-nonce",
        &payload,
    )
    .unwrap();
    let signature = sign(&private_key, &message);
    let encoded = serde_json::to_vec(&payload).unwrap();

    auth.verify_write_at(
        &public_key,
        1_300,
        "future-skewed-nonce",
        &signature,
        "POST",
        "/operators/voting",
        &encoded,
        1_001,
    )
    .await
    .unwrap();
    assert!(matches!(
        auth.verify_write_at(
            &public_key,
            1_300,
            "future-skewed-nonce",
            &signature,
            "POST",
            "/operators/voting",
            &encoded,
            1_600,
        )
        .await,
        Err(AuthError::ReplayedNonce)
    ));
}

async fn setup() -> (AuthService, PrivateKey, String) {
    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let operators = database.node_operators();

    let secret_key = secp256k1::SecretKey::from_slice(&[42; 32]).unwrap();
    let private_key = PrivateKey::new(secret_key, Network::Regtest);
    let compressed_public_key = private_key
        .public_key(&secp256k1::Secp256k1::new())
        .inner
        .serialize();
    let public_key = secp256k1::PublicKey::from_slice(&compressed_public_key)
        .unwrap()
        .x_only_public_key()
        .0
        .serialize();
    operators.add(compressed_public_key).await.unwrap();

    (
        AuthService::new(operators, AuthNetwork::ElementsRegtest),
        private_key,
        hex::encode(public_key),
    )
}
