use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State, http::HeaderMap};
use bitcoin::{Address, CompressedPublicKey, address::KnownHrp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    db::node_operator::NodeOperatorStore,
    external_api::{ApiError, ExternalApiState},
};

const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const WRITE_WINDOW: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid operator public key")]
    InvalidPublicKey,
    #[error("operator is not authorized")]
    Unauthorized,
    #[error("authentication challenge is invalid or expired")]
    InvalidChallenge,
    #[error("authentication token is invalid or expired")]
    InvalidToken,
    #[error("BIP322 signature is invalid")]
    InvalidSignature,
    #[error("signed request timestamp is outside the accepted window")]
    InvalidTimestamp,
    #[error("signed request nonce is invalid")]
    InvalidNonce,
    #[error("signed request nonce has already been used")]
    ReplayedNonce,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("secure random generation failed")]
    Random,
    #[error(transparent)]
    Store(#[from] crate::db::node_operator::Error),
}

#[derive(Clone, Debug, Serialize)]
pub struct Challenge {
    pub message: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessToken {
    pub token: String,
    pub expires_at: u64,
}

#[derive(Deserialize)]
pub(super) struct ChallengeRequest {
    public_key: String,
}

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Deserialize)]
pub(super) struct SignedRequest<T> {
    pub(super) public_key: String,
    pub(super) timestamp: u64,
    pub(super) nonce: String,
    pub(super) signature: String,
    pub(super) payload: T,
}

#[derive(Clone)]
pub struct AuthService {
    operators: NodeOperatorStore,
    state: Arc<Mutex<AuthState>>,
}

#[derive(Default)]
struct AuthState {
    challenges: HashMap<String, ExpiringOperator>,
    tokens: HashMap<String, ExpiringOperator>,
    nonces: HashMap<(String, String), u64>,
}

struct ExpiringOperator {
    public_key: String,
    expires_at: u64,
}

impl AuthService {
    pub fn new(operators: NodeOperatorStore) -> Self {
        Self {
            operators,
            state: Arc::new(Mutex::new(AuthState::default())),
        }
    }

    pub async fn issue_challenge(&self, public_key: &str) -> Result<Challenge, AuthError> {
        self.issue_challenge_at(public_key, unix_time()?).await
    }

    pub async fn exchange_token(
        &self,
        public_key: &str,
        message: &str,
        signature: &str,
    ) -> Result<AccessToken, AuthError> {
        self.exchange_token_at(public_key, message, signature, unix_time()?)
            .await
    }

    pub async fn authenticate_token(&self, token: &str) -> Result<String, AuthError> {
        self.authenticate_token_at(token, unix_time()?).await
    }

    pub(super) async fn verify_write<T: Serialize>(
        &self,
        request: &SignedRequest<T>,
        method: &str,
        path: &str,
    ) -> Result<String, AuthError> {
        let payload = canonical_json(&request.payload).map_err(|_| AuthError::InvalidSignature)?;

        self.verify_write_at(
            &request.public_key,
            request.timestamp,
            &request.nonce,
            &request.signature,
            method,
            path,
            &payload,
            unix_time()?,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) fn write_message<T: Serialize>(
        method: &str,
        path: &str,
        timestamp: u64,
        nonce: &str,
        payload: &T,
    ) -> Result<String, serde_json::Error> {
        let payload = canonical_json(payload)?;
        Ok(write_message(method, path, timestamp, nonce, &payload))
    }

    async fn issue_challenge_at(&self, public_key: &str, now: u64) -> Result<Challenge, AuthError> {
        let (public_key, bytes) = parse_public_key(public_key)?;
        self.require_operator(bytes).await?;

        let message = format!(
            "high-storm:operator-auth:v1\n{public_key}\n{}",
            random_hex()?
        );
        let expires_at = now + CHALLENGE_TTL.as_secs();

        let mut state = self.state.lock().await;
        state.cleanup(now);
        state.challenges.insert(
            message.clone(),
            ExpiringOperator {
                public_key,
                expires_at,
            },
        );

        Ok(Challenge {
            message,
            expires_at,
        })
    }

    async fn exchange_token_at(
        &self,
        public_key: &str,
        message: &str,
        signature: &str,
        now: u64,
    ) -> Result<AccessToken, AuthError> {
        let (public_key, bytes) = parse_public_key(public_key)?;
        self.require_operator(bytes).await?;

        {
            let mut state = self.state.lock().await;
            state.cleanup(now);
            let challenge = state
                .challenges
                .get(message)
                .ok_or(AuthError::InvalidChallenge)?;
            if challenge.public_key != public_key {
                return Err(AuthError::InvalidChallenge);
            }
        }

        verify_signature(bytes, message, signature)?;

        let mut state = self.state.lock().await;
        let challenge = state
            .challenges
            .remove(message)
            .ok_or(AuthError::InvalidChallenge)?;
        if challenge.public_key != public_key || challenge.expires_at <= now {
            return Err(AuthError::InvalidChallenge);
        }

        let token = random_hex()?;
        let expires_at = now + TOKEN_TTL.as_secs();
        state.tokens.insert(
            token.clone(),
            ExpiringOperator {
                public_key,
                expires_at,
            },
        );

        Ok(AccessToken { token, expires_at })
    }

    async fn authenticate_token_at(&self, token: &str, now: u64) -> Result<String, AuthError> {
        let public_key = {
            let mut state = self.state.lock().await;
            state.cleanup(now);
            state
                .tokens
                .get(token)
                .map(|token| token.public_key.clone())
                .ok_or(AuthError::InvalidToken)?
        };

        let (_, bytes) = parse_public_key(&public_key)?;
        self.require_operator(bytes).await?;

        Ok(public_key)
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_write_at(
        &self,
        public_key: &str,
        timestamp: u64,
        nonce: &str,
        signature: &str,
        method: &str,
        path: &str,
        payload: &[u8],
        now: u64,
    ) -> Result<String, AuthError> {
        if timestamp.abs_diff(now) > WRITE_WINDOW.as_secs() {
            return Err(AuthError::InvalidTimestamp);
        }
        if nonce.is_empty() || nonce.len() > 128 {
            return Err(AuthError::InvalidNonce);
        }

        let (public_key, bytes) = parse_public_key(public_key)?;
        self.require_operator(bytes).await?;

        let message = write_message(method, path, timestamp, nonce, payload);
        verify_signature(bytes, &message, signature)?;

        let mut state = self.state.lock().await;
        state.cleanup(now);
        if state
            .nonces
            .insert(
                (public_key.clone(), nonce.to_string()),
                now + WRITE_WINDOW.as_secs(),
            )
            .is_some()
        {
            return Err(AuthError::ReplayedNonce);
        }

        Ok(public_key)
    }

    async fn require_operator(&self, public_key: [u8; 33]) -> Result<(), AuthError> {
        if self.operators.contains(public_key).await? {
            Ok(())
        } else {
            Err(AuthError::Unauthorized)
        }
    }
}

pub(super) async fn issue_challenge(
    State(state): State<ExternalApiState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<Challenge>, ApiError> {
    state
        .auth
        .issue_challenge(&request.public_key)
        .await
        .map(Json)
        .map_err(Into::into)
}

pub(super) async fn exchange_token(
    State(state): State<ExternalApiState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<AccessToken>, ApiError> {
    state
        .auth
        .exchange_token(&request.public_key, &request.message, &request.signature)
        .await
        .map(Json)
        .map_err(Into::into)
}

pub(super) async fn authenticate_bearer(
    auth: &AuthService,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    auth.authenticate_token(token).await?;
    Ok(())
}

impl AuthState {
    fn cleanup(&mut self, now: u64) {
        self.challenges.retain(|_, value| value.expires_at > now);
        self.tokens.retain(|_, value| value.expires_at > now);
        self.nonces.retain(|_, expires_at| *expires_at > now);
    }
}

fn parse_public_key(encoded: &str) -> Result<(String, [u8; 33]), AuthError> {
    let bytes = hex::decode(encoded).map_err(|_| AuthError::InvalidPublicKey)?;
    let public_key =
        CompressedPublicKey::from_slice(&bytes).map_err(|_| AuthError::InvalidPublicKey)?;
    let bytes = public_key.to_bytes();
    Ok((hex::encode(bytes), bytes))
}

fn verify_signature(public_key: [u8; 33], message: &str, signature: &str) -> Result<(), AuthError> {
    let public_key =
        CompressedPublicKey::from_slice(&public_key).map_err(|_| AuthError::InvalidPublicKey)?;
    let address = Address::p2wpkh(&public_key, KnownHrp::Mainnet);
    bip322::verify_simple_encoded(&address.to_string(), message, signature)
        .map_err(|_| AuthError::InvalidSignature)
}

fn write_message(method: &str, path: &str, timestamp: u64, nonce: &str, payload: &[u8]) -> String {
    format!(
        "high-storm:operator-write:v1\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path,
        timestamp,
        nonce,
        hex::encode(Sha256::digest(payload))
    )
}

fn canonical_json<T: Serialize>(payload: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&serde_json::to_value(payload)?)
}

fn random_hex() -> Result<String, AuthError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| AuthError::Random)?;
    Ok(hex::encode(bytes))
}

fn unix_time() -> Result<u64, AuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AuthError::Clock)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Network, PrivateKey, secp256k1};

    use crate::db::Database;

    use super::*;

    #[tokio::test]
    async fn exchanges_a_real_bip322_proof_for_a_one_time_token() {
        let (auth, private_key, public_key) = setup().await;
        let challenge = auth.issue_challenge_at(&public_key, 1_000).await.unwrap();
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
    async fn rejects_replayed_signed_writes() {
        let (auth, private_key, public_key) = setup().await;
        let payload = serde_json::json!({"kind": "split_storm_eye"});
        let message = AuthService::write_message(
            "POST",
            "/operators/voting",
            1_000,
            "unique-nonce",
            &payload,
        )
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
            1_001,
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
                1_001,
            )
            .await,
            Err(AuthError::ReplayedNonce)
        ));
    }

    async fn setup() -> (AuthService, PrivateKey, String) {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let operators = database.node_operators();

        let secret_key = secp256k1::SecretKey::from_slice(&[42; 32]).unwrap();
        let private_key = PrivateKey::new(secret_key, Network::Bitcoin);
        let public_key = private_key
            .public_key(&secp256k1::Secp256k1::new())
            .inner
            .serialize();
        operators.add(public_key).await.unwrap();

        (
            AuthService::new(operators),
            private_key,
            hex::encode(public_key),
        )
    }

    fn sign(private_key: &PrivateKey, message: &str) -> String {
        bip322::sign_simple_encoded(
            &Address::p2wpkh(
                &CompressedPublicKey::from_private_key(&secp256k1::Secp256k1::new(), private_key)
                    .unwrap(),
                KnownHrp::Mainnet,
            )
            .to_string(),
            message,
            &[private_key.to_wif()],
            None,
        )
        .unwrap()
    }
}
