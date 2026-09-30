use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State, http::HeaderMap};
use bitcoin::{
    Address, Network,
    hashes::Hash,
    secp256k1::{
        Message, PublicKey, Secp256k1, XOnlyPublicKey,
        ecdsa::{RecoverableSignature, RecoveryId},
    },
    sign_message::signed_msg_hash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simplex::provider::SimplicityNetwork;
use tokio::sync::Mutex;

use crate::{
    db::node_operator::NodeOperatorStore,
    external_api::{ApiError, ExternalApiState},
};

const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const WRITE_WINDOW: Duration = Duration::from_secs(5 * 60);
const HUMID_ECDSA_SCHEME: &str = "bitcoin-signed-message-ecdsa-v1";
const LIQUID_MAINNET_CHAIN_ID: &str = "bip122:1466275836220db2944ca059a3a10ef6";
const LIQUID_TESTNET_CHAIN_ID: &str = "bip122:a771da8e52ee6ad581ed1e9a99825e5b";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SignatureScheme {
    Bip322V1,
    HumidEcdsaV1,
}

impl SignatureScheme {
    fn from_request(value: Option<&str>) -> Result<Self, AuthError> {
        match value {
            None => Ok(Self::Bip322V1),
            Some(HUMID_ECDSA_SCHEME) => Ok(Self::HumidEcdsaV1),
            Some(_) => Err(AuthError::InvalidSignatureScheme),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Bip322V1 => "bip322-v1",
            Self::HumidEcdsaV1 => HUMID_ECDSA_SCHEME,
        }
    }
}

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
    #[error("operator signature is invalid")]
    InvalidSignature,
    #[error("signature scheme is invalid or unsupported")]
    InvalidSignatureScheme,
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
    pub network: AuthNetwork,
    pub signature_scheme: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccessToken {
    pub token: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthConfig {
    pub network: AuthNetwork,
    pub caip2_chain_id: Option<&'static str>,
    pub signature_scheme: &'static str,
    pub descriptor_type: &'static str,
    pub descriptor_format: &'static str,
    pub identity_derivation: IdentityDerivation,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityDerivation {
    pub branch: u32,
    pub index: u32,
}

#[derive(Deserialize)]
pub(super) struct ChallengeRequest {
    public_key: String,
    signature_scheme: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct TokenRequest {
    public_key: String,
    message: String,
    signature: String,
    signature_scheme: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SignedRequest<T> {
    pub(super) public_key: String,
    pub(super) signature_scheme: Option<String>,
    pub(super) timestamp: u64,
    pub(super) nonce: String,
    pub(super) signature: String,
    pub(super) payload: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AuthNetwork {
    LiquidV1,
    LiquidTestnet,
    ElementsRegtest,
}

impl AuthNetwork {
    pub(crate) fn from_chain(chain: &str) -> Option<Self> {
        match chain {
            "liquidv1" => Some(Self::LiquidV1),
            "liquidtestnet" => Some(Self::LiquidTestnet),
            "elementsregtest" => Some(Self::ElementsRegtest),
            _ => None,
        }
    }

    fn bitcoin_network(self) -> Network {
        match self {
            Self::LiquidV1 => Network::Bitcoin,
            Self::LiquidTestnet => Network::Testnet,
            Self::ElementsRegtest => Network::Regtest,
        }
    }

    fn caip2_chain_id(self) -> Option<&'static str> {
        match self {
            Self::LiquidV1 => Some(LIQUID_MAINNET_CHAIN_ID),
            Self::LiquidTestnet => Some(LIQUID_TESTNET_CHAIN_ID),
            Self::ElementsRegtest => None,
        }
    }

    pub(crate) fn simplicity_network(self) -> SimplicityNetwork {
        match self {
            Self::LiquidV1 => SimplicityNetwork::Liquid,
            Self::LiquidTestnet => SimplicityNetwork::LiquidTestnet,
            Self::ElementsRegtest => SimplicityNetwork::default_regtest(),
        }
    }
}

#[derive(Clone)]
pub struct AuthService {
    operators: NodeOperatorStore,
    network: AuthNetwork,
    state: Arc<Mutex<AuthState>>,
}

#[derive(Default)]
struct AuthState {
    challenges: HashMap<String, ExpiringOperator>,
    tokens: HashMap<String, ExpiringOperator>,
    nonces: HashMap<(String, SignatureScheme, String), u64>,
}

struct ExpiringOperator {
    public_key: String,
    signature_scheme: SignatureScheme,
    expires_at: u64,
}

impl AuthService {
    pub fn new(operators: NodeOperatorStore, network: AuthNetwork) -> Self {
        Self {
            operators,
            network,
            state: Arc::new(Mutex::new(AuthState::default())),
        }
    }

    pub(crate) fn network(&self) -> AuthNetwork {
        self.network
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

        let signature_scheme = SignatureScheme::from_request(request.signature_scheme.as_deref())?;

        self.verify_write_for_scheme_at(
            &request.public_key,
            request.timestamp,
            &request.nonce,
            &request.signature,
            signature_scheme,
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
        Ok(write_message(
            SignatureScheme::Bip322V1,
            method,
            path,
            timestamp,
            nonce,
            &payload,
        ))
    }

    #[cfg(test)]
    async fn issue_challenge_at(&self, public_key: &str, now: u64) -> Result<Challenge, AuthError> {
        self.issue_challenge_for_scheme_at(public_key, SignatureScheme::Bip322V1, now)
            .await
    }

    async fn issue_challenge_for_scheme_at(
        &self,
        public_key: &str,
        signature_scheme: SignatureScheme,
        now: u64,
    ) -> Result<Challenge, AuthError> {
        let (public_key, parsed_key) = parse_public_key(public_key, signature_scheme)?;
        self.require_operator(parsed_key).await?;

        let message = challenge_message(signature_scheme, &public_key, &random_hex()?);
        let expires_at = now + CHALLENGE_TTL.as_secs();

        let mut state = self.state.lock().await;
        state.cleanup(now);
        if let Some((message, challenge)) = state.challenges.iter().find(|(_, challenge)| {
            challenge.public_key == public_key && challenge.signature_scheme == signature_scheme
        }) {
            return Ok(Challenge {
                message: message.clone(),
                expires_at: challenge.expires_at,
                network: self.network,
                signature_scheme: signature_scheme.as_str().to_string(),
            });
        }
        state.challenges.insert(
            message.clone(),
            ExpiringOperator {
                public_key,
                signature_scheme,
                expires_at,
            },
        );

        Ok(Challenge {
            message,
            expires_at,
            network: self.network,
            signature_scheme: signature_scheme.as_str().to_string(),
        })
    }

    #[cfg(test)]
    async fn exchange_token_at(
        &self,
        public_key: &str,
        message: &str,
        signature: &str,
        now: u64,
    ) -> Result<AccessToken, AuthError> {
        self.exchange_token_for_scheme_at(
            public_key,
            message,
            signature,
            SignatureScheme::Bip322V1,
            now,
        )
        .await
    }

    async fn exchange_token_for_scheme_at(
        &self,
        public_key: &str,
        message: &str,
        signature: &str,
        signature_scheme: SignatureScheme,
        now: u64,
    ) -> Result<AccessToken, AuthError> {
        let (public_key, parsed_key) = parse_public_key(public_key, signature_scheme)?;
        self.require_operator(parsed_key).await?;

        {
            let mut state = self.state.lock().await;
            state.cleanup(now);
            let challenge = state
                .challenges
                .get(message)
                .ok_or(AuthError::InvalidChallenge)?;
            if challenge.public_key != public_key || challenge.signature_scheme != signature_scheme
            {
                return Err(AuthError::InvalidChallenge);
            }
        }

        verify_signature(parsed_key, self.network, message, signature)?;

        let mut state = self.state.lock().await;
        let challenge = state
            .challenges
            .remove(message)
            .ok_or(AuthError::InvalidChallenge)?;
        if challenge.public_key != public_key
            || challenge.signature_scheme != signature_scheme
            || challenge.expires_at <= now
        {
            return Err(AuthError::InvalidChallenge);
        }

        let token = random_hex()?;
        let expires_at = now + TOKEN_TTL.as_secs();
        state.tokens.insert(
            token.clone(),
            ExpiringOperator {
                public_key,
                signature_scheme,
                expires_at,
            },
        );

        Ok(AccessToken { token, expires_at })
    }

    async fn authenticate_token_at(&self, token: &str, now: u64) -> Result<String, AuthError> {
        let (public_key, signature_scheme) = {
            let mut state = self.state.lock().await;
            state.cleanup(now);
            state
                .tokens
                .get(token)
                .map(|token| (token.public_key.clone(), token.signature_scheme))
                .ok_or(AuthError::InvalidToken)?
        };

        let (_, parsed_key) = parse_public_key(&public_key, signature_scheme)?;
        self.require_operator(parsed_key).await?;

        Ok(public_key)
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
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
        self.verify_write_for_scheme_at(
            public_key,
            timestamp,
            nonce,
            signature,
            SignatureScheme::Bip322V1,
            method,
            path,
            payload,
            now,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_write_for_scheme_at(
        &self,
        public_key: &str,
        timestamp: u64,
        nonce: &str,
        signature: &str,
        signature_scheme: SignatureScheme,
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

        let (public_key, parsed_key) = parse_public_key(public_key, signature_scheme)?;
        self.require_operator(parsed_key).await?;

        let message = write_message(signature_scheme, method, path, timestamp, nonce, payload);
        verify_signature(parsed_key, self.network, &message, signature)?;

        let mut state = self.state.lock().await;
        state.cleanup(now);
        let nonce_expires_at = timestamp
            .saturating_add(WRITE_WINDOW.as_secs())
            .saturating_add(1);
        if state
            .nonces
            .insert(
                (public_key.clone(), signature_scheme, nonce.to_string()),
                nonce_expires_at,
            )
            .is_some()
        {
            return Err(AuthError::ReplayedNonce);
        }

        Ok(public_key)
    }

    async fn require_operator(&self, public_key: OperatorPublicKey) -> Result<(), AuthError> {
        let authorized = match public_key {
            OperatorPublicKey::XOnly(public_key) => {
                self.operators.contains_xonly(public_key).await?
            }
            OperatorPublicKey::Compressed(public_key) => {
                self.operators.contains(public_key).await?
            }
        };

        if authorized {
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
    let signature_scheme = SignatureScheme::from_request(request.signature_scheme.as_deref())?;

    state
        .auth
        .issue_challenge_for_scheme_at(&request.public_key, signature_scheme, unix_time()?)
        .await
        .map(Json)
        .map_err(Into::into)
}

pub(super) async fn get_config(State(state): State<ExternalApiState>) -> Json<AuthConfig> {
    Json(AuthConfig {
        network: state.auth.network(),
        caip2_chain_id: state.auth.network().caip2_chain_id(),
        signature_scheme: HUMID_ECDSA_SCHEME,
        descriptor_type: "publicWalletDescriptor",
        descriptor_format: "bip380-split-branches",
        identity_derivation: IdentityDerivation {
            branch: 0,
            index: 0,
        },
    })
}

pub(super) async fn exchange_token(
    State(state): State<ExternalApiState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<AccessToken>, ApiError> {
    let signature_scheme = SignatureScheme::from_request(request.signature_scheme.as_deref())?;

    state
        .auth
        .exchange_token_for_scheme_at(
            &request.public_key,
            &request.message,
            &request.signature,
            signature_scheme,
            unix_time()?,
        )
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

#[derive(Clone, Copy)]
enum OperatorPublicKey {
    XOnly([u8; 32]),
    Compressed([u8; 33]),
}

fn parse_public_key(
    encoded: &str,
    signature_scheme: SignatureScheme,
) -> Result<(String, OperatorPublicKey), AuthError> {
    let bytes = hex::decode(encoded).map_err(|_| AuthError::InvalidPublicKey)?;

    match signature_scheme {
        SignatureScheme::Bip322V1 => {
            let public_key =
                XOnlyPublicKey::from_slice(&bytes).map_err(|_| AuthError::InvalidPublicKey)?;
            let bytes = public_key.serialize();
            Ok((hex::encode(bytes), OperatorPublicKey::XOnly(bytes)))
        }
        SignatureScheme::HumidEcdsaV1 => {
            let public_key =
                PublicKey::from_slice(&bytes).map_err(|_| AuthError::InvalidPublicKey)?;
            let bytes = public_key.serialize();
            Ok((hex::encode(bytes), OperatorPublicKey::Compressed(bytes)))
        }
    }
}

fn verify_signature(
    public_key: OperatorPublicKey,
    network: AuthNetwork,
    message: &str,
    signature: &str,
) -> Result<(), AuthError> {
    match public_key {
        OperatorPublicKey::XOnly(public_key) => {
            let public_key =
                XOnlyPublicKey::from_slice(&public_key).map_err(|_| AuthError::InvalidPublicKey)?;
            let address = Address::p2tr(
                &Secp256k1::verification_only(),
                public_key,
                None,
                network.bitcoin_network(),
            );
            bip322::verify_simple_encoded(&address.to_string(), message, signature)
                .map_err(|_| AuthError::InvalidSignature)
        }
        OperatorPublicKey::Compressed(expected_public_key) => {
            let signature_bytes: [u8; 65] = hex::decode(signature)
                .map_err(|_| AuthError::InvalidSignature)?
                .try_into()
                .map_err(|_| AuthError::InvalidSignature)?;
            let recovery_id = RecoveryId::from_i32(i32::from(signature_bytes[64]))
                .map_err(|_| AuthError::InvalidSignature)?;
            let signature = RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id)
                .map_err(|_| AuthError::InvalidSignature)?;
            let message = Message::from_digest(signed_msg_hash(message).to_byte_array());
            let recovered = Secp256k1::verification_only()
                .recover_ecdsa(&message, &signature)
                .map_err(|_| AuthError::InvalidSignature)?;

            if recovered.serialize() == expected_public_key {
                Ok(())
            } else {
                Err(AuthError::InvalidSignature)
            }
        }
    }
}

fn challenge_message(signature_scheme: SignatureScheme, public_key: &str, nonce: &str) -> String {
    match signature_scheme {
        SignatureScheme::Bip322V1 => {
            format!("high-storm:operator-auth:v1\n{public_key}\n{nonce}")
        }
        SignatureScheme::HumidEcdsaV1 => format!(
            "high-storm:operator-auth:v2\n{}\n{public_key}\n{nonce}",
            signature_scheme.as_str()
        ),
    }
}

fn write_message(
    signature_scheme: SignatureScheme,
    method: &str,
    path: &str,
    timestamp: u64,
    nonce: &str,
    payload: &[u8],
) -> String {
    let payload_hash = hex::encode(Sha256::digest(payload));

    match signature_scheme {
        SignatureScheme::Bip322V1 => format!(
            "high-storm:operator-write:v1\n{}\n{}\n{}\n{}\n{}",
            method.to_ascii_uppercase(),
            path,
            timestamp,
            nonce,
            payload_hash
        ),
        SignatureScheme::HumidEcdsaV1 => format!(
            "high-storm:operator-write:v2\n{}\n{}\n{}\n{}\n{}\n{}",
            signature_scheme.as_str(),
            method.to_ascii_uppercase(),
            path,
            timestamp,
            nonce,
            payload_hash
        ),
    }
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
    use bitcoin::{
        Network, PrivateKey,
        secp256k1::{self, Message, Secp256k1},
        sign_message::signed_msg_hash,
    };

    use crate::db::Database;

    use super::*;

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
            .exchange_token_for_scheme_at(
                &public_key,
                &challenge.message,
                &signature,
                scheme,
                1_001,
            )
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

    fn sign_humid(private_key: &PrivateKey, message: &str) -> String {
        let message = Message::from_digest(signed_msg_hash(message).to_byte_array());
        let signature =
            Secp256k1::signing_only().sign_ecdsa_recoverable(&message, &private_key.inner);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut encoded = Vec::from(compact);
        encoded.push(recovery_id.to_i32() as u8);
        hex::encode(encoded)
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
}
