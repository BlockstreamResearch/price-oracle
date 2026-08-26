pub mod auth;
mod dto;

use std::net::SocketAddr;

use auth::{AccessToken, AuthError, AuthService, Challenge, SignedRequest};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use dto::{VotingProposal, VotingResponse};
use serde::{Deserialize, Serialize};
use storm::PeerStatus;

use crate::{HighStormHandle, VotingError, db::node_operator::NodeOperatorStore};

#[derive(Clone)]
struct RestState {
    node: HighStormHandle,
    auth: AuthService,
}

pub struct RestServer {
    listener: tokio::net::TcpListener,
    router: Router,
}

impl RestServer {
    pub async fn bind(
        address: SocketAddr,
        node: HighStormHandle,
        operators: NodeOperatorStore,
    ) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(address).await?;
        Ok(Self {
            listener,
            router: router(node, operators),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> std::io::Result<()> {
        axum::serve(self.listener, self.router).await
    }
}

pub fn router(node: HighStormHandle, operators: NodeOperatorStore) -> Router {
    let state = RestState {
        node,
        auth: AuthService::new(operators),
    };
    Router::new()
        .nest(
            "/users",
            Router::new()
                .route("/", any(not_implemented))
                .route("/{*path}", any(not_implemented)),
        )
        .route("/operators/auth/challenge", post(issue_challenge))
        .route("/operators/auth/token", post(exchange_token))
        .route("/operators/state", get(get_network_state))
        .route("/operators/state/peers", get(get_network_peers))
        .route("/operators/voting", get(list_votings).post(create_voting))
        .route("/operators/voting/{hash}", get(get_voting))
        .route("/operators/voting/{hash}/approve", post(approve_voting))
        .with_state(state)
}

#[derive(Deserialize)]
struct ChallengeRequest {
    public_key: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct EmptyPayload {}

#[derive(Serialize)]
struct CreatedVoting {
    message_hash: String,
}

#[derive(Serialize)]
struct NetworkStateResponse {
    block_height: u64,
    local_public_key: String,
    coordinator_public_key: String,
    is_coordinator: bool,
    total_peers: usize,
    online_peers: usize,
    inactive_peers: usize,
    banned_peers: usize,
    pending_votings: usize,
    approved_votings: usize,
}

#[derive(Serialize)]
struct NetworkPeerResponse {
    public_key: String,
    socket_address: Option<String>,
    last_seen: Option<u64>,
    status: &'static str,
    is_local: bool,
    is_coordinator: bool,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

async fn issue_challenge(
    State(state): State<RestState>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<Challenge>, ApiError> {
    state
        .auth
        .issue_challenge(&request.public_key)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn exchange_token(
    State(state): State<RestState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<AccessToken>, ApiError> {
    state
        .auth
        .exchange_token(&request.public_key, &request.message, &request.signature)
        .await
        .map(Json)
        .map_err(Into::into)
}

async fn get_network_state(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<NetworkStateResponse>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    let peers = state.node.peers().await;
    let votings = state.node.voting_requests().await?;
    let coordinator_public_key = state.node.coordinator_public_key();
    let local_public_key = peers
        .iter()
        .find(|peer| peer.status == PeerStatus::Controlled)
        .map(|peer| peer.compressed_public_key)
        .ok_or_else(|| ApiError::internal("local peer is missing from the peer table"))?;
    let online_peers = peers
        .iter()
        .filter(|peer| matches!(peer.status, PeerStatus::Controlled | PeerStatus::Active))
        .count();
    let pending_votings = votings
        .iter()
        .filter(|voting| voting.status == crate::VotingStatus::Pending)
        .count();

    Ok(Json(NetworkStateResponse {
        block_height: state.node.block_height(),
        local_public_key: hex::encode(local_public_key),
        coordinator_public_key: hex::encode(coordinator_public_key),
        is_coordinator: local_public_key == coordinator_public_key,
        total_peers: peers.len(),
        online_peers,
        inactive_peers: peers
            .iter()
            .filter(|peer| peer.status == PeerStatus::Inactive)
            .count(),
        banned_peers: peers
            .iter()
            .filter(|peer| peer.status == PeerStatus::Banned)
            .count(),
        pending_votings,
        approved_votings: votings.len() - pending_votings,
    }))
}

async fn get_network_peers(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<Vec<NetworkPeerResponse>>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    let coordinator_public_key = state.node.coordinator_public_key();
    Ok(Json(
        state
            .node
            .peers()
            .await
            .into_iter()
            .map(|peer| NetworkPeerResponse {
                public_key: hex::encode(peer.compressed_public_key),
                socket_address: peer.socket_address,
                last_seen: peer.last_seen,
                status: peer_status_name(peer.status),
                is_local: peer.status == PeerStatus::Controlled,
                is_coordinator: peer.compressed_public_key == coordinator_public_key,
            })
            .collect(),
    ))
}

async fn list_votings(
    State(state): State<RestState>,
    headers: HeaderMap,
) -> Result<Json<Vec<VotingResponse>>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    state
        .node
        .voting_requests()
        .await?
        .into_iter()
        .map(VotingResponse::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
        .map_err(ApiError::internal)
}

async fn get_voting(
    State(state): State<RestState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Result<Json<VotingResponse>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    let hash = parse_hash(&hash)?;
    let voting = state
        .node
        .voting_request(hash)
        .await?
        .ok_or_else(|| ApiError::not_found("voting request does not exist"))?;
    VotingResponse::try_from(voting)
        .map(Json)
        .map_err(ApiError::internal)
}

async fn create_voting(
    State(state): State<RestState>,
    Json(request): Json<SignedRequest<VotingProposal>>,
) -> Result<(StatusCode, Json<CreatedVoting>), ApiError> {
    state
        .auth
        .verify_write(&request, "POST", "/operators/voting")
        .await?;
    let voting = request
        .payload
        .into_request()
        .map_err(ApiError::bad_request)?;
    let message_hash = state.node.create_voting_request(voting).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedVoting {
            message_hash: hex::encode(message_hash),
        }),
    ))
}

async fn approve_voting(
    State(state): State<RestState>,
    Path(hash): Path<String>,
    Json(request): Json<SignedRequest<EmptyPayload>>,
) -> Result<StatusCode, ApiError> {
    let path = format!("/operators/voting/{hash}/approve");
    state.auth.verify_write(&request, "POST", &path).await?;
    state
        .node
        .approve_voting_request(parse_hash(&hash)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate_bearer(auth: &AuthService, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    auth.authenticate_token(token).await?;
    Ok(())
}

fn parse_hash(encoded: &str) -> Result<[u8; 32], ApiError> {
    hex::decode(encoded)
        .map_err(|_| ApiError::bad_request("invalid voting request hash"))?
        .try_into()
        .map_err(|_| ApiError::bad_request("invalid voting request hash"))
}

fn peer_status_name(status: PeerStatus) -> &'static str {
    match status {
        PeerStatus::Controlled => "controlled",
        PeerStatus::Active => "active",
        PeerStatus::Inactive => "inactive",
        PeerStatus::Banned => "banned",
    }
}

async fn not_implemented() -> ApiError {
    ApiError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "user API is not implemented".to_string(),
    }
}

impl ApiError {
    fn bad_request(message: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn unauthorized(message: impl ToString) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    fn not_found(message: impl ToString) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    fn internal(message: impl ToString) -> Self {
        tracing::error!(error = %message.to_string(), "REST request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".to_string(),
        }
    }
}

impl From<AuthError> for ApiError {
    fn from(error: AuthError) -> Self {
        let status = match error {
            AuthError::InvalidPublicKey
            | AuthError::InvalidChallenge
            | AuthError::InvalidTimestamp
            | AuthError::InvalidNonce => StatusCode::BAD_REQUEST,
            AuthError::Unauthorized => StatusCode::FORBIDDEN,
            AuthError::ReplayedNonce => StatusCode::CONFLICT,
            AuthError::InvalidToken | AuthError::InvalidSignature => StatusCode::UNAUTHORIZED,
            AuthError::Clock | AuthError::Random | AuthError::Store(_) => {
                return Self::internal(error);
            }
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl From<VotingError> for ApiError {
    fn from(error: VotingError) -> Self {
        let status = match error {
            VotingError::InvalidRequest(_) | VotingError::InvalidApproval(_) => {
                StatusCode::BAD_REQUEST
            }
            VotingError::UnknownRequest(_) => StatusCode::NOT_FOUND,
            VotingError::DuplicateRequest(_) | VotingError::DuplicateApproval(_) => {
                StatusCode::CONFLICT
            }
            _ => return Self::internal(error),
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use bitcoin::{
        Address, CompressedPublicKey, Network, PrivateKey, address::KnownHrp, secp256k1,
    };
    use http_body_util::BodyExt;
    use secp256k1_zkp::{Secp256k1, SecretKey};
    use storm::{Peer, Storm};
    use tower::ServiceExt;

    use crate::{HighStorm, db::Database};

    use super::*;

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
            CompressedPublicKey::from_private_key(&secp256k1::Secp256k1::new(), private_key)
                .unwrap();
        bip322::sign_simple_encoded(
            &Address::p2wpkh(&public_key, KnownHrp::Mainnet).to_string(),
            message,
            &[private_key.to_wif()],
            None,
        )
        .unwrap()
    }
}
