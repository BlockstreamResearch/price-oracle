pub(crate) mod fee_utxo;
mod operators;
mod prices;
#[cfg(test)]
mod tests;
pub(crate) mod users;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, HttpBody, to_bytes},
    extract::{ConnectInfo, Request, State, connect_info::Connected},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError},
};
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
};

use crate::{
    HighStormHandle, VotingError,
    db::{Database, node_operator::NodeOperatorStore, user_request::UserRequestStore},
};
use fee_utxo::{FeeUtxoValidationError, FeeUtxoValidator};
use operators::{AuthError, AuthService, auth::AuthNetwork};

const MAX_API_CONCURRENCY: usize = 32;
const MAX_API_CONNECTIONS: usize = 256;
const MAX_API_CONNECTIONS_PER_CLIENT: usize = 16;
const MAX_API_REQUESTS_PER_CLIENT: usize = 4;
const MAX_API_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_API_BODY_READS: usize = 128;
const API_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

struct ApiRequestLimits {
    concurrency: Semaphore,
    body_reads: Semaphore,
    clients: ClientLimits,
    overload_rejections: AtomicU64,
}

struct ClientLimits {
    concurrency: usize,
    clients: Mutex<HashMap<IpAddr, Weak<Semaphore>>>,
}

impl ClientLimits {
    fn new(concurrency: usize) -> Self {
        Self {
            concurrency,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(&self, address: IpAddr) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        let mut clients = self
            .clients
            .lock()
            .expect("API client limits lock poisoned");
        clients.retain(|_, limit| limit.strong_count() > 0);
        let address = address.to_canonical();
        let limit = clients
            .get(&address)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let limit = Arc::new(Semaphore::new(self.concurrency));
                clients.insert(address, Arc::downgrade(&limit));
                limit
            });
        limit.try_acquire_owned()
    }
}

#[derive(Clone, Copy)]
struct ApiClientAddress(SocketAddr);

impl Connected<axum::serve::IncomingStream<'_, LimitedListener>> for ApiClientAddress {
    fn connect_info(stream: axum::serve::IncomingStream<'_, LimitedListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

struct LimitedListener {
    listener: TcpListener,
    connections: Arc<Semaphore>,
    clients: ClientLimits,
}

impl LimitedListener {
    fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            connections: Arc::new(Semaphore::new(MAX_API_CONNECTIONS)),
            clients: ClientLimits::new(MAX_API_CONNECTIONS_PER_CLIENT),
        }
    }
}

impl axum::serve::Listener for LimitedListener {
    type Io = LimitedConnection;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = axum::serve::Listener::accept(&mut self.listener).await;
            let Ok(connection_permit) = self.connections.clone().try_acquire_owned() else {
                continue;
            };
            let Ok(client_permit) = self.clients.try_acquire(address.ip()) else {
                continue;
            };
            return (
                LimitedConnection {
                    stream,
                    _connection_permit: connection_permit,
                    _client_permit: client_permit,
                },
                address,
            );
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
}

struct LimitedConnection {
    stream: TcpStream,
    _connection_permit: OwnedSemaphorePermit,
    _client_permit: OwnedSemaphorePermit,
}

impl AsyncRead for LimitedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(context, buffers)
    }
}

#[derive(Clone)]
pub(super) struct ExternalApiState {
    pub(super) node: HighStormHandle,
    pub(super) auth: AuthService,
    pub(super) user_requests: UserRequestStore,
    pub(super) fee_utxos: FeeUtxoValidator,
}

pub struct ExternalApiServer {
    listener: tokio::net::TcpListener,
    router: Router,
}

impl ExternalApiServer {
    pub async fn bind(
        address: SocketAddr,
        node: HighStormHandle,
        database: &Database,
        elements_rpc: &crate::config::ElementsRpcConfig,
        protocol_config: &crate::config::ProtocolConfig,
    ) -> Result<Self, ExternalApiError> {
        let listener = tokio::net::TcpListener::bind(address).await?;
        let auth_network = detect_auth_network(elements_rpc.clone()).await?;
        let fee_utxos = FeeUtxoValidator::new(
            elements_rpc,
            database.network_assets(),
            database.monitored_utxos(),
            protocol_config,
        )?;
        Ok(Self {
            listener,
            router: router(
                node,
                database.node_operators(),
                database.user_requests(),
                fee_utxos,
                auth_network,
            ),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> std::io::Result<()> {
        axum::serve(
            LimitedListener::new(self.listener),
            self.router
                .into_make_service_with_connect_info::<ApiClientAddress>(),
        )
        .await
    }
}

pub(crate) fn router(
    node: HighStormHandle,
    operators: NodeOperatorStore,
    user_requests: UserRequestStore,
    fee_utxos: FeeUtxoValidator,
    auth_network: AuthNetwork,
) -> Router {
    let state = ExternalApiState {
        node,
        auth: AuthService::new(operators, auth_network),
        user_requests,
        fee_utxos,
    };
    with_request_limits(
        Router::new()
            .nest("/users", users::router())
            .nest("/operators", operators::router())
            .nest("/price-feeds", prices::router())
            .with_state(state),
    )
    .layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
    )
}

fn with_request_limits(router: Router) -> Router {
    router
        .layer(middleware::from_fn_with_state(
            Arc::new(ApiRequestLimits {
                concurrency: Semaphore::new(MAX_API_CONCURRENCY),
                body_reads: Semaphore::new(MAX_API_BODY_READS),
                clients: ClientLimits::new(MAX_API_REQUESTS_PER_CLIENT),
                overload_rejections: AtomicU64::new(0),
            }),
            limit_concurrency,
        ))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            API_REQUEST_TIMEOUT,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_API_BODY_BYTES))
}

async fn limit_concurrency(
    State(limits): State<Arc<ApiRequestLimits>>,
    request: Request,
    next: Next,
) -> Response {
    let _client_permit = match request.extensions().get::<ConnectInfo<ApiClientAddress>>() {
        Some(ConnectInfo(ApiClientAddress(address))) => {
            match limits.clients.try_acquire(address.ip()) {
                Ok(permit) => Some(permit),
                Err(_) => {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(ErrorBody {
                            error: "too many in-flight requests from this client".into(),
                        }),
                    )
                        .into_response();
                }
            }
        }
        None => None,
    };
    let body_permit = if request.body().is_end_stream() {
        None
    } else {
        match limits.body_reads.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return ApiError::unavailable("external API body-read limit reached")
                    .into_response();
            }
        }
    };
    let (parts, body) = request.into_parts();
    let bytes =
        match tokio::time::timeout(API_BODY_READ_TIMEOUT, to_bytes(body, MAX_API_BODY_BYTES)).await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => {
                use std::error::Error;
                let mut source = Some(&error as &(dyn Error + 'static));
                let mut too_large = false;
                while let Some(error) = source {
                    if error.is::<http_body_util::LengthLimitError>() {
                        too_large = true;
                        break;
                    }
                    source = error.source();
                }
                let status = if too_large {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                return (
                    status,
                    Json(ErrorBody {
                        error: "invalid request body".into(),
                    }),
                )
                    .into_response();
            }
            Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
        };
    drop(body_permit);
    let request = Request::from_parts(parts, Body::from(bytes));

    let Ok(_permit) = limits.concurrency.try_acquire() else {
        let rejected = limits
            .overload_rejections
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if rejected.is_power_of_two() {
            tracing::warn!(rejected, "external API concurrency limit reached");
        }
        return ApiError::unavailable("external API is busy; retry later").into_response();
    };
    next.run(request).await
}

#[derive(Debug, thiserror::Error)]
pub enum ExternalApiError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    FeeUtxoValidation(#[from] FeeUtxoValidationError),
    #[error(transparent)]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
    #[error("Elements chain detection task failed: {0}")]
    ChainDetectionTask(#[from] tokio::task::JoinError),
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
}

async fn detect_auth_network(
    elements_rpc: crate::config::ElementsRpcConfig,
) -> Result<AuthNetwork, ExternalApiError> {
    tokio::task::spawn_blocking(move || {
        let client = Client::new(
            &elements_rpc.url,
            Auth::UserPass(elements_rpc.username, elements_rpc.password),
        )?;
        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
        AuthNetwork::from_chain(&chain.chain)
            .ok_or_else(|| ExternalApiError::UnsupportedChain(chain.chain))
    })
    .await?
}

/// Only the coordinator serves the user API; the other members answer nothing.
async fn require_coordinator(state: &ExternalApiState) -> Result<(), ApiError> {
    if state.node.is_coordinator().await {
        Ok(())
    } else {
        Err(ApiError::unavailable("this node is not the coordinator"))
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub(super) struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub(super) fn bad_request(message: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    pub(super) fn unauthorized(message: impl ToString) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    pub(super) fn not_found(message: impl ToString) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    pub(super) fn conflict(message: impl ToString) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.to_string(),
        }
    }

    pub(super) fn unavailable(message: impl ToString) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.to_string(),
        }
    }

    pub(super) fn internal(message: impl ToString) -> Self {
        tracing::error!(error = %message.to_string(), "external API request failed");
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
            | AuthError::InvalidSignatureScheme
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
