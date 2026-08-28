mod operators;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::any,
};
use serde::Serialize;

use crate::{HighStormHandle, VotingError, db::node_operator::NodeOperatorStore};
use operators::{AuthError, AuthService};

#[derive(Clone)]
pub(super) struct ExternalApiState {
    pub(super) node: HighStormHandle,
    pub(super) auth: AuthService,
}

pub struct ExternalApiServer {
    listener: tokio::net::TcpListener,
    router: Router,
}

impl ExternalApiServer {
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
    let state = ExternalApiState {
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
        .nest("/operators", operators::router())
        .with_state(state)
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub(super) struct ApiError {
    status: StatusCode,
    message: String,
}

async fn not_implemented() -> ApiError {
    ApiError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "user API is not implemented".to_string(),
    }
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
