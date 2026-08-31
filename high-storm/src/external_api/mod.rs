mod operators;
#[cfg(test)]
mod tests;
mod users;

use std::net::SocketAddr;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{
    HighStormHandle, VotingError,
    db::{node_operator::NodeOperatorStore, user_request::UserRequestStore},
};
use operators::{AuthError, AuthService};

#[derive(Clone)]
pub(super) struct ExternalApiState {
    pub(super) node: HighStormHandle,
    pub(super) auth: AuthService,
    pub(super) user_requests: UserRequestStore,
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
        user_requests: UserRequestStore,
    ) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(address).await?;
        Ok(Self {
            listener,
            router: router(node, operators, user_requests),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self) -> std::io::Result<()> {
        axum::serve(self.listener, self.router).await
    }
}

pub fn router(
    node: HighStormHandle,
    operators: NodeOperatorStore,
    user_requests: UserRequestStore,
) -> Router {
    let state = ExternalApiState {
        node,
        auth: AuthService::new(operators),
        user_requests,
    };
    Router::new()
        .nest("/users", users::router())
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

    pub(super) fn unprocessable(message: impl ToString) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
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
