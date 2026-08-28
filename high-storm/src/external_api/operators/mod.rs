pub(super) mod auth;
mod state;
mod voting;

use axum::{
    Router,
    routing::{get, post},
};

use super::ExternalApiState;
pub(super) use auth::{AuthError, AuthService};

pub(super) fn router() -> Router<ExternalApiState> {
    Router::new()
        .route("/auth/challenge", post(auth::issue_challenge))
        .route("/auth/token", post(auth::exchange_token))
        .route("/state", get(state::get_network_state))
        .route("/state/peers", get(state::get_network_peers))
        .route(
            "/voting",
            get(voting::list_votings).post(voting::create_voting),
        )
        .route("/voting/{hash}", get(voting::get_voting))
        .route("/voting/{hash}/approve", post(voting::approve_voting))
}
