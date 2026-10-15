pub(super) mod auth;
mod droplets;
mod price_sources;
mod state;
mod storm_eyes;
mod voting;

use axum::{
    Router,
    routing::{get, post},
};

use super::ExternalApiState;
pub(super) use auth::{AuthError, AuthService};

pub(super) fn router() -> Router<ExternalApiState> {
    Router::new()
        .route("/auth/config", get(auth::get_config))
        .route("/auth/challenge", post(auth::issue_challenge))
        .route("/auth/token", post(auth::exchange_token))
        .route("/state", get(state::get_network_state))
        .route("/state/peers", get(state::get_network_peers))
        .route("/storm-eyes", get(storm_eyes::get_storm_eyes))
        .route("/droplets", get(droplets::get_droplets))
        .route("/droplets/exchange", post(droplets::exchange_droplets))
        .route("/price-sources", get(price_sources::get_price_sources))
        .route(
            "/price-sources/freeze",
            post(price_sources::freeze_price_source),
        )
        .route(
            "/price-sources/unfreeze",
            post(price_sources::unfreeze_price_source),
        )
        .route(
            "/voting",
            get(voting::list_votings).post(voting::create_voting),
        )
        .route("/voting/{hash}", get(voting::get_voting))
        .route("/voting/{hash}/approve", post(voting::approve_voting))
        .route("/voting/{hash}/execute", post(voting::execute_voting))
}
