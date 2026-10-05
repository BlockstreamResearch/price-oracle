use axum::{Json, extract::State, http::HeaderMap};
use price_feed::{FeedId, SourceObservation, SourceState};
use serde::{Deserialize, Serialize};

use super::auth::{SignedRequest, authenticate_bearer};
use crate::{
    FeedSources, PriceSourceError, PriceSourceInfo,
    external_api::{ApiError, ExternalApiState},
};

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct PriceSourcePayload {
    feed_id: FeedId,
    /// The source's name, as the listing gives it.
    source: String,
}

#[derive(Serialize)]
pub(super) struct PriceSourcesResponse {
    /// A coordinator that freezes every source of a feed stops priced
    /// issuance at that feed for the whole network.
    is_coordinator: bool,
    feeds: Vec<FeedSourcesResponse>,
}

#[derive(Serialize)]
struct FeedSourcesResponse {
    id: FeedId,
    symbol: String,
    available: bool,
    sources: Vec<SourceResponse>,
}

#[derive(Serialize)]
struct SourceResponse {
    name: &'static str,
    state: &'static str,
    failures: u32,
    retry_at: Option<u64>,
    frozen_at: Option<u64>,
    observation: Option<SourceObservation>,
}

pub(super) async fn get_price_sources(
    State(state): State<ExternalApiState>,
    headers: HeaderMap,
) -> Result<Json<PriceSourcesResponse>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;

    Ok(Json(response(&state).await?))
}

/// Local to this node: nothing is broadcast, and only the price this node
/// attests and signs changes.
pub(super) async fn freeze_price_source(
    State(state): State<ExternalApiState>,
    Json(request): Json<SignedRequest<PriceSourcePayload>>,
) -> Result<Json<PriceSourcesResponse>, ApiError> {
    set_frozen(state, request, "/operators/price-sources/freeze", true).await
}

pub(super) async fn unfreeze_price_source(
    State(state): State<ExternalApiState>,
    Json(request): Json<SignedRequest<PriceSourcePayload>>,
) -> Result<Json<PriceSourcesResponse>, ApiError> {
    set_frozen(state, request, "/operators/price-sources/unfreeze", false).await
}

async fn set_frozen(
    state: ExternalApiState,
    request: SignedRequest<PriceSourcePayload>,
    path: &str,
    frozen: bool,
) -> Result<Json<PriceSourcesResponse>, ApiError> {
    state.auth.verify_write(&request, "POST", path).await?;

    let PriceSourcePayload { feed_id, source } = request.payload;
    state
        .node
        .set_price_source_frozen(feed_id, &source, frozen)
        .await
        .map_err(map_error)?;
    tracing::info!(
        feed = feed_id,
        source,
        frozen,
        "the operator changed a price source"
    );
    Ok(Json(response(&state).await?))
}

async fn response(state: &ExternalApiState) -> Result<PriceSourcesResponse, ApiError> {
    let feeds = state.node.price_sources().await.map_err(map_error)?;
    Ok(PriceSourcesResponse {
        is_coordinator: state.node.is_coordinator().await,
        feeds: feeds.into_iter().map(feed_response).collect(),
    })
}

fn feed_response(feed: FeedSources) -> FeedSourcesResponse {
    FeedSourcesResponse {
        id: feed.feed.id,
        symbol: format!("{}/{}", feed.feed.base.symbol(), feed.feed.quote.symbol()),
        available: feed.available,
        sources: feed.sources.into_iter().map(source_response).collect(),
    }
}

fn source_response(source: PriceSourceInfo) -> SourceResponse {
    SourceResponse {
        name: source.name,
        state: match source.status.state {
            SourceState::Active => "active",
            SourceState::Dropped => "dropped",
            SourceState::Frozen => "frozen",
        },
        failures: source.status.failures,
        retry_at: source.status.retry_at,
        frozen_at: source.frozen_at,
        observation: source.status.observation,
    }
}

fn map_error(error: PriceSourceError) -> ApiError {
    match error {
        PriceSourceError::UnknownFeed(_) | PriceSourceError::UnknownSource { .. } => {
            ApiError::not_found(error)
        }
        PriceSourceError::CrossPair(_) => ApiError::bad_request(error),
        PriceSourceError::Database(_) | PriceSourceError::RenamedSource { .. } => {
            ApiError::internal(error)
        }
    }
}
