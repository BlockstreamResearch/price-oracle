use axum::{
    Json,
    extract::{Path, State},
    http::header,
    response::IntoResponse,
};
use price_feed::{FeedDefinition, FeedId, FeedKind, PriceFeedData};
use serde::Serialize;

use super::{ApiError, ExternalApiState, require_coordinator};
use crate::high_storm::{ExchangeRateInfo, FeedRate, PriceAttestation};

/// A rate is only ever the one this node holds now, and a cache serving it
/// past its `valid_until` is the stale read the node takes care to avoid.
const RATE_CACHE: &str = "no-store";
const MAX_ECHOED_ID: usize = 16;

pub(super) fn router() -> axum::Router<ExternalApiState> {
    axum::Router::new()
        .route("/", axum::routing::get(list_feeds))
        .route("/{id}", axum::routing::get(get_rate))
}

#[derive(Serialize)]
struct FeedInfo {
    id: FeedId,
    symbol: String,
    base: &'static str,
    quote: &'static str,
    /// The scale of every price of this feed, so a client can read one without
    /// fetching it first.
    decimals: u32,
    kind: &'static str,
}

impl From<&FeedDefinition> for FeedInfo {
    fn from(definition: &FeedDefinition) -> Self {
        Self {
            id: definition.id,
            symbol: format!("{}/{}", definition.base.symbol(), definition.quote.symbol()),
            base: definition.base.symbol(),
            quote: definition.quote.symbol(),
            decimals: definition.decimals,
            kind: match definition.kind {
                FeedKind::Direct => "direct",
                FeedKind::Cross => "cross",
            },
        }
    }
}

/// The registry, by the ids every node shares.
async fn list_feeds(
    State(state): State<ExternalApiState>,
) -> Result<Json<Vec<FeedInfo>>, ApiError> {
    require_coordinator(&state).await?;

    Ok(Json(
        state
            .node
            .price_feeds()
            .iter()
            .map(FeedInfo::from)
            .collect(),
    ))
}

#[derive(Serialize)]
struct ExchangeRate {
    main: Attestation,
    auxiliary: Vec<Attestation>,
}

#[derive(Serialize)]
struct Attestation {
    feed: PriceFeedData,
    signature: String,
    public_key: String,
}

impl From<ExchangeRateInfo> for ExchangeRate {
    fn from(rate: ExchangeRateInfo) -> Self {
        Self {
            main: Attestation::from(rate.main),
            auxiliary: rate.auxiliary.into_iter().map(Attestation::from).collect(),
        }
    }
}

impl From<PriceAttestation> for Attestation {
    fn from(attestation: PriceAttestation) -> Self {
        Self {
            feed: attestation.feed,
            signature: hex::encode(attestation.signature),
            public_key: hex::encode(attestation.public_key),
        }
    }
}

/// The same shape for a Direct feed and a Cross pair. The id is parsed here,
/// so a malformed one is answered in this API's error shape rather than axum's.
async fn get_rate(
    State(state): State<ExternalApiState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_coordinator(&state).await?;
    let feed: FeedId = id.parse().map_err(|_| {
        ApiError::bad_request(format!(
            "invalid price feed id '{}'",
            id.chars().take(MAX_ECHOED_ID).collect::<String>()
        ))
    })?;
    if state.node.price_feed(feed).is_none() {
        return Err(ApiError::not_found(format!("unknown price feed '{feed}'")));
    }

    let rate = match state
        .node
        .exchange_rate(feed)
        .await
        .map_err(ApiError::internal)?
    {
        FeedRate::Current(rate) => rate,
        FeedRate::Expired => {
            return Err(ApiError::unavailable(format!(
                "the price of feed '{feed}' has expired"
            )));
        }
        FeedRate::Unattested => {
            return Err(ApiError::unavailable(format!(
                "feed '{feed}' has not been attested yet"
            )));
        }
    };

    Ok((
        [(header::CACHE_CONTROL, RATE_CACHE)],
        Json(ExchangeRate::from(rate)),
    ))
}
