use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};
use simplex::simplicityhl::{elements::Txid, simplicity::hashes::Hash};

use super::auth::{SignedRequest, authenticate_bearer};
use crate::{
    DropletsError,
    db::droplet::{DropletBalance, DropletExchangeRequest},
    external_api::{ApiError, ExternalApiState},
    high_storm::exchange_recipient_amount,
};

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct ExchangeDropletsPayload {
    amount: u64,
    address: String,
}

#[derive(Debug, Serialize)]
pub(super) struct DropletsResponse {
    amount: u64,
    exchange_fee_sats: u64,
    exchange_locked: bool,
    block_height: u64,
    next_leader_block: Option<u64>,
    request: Option<ExchangeRequestResponse>,
    history: Vec<ExchangeRequestResponse>,
}

#[derive(Debug, Serialize)]
struct ExchangeRequestResponse {
    id: String,
    status: String,
    amount: u64,
    requested_at_block: u64,
    completed_txid: Option<String>,
    last_error: Option<String>,
}

pub(super) async fn get_droplets(
    State(state): State<ExternalApiState>,
    headers: HeaderMap,
) -> Result<Json<DropletsResponse>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;

    let (balance, request) = state
        .node
        .droplet_state()
        .await
        .map_err(ApiError::internal)?;
    let history = state
        .node
        .droplet_history()
        .await
        .map_err(ApiError::internal)?;
    let next_leader_block = state.node.next_local_leader_height().await;
    Ok(Json(response(
        balance,
        request,
        history,
        state.node.droplet_exchange_fee_sats(),
        state.node.block_height(),
        next_leader_block,
    )?))
}

pub(super) async fn exchange_droplets(
    State(state): State<ExternalApiState>,
    Json(request): Json<SignedRequest<ExchangeDropletsPayload>>,
) -> Result<(StatusCode, Json<DropletsResponse>), ApiError> {
    state
        .auth
        .verify_write(&request, "POST", "/operators/droplets/exchange")
        .await?;

    let queued_future = state
        .node
        .queue_droplet_exchange(request.payload.amount, request.payload.address.trim());
    let queued = queued_future.await.map_err(map_droplets_error)?;
    let balance = state
        .node
        .droplet_state()
        .await
        .map_err(ApiError::internal)?
        .0;
    let history = state
        .node
        .droplet_history()
        .await
        .map_err(ApiError::internal)?;
    let next_leader_block = state.node.next_local_leader_height().await;

    Ok((
        StatusCode::ACCEPTED,
        Json(response(
            balance,
            Some(queued),
            history,
            state.node.droplet_exchange_fee_sats(),
            state.node.block_height(),
            next_leader_block,
        )?),
    ))
}

fn response(
    balance: Option<DropletBalance>,
    request: Option<DropletExchangeRequest>,
    history: Vec<DropletExchangeRequest>,
    exchange_fee_sats: u64,
    block_height: u64,
    next_leader_block: Option<u64>,
) -> Result<DropletsResponse, ApiError> {
    let request = request.map(exchange_request_response).transpose()?;
    let history = history
        .into_iter()
        .map(exchange_request_response)
        .collect::<Result<_, _>>()?;
    Ok(DropletsResponse {
        amount: balance.as_ref().map_or(0, |balance| balance.amount),
        exchange_fee_sats,
        exchange_locked: balance.is_some_and(|balance| balance.exchange_locked),
        block_height,
        next_leader_block,
        request,
        history,
    })
}

fn exchange_request_response(
    request: DropletExchangeRequest,
) -> Result<ExchangeRequestResponse, ApiError> {
    Ok(ExchangeRequestResponse {
        id: hex::encode(request.signing_hash),
        status: request.status,
        amount: exchange_recipient_amount(&request.transaction).map_err(ApiError::internal)?,
        requested_at_block: request.requested_at_block,
        completed_txid: request
            .completed_txid
            .map(|txid| Txid::from_byte_array(txid).to_string()),
        last_error: request.last_error,
    })
}

fn map_droplets_error(error: DropletsError) -> ApiError {
    match error {
        DropletsError::Invalid(_) | DropletsError::Transaction(_) | DropletsError::Pset(_) => {
            ApiError::bad_request(error)
        }
        DropletsError::MissingAsset(_) => ApiError::conflict(error),
        _ => ApiError::internal(error),
    }
}
