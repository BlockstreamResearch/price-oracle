use axum::{Json, extract::State, http::HeaderMap};
use serde::Serialize;

use super::auth::authenticate_bearer;
use crate::{
    StormEyeInventoryItem, StormEyeState,
    external_api::{ApiError, ExternalApiState},
};

#[derive(Serialize)]
pub(super) struct StormEyesResponse {
    block_height: u64,
    utxos: Vec<StormEyeResponse>,
}

#[derive(Serialize)]
pub(super) struct StormEyeResponse {
    txid: String,
    output_index: u32,
    amount: u64,
    confirmations: u64,
    state: &'static str,
    voting_request_hashes: Vec<String>,
}

pub(super) async fn get_storm_eyes(
    State(state): State<ExternalApiState>,
    headers: HeaderMap,
) -> Result<Json<StormEyesResponse>, ApiError> {
    authenticate_bearer(&state.auth, &headers).await?;
    let block_height = state.node.block_height();
    let utxos = state
        .node
        .storm_eye_utxos()
        .await?
        .into_iter()
        .map(StormEyeResponse::from)
        .collect();

    Ok(Json(StormEyesResponse {
        block_height,
        utxos,
    }))
}

impl From<StormEyeInventoryItem> for StormEyeResponse {
    fn from(utxo: StormEyeInventoryItem) -> Self {
        Self {
            txid: hex::encode(utxo.txid),
            output_index: utxo.output_index,
            amount: utxo.amount,
            confirmations: utxo.confirmations,
            state: match utxo.state {
                StormEyeState::Available => "available",
                StormEyeState::Proposed => "proposed",
                StormEyeState::Executing => "executing",
            },
            voting_request_hashes: utxo
                .voting_request_hashes
                .into_iter()
                .map(hex::encode)
                .collect(),
        }
    }
}
