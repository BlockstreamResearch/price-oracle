use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use secp256k1::{XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ApiError, ExternalApiState};
use crate::db::user_request::{FeeUtxo, InsertPendingResult};

const USER_REQUEST_TAG: &str = "OracleNetworkV1/NetworkUserRequests";
const MAX_REQUESTS_PER_BATCH: usize = 100;
const MAX_FEE_UTXOS_PER_BATCH: usize = 100;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

pub(super) fn router() -> axum::Router<ExternalApiState> {
    axum::Router::new()
        .route("/requests", axum::routing::post(create_request))
        .route("/requests/{hash}", axum::routing::get(get_request))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkUserRequests {
    pub header: UserRequestHeader,
    pub requests: Vec<UserRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserRequestHeader {
    pub signature: String,
    pub public_key: String,
    pub fee_utxos: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserRequest {
    pub kind: String,
    pub payload: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TickUtxoRequestDetails {
    pub(crate) utxo_auth_method: UtxoAuthMethod,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UtxoAuthMethod {
    pub(crate) kind: String,
    pub(crate) auth_data: String,
}

#[derive(Serialize)]
struct CreatedRequest {
    request_hash: String,
}

#[derive(Serialize)]
struct UserRequestStatus {
    status: String,
    payload: Option<String>,
}

async fn create_request(
    State(state): State<ExternalApiState>,
    Json(request): Json<NetworkUserRequests>,
) -> Result<(StatusCode, Json<CreatedRequest>), ApiError> {
    require_coordinator(&state).await?;
    let fee_utxos = validate_request(&request)?;
    let owner = parse_hex_array::<32>(&request.header.public_key, "user public key")?;
    state
        .fee_utxos
        .validate(&fee_utxos, owner, request.requests.len())
        .await
        .map_err(|error| match error {
            super::fee_utxo::FeeUtxoValidationError::MissingUtxo(_)
            | super::fee_utxo::FeeUtxoValidationError::InsufficientConfirmations { .. }
            | super::fee_utxo::FeeUtxoValidationError::WrongAsset(_)
            | super::fee_utxo::FeeUtxoValidationError::WrongOwner(_)
            | super::fee_utxo::FeeUtxoValidationError::InsufficientValue { .. }
            | super::fee_utxo::FeeUtxoValidationError::InvalidValue(_)
            | super::fee_utxo::FeeUtxoValidationError::InvalidPublicKey => {
                ApiError::bad_request(error)
            }
            _ => ApiError::unavailable(error),
        })?;
    let encoded = serde_json::to_vec(&request).map_err(ApiError::internal)?;
    let request_hash: [u8; 32] = Sha256::digest(&encoded).into();
    match state
        .user_requests
        .insert_pending(
            request_hash,
            &encoded,
            state.node.block_height(),
            &fee_utxos,
        )
        .await
        .map_err(ApiError::internal)?
    {
        InsertPendingResult::Inserted => {}
        InsertPendingResult::RequestExists => {
            return Err(ApiError::conflict("user request already exists"));
        }
        InsertPendingResult::FeeUtxoReserved(fee_utxo) => {
            return Err(ApiError::conflict(format!(
                "fee UTXO '{}:{}' is reserved by another user request",
                hex::encode(fee_utxo.txid),
                fee_utxo.output_index
            )));
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(CreatedRequest {
            request_hash: hex::encode(request_hash),
        }),
    ))
}

async fn get_request(
    State(state): State<ExternalApiState>,
    Path(hash): Path<String>,
) -> Result<Json<UserRequestStatus>, ApiError> {
    require_coordinator(&state).await?;
    let request_hash = parse_hex_array(&hash, "user request hash")?;
    let request = state
        .user_requests
        .get(request_hash)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("user request does not exist"))?;
    let payload = request
        .payload
        .map(String::from_utf8)
        .transpose()
        .map_err(ApiError::internal)?;
    Ok(Json(UserRequestStatus {
        status: request.status,
        payload,
    }))
}

async fn require_coordinator(state: &ExternalApiState) -> Result<(), ApiError> {
    if state.node.is_coordinator().await {
        Ok(())
    } else {
        Err(ApiError::unavailable("this node is not the coordinator"))
    }
}

fn validate_request(request: &NetworkUserRequests) -> Result<Vec<FeeUtxo>, ApiError> {
    if request.requests.is_empty() {
        return Err(ApiError::bad_request(
            "at least one user request is required",
        ));
    }
    if request.requests.len() > MAX_REQUESTS_PER_BATCH {
        return Err(ApiError::bad_request(format!(
            "a batch cannot contain more than {MAX_REQUESTS_PER_BATCH} requests"
        )));
    }
    let fee_utxos = validate_fee_utxos(&request.header.fee_utxos)?;
    for user_request in &request.requests {
        validate_tick_request(user_request)?;
    }
    verify_signature(request)?;

    Ok(fee_utxos)
}

pub(crate) fn validate_encoded_request(
    encoded: &[u8],
) -> Result<(NetworkUserRequests, Vec<FeeUtxo>), String> {
    let request: NetworkUserRequests =
        serde_json::from_slice(encoded).map_err(|error| error.to_string())?;
    let fee_utxos = validate_request(&request).map_err(|error| error.message)?;

    Ok((request, fee_utxos))
}

fn validate_fee_utxos(fee_utxos: &[String]) -> Result<Vec<FeeUtxo>, ApiError> {
    if fee_utxos.is_empty() {
        return Err(ApiError::bad_request("at least one fee UTXO is required"));
    }
    if fee_utxos.len() > MAX_FEE_UTXOS_PER_BATCH {
        return Err(ApiError::bad_request(format!(
            "a batch cannot contain more than {MAX_FEE_UTXOS_PER_BATCH} fee UTXOs"
        )));
    }
    let mut parsed = Vec::with_capacity(fee_utxos.len());
    let mut seen = HashSet::with_capacity(fee_utxos.len());
    for utxo in fee_utxos {
        let (txid, output_index) = utxo
            .split_once(':')
            .ok_or_else(|| ApiError::bad_request(format!("invalid fee UTXO '{utxo}'")))?;
        let fee_utxo = FeeUtxo {
            txid: parse_hex_array::<32>(txid, "fee UTXO transaction id")?,
            output_index: output_index
                .parse::<u32>()
                .map_err(|_| ApiError::bad_request(format!("invalid fee UTXO '{utxo}'")))?,
        };
        if !seen.insert(fee_utxo.clone()) {
            return Err(ApiError::bad_request(format!(
                "duplicate fee UTXO '{utxo}'"
            )));
        }
        parsed.push(fee_utxo);
    }
    Ok(parsed)
}

fn validate_tick_request(request: &UserRequest) -> Result<(), ApiError> {
    if request.kind == "signed-price-data" {
        return Err(ApiError::unprocessable(
            "signed-price-data requests are not supported yet",
        ));
    }
    if request.kind != "tick-utxo" {
        return Err(ApiError::bad_request(format!(
            "unknown user request kind '{}'",
            request.kind
        )));
    }
    if request.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ApiError::bad_request(format!(
            "request payload cannot exceed {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    let details: TickUtxoRequestDetails = serde_json::from_str(&request.payload)
        .map_err(|error| ApiError::bad_request(format!("invalid tick-utxo payload: {error}")))?;
    validate_auth_method(&details.utxo_auth_method)
}

fn validate_auth_method(method: &UtxoAuthMethod) -> Result<(), ApiError> {
    match method.kind.as_str() {
        "asset-id-auth" => {
            parse_hex_array::<32>(&method.auth_data, "authentication asset id")?;
        }
        "scriptPubKey-auth" => {
            let script = hex::decode(&method.auth_data)
                .map_err(|_| ApiError::bad_request("invalid authentication scriptPubKey"))?;
            if script.is_empty() {
                return Err(ApiError::bad_request(
                    "authentication scriptPubKey cannot be empty",
                ));
            }
        }
        "signature-auth" => {
            let public_key =
                parse_hex_array::<32>(&method.auth_data, "authentication x-only public key")?;
            XOnlyPublicKey::from_byte_array(public_key)
                .map_err(|_| ApiError::bad_request("invalid authentication x-only public key"))?;
        }
        kind => {
            return Err(ApiError::bad_request(format!(
                "unknown UTXO authentication kind '{kind}'"
            )));
        }
    }
    Ok(())
}

fn verify_signature(request: &NetworkUserRequests) -> Result<(), ApiError> {
    let public_key_bytes = parse_hex_array::<32>(&request.header.public_key, "user public key")?;
    let public_key = XOnlyPublicKey::from_byte_array(public_key_bytes)
        .map_err(|_| ApiError::bad_request("invalid user public key"))?;
    let signature_bytes = parse_hex_array::<64>(&request.header.signature, "user signature")?;
    let signature = schnorr::Signature::from_byte_array(signature_bytes);
    schnorr::verify(&signature, &signing_hash(request), &public_key)
        .map_err(|_| ApiError::unauthorized("user signature is invalid"))
}

pub(super) fn signing_hash(request: &NetworkUserRequests) -> [u8; 32] {
    let mut message = Vec::new();
    for user_request in &request.requests {
        message.extend_from_slice(user_request.payload.as_bytes());
    }
    for fee_utxo in &request.header.fee_utxos {
        message.extend_from_slice(fee_utxo.as_bytes());
    }
    tagged_hash(USER_REQUEST_TAG, &message)
}

fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}

fn parse_hex_array<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N], ApiError> {
    hex::decode(encoded)
        .map_err(|_| ApiError::bad_request(format!("invalid {name}")))?
        .try_into()
        .map_err(|_| ApiError::bad_request(format!("invalid {name}")))
}
