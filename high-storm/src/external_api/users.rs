use std::{collections::HashSet, sync::LazyLock};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use bitcoin::{
    hashes::Hash,
    secp256k1::{
        Message, PublicKey, Secp256k1,
        ecdsa::{RecoverableSignature, RecoveryId},
    },
    sign_message::signed_msg_hash,
};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use contracts::voucher::{Voucher, VoucherAuthMethod, VoucherParameters};
use price_feed::{FeedId, FeedRegistry};
use secp256k1::{XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use simplex::simplicityhl::elements::AssetId;

use super::{ApiError, ExternalApiState, require_coordinator};
use crate::crypto::tagged_hash;
use crate::db::{
    network_asset::{ORACLE_VERIFIER_KIND, STORM_EYE_KIND, TICK_ASSET_KIND},
    user_request::{FeeUtxo, InsertPendingResult},
};

const USER_REQUEST_TAG: &str = "OracleNetworkV1/NetworkUserRequests";
pub(super) const HUMID_USER_SIGNATURE_SCHEME: &str = "bitcoin-signed-message-ecdsa-v1";
const TICK_REQUEST_KIND: &str = "tick-utxo";
pub(crate) const PRICE_REQUEST_KIND: &str = "signed-price-data";

/// The same feeds every node registers, read on the consensus path too.
static REGISTRY: LazyLock<FeedRegistry> = LazyLock::new(FeedRegistry::default);
const MAX_REQUESTS_PER_BATCH: usize = 100;
const MAX_FEE_UTXOS_PER_BATCH: usize = 100;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

pub(super) fn router() -> axum::Router<ExternalApiState> {
    axum::Router::new()
        .route("/account/{public_key}", axum::routing::get(get_account))
        .route("/check-fee-utxos", axum::routing::post(check_fee_utxos))
        .route("/requests", axum::routing::post(create_request))
        .route("/requests/{hash}", axum::routing::get(get_request))
}

#[derive(Serialize)]
struct OracleAccount {
    address: String,
    script_pubkey: String,
    storm_eye_asset_id: String,
    tick_asset_id: String,
    tick_script_pubkey: String,
    /// The asset a `signed-price-data` request is issued in.
    oracle_verifier_asset_id: String,
    network: super::operators::auth::AuthNetwork,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountQuery {
    auth_script_pubkey: Option<String>,
}

async fn get_account(
    State(state): State<ExternalApiState>,
    Path(public_key): Path<String>,
    Query(query): Query<AccountQuery>,
) -> Result<Json<OracleAccount>, ApiError> {
    let owner = parse_hex_array::<32>(&public_key, "user public key")?;
    let owner = XOnlyPublicKey::from_byte_array(owner)
        .map_err(|_| ApiError::bad_request("invalid user public key"))?;
    let storm_eye = state
        .node
        .network_asset(STORM_EYE_KIND)
        .await
        .map_err(ApiError::unavailable)?
        .ok_or_else(|| ApiError::unavailable("Storm Eye asset is not active"))?;
    let network = state.auth.network();
    let program = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye.asset_id,
        account_owner_pubkey: owner.serialize(),
    });
    let simplicity_network = network.simplicity_network();
    let tick = state
        .node
        .network_asset(TICK_ASSET_KIND)
        .await
        .map_err(ApiError::unavailable)?
        .ok_or_else(|| ApiError::unavailable("Tick asset is not active"))?;
    let oracle_verifier = state
        .node
        .network_asset(ORACLE_VERIFIER_KIND)
        .await
        .map_err(ApiError::unavailable)?
        .ok_or_else(|| ApiError::unavailable("Oracle Verifier asset is not active"))?;
    let auth_method = match query.auth_script_pubkey {
        Some(script) => {
            validate_auth_method(&UtxoAuthMethod {
                kind: "scriptPubKey-auth".into(),
                auth_data: script.clone(),
            })?;
            VoucherAuthMethod::Script {
                auth_script_hash: Sha256::digest(
                    hex::decode(script).map_err(ApiError::bad_request)?,
                )
                .into(),
            }
        }
        None => VoucherAuthMethod::Signature {
            auth_pubkey: owner.serialize(),
        },
    };
    let voucher = Voucher::new(VoucherParameters {
        storm_eye_asset_id: AssetId::from_byte_array(storm_eye.asset_id),
        auth_method,
        network: simplicity_network,
    });

    Ok(Json(OracleAccount {
        address: program
            .as_ref()
            .get_tr_address(&simplicity_network)
            .to_string(),
        script_pubkey: hex::encode(program.get_script_pubkey(&simplicity_network).into_bytes()),
        storm_eye_asset_id: AssetId::from_byte_array(storm_eye.asset_id).to_string(),
        tick_asset_id: AssetId::from_byte_array(tick.asset_id).to_string(),
        tick_script_pubkey: hex::encode(voucher.get_script_pubkey().into_bytes()),
        oracle_verifier_asset_id: AssetId::from_byte_array(oracle_verifier.asset_id).to_string(),
        network,
    }))
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
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
    /// The feed a `signed-price-data` request is issued at; a Tick names none.
    /// Spelled as the specification spells it, since `deny_unknown_fields`
    /// makes any other spelling a rejection rather than a field a client omits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) price_feed_id: Option<FeedId>,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckFeeUtxosRequest {
    fee_utxos: Vec<String>,
}

#[derive(Serialize)]
struct CheckFeeUtxosResponse {
    reserved: Vec<String>,
    usable: Vec<String>,
}

async fn check_fee_utxos(
    State(state): State<ExternalApiState>,
    Json(request): Json<CheckFeeUtxosRequest>,
) -> Result<Json<CheckFeeUtxosResponse>, ApiError> {
    require_coordinator(&state).await?;
    let fee_utxos = validate_fee_utxos(&request.fee_utxos)?;
    let reservations = state
        .fee_utxos
        .reserved_for_burning(&fee_utxos)
        .await
        .map_err(ApiError::unavailable)?;
    let mut response = CheckFeeUtxosResponse {
        reserved: Vec::new(),
        usable: Vec::new(),
    };
    for (fee_utxo, reserved) in request.fee_utxos.into_iter().zip(reservations) {
        if reserved {
            response.reserved.push(fee_utxo);
        } else {
            response.usable.push(fee_utxo);
        }
    }

    Ok(Json(response))
}

async fn create_request(
    State(state): State<ExternalApiState>,
    Json(request): Json<NetworkUserRequests>,
) -> Result<(StatusCode, Json<CreatedRequest>), ApiError> {
    require_coordinator(&state).await?;
    let (fee_utxos, _) = validate_request(&request)?;
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
            super::fee_utxo::FeeUtxoValidationError::ReservedForBurning(_) => {
                ApiError::conflict(error)
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

/// Its fee UTXOs, and the feed it is issued at, if any.
fn validate_request(
    request: &NetworkUserRequests,
) -> Result<(Vec<FeeUtxo>, Option<FeedId>), ApiError> {
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
    // One message carries one feed, so one batch names one too.
    let mut instructed = None;
    for user_request in &request.requests {
        if let Some(feed) = validate_user_request(user_request)? {
            if instructed.is_some_and(|named| named != feed) {
                return Err(ApiError::bad_request(
                    "a batch cannot name more than one price feed",
                ));
            }
            instructed = Some(feed);
        }
    }
    verify_signature(request)?;

    Ok((fee_utxos, instructed))
}

/// The batch, its fee UTXOs, and the feed it is issued at, if any.
pub(crate) fn validate_encoded_request(
    encoded: &[u8],
) -> Result<(NetworkUserRequests, Vec<FeeUtxo>, Option<FeedId>), String> {
    let request: NetworkUserRequests =
        serde_json::from_slice(encoded).map_err(|error| error.to_string())?;
    let (fee_utxos, feed) = validate_request(&request).map_err(|error| error.message)?;

    Ok((request, fee_utxos, feed))
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

/// The feed the request is issued at, for a `signed-price-data` request.
fn validate_user_request(request: &UserRequest) -> Result<Option<FeedId>, ApiError> {
    let kind = request.kind.as_str();
    if kind != TICK_REQUEST_KIND && kind != PRICE_REQUEST_KIND {
        return Err(ApiError::bad_request(format!(
            "unknown user request kind '{kind}'"
        )));
    }
    if request.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ApiError::bad_request(format!(
            "request payload cannot exceed {MAX_PAYLOAD_BYTES} bytes"
        )));
    }
    let details: TickUtxoRequestDetails = serde_json::from_str(&request.payload)
        .map_err(|error| ApiError::bad_request(format!("invalid {kind} payload: {error}")))?;
    validate_auth_method(&details.utxo_auth_method)?;

    // The user signs the payload, not the kind, so the two kinds keep payload
    // shapes that exclude each other: a batch replayed as the other kind fails
    // here rather than passing as something its signer did not ask for.
    match (kind, details.price_feed_id) {
        (TICK_REQUEST_KIND, None) => Ok(None),
        (TICK_REQUEST_KIND, Some(_)) => Err(ApiError::bad_request(
            "a tick-utxo request cannot name a price feed",
        )),
        (_, None) => Err(ApiError::bad_request(format!(
            "a {PRICE_REQUEST_KIND} request must name a price feed"
        ))),
        (_, Some(feed)) => match REGISTRY.get(feed) {
            Some(_) => Ok(Some(feed)),
            None => Err(ApiError::bad_request(format!(
                "unknown price feed '{feed}'"
            ))),
        },
    }
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
    if let Some(scheme) = request.header.signature_scheme.as_deref() {
        if scheme != HUMID_USER_SIGNATURE_SCHEME {
            return Err(ApiError::bad_request("unsupported user signature scheme"));
        }
        let encoded_key = request
            .header
            .signing_public_key
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("signing public key is required"))?;
        let signing_key_bytes = parse_hex_array::<33>(encoded_key, "signing public key")?;
        let signing_key = PublicKey::from_slice(&signing_key_bytes)
            .map_err(|_| ApiError::bad_request("invalid signing public key"))?;
        if signing_key.x_only_public_key().0.serialize() != public_key_bytes {
            return Err(ApiError::unauthorized(
                "signing key does not own the oracle account",
            ));
        }
        let signature_bytes = parse_hex_array::<65>(&request.header.signature, "user signature")?;
        let recovery_id = RecoveryId::from_i32(i32::from(signature_bytes[64]))
            .map_err(|_| ApiError::unauthorized("invalid user signature"))?;
        let signature = RecoverableSignature::from_compact(&signature_bytes[..64], recovery_id)
            .map_err(|_| ApiError::unauthorized("invalid user signature"))?;
        let message =
            Message::from_digest(signed_msg_hash(&humid_signing_message(request)?).to_byte_array());
        let recovered = Secp256k1::verification_only()
            .recover_ecdsa(&message, &signature)
            .map_err(|_| ApiError::unauthorized("user signature is invalid"))?;
        return if recovered == signing_key {
            Ok(())
        } else {
            Err(ApiError::unauthorized("user signature is invalid"))
        };
    }
    if request.header.signing_public_key.is_some() {
        return Err(ApiError::bad_request(
            "signing public key requires a signature scheme",
        ));
    }
    let signature_bytes = parse_hex_array::<64>(&request.header.signature, "user signature")?;
    let signature = schnorr::Signature::from_byte_array(signature_bytes);
    schnorr::verify(&signature, &signing_hash(request), &public_key)
        .map_err(|_| ApiError::unauthorized("user signature is invalid"))
}

pub(super) fn humid_signing_message(request: &NetworkUserRequests) -> Result<String, ApiError> {
    let body = serde_json::to_string(&(
        &request.header.public_key,
        &request.header.signing_public_key,
        &request.header.fee_utxos,
        &request.requests,
    ))
    .map_err(ApiError::internal)?;
    Ok(format!(
        "{USER_REQUEST_TAG}\n{HUMID_USER_SIGNATURE_SCHEME}\n{body}"
    ))
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

fn parse_hex_array<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N], ApiError> {
    hex::decode(encoded)
        .map_err(|_| ApiError::bad_request(format!("invalid {name}")))?
        .try_into()
        .map_err(|_| ApiError::bad_request(format!("invalid {name}")))
}
