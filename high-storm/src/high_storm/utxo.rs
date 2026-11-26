//! UTXO lookups and checks over Elements RPC shared by the issuance, burn,
//! exchange, renewal and voting rounds.

use std::str::FromStr;

use bitcoincore_rpc::{Client, RpcApi};
use serde::Deserialize;
use serde_json::Number;
use simplex::{
    simplicityhl::elements::{
        AssetId, OutPoint, Script, TxOut, Txid, confidential, pset::PartiallySignedTransaction,
    },
    transaction::{PartialOutput, UtxoError, utxo::UTXO},
};

use crate::external_api::fee_utxo::parse_coin_value;

use super::user_requests::UserRequestError;

#[derive(Clone, Copy)]
pub(crate) enum StormEyePool {
    UserRequests(usize),
    NetworkLeader(usize),
    /// The last leader-half Storm Eye not yet spent this block.
    AnyNetworkLeader,
}

/// Lanes index the block's confirmed Storm Eyes, so one lane's broadcast never shifts another's.
pub(crate) fn find_contract_utxo(
    client: &Client,
    script: &[u8],
    expected_asset: Option<[u8; 32]>,
    pool: StormEyePool,
) -> Result<UTXO, UserRequestError> {
    let candidates = scan_contract_utxos(client, script, expected_asset)?;
    let unavailable = || UserRequestError::Invalid("required Storm Eye pool is unavailable".into());
    if let StormEyePool::AnyNetworkLeader = pool {
        return candidates[candidates.len() / 2..]
            .iter()
            .rev()
            .find(|(_, spent_in_mempool)| !spent_in_mempool)
            .map(|(utxo, _)| utxo.clone())
            .ok_or_else(unavailable);
    }
    let (selected, spent_in_mempool) = storm_eye_pool_index(candidates.len(), pool)
        .and_then(|index| candidates.get(index))
        .ok_or_else(unavailable)?;
    if *spent_in_mempool {
        return Err(UserRequestError::Invalid(
            "Storm Eye lane was already used in this block".into(),
        ));
    }

    Ok(selected.clone())
}

/// Confirmed contract UTXOs in outpoint order, each flagged if spent in the mempool.
pub(super) fn scan_contract_utxos(
    client: &Client,
    script: &[u8],
    expected_asset: Option<[u8; 32]>,
) -> Result<Vec<(UTXO, bool)>, UserRequestError> {
    let descriptor = format!("raw({})", hex::encode(script));
    let scan: ScanResult = client.call(
        "scantxoutset",
        &["start".into(), serde_json::json!([descriptor])],
    )?;
    let mut candidates = Vec::with_capacity(scan.unspents.len());
    for unspent in scan.unspents {
        if !matches_scanned_asset(unspent.asset.as_deref(), expected_asset) {
            continue;
        }
        let txid = Txid::from_str(&unspent.txid)
            .map_err(|_| UserRequestError::Invalid("invalid scanned UTXO txid".into()))?;
        let Some(utxo) =
            get_optional_explicit_outpoint_ignoring_mempool(client, txid, unspent.vout)?
        else {
            continue;
        };
        if matches_expected_asset(utxo.asset()?, expected_asset) {
            let spent_in_mempool =
                get_optional_explicit_outpoint(client, txid, unspent.vout)?.is_none();
            candidates.push((utxo, spent_in_mempool));
        }
    }

    candidates
        .sort_unstable_by_key(|(utxo, _)| (utxo.outpoint.txid.to_byte_array(), utxo.outpoint.vout));

    Ok(candidates)
}

fn matches_expected_asset(actual: AssetId, expected: Option<[u8; 32]>) -> bool {
    expected.is_none_or(|expected| actual == AssetId::from_byte_array(expected))
}

fn matches_scanned_asset(actual: Option<&str>, expected: Option<[u8; 32]>) -> bool {
    expected.is_none_or(|expected| {
        actual.and_then(|asset| AssetId::from_str(asset).ok())
            == Some(AssetId::from_byte_array(expected))
    })
}

fn storm_eye_pool_index(candidate_count: usize, pool: StormEyePool) -> Option<usize> {
    let coordinator_count = candidate_count / 2;
    let index = match pool {
        StormEyePool::UserRequests(lane) if lane < coordinator_count => lane,
        StormEyePool::NetworkLeader(lane) if lane < candidate_count - coordinator_count => {
            coordinator_count + lane
        }
        _ => return None,
    };
    Some(index)
}

#[derive(Deserialize)]
pub(super) struct GetTxOut {
    pub(super) confirmations: u64,
    asset: Option<String>,
    value: Option<Number>,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: GetTxOutScript,
}

#[derive(Deserialize)]
struct GetTxOutScript {
    hex: String,
}

pub(crate) fn get_explicit_outpoint(
    client: &Client,
    txid: Txid,
    output_index: u32,
) -> Result<UTXO, UserRequestError> {
    get_optional_explicit_outpoint(client, txid, output_index)?
        .ok_or_else(|| UserRequestError::Invalid("required UTXO is unavailable".into()))
}

pub(crate) fn get_optional_explicit_outpoint(
    client: &Client,
    txid: Txid,
    output_index: u32,
) -> Result<Option<UTXO>, UserRequestError> {
    get_optional_explicit_outpoint_with_mempool(client, txid, output_index, true)
}

pub(crate) fn get_optional_explicit_outpoint_ignoring_mempool(
    client: &Client,
    txid: Txid,
    output_index: u32,
) -> Result<Option<UTXO>, UserRequestError> {
    get_optional_explicit_outpoint_with_mempool(client, txid, output_index, false)
}

fn get_optional_explicit_outpoint_with_mempool(
    client: &Client,
    txid: Txid,
    output_index: u32,
    include_mempool: bool,
) -> Result<Option<UTXO>, UserRequestError> {
    let Some(output) = get_txout_optional(client, txid, output_index, include_mempool)? else {
        return Ok(None);
    };

    explicit_outpoint(txid, output_index, output).map(Some)
}

pub(super) fn explicit_outpoint(
    txid: Txid,
    output_index: u32,
    output: GetTxOut,
) -> Result<UTXO, UserRequestError> {
    let asset = AssetId::from_str(
        output
            .asset
            .as_deref()
            .ok_or_else(|| UserRequestError::Invalid("UTXO asset must be explicit".into()))?,
    )
    .map_err(|_| UserRequestError::Invalid("invalid UTXO asset".into()))?;
    let value = parse_coin_value(
        output
            .value
            .as_ref()
            .ok_or_else(|| UserRequestError::Invalid("UTXO value must be explicit".into()))?,
    )
    .ok_or_else(|| UserRequestError::Invalid("invalid UTXO value".into()))?;
    let script = hex::decode(output.script_pub_key.hex)
        .map_err(|_| UserRequestError::Invalid("invalid UTXO script".into()))?;

    Ok(UTXO {
        outpoint: OutPoint::new(txid, output_index),
        txout: TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(value),
            script_pubkey: Script::from(script),
            ..Default::default()
        },
        secrets: None,
    })
}

pub(super) fn get_txout_optional(
    client: &Client,
    txid: Txid,
    output_index: u32,
    include_mempool: bool,
) -> Result<Option<GetTxOut>, UserRequestError> {
    Ok(client.call::<Option<GetTxOut>>(
        "gettxout",
        &[
            txid.to_string().into(),
            output_index.into(),
            include_mempool.into(),
        ],
    )?)
}

pub(crate) fn output_from_utxo(utxo: &UTXO) -> Result<PartialOutput, UtxoError> {
    Ok(PartialOutput::new(
        utxo.txout.script_pubkey.clone(),
        utxo.amount()?,
        utxo.asset()?,
    ))
}

pub(crate) fn is_fully_explicit_output(
    output: &simplex::simplicityhl::elements::pset::Output,
) -> bool {
    output.amount.is_some()
        && output.asset.is_some()
        && output.amount_comm.is_none()
        && output.asset_comm.is_none()
        && output.value_rangeproof.is_none()
        && output.asset_surjection_proof.is_none()
        && output.blinding_key.is_none()
        && output.ecdh_pubkey.is_none()
        && output.blinder_index.is_none()
        && output.blind_value_proof.is_none()
        && output.blind_asset_proof.is_none()
}

pub(crate) fn witness_utxo(
    pset: &PartiallySignedTransaction,
    index: usize,
) -> Result<&simplex::simplicityhl::elements::TxOut, UserRequestError> {
    pset.inputs()
        .get(index)
        .and_then(|input| input.witness_utxo.as_ref())
        .ok_or_else(|| UserRequestError::Invalid(format!("input {index} has no witness UTXO")))
}

pub(crate) fn require_explicit_utxo(
    utxo: &simplex::simplicityhl::elements::TxOut,
    asset: AssetId,
    script: &[u8],
    name: &str,
) -> Result<(), UserRequestError> {
    if utxo.asset.explicit() != Some(asset) || utxo.script_pubkey.as_bytes() != script {
        return Err(UserRequestError::Invalid(format!("invalid {name} input")));
    }
    if utxo.value.explicit().is_none() {
        return Err(UserRequestError::Invalid(format!(
            "{name} input must be explicit"
        )));
    }
    Ok(())
}

pub(crate) fn require_preserved_output(
    pset: &PartiallySignedTransaction,
    index: usize,
    input: &simplex::simplicityhl::elements::TxOut,
    name: &str,
) -> Result<(), UserRequestError> {
    let output = pset
        .outputs()
        .get(index)
        .ok_or_else(|| UserRequestError::Invalid(format!("missing {name} output")))?;
    let output = output.to_txout();
    if output.asset != input.asset
        || output.value != input.value
        || output.script_pubkey != input.script_pubkey
    {
        return Err(UserRequestError::Invalid(format!(
            "{name} is not preserved"
        )));
    }
    Ok(())
}

#[derive(Deserialize)]
pub(super) struct ScanResult {
    pub(super) unspents: Vec<ScannedUtxo>,
}

#[derive(Deserialize)]
pub(super) struct ScannedUtxo {
    pub(super) txid: String,
    pub(super) vout: u32,
    asset: Option<String>,
    pub(super) height: Option<u64>,
}

#[cfg(test)]
mod tests;
