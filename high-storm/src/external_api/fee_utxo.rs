use std::sync::Arc;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use serde::Deserialize;
use serde_json::{Number, Value};
use simplex::{provider::SimplicityNetwork, simplicityhl::elements::secp256k1_zkp::XOnlyPublicKey};
use url::Url;

use crate::{
    config::{ElementsRpcConfig, UserRequestsConfig},
    db::{network_asset::NetworkAssetStore, network_asset::STORM_EYE_KIND, user_request::FeeUtxo},
};

pub(crate) const MIN_FEE_UTXO_CONFIRMATIONS: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum FeeUtxoValidationError {
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("network asset database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Storm Eye asset is not active")]
    MissingStormEye,
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
    #[error("fee UTXO '{0}' does not exist or is already spent")]
    MissingUtxo(String),
    #[error("fee UTXO '{outpoint}' has {actual} confirmations but at least {required} is required")]
    InsufficientConfirmations {
        outpoint: String,
        actual: u64,
        required: u64,
    },
    #[error("fee UTXO '{0}' is not policy asset")]
    WrongAsset(String),
    #[error("fee UTXO '{0}' is not owned by the requester's Account contract")]
    WrongOwner(String),
    #[error("fee UTXOs provide {actual} sats but at least {required} sats are required")]
    InsufficientValue { actual: u64, required: u64 },
    #[error("configured user request fees overflow")]
    PolicyOverflow,
    #[error("fee UTXO '{0}' has an invalid value")]
    InvalidValue(String),
    #[error("invalid requester public key")]
    InvalidPublicKey,
    #[error("fee UTXO validation task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

#[derive(Clone)]
pub(crate) struct FeeUtxoValidator {
    inner: FeeUtxoValidatorInner,
}

#[derive(Clone)]
enum FeeUtxoValidatorInner {
    Elements(Arc<ElementsFeeUtxoValidator>),
    #[cfg(test)]
    AllowAll,
}

impl FeeUtxoValidator {
    pub(super) fn new(
        config: &ElementsRpcConfig,
        assets: NetworkAssetStore,
        user_requests: &UserRequestsConfig,
    ) -> Result<Self, FeeUtxoValidationError> {
        let mut url = Url::parse(&config.url)?;
        url.path_segments_mut()
            .map_err(|_| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
            .pop_if_empty()
            .push("wallet")
            .push(&config.wallet);

        Ok(Self {
            inner: FeeUtxoValidatorInner::Elements(Arc::new(ElementsFeeUtxoValidator {
                rpc_url: url.to_string(),
                auth: Auth::UserPass(config.username.clone(), config.password.clone()),
                assets,
                user_requests: user_requests.clone(),
            })),
        })
    }

    #[cfg(test)]
    pub(super) fn allow_all() -> Self {
        Self {
            inner: FeeUtxoValidatorInner::AllowAll,
        }
    }

    pub(super) async fn validate(
        &self,
        fee_utxos: &[FeeUtxo],
        owner: [u8; 32],
        request_count: usize,
    ) -> Result<(), FeeUtxoValidationError> {
        match &self.inner {
            FeeUtxoValidatorInner::Elements(validator) => {
                validator.validate(fee_utxos, owner, request_count).await
            }
            #[cfg(test)]
            FeeUtxoValidatorInner::AllowAll => Ok(()),
        }
    }
}

struct ElementsFeeUtxoValidator {
    rpc_url: String,
    auth: Auth,
    assets: NetworkAssetStore,
    user_requests: UserRequestsConfig,
}

impl ElementsFeeUtxoValidator {
    async fn validate(
        &self,
        fee_utxos: &[FeeUtxo],
        owner: [u8; 32],
        request_count: usize,
    ) -> Result<(), FeeUtxoValidationError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(FeeUtxoValidationError::MissingStormEye)?;
        let rpc_url = self.rpc_url.clone();
        let auth = self.auth.clone();
        let fee_utxos = fee_utxos.to_vec();
        let minimum_value = minimum_fee_value(request_count, &self.user_requests)?;

        tokio::task::spawn_blocking(move || {
            validate_with_rpc(
                &rpc_url,
                auth,
                &fee_utxos,
                owner,
                storm_eye.asset_id,
                minimum_value,
            )
        })
        .await?
    }
}

fn validate_with_rpc(
    rpc_url: &str,
    auth: Auth,
    fee_utxos: &[FeeUtxo],
    owner: [u8; 32],
    storm_eye_asset_id: [u8; 32],
    minimum_value: u64,
) -> Result<(), FeeUtxoValidationError> {
    let client = Client::new(rpc_url, auth)?;
    let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
    let network = match chain.chain.as_str() {
        "liquidv1" => SimplicityNetwork::Liquid,
        "liquidtestnet" => SimplicityNetwork::LiquidTestnet,
        "elementsregtest" => SimplicityNetwork::default_regtest(),
        _ => return Err(FeeUtxoValidationError::UnsupportedChain(chain.chain)),
    };
    let policy_asset: SidechainInfo = client.call("getsidechaininfo", &[])?;
    let owner =
        XOnlyPublicKey::from_slice(&owner).map_err(|_| FeeUtxoValidationError::InvalidPublicKey)?;
    let account_script = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id,
        account_owner_pubkey: owner.serialize(),
    })
    .get_script_pubkey(&network);

    let mut total_value = 0u64;
    for fee_utxo in fee_utxos {
        let outpoint = format!("{}:{}", hex::encode(fee_utxo.txid), fee_utxo.output_index);
        let output: Option<GetTxOut> = client.call(
            "gettxout",
            &[
                hex::encode(fee_utxo.txid).into(),
                fee_utxo.output_index.into(),
                true.into(),
            ],
        )?;
        let output = output.ok_or_else(|| FeeUtxoValidationError::MissingUtxo(outpoint.clone()))?;
        require_confirmation_depth(&output, &outpoint)?;
        if output.asset.as_deref() != Some(&policy_asset.pegged_asset) {
            return Err(FeeUtxoValidationError::WrongAsset(outpoint));
        }
        if output.script_pub_key.hex != hex::encode(account_script.as_bytes()) {
            return Err(FeeUtxoValidationError::WrongOwner(outpoint));
        }
        let value = output
            .value
            .as_ref()
            .and_then(parse_coin_value)
            .ok_or_else(|| FeeUtxoValidationError::InvalidValue(outpoint))?;
        total_value = total_value
            .checked_add(value)
            .ok_or(FeeUtxoValidationError::PolicyOverflow)?;
    }
    if total_value < minimum_value {
        return Err(FeeUtxoValidationError::InsufficientValue {
            actual: total_value,
            required: minimum_value,
        });
    }

    Ok(())
}

fn require_confirmation_depth(
    output: &GetTxOut,
    outpoint: &str,
) -> Result<(), FeeUtxoValidationError> {
    if output.confirmations < MIN_FEE_UTXO_CONFIRMATIONS {
        return Err(FeeUtxoValidationError::InsufficientConfirmations {
            outpoint: outpoint.to_string(),
            actual: output.confirmations,
            required: MIN_FEE_UTXO_CONFIRMATIONS,
        });
    }

    Ok(())
}

fn minimum_fee_value(
    request_count: usize,
    config: &UserRequestsConfig,
) -> Result<u64, FeeUtxoValidationError> {
    let request_count =
        u64::try_from(request_count).map_err(|_| FeeUtxoValidationError::PolicyOverflow)?;
    config
        .operational_fee_sats
        .checked_add(config.tick_burn_reserve_sats)
        .and_then(|per_request| per_request.checked_mul(request_count))
        .and_then(|request_fees| request_fees.checked_add(config.issuance_transaction_fee_sats))
        .ok_or(FeeUtxoValidationError::PolicyOverflow)
}

pub(crate) fn parse_coin_value(value: &Number) -> Option<u64> {
    let encoded = value.to_string();
    let (mantissa, exponent) = match encoded.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().ok()?),
        None => (&*encoded, 0),
    };
    if mantissa.starts_with('-') {
        return None;
    }
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = format!("{whole}{fraction}").parse::<u64>().ok()?;
    let scale = 8i32
        .checked_add(exponent)?
        .checked_sub(fraction.len() as i32)?;
    if scale >= 0 {
        digits.checked_mul(10u64.checked_pow(scale as u32)?)
    } else {
        let divisor = 10u64.checked_pow(scale.unsigned_abs())?;
        (digits % divisor == 0).then_some(digits / divisor)
    }
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
}

#[derive(Deserialize)]
struct SidechainInfo {
    pegged_asset: String,
}

#[derive(Deserialize)]
struct GetTxOut {
    confirmations: u64,
    asset: Option<String>,
    value: Option<Number>,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
    #[serde(flatten)]
    _other: std::collections::HashMap<String, Value>,
}

#[derive(Deserialize)]
struct ScriptPubKey {
    hex: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output_with_confirmations(confirmations: u64) -> GetTxOut {
        GetTxOut {
            confirmations,
            asset: None,
            value: None,
            script_pub_key: ScriptPubKey { hex: String::new() },
            _other: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn requires_at_least_one_confirmation() {
        let error = require_confirmation_depth(&output_with_confirmations(0), "txid:0")
            .expect_err("unconfirmed output must be rejected");
        assert!(matches!(
            error,
            FeeUtxoValidationError::InsufficientConfirmations {
                actual: 0,
                required: MIN_FEE_UTXO_CONFIRMATIONS,
                ..
            }
        ));
        require_confirmation_depth(&output_with_confirmations(1), "txid:0")
            .expect("one confirmation must be accepted");
    }

    #[test]
    fn parses_elements_coin_values_as_exact_satoshis() {
        assert_eq!(
            parse_coin_value(&Number::from_f64(1.00000001).unwrap()),
            Some(100_000_001)
        );
        assert_eq!(
            parse_coin_value(&Number::from_f64(0.00000001).unwrap()),
            Some(1)
        );
    }

    #[test]
    fn requires_request_fees_reserves_and_a_round_fee() {
        let config = UserRequestsConfig {
            operational_fee_sats: 1_000,
            tick_burn_reserve_sats: 2_000,
            issuance_transaction_fee_sats: 500,
        };

        assert_eq!(minimum_fee_value(3, &config).unwrap(), 9_500);
    }
}
