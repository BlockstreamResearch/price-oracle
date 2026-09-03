use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::{
    account::{AccountProgram, derived_account::AccountArguments},
    auth::derived_auth::AuthWitness,
    tick_asset::{TickAssetProgram, derived_tick_asset::TickAssetArguments},
    treasury::{
        TreasuryProgram,
        derived_treasury::{TreasuryArguments, TreasuryWitness},
    },
};
use secp256k1_zkp::{
    Message, PublicKey, RangeProof, Secp256k1, SurjectionProof, XOnlyPublicKey, schnorr::Signature,
};
use serde::{Deserialize, Serialize};
use serde_json::Number;
use sha2::Digest;
use simplex::{
    either::Either,
    program::ProgramTrait,
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, BlindAssetProofs, BlindValueProofs, BlockHash, OutPoint, Script, TxOut,
        TxOutSecrets, Txid, confidential, encode, pset::PartiallySignedTransaction,
    },
    simplicityhl::simplicity::hashes::Hash,
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage,
        partial_input::IssuanceInput, utxo::UTXO,
    },
    utils::hash_script,
};
use url::Url;

use crate::{
    NetworkAsset,
    config::{ElementsRpcConfig, UserRequestsConfig},
    db::{
        network_asset::{NetworkAssetStore, STORM_EYE_KIND, TICK_ASSET_KIND},
        user_request::{FeeUtxo, UserRequestStore},
    },
    external_api::{
        fee_utxo::{MIN_FEE_UTXO_CONFIRMATIONS, parse_coin_value},
        users::{TickUtxoRequestDetails, UtxoAuthMethod, validate_encoded_request},
    },
};

use super::{
    SigningResult,
    assets::{
        StormEyeContractData, TickAssetContractData, storm_eye_program, treasury_blinding_secret,
    },
    message::{ExecuteUserRequests, ExternalRequests},
    signing::SigningError,
};

const MAX_TICK_TIME_SKEW_SECS: u64 = 120;
const STORM_EYE_TAG: &str = "OracleNetworkV1/StormEye";
const MAX_REQUESTS_PER_ROUND: u32 = 100;
type PackedStormTreeProof = [Either<(), (bool, [u8; 32])>; storm_tree::TREE_DEPTH as usize];

pub(crate) struct PreparedRound {
    pub(crate) request: ExecuteUserRequests,
    final_transaction: FinalTransaction,
    pset: PartiallySignedTransaction,
    spent_utxos: Vec<TxOut>,
    request_results: Vec<PreparedRequestResult>,
    network: SimplicityNetwork,
    storm_eye: NetworkAsset,
}

struct PreparedRequestResult {
    request_hash: [u8; 32],
    results: Vec<RequestResult>,
}

#[derive(Serialize, Deserialize)]
struct NetworkRequestsResult {
    txid: String,
    results: Vec<RequestResult>,
}

#[derive(Serialize, Deserialize)]
struct RequestResult {
    kind: String,
    vout: u64,
    auth_method: UtxoAuthMethod,
    payload: String,
}

#[derive(Serialize)]
struct TickUtxoDetails {
    timestamp: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum UserRequestError {
    #[error("network asset database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("user request database operation failed: {0}")]
    RequestDatabase(#[from] crate::db::user_request::Error),
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid ExecuteUserRequests message: {0}")]
    Invalid(String),
    #[error("failed to decode transaction: {0}")]
    Transaction(#[from] encode::Error),
    #[error("failed to reconstruct Storm Eye: {0}")]
    StormEye(#[from] super::assets::AssetError),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
    #[error("system clock is before Unix epoch")]
    Clock,
    #[error("distributed signing failed: {0}")]
    Signing(#[from] SigningError),
    #[error("failed to encode request result: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to finalize covenant input: {0}")]
    Program(#[from] simplex::program::ProgramError),
    #[error("failed to encode protocol message: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("failed to extract final transaction: {0}")]
    Pset(String),
}

#[derive(Clone)]
pub(crate) struct UserRequestProcessor {
    requests: UserRequestStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    config: UserRequestsConfig,
}

impl UserRequestProcessor {
    pub(crate) fn new(
        requests: UserRequestStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        config: UserRequestsConfig,
    ) -> Self {
        Self {
            requests,
            assets,
            elements_rpc,
            config,
        }
    }

    pub(crate) async fn validate_execute(
        &self,
        request: &ExecuteUserRequests,
    ) -> Result<(), UserRequestError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(UserRequestError::MissingAsset(STORM_EYE_KIND))?;
        let tick_asset = self
            .assets
            .get(TICK_ASSET_KIND)
            .await?
            .ok_or(UserRequestError::MissingAsset(TICK_ASSET_KIND))?;
        let network = self.network()?;

        validate_execute_request(request, &storm_eye, &tick_asset, &self.config, &network)
    }

    pub(crate) async fn prepare_round(&self) -> Result<Option<PreparedRound>, UserRequestError> {
        let pending = self.requests.list_pending(MAX_REQUESTS_PER_ROUND).await?;
        if pending.is_empty() {
            return Ok(None);
        }
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(UserRequestError::MissingAsset(STORM_EYE_KIND))?;
        let tick_asset = self
            .assets
            .get(TICK_ASSET_KIND)
            .await?
            .ok_or(UserRequestError::MissingAsset(TICK_ASSET_KIND))?;
        let network = self.network()?;
        let rpc = self.client()?;
        let storm_eye_utxo =
            find_contract_utxo(&rpc, &storm_eye.contract_script, Some(storm_eye.asset_id))?;
        let token_utxo = find_token_utxo(&rpc, &tick_asset)?;
        let token_secrets = token_utxo
            .secrets
            .ok_or_else(|| UserRequestError::Invalid("Tick token secrets are missing".into()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UserRequestError::Clock)?
            .as_secs();
        let mut decoded = Vec::with_capacity(pending.len());
        let mut tick_count = 0usize;
        for stored in pending {
            let (request, fee_utxos) =
                validate_encoded_request(&stored.request).map_err(UserRequestError::Invalid)?;
            let account = AccountProgram::new(&AccountArguments {
                storm_eye_asset_id: storm_eye.asset_id,
                account_owner_pubkey: decode_array(&request.header.public_key)?,
            });
            let account_script = account.get_script_pubkey(&network);
            let mut resolved_fee_utxos = Vec::with_capacity(fee_utxos.len());
            let mut unavailable = None;
            for fee_utxo in fee_utxos {
                let outpoint = format!("{}:{}", hex::encode(fee_utxo.txid), fee_utxo.output_index);
                let Some(utxo) = get_confirmed_fee_outpoint(&rpc, &fee_utxo)? else {
                    unavailable = Some(format!(
                        "fee UTXO '{outpoint}' is unavailable or has fewer than \
                         {MIN_FEE_UTXO_CONFIRMATIONS} confirmations"
                    ));
                    break;
                };
                if utxo.asset() != network.policy_asset()
                    || utxo.txout.script_pubkey != account_script
                {
                    unavailable = Some(format!(
                        "fee UTXO '{outpoint}' no longer satisfies the request fee policy"
                    ));
                    break;
                }
                resolved_fee_utxos.push(utxo);
            }
            if let Some(reason) = unavailable {
                self.requests
                    .mark_failed(stored.request_hash, reason.as_bytes())
                    .await?;
                tracing::warn!(
                    request_hash = %hex::encode(stored.request_hash),
                    %reason,
                    "rejected pending user request before issuance"
                );
                continue;
            }

            tick_count += request.requests.len();
            decoded.push((stored, request, resolved_fee_utxos));
        }
        if decoded.is_empty() {
            return Ok(None);
        }
        let issuance_amount = timestamp
            .checked_mul(tick_count as u64)
            .ok_or_else(|| UserRequestError::Invalid("Tick issuance amount overflow".into()))?;

        let mut final_transaction = FinalTransaction::new();
        let auth_program = storm_eye_program(&storm_eye)?;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
                UserRequestError::Invalid("Storm Eye contract data is missing".into())
            })?)?;
        let signing_branch = contract_data.storm_tree_root;
        final_transaction.add_program_input(
            PartialInput::new(storm_eye_utxo.clone()),
            ProgramInput::new(
                Box::new(auth_program.as_ref().clone()),
                Box::new(AuthWitness {
                    path: Either::Left((
                        (contract_data.storm_tree_root, contract_data.rescue_height),
                        (
                            [0; 64],
                            signing_branch,
                            std::array::from_fn(|_| Either::Left(())),
                        ),
                        Either::Left(0),
                    )),
                }),
            ),
            RequiredSignature::witness_tagged("PATH", ["Left", "1", "0"], STORM_EYE_TAG),
        );
        let treasury = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        });
        final_transaction.add_program_issuance_input(
            PartialInput::new(token_utxo.clone()),
            ProgramInput::new(
                Box::new(treasury.as_ref().clone()),
                Box::new(TreasuryWitness {
                    storm_eye_input_index: 0,
                }),
            ),
            IssuanceInput::new_reissuance(
                issuance_amount,
                tick_asset
                    .entropy
                    .ok_or_else(|| UserRequestError::Invalid("Tick entropy is missing".into()))?,
            ),
            RequiredSignature::None,
        );

        let policy_asset = network.policy_asset();
        let tick_asset_id = asset_id(tick_asset.asset_id)?;
        let mut spent_utxo_secrets = vec![
            explicit_txout_secrets(&storm_eye_utxo.txout)?,
            token_secrets,
            TxOutSecrets::new(
                tick_asset_id,
                confidential::AssetBlindingFactor::zero(),
                issuance_amount,
                confidential::ValueBlindingFactor::zero(),
            ),
        ];
        let mut spent_utxos = vec![storm_eye_utxo.txout.clone(), token_utxo.txout.clone()];
        let mut account_balances = Vec::with_capacity(decoded.len());
        for (_, request, fee_utxos) in &decoded {
            let owner = decode_array(&request.header.public_key)?;
            let account = AccountProgram::new(&AccountArguments {
                storm_eye_asset_id: storm_eye.asset_id,
                account_owner_pubkey: owner,
            });
            let mut input_total = 0u64;
            for utxo in fee_utxos {
                input_total = input_total
                    .checked_add(utxo.amount())
                    .ok_or_else(|| UserRequestError::Invalid("fee input overflow".into()))?;
                spent_utxo_secrets.push(explicit_txout_secrets(&utxo.txout)?);
                spent_utxos.push(utxo.txout.clone());
                final_transaction.add_program_input(
                    PartialInput::new(utxo.clone()),
                    ProgramInput::new(
                        Box::new(account.as_ref().clone()),
                        Box::new(
                            contracts::artifacts::account::derived_account::AccountWitness {
                                storm_eye_input_index: 0,
                            },
                        ),
                    ),
                    RequiredSignature::None,
                );
            }
            account_balances.push(input_total);
        }

        final_transaction.add_output(output_from_utxo(&storm_eye_utxo));
        final_transaction.add_output(output_from_utxo(&token_utxo));
        let mut request_results = Vec::with_capacity(decoded.len());
        for (stored, request, _) in &decoded {
            let mut results = Vec::with_capacity(request.requests.len());
            for user_request in &request.requests {
                let details: TickUtxoRequestDetails = serde_json::from_str(&user_request.payload)?;
                let vout = final_transaction.n_outputs();
                final_transaction.add_output(PartialOutput::new(
                    tick_program(storm_eye.asset_id, &details)?.get_script_pubkey(&network),
                    timestamp,
                    tick_asset_id,
                ));
                results.push(RequestResult {
                    kind: user_request.kind.clone(),
                    vout: vout as u64,
                    auth_method: details.utxo_auth_method,
                    payload: serde_json::to_string(&TickUtxoDetails { timestamp })?,
                });
            }
            request_results.push(PreparedRequestResult {
                request_hash: stored.request_hash,
                results,
            });
        }
        let account_requirements = decoded
            .iter()
            .zip(&account_balances)
            .map(|((_, request, _), input_total)| (request.requests.len(), *input_total))
            .collect::<Vec<_>>();
        let account_reserves = allocate_account_reserves(&account_requirements, &self.config)?;
        for ((_, request, _), reserve) in decoded.iter().zip(account_reserves) {
            let account = AccountProgram::new(&AccountArguments {
                storm_eye_asset_id: storm_eye.asset_id,
                account_owner_pubkey: decode_array(&request.header.public_key)?,
            });
            final_transaction.add_output(PartialOutput::new(
                account.get_script_pubkey(&network),
                reserve,
                policy_asset,
            ));
        }
        final_transaction.add_output(PartialOutput::new(
            treasury.get_script_pubkey(&network),
            self.config.operational_fee_sats * tick_count as u64,
            policy_asset,
        ));
        final_transaction.add_output(PartialOutput::new(
            Script::new(),
            self.config.issuance_transaction_fee_sats,
            policy_asset,
        ));

        let (mut pset, _) = final_transaction.extract_pst();
        let output_secrets = pset
            .outputs()
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != 1)
            .map(|(_, output)| explicit_txout_secrets(&output.to_txout()))
            .collect::<Result<Vec<_>, _>>()?;
        let output_secret_refs = output_secrets.iter().collect::<Vec<_>>();
        let secp = Secp256k1::new();
        let treasury_blinding_public_key =
            PublicKey::from_secret_key(&secp, &treasury_blinding_secret());
        let (token_output, _, _, _) = TxOut::new_last_confidential(
            &mut secp256k1_zkp::rand::thread_rng(),
            &secp,
            token_secrets.value,
            token_secrets.asset,
            token_utxo.txout.script_pubkey.clone(),
            treasury_blinding_public_key,
            &spent_utxo_secrets,
            &output_secret_refs,
        )
        .map_err(|_| UserRequestError::Invalid("failed to reblind Tick token".into()))?;
        let mut token_pset_output =
            simplex::simplicityhl::elements::pset::Output::from_txout(token_output);
        token_pset_output.blinding_key = Some(
            simplex::simplicityhl::elements::bitcoin::PublicKey::new(treasury_blinding_public_key),
        );
        token_pset_output.blinder_index = Some(1);
        pset.outputs_mut()[1] = token_pset_output;
        let token_input = &mut pset.inputs_mut()[1];
        let token_asset_commitment = token_utxo
            .txout
            .asset
            .commitment()
            .ok_or_else(|| UserRequestError::Invalid("Tick token asset is explicit".into()))?;
        let token_value_commitment = token_utxo
            .txout
            .value
            .commitment()
            .ok_or_else(|| UserRequestError::Invalid("Tick token value is explicit".into()))?;
        token_input.asset = Some(token_secrets.asset);
        token_input.amount = Some(token_secrets.value);
        token_input.blind_asset_proof = Some(Box::new(
            SurjectionProof::blind_asset_proof(
                &mut secp256k1_zkp::rand::thread_rng(),
                &secp,
                token_secrets.asset,
                token_secrets.asset_bf,
            )
            .map_err(|_| UserRequestError::Invalid("failed to prove Tick token asset".into()))?,
        ));
        token_input.blind_value_proof = Some(Box::new(
            RangeProof::blind_value_proof(
                &mut secp256k1_zkp::rand::thread_rng(),
                &secp,
                token_secrets.value,
                token_value_commitment,
                token_asset_commitment,
                token_secrets.value_bf,
            )
            .map_err(|_| UserRequestError::Invalid("failed to prove Tick token value".into()))?,
        ));
        let env = auth_program.as_ref().get_env(&pset, 0, &network)?;
        let sighash = env.c_tx_env().sighash_all().to_byte_array();
        let signing_hash = SigMessage::Tagged(STORM_EYE_TAG.to_string()).digest(sighash);
        let external_requests = decoded
            .iter()
            .map(|(stored, _, _)| ExternalRequests {
                request_hash: stored.request_hash,
                network_user_requests: stored.request.clone(),
                additional_payload: None,
            })
            .collect();
        let request = ExecuteUserRequests {
            tx: encode::serialize(&pset),
            signing_hash,
            signing_storm_tree_branch: signing_branch,
            external_requests,
        };

        Ok(Some(PreparedRound {
            request,
            final_transaction,
            pset,
            spent_utxos,
            request_results,
            network,
            storm_eye,
        }))
    }

    pub(crate) async fn finalize_and_broadcast(
        &self,
        prepared: PreparedRound,
        signing: SigningResult,
        proof: storm_tree::StormTreeProof,
    ) -> Result<usize, UserRequestError> {
        let signature = *signing
            .signatures
            .first()
            .ok_or_else(|| UserRequestError::Invalid("missing Storm Eye signature".into()))?;
        let branch_key = XOnlyPublicKey::from_slice(&signing.signing_storm_tree_branch)
            .map_err(|_| UserRequestError::Invalid("invalid Storm Eye signing branch".into()))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| UserRequestError::Invalid("invalid Storm Eye signature".into()))?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest_slice(&prepared.request.signing_hash)
                    .expect("the signing hash has 32 bytes"),
                &branch_key,
            )
            .map_err(|_| {
                UserRequestError::Invalid(
                    "Storm Eye signature failed independent BIP340 verification".into(),
                )
            })?;
        let signature = *signature.as_ref();
        let mut transaction = prepared.final_transaction;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(prepared.storm_eye.contract_data.as_deref().ok_or_else(
                || UserRequestError::Invalid("Storm Eye contract data is missing".into()),
            )?)?;
        if !storm_tree::StormTree::verify_branch(
            &contract_data.storm_tree_root,
            &signing.signing_storm_tree_branch,
            &proof,
        ) {
            return Err(UserRequestError::Invalid(
                "signing branch is not included in the Storm Eye root".into(),
            ));
        }
        let proof = pack_proof(&proof)?;
        transaction.inputs_mut()[0]
            .program_input
            .as_mut()
            .expect("Storm Eye is a program input")
            .witness = Box::new(AuthWitness {
            path: Either::Left((
                (contract_data.storm_tree_root, contract_data.rescue_height),
                (signature, signing.signing_storm_tree_branch, proof),
                Either::Left(0),
            )),
        });

        let mut pset = prepared.pset;
        for (index, input) in transaction.inputs().iter().enumerate() {
            let Some(program_input) = &input.program_input else {
                continue;
            };
            let final_witness = program_input
                .program
                .finalize(
                    &pset,
                    &program_input.witness.build_witness(),
                    index,
                    &prepared.network,
                )
                .map_err(|error| {
                    UserRequestError::Invalid(format!(
                        "failed to finalize covenant input {index}: {error}"
                    ))
                })?;
            pset.inputs_mut()[index].final_script_witness = Some(final_witness);
        }
        let storm_eye_program = storm_eye_program(&prepared.storm_eye)?;
        let final_env = storm_eye_program
            .as_ref()
            .get_env(&pset, 0, &prepared.network)?;
        let final_sighash = final_env.c_tx_env().sighash_all().to_byte_array();
        let final_signing_hash =
            SigMessage::Tagged(STORM_EYE_TAG.to_string()).digest(final_sighash);
        if final_signing_hash != prepared.request.signing_hash {
            return Err(UserRequestError::Invalid(
                "final Tick issuance signing hash changed".into(),
            ));
        }
        let final_tx = pset
            .extract_tx()
            .map_err(|error| UserRequestError::Pset(error.to_string()))?;
        final_tx
            .verify_tx_amt_proofs(&Secp256k1::new(), &prepared.spent_utxos)
            .map_err(|error| {
                UserRequestError::Invalid(format!(
                    "failed to verify Tick issuance amounts and proofs: {error}"
                ))
            })?;
        let txid = final_tx.txid().to_string();
        let transaction_hex = hex::encode(encode::serialize(&final_tx));
        tracing::debug!(%txid, "prepared Tick issuance transaction");
        let client = self.client()?;
        let broadcast_txid: String =
            client.call("sendrawtransaction", &[transaction_hex.into()])?;
        if broadcast_txid != txid {
            return Err(UserRequestError::Invalid(
                "broadcast transaction id mismatch".into(),
            ));
        }

        let mut updated = 0;
        for result in prepared.request_results {
            let payload = serde_json::to_vec(&NetworkRequestsResult {
                txid: txid.clone(),
                results: result.results,
            })?;
            updated += usize::from(
                self.requests
                    .mark_processing(result.request_hash, &payload)
                    .await?,
            );
        }

        Ok(updated)
    }

    pub(crate) async fn reconcile_confirmations(&self) -> Result<usize, UserRequestError> {
        let processing = self.requests.list_processing().await?;
        if processing.is_empty() {
            return Ok(0);
        }
        let client = self.client()?;
        let mut updated = 0;
        for request in processing {
            let Some(payload) = request.payload else {
                continue;
            };
            let result: NetworkRequestsResult = serde_json::from_slice(&payload)?;
            let confirmation: RawTransactionInfo = client.call(
                "getrawtransaction",
                &[result.txid.clone().into(), true.into()],
            )?;
            if confirmation.confirmations > 0 {
                updated += usize::from(self.requests.mark_executed(request.request_hash).await?);
            }
        }

        Ok(updated)
    }

    fn network(&self) -> Result<SimplicityNetwork, UserRequestError> {
        let client = self.client()?;
        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;

        match chain.chain.as_str() {
            "liquidv1" => Ok(SimplicityNetwork::Liquid),
            "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
            "elementsregtest" => {
                let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
                let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
                elements_regtest_network(&sidechain.pegged_asset, &genesis_hash)
            }
            _ => Err(UserRequestError::UnsupportedChain(chain.chain)),
        }
    }

    fn client(&self) -> Result<Client, UserRequestError> {
        let mut url = Url::parse(&self.elements_rpc.url)?;
        url.path_segments_mut()
            .map_err(|_| url::ParseError::RelativeUrlWithCannotBeABaseBase)?
            .pop_if_empty()
            .push("wallet")
            .push(&self.elements_rpc.wallet);
        Ok(Client::new(
            url.as_str(),
            Auth::UserPass(
                self.elements_rpc.username.clone(),
                self.elements_rpc.password.clone(),
            ),
        )?)
    }
}

fn elements_regtest_network(
    policy_asset: &str,
    genesis_hash: &str,
) -> Result<SimplicityNetwork, UserRequestError> {
    Ok(SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_str(policy_asset)
            .map_err(|_| UserRequestError::Invalid("invalid regtest policy asset".into()))?,
        genesis_hash: BlockHash::from_str(genesis_hash)
            .map_err(|_| UserRequestError::Invalid("invalid regtest genesis block hash".into()))?,
    })
}

fn find_contract_utxo(
    client: &Client,
    script: &[u8],
    expected_asset: Option<[u8; 32]>,
) -> Result<UTXO, UserRequestError> {
    let descriptor = format!("raw({})", hex::encode(script));
    let scan: ScanResult = client.call(
        "scantxoutset",
        &["start".into(), serde_json::json!([descriptor])],
    )?;
    for unspent in scan.unspents {
        let outpoint = FeeUtxo {
            txid: decode_array(&unspent.txid)?,
            output_index: unspent.vout,
        };
        let utxo = get_outpoint(client, &outpoint)?;
        let asset_matches = expected_asset
            .is_none_or(|expected| utxo.asset() == AssetId::from_byte_array(expected));
        if asset_matches {
            return Ok(utxo);
        }
    }

    Err(UserRequestError::Invalid(
        "required network covenant UTXO is unavailable".into(),
    ))
}

fn find_token_utxo(client: &Client, tick_asset: &NetworkAsset) -> Result<UTXO, UserRequestError> {
    let token_id = asset_id(
        tick_asset
            .reissuance_token_id
            .ok_or_else(|| UserRequestError::Invalid("Tick token id is missing".into()))?,
    )?;
    let token_txout = tick_token_txout(tick_asset)?;
    let secrets = token_txout
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .map_err(|_| UserRequestError::Invalid("failed to unblind Tick token".into()))?;
    if secrets.asset != token_id
        || token_txout.script_pubkey.as_bytes() != tick_asset.contract_script
        || !token_txout.asset.is_confidential()
        || !token_txout.value.is_confidential()
    {
        return Err(UserRequestError::Invalid(
            "invalid confidential Tick token template".into(),
        ));
    }

    let descriptor = format!("raw({})", hex::encode(&tick_asset.contract_script));
    let scan: ScanResult = client.call(
        "scantxoutset",
        &["start".into(), serde_json::json!([descriptor])],
    )?;
    for unspent in scan.unspents {
        let txid = Txid::from_str(&unspent.txid)
            .map_err(|_| UserRequestError::Invalid("invalid Tick token txid".into()))?;
        let transaction = get_raw_transaction(client, txid, unspent.height)?;
        let Some(candidate) = transaction.output.get(unspent.vout as usize).cloned() else {
            continue;
        };
        let Ok(candidate_secrets) =
            candidate.unblind(&Secp256k1::new(), treasury_blinding_secret())
        else {
            continue;
        };
        if candidate_secrets.asset == secrets.asset
            && candidate_secrets.value == secrets.value
            && candidate.script_pubkey.as_bytes() == tick_asset.contract_script
            && candidate.asset.is_confidential()
            && candidate.value.is_confidential()
        {
            return Ok(UTXO {
                outpoint: OutPoint::new(txid, unspent.vout),
                txout: candidate,
                secrets: Some(candidate_secrets),
            });
        }
    }

    Err(UserRequestError::Invalid(
        "confidential Tick token UTXO is unavailable".into(),
    ))
}

fn tick_token_txout(tick_asset: &NetworkAsset) -> Result<TxOut, UserRequestError> {
    let contract_data: TickAssetContractData = postcard::from_bytes(
        tick_asset
            .contract_data
            .as_deref()
            .ok_or_else(|| UserRequestError::Invalid("Tick contract data is missing".into()))?,
    )?;

    let transaction: simplex::simplicityhl::elements::Transaction =
        encode::deserialize(&contract_data.issuance_tx)
            .map_err(|_| UserRequestError::Invalid("invalid Tick issuance transaction".into()))?;
    transaction
        .output
        .get(contract_data.token_output_index as usize)
        .cloned()
        .ok_or_else(|| UserRequestError::Invalid("invalid Tick token output index".into()))
}

fn get_outpoint(client: &Client, outpoint: &FeeUtxo) -> Result<UTXO, UserRequestError> {
    let txid = Txid::from_str(&hex::encode(outpoint.txid))
        .map_err(|_| UserRequestError::Invalid("invalid UTXO txid".into()))?;
    get_explicit_outpoint(client, txid, outpoint.output_index)
}

#[derive(Deserialize)]
struct GetTxOut {
    confirmations: u64,
    asset: Option<String>,
    value: Option<Number>,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: GetTxOutScript,
}

#[derive(Deserialize)]
struct GetTxOutScript {
    hex: String,
}

#[derive(Deserialize)]
struct SidechainInfo {
    pegged_asset: String,
}

fn get_explicit_outpoint(
    client: &Client,
    txid: Txid,
    output_index: u32,
) -> Result<UTXO, UserRequestError> {
    let output = get_txout(client, txid, output_index)?;
    explicit_outpoint(txid, output_index, output)
}

fn explicit_outpoint(
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

fn get_txout(client: &Client, txid: Txid, output_index: u32) -> Result<GetTxOut, UserRequestError> {
    get_txout_optional(client, txid, output_index)?
        .ok_or_else(|| UserRequestError::Invalid("required UTXO is unavailable".into()))
}

fn get_confirmed_fee_outpoint(
    client: &Client,
    outpoint: &FeeUtxo,
) -> Result<Option<UTXO>, UserRequestError> {
    let txid = Txid::from_str(&hex::encode(outpoint.txid))
        .map_err(|_| UserRequestError::Invalid("invalid UTXO txid".into()))?;
    let Some(output) = get_txout_optional(client, txid, outpoint.output_index)? else {
        return Ok(None);
    };
    if output.confirmations < MIN_FEE_UTXO_CONFIRMATIONS {
        return Ok(None);
    }

    explicit_outpoint(txid, outpoint.output_index, output).map(Some)
}

fn get_txout_optional(
    client: &Client,
    txid: Txid,
    output_index: u32,
) -> Result<Option<GetTxOut>, UserRequestError> {
    Ok(client.call::<Option<GetTxOut>>(
        "gettxout",
        &[txid.to_string().into(), output_index.into(), true.into()],
    )?)
}

fn get_raw_transaction(
    client: &Client,
    txid: Txid,
    block_height: Option<u64>,
) -> Result<simplex::simplicityhl::elements::Transaction, UserRequestError> {
    let raw: String = if let Some(height) = block_height {
        let block_hash: String = client.call("getblockhash", &[height.into()])?;
        client.call(
            "getrawtransaction",
            &[txid.to_string().into(), false.into(), block_hash.into()],
        )?
    } else {
        client.call(
            "getrawtransaction",
            &[txid.to_string().into(), false.into()],
        )?
    };
    encode::deserialize(
        &hex::decode(raw)
            .map_err(|_| UserRequestError::Invalid("invalid Tick token transaction".into()))?,
    )
    .map_err(UserRequestError::Transaction)
}

fn explicit_txout_secrets(txout: &TxOut) -> Result<TxOutSecrets, UserRequestError> {
    let asset = txout
        .asset
        .explicit()
        .ok_or_else(|| UserRequestError::Invalid("expected explicit transaction asset".into()))?;
    let value = txout
        .value
        .explicit()
        .ok_or_else(|| UserRequestError::Invalid("expected explicit transaction value".into()))?;
    Ok(TxOutSecrets::new(
        asset,
        confidential::AssetBlindingFactor::zero(),
        value,
        confidential::ValueBlindingFactor::zero(),
    ))
}

fn output_from_utxo(utxo: &UTXO) -> PartialOutput {
    PartialOutput::new(
        utxo.txout.script_pubkey.clone(),
        utxo.amount(),
        utxo.asset(),
    )
}

fn pack_proof(
    proof: &storm_tree::StormTreeProof,
) -> Result<PackedStormTreeProof, UserRequestError> {
    if proof.siblings.len() > storm_tree::TREE_DEPTH as usize {
        return Err(UserRequestError::Invalid(
            "Storm Tree proof is too deep".into(),
        ));
    }
    Ok(std::array::from_fn(|index| {
        proof
            .siblings
            .get(index)
            .copied()
            .map_or(Either::Left(()), Either::Right)
    }))
}

fn validate_execute_request(
    request: &ExecuteUserRequests,
    storm_eye: &NetworkAsset,
    tick_asset: &NetworkAsset,
    config: &UserRequestsConfig,
    network: &SimplicityNetwork,
) -> Result<(), UserRequestError> {
    if request.external_requests.is_empty() {
        return Err(UserRequestError::Invalid("no external requests".into()));
    }
    let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
    if pset.inputs().len() < 3 || pset.outputs().len() < 5 {
        return Err(UserRequestError::Invalid(
            "issuance transaction is incomplete".into(),
        ));
    }

    let storm_eye_program = storm_eye_program(storm_eye)?;
    let storm_eye_input = witness_utxo(&pset, 0)?;
    let storm_eye_asset_id = asset_id(storm_eye.asset_id)?;
    require_explicit_utxo(
        storm_eye_input,
        storm_eye_asset_id,
        &storm_eye.contract_script,
        "Storm Eye",
    )?;
    require_preserved_output(&pset, 0, storm_eye_input, "Storm Eye")?;

    let token_input = witness_utxo(&pset, 1)?;
    let expected_token = tick_token_txout(tick_asset)?;
    let expected_token_secrets = expected_token
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .map_err(|_| UserRequestError::Invalid("failed to unblind Tick token template".into()))?;
    let token_input_map = &pset.inputs()[1];
    let token_asset_commitment = token_input
        .asset
        .commitment()
        .ok_or_else(|| UserRequestError::Invalid("Tick token asset is explicit".into()))?;
    let token_value_commitment = token_input
        .value
        .commitment()
        .ok_or_else(|| UserRequestError::Invalid("Tick token value is explicit".into()))?;
    let secp = Secp256k1::new();
    if token_input_map.asset != Some(expected_token_secrets.asset)
        || token_input_map.amount != Some(expected_token_secrets.value)
        || token_input.script_pubkey != expected_token.script_pubkey
        || !token_input.asset.is_confidential()
        || !token_input.value.is_confidential()
        || !token_input_map
            .blind_asset_proof
            .as_ref()
            .is_some_and(|proof| {
                proof.blind_asset_proof_verify(
                    &secp,
                    expected_token_secrets.asset,
                    token_asset_commitment,
                )
            })
        || !token_input_map
            .blind_value_proof
            .as_ref()
            .is_some_and(|proof| {
                proof.blind_value_proof_verify(
                    &secp,
                    expected_token_secrets.value,
                    token_asset_commitment,
                    token_value_commitment,
                )
            })
    {
        return Err(UserRequestError::Invalid(
            "invalid Tick reissuance token input".into(),
        ));
    }
    let token_output = pset.outputs()[1].to_txout();
    let token_output_secrets = token_output
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .map_err(|_| UserRequestError::Invalid("failed to unblind Tick token output".into()))?;
    if token_output_secrets.asset != expected_token_secrets.asset
        || token_output_secrets.value != expected_token_secrets.value
        || token_output.script_pubkey != token_input.script_pubkey
        || !token_output.asset.is_confidential()
        || !token_output.value.is_confidential()
    {
        return Err(UserRequestError::Invalid(
            "Tick reissuance token is not preserved".into(),
        ));
    }

    let mut expected_fee_inputs = 0usize;
    let mut expected_ticks = Vec::new();
    let mut expected_account_scripts = Vec::new();
    for external in &request.external_requests {
        let request_hash: [u8; 32] = sha2::Sha256::digest(&external.network_user_requests).into();
        if request_hash != external.request_hash {
            return Err(UserRequestError::Invalid(
                "external request hash mismatch".into(),
            ));
        }
        if external.additional_payload.is_some() {
            return Err(UserRequestError::Invalid(
                "additional payload is unsupported for Tick requests".into(),
            ));
        }
        let (user_request, fee_utxos) = validate_encoded_request(&external.network_user_requests)
            .map_err(UserRequestError::Invalid)?;
        let owner = secp256k1_zkp::XOnlyPublicKey::from_slice(
            &hex::decode(&user_request.header.public_key)
                .map_err(|_| UserRequestError::Invalid("invalid requester public key".into()))?,
        )
        .map_err(|_| UserRequestError::Invalid("invalid requester public key".into()))?;
        let account_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: owner.serialize(),
        })
        .get_script_pubkey(network);

        let mut input_total = 0u64;
        for fee_utxo in &fee_utxos {
            let input_index = 2 + expected_fee_inputs;
            let input = pset.inputs().get(input_index).ok_or_else(|| {
                UserRequestError::Invalid("a submitted fee UTXO is missing".into())
            })?;
            let expected_txid =
                simplex::simplicityhl::elements::Txid::from_str(&hex::encode(fee_utxo.txid))
                    .map_err(|_| UserRequestError::Invalid("invalid fee UTXO txid".into()))?;
            if input.previous_txid != expected_txid
                || input.previous_output_index != fee_utxo.output_index
                || input
                    .witness_utxo
                    .as_ref()
                    .is_none_or(|utxo| utxo.script_pubkey != account_script)
            {
                return Err(UserRequestError::Invalid(
                    "fee UTXO input does not match the signed user request".into(),
                ));
            }
            let amount = input
                .witness_utxo
                .as_ref()
                .and_then(|utxo| utxo.value.explicit())
                .ok_or_else(|| UserRequestError::Invalid("fee UTXO must be explicit".into()))?;
            input_total = input_total
                .checked_add(amount)
                .ok_or_else(|| UserRequestError::Invalid("fee input overflow".into()))?;
            expected_fee_inputs += 1;
        }

        for user_request in &user_request.requests {
            let details: TickUtxoRequestDetails = serde_json::from_str(&user_request.payload)
                .map_err(|error| UserRequestError::Invalid(error.to_string()))?;
            expected_ticks.push(details);
        }
        expected_account_scripts.push((account_script, user_request.requests.len(), input_total));
    }
    if pset.inputs().len() != 2 + expected_fee_inputs {
        return Err(UserRequestError::Invalid(
            "issuance transaction has unrequested inputs".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UserRequestError::Clock)?
        .as_secs();
    let tick_asset_id = asset_id(tick_asset.asset_id)?;
    let mut issued_amount = 0u64;
    for (offset, details) in expected_ticks.iter().enumerate() {
        let output = pset.outputs().get(2 + offset).ok_or_else(|| {
            UserRequestError::Invalid("a requested Tick output is missing".into())
        })?;
        let timestamp = output
            .amount
            .ok_or_else(|| UserRequestError::Invalid("Tick amount is confidential".into()))?;
        if timestamp.abs_diff(now) > MAX_TICK_TIME_SKEW_SECS {
            return Err(UserRequestError::Invalid(
                "Tick timestamp is outside the accepted window".into(),
            ));
        }
        let expected_script = tick_program(storm_eye.asset_id, details)?.get_script_pubkey(network);
        if output.asset != Some(tick_asset_id) || output.script_pubkey != expected_script {
            return Err(UserRequestError::Invalid(
                "Tick output does not match the requested authentication method".into(),
            ));
        }
        issued_amount = issued_amount
            .checked_add(timestamp)
            .ok_or_else(|| UserRequestError::Invalid("Tick issuance amount overflow".into()))?;
    }
    let issuance_input = &pset.inputs()[1];
    if issuance_input.issuance_value_amount != Some(issued_amount)
        || issuance_input.issuance_asset_entropy != tick_asset.entropy
        || issuance_input.issuance_value_comm.is_some()
        || issuance_input.issuance_value_rangeproof.is_some()
        || issuance_input.in_issuance_blind_value_proof.is_some()
    {
        return Err(UserRequestError::Invalid(
            "Tick reissuance metadata does not match the requested outputs".into(),
        ));
    }

    let policy_asset = network.policy_asset();
    validate_accounting_outputs(
        &pset,
        &expected_account_scripts,
        expected_ticks.len(),
        storm_eye.asset_id,
        policy_asset,
        config,
        network,
    )?;

    let env = storm_eye_program
        .as_ref()
        .get_env(&pset, 0, network)
        .map_err(|error| {
            UserRequestError::Invalid(format!("cannot derive Storm Eye sighash: {error}"))
        })?;
    let sighash = env.c_tx_env().sighash_all().to_byte_array();
    let signing_hash = SigMessage::Tagged(STORM_EYE_TAG.to_string()).digest(sighash);
    if signing_hash != request.signing_hash {
        return Err(UserRequestError::Invalid("signing hash mismatch".into()));
    }

    Ok(())
}

fn tick_program(
    storm_eye_asset_id: [u8; 32],
    details: &TickUtxoRequestDetails,
) -> Result<TickAssetProgram, UserRequestError> {
    let mut arguments = TickAssetArguments {
        storm_eye_asset_id,
        auth_method: 0,
        auth_asset_id: [0; 32],
        auth_script_hash: [0; 32],
        auth_pubkey: [0; 32],
    };
    match details.utxo_auth_method.kind.as_str() {
        "asset-id-auth" => {
            arguments.auth_asset_id = decode_array(&details.utxo_auth_method.auth_data)?;
        }
        "scriptPubKey-auth" => {
            arguments.auth_method = 1;
            let script = Script::from(
                hex::decode(&details.utxo_auth_method.auth_data)
                    .map_err(|_| UserRequestError::Invalid("invalid auth script".into()))?,
            );
            arguments.auth_script_hash = hash_script(&script);
        }
        "signature-auth" => {
            arguments.auth_method = 2;
            arguments.auth_pubkey = decode_array(&details.utxo_auth_method.auth_data)?;
        }
        _ => {
            return Err(UserRequestError::Invalid(
                "unsupported Tick auth method".into(),
            ));
        }
    }

    Ok(TickAssetProgram::new(&arguments))
}

fn validate_accounting_outputs(
    pset: &PartiallySignedTransaction,
    accounts: &[(Script, usize, u64)],
    tick_count: usize,
    storm_eye_asset_id: [u8; 32],
    policy_asset: AssetId,
    config: &UserRequestsConfig,
    network: &SimplicityNetwork,
) -> Result<(), UserRequestError> {
    let expected_output_count = 2 + tick_count + accounts.len() + 2;
    if pset.outputs().len() != expected_output_count {
        return Err(UserRequestError::Invalid(
            "issuance transaction has unexpected outputs".into(),
        ));
    }
    for (index, output) in pset.outputs().iter().enumerate() {
        if index != 1 && !is_fully_explicit_output(output) {
            return Err(UserRequestError::Invalid(format!(
                "issuance output {index} must be explicit"
            )));
        }
    }

    let treasury_script =
        TreasuryProgram::new(&TreasuryArguments { storm_eye_asset_id }).get_script_pubkey(network);
    let expected_operational = config
        .operational_fee_sats
        .checked_mul(tick_count as u64)
        .ok_or_else(|| UserRequestError::Invalid("operational fee overflow".into()))?;
    let treasury_ok = pset.outputs().iter().any(|output| {
        output.script_pubkey == treasury_script
            && output.asset == Some(policy_asset)
            && output.amount == Some(expected_operational)
    });
    if !treasury_ok {
        return Err(UserRequestError::Invalid(
            "Treasury operational fee output is missing".into(),
        ));
    }
    let account_requirements = accounts
        .iter()
        .map(|(_, request_count, input_total)| (*request_count, *input_total))
        .collect::<Vec<_>>();
    let account_reserves = allocate_account_reserves(&account_requirements, config)?;
    for (index, ((script, _, _), expected_reserve)) in
        accounts.iter().zip(account_reserves).enumerate()
    {
        let output = pset.outputs().get(2 + tick_count + index).ok_or_else(|| {
            UserRequestError::Invalid("user burn-fee reserve output is missing".into())
        })?;
        if output.script_pubkey != *script
            || output.asset != Some(policy_asset)
            || output.amount != Some(expected_reserve)
        {
            return Err(UserRequestError::Invalid(
                "invalid user burn-fee reserve output".into(),
            ));
        }
    }
    if !pset.outputs().iter().any(|output| {
        output.script_pubkey.is_empty()
            && output.asset == Some(policy_asset)
            && output.amount == Some(config.issuance_transaction_fee_sats)
    }) {
        return Err(UserRequestError::Invalid(
            "miner fee output is missing".into(),
        ));
    }
    let input_total = pset.inputs()[2..].iter().try_fold(0u64, |total, input| {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| UserRequestError::Invalid("fee UTXO is missing".into()))?;
        if utxo.asset.explicit() != Some(policy_asset) {
            return Err(UserRequestError::Invalid("fee UTXO asset mismatch".into()));
        }
        total
            .checked_add(
                utxo.value
                    .explicit()
                    .ok_or_else(|| UserRequestError::Invalid("fee UTXO must be explicit".into()))?,
            )
            .ok_or_else(|| UserRequestError::Invalid("fee input overflow".into()))
    })?;
    let output_total = pset.outputs().iter().try_fold(0u64, |total, output| {
        if output.asset != Some(policy_asset) {
            return Ok(total);
        }
        total
            .checked_add(output.amount.ok_or_else(|| {
                UserRequestError::Invalid("policy asset output must be explicit".into())
            })?)
            .ok_or_else(|| UserRequestError::Invalid("fee output overflow".into()))
    })?;
    if input_total != output_total {
        return Err(UserRequestError::Invalid(
            "policy asset inputs and outputs do not balance".into(),
        ));
    }

    Ok(())
}

fn is_fully_explicit_output(output: &simplex::simplicityhl::elements::pset::Output) -> bool {
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

fn allocate_account_reserves(
    accounts: &[(usize, u64)],
    config: &UserRequestsConfig,
) -> Result<Vec<u64>, UserRequestError> {
    let mut transaction_fee_remaining = config.issuance_transaction_fee_sats;
    let mut reserves = Vec::with_capacity(accounts.len());

    for (request_count, input_total) in accounts {
        let operational_fee = config
            .operational_fee_sats
            .checked_mul(*request_count as u64)
            .ok_or_else(|| UserRequestError::Invalid("operational fee overflow".into()))?;
        let minimum_reserve = config
            .tick_burn_reserve_sats
            .checked_mul(*request_count as u64)
            .ok_or_else(|| UserRequestError::Invalid("burn reserve overflow".into()))?;
        let available_for_fee = input_total
            .checked_sub(operational_fee)
            .and_then(|amount| amount.checked_sub(minimum_reserve))
            .ok_or_else(|| UserRequestError::Invalid("insufficient user fee funds".into()))?;
        let transaction_fee = available_for_fee.min(transaction_fee_remaining);
        transaction_fee_remaining -= transaction_fee;
        reserves.push(input_total - operational_fee - transaction_fee);
    }
    if transaction_fee_remaining != 0 {
        return Err(UserRequestError::Invalid(
            "insufficient funds for the issuance transaction fee".into(),
        ));
    }

    Ok(reserves)
}

fn witness_utxo(
    pset: &PartiallySignedTransaction,
    index: usize,
) -> Result<&simplex::simplicityhl::elements::TxOut, UserRequestError> {
    pset.inputs()
        .get(index)
        .and_then(|input| input.witness_utxo.as_ref())
        .ok_or_else(|| UserRequestError::Invalid(format!("input {index} has no witness UTXO")))
}

fn require_explicit_utxo(
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

fn require_preserved_output(
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

fn asset_id(bytes: [u8; 32]) -> Result<AssetId, UserRequestError> {
    Ok(AssetId::from_byte_array(bytes))
}

fn decode_array(encoded: &str) -> Result<[u8; 32], UserRequestError> {
    hex::decode(encoded)
        .map_err(|_| UserRequestError::Invalid("invalid authentication data".into()))?
        .try_into()
        .map_err(|_| UserRequestError::Invalid("invalid authentication data".into()))
}

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
}

#[derive(Deserialize)]
struct ScanResult {
    unspents: Vec<ScannedUtxo>,
}

#[derive(Deserialize)]
struct ScannedUtxo {
    txid: String,
    vout: u32,
    height: Option<u64>,
}

#[derive(Deserialize)]
struct RawTransactionInfo {
    #[serde(default)]
    confirmations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> UserRequestsConfig {
        UserRequestsConfig {
            operational_fee_sats: 100,
            tick_burn_reserve_sats: 200,
            issuance_transaction_fee_sats: 150,
        }
    }

    #[test]
    fn allocates_transaction_fee_across_account_surplus() {
        let reserves = allocate_account_reserves(&[(1, 400), (1, 500)], &config()).unwrap();

        assert_eq!(reserves, vec![200, 350]);
    }

    #[test]
    fn rejects_insufficient_aggregate_transaction_fee() {
        let error = allocate_account_reserves(&[(1, 349), (1, 400)], &config()).unwrap_err();

        assert!(matches!(error, UserRequestError::Invalid(message)
            if message == "insufficient funds for the issuance transaction fee"));
    }

    #[test]
    fn uses_custom_regtest_genesis_for_simplicity_environment() {
        let policy_asset = SimplicityNetwork::default_regtest()
            .policy_asset()
            .to_string();
        let genesis_hash = "209577bda6bf4b5804bd46f8621580dd6d4e8bfa2d190e1c50e932492baca07d";

        let network = elements_regtest_network(&policy_asset, genesis_hash).unwrap();

        assert_eq!(network.genesis_block_hash().to_string(), genesis_hash);
        assert_eq!(network.policy_asset().to_string(), policy_asset);
    }
}
