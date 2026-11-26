use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use bitcoincore_rpc::{Client, RpcApi};
use contracts::artifacts::{
    account::{AccountProgram, derived_account::AccountArguments},
    treasury::{
        TreasuryProgram,
        derived_treasury::{TreasuryArguments, TreasuryWitness},
    },
};
use secp256k1_zkp::{Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use simplex::{
    either::Either,
    program::ProgramTrait,
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, BlockHash, OutPoint, Script, TxOut, TxOutSecrets, Txid,
        confidential::{self, RangeProof, SurjectionProof},
        encode,
        pset::PartiallySignedTransaction,
    },
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage,
        partial_input::IssuanceInput, utxo::UTXO,
    },
};

use crate::high_storm::elements;
use crate::high_storm::elements::RawTransactionInfo;
use crate::{
    NetworkAsset,
    config::{ElementsRpcConfig, ProtocolConfig},
    db::{
        monitored_utxo::MonitoredUtxoStore,
        network_asset::{NetworkAssetStore, ORACLE_VERIFIER_KIND, STORM_EYE_KIND, TICK_ASSET_KIND},
        user_request::{FeeUtxo, UserRequestStore},
    },
    external_api::{
        fee_utxo::MIN_FEE_UTXO_CONFIRMATIONS,
        users::{
            PRICE_REQUEST_KIND, TickUtxoRequestDetails, UtxoAuthMethod, validate_encoded_request,
        },
    },
};
use price_feed::{FeedId, PriceFeedData};
use storm_tree::StormTreeBranch;

use super::elements::{STORM_EYE_TAG, asset_id, finalized_dummy_weight, pack_proof};
use super::utxo::{
    ScanResult, StormEyePool, explicit_outpoint, find_contract_utxo, get_txout_optional,
    is_fully_explicit_output, output_from_utxo, require_explicit_utxo, require_preserved_output,
    scan_contract_utxos, witness_utxo,
};
use super::{
    SigningResult,
    assets::{
        StormEyeContractData, TickAssetContractData, storm_eye_program, treasury_blinding_secret,
    },
    issuance::{IssuedUtxoDescriptor, MAX_ISSUED_DESCRIPTORS},
    message::{ChainTip, ExecuteUserRequests, ExternalRequests},
    prices::{Prices, price_hash},
    signing::{SIGNING_SESSION_TIMEOUT, SigningError},
};

const MAX_TICK_TIME_SKEW_SECS: u64 = 120;
/// Ten blocks, about ten minutes at the target interval: long enough to ride
/// out a restart or a slow poll, short enough not to strand a user's fees on a
/// feed this node never prices.
pub(crate) const MAX_UNPRICED_REQUEST_BLOCKS: u64 = 10;
/// How many pending requests a round reads at a time while looking for ones it
/// can issue.
const PENDING_SCAN_PAGE: u32 = 100;
/// The most pending requests one round reads. Every row costs a signature
/// check, so the scan stays bounded even when the queue ahead of it is all
/// requests this round cannot issue.
const MAX_PENDING_SCAN: usize = 1_000;
const MAX_MEMPOOL_TOKEN_CHAIN_LENGTH: usize = 100;
const MAX_REQUESTS_PER_ROUND: u32 = 100;
/// Verifier key until an attempt sets the branch (secp256k1 generator).
const PLACEHOLDER_SIGNER: StormTreeBranch = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

pub(crate) struct PreparedRound {
    pub(crate) request: ExecuteUserRequests,
    pub(crate) transaction: RoundTransaction,
    final_transaction: FinalTransaction,
    spent_utxos: Vec<TxOut>,
    request_results: Vec<PreparedRequestResult>,
    max_transaction_weight: usize,
    instructed: Option<PriceFeedData>,
}

/// Issuance tx before its signing branch is known.
#[derive(Clone)]
pub(crate) struct RoundTransaction {
    pset: PartiallySignedTransaction,
    descriptors: Vec<IssuedUtxoDescriptor>,
    descriptor_output: usize,
    storm_eye: NetworkAsset,
    network: SimplicityNetwork,
}

/// A token a round spends and the amount it reissues.
struct RoundToken {
    asset: NetworkAsset,
    utxo: UTXO,
    secrets: TxOutSecrets,
    issuance_amount: u64,
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

/// Payload of a `signed-price-data` result.
#[derive(Serialize)]
struct SignedPriceDataDetails {
    price_data: String,
    storm_tree_bloom: StormTreeBloom,
}

/// Everything needed to check the network signature over `price_data`. The
/// root it proves against is the Storm Eye's on-chain one, so a reader takes
/// that from the chain rather than from here.
#[derive(Clone, Serialize)]
struct StormTreeBloom {
    signature: String,
    branch: String,
    proof: Vec<BloomStep>,
}

#[derive(Clone, Serialize)]
struct BloomStep {
    right: bool,
    hash: String,
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
    #[error("the instructed price was refused: {0}")]
    InstructedPrice(#[from] price_feed::ValidationError),
}

#[derive(Clone)]
pub(crate) struct UserRequestProcessor {
    requests: UserRequestStore,
    monitored_utxos: MonitoredUtxoStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    config: ProtocolConfig,
    prices: Prices,
}

impl UserRequestProcessor {
    pub(crate) fn new(
        requests: UserRequestStore,
        monitored_utxos: MonitoredUtxoStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        config: ProtocolConfig,
        prices: Prices,
    ) -> Self {
        Self {
            requests,
            monitored_utxos,
            assets,
            elements_rpc,
            config,
            prices,
        }
    }

    /// A rate this node refuses rejects the whole message. Returns the rate the
    /// round is issued at, which is the only one this node will sign beside it.
    pub(crate) async fn validate_execute(
        &self,
        request: &ExecuteUserRequests,
    ) -> Result<Option<PriceFeedData>, UserRequestError> {
        let storm_eye = self.asset(STORM_EYE_KIND).await?;
        let tick_asset = self.assets.get(TICK_ASSET_KIND).await?;
        let verifier_asset = self.assets.get(ORACLE_VERIFIER_KIND).await?;
        let network = self.network()?;

        let instructed = validate_execute_request(
            request,
            &storm_eye,
            tick_asset.as_ref(),
            verifier_asset.as_ref(),
            &self.config,
            &network,
        )?;
        let fee_utxos = request
            .external_requests
            .iter()
            .map(|external| {
                validate_encoded_request(&external.network_user_requests)
                    .map(|(_, fee_utxos, _)| fee_utxos)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(UserRequestError::Invalid)?
            .concat();
        require_unreserved_anchored_fee_utxos(
            &self.monitored_utxos,
            &self.client()?,
            request.chain_tip,
            &fee_utxos,
        )
        .await?;
        if let Some(instructed) = instructed {
            self.prices.validate_instruction(&instructed).await?;
        }
        Ok(instructed)
    }

    pub(crate) async fn prepare_round(
        &self,
        block_height: u64,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<Option<PreparedRound>, UserRequestError> {
        let mut lower_limit = 1u32;
        let mut upper_limit = MAX_REQUESTS_PER_ROUND;
        let mut request_limit = upper_limit;
        let mut best = None;

        while lower_limit <= upper_limit {
            let Some(candidate) = self
                .prepare_round_candidate(
                    block_height,
                    storm_eye_lane,
                    request_limit,
                    max_transaction_weight,
                )
                .await?
            else {
                return Ok(best);
            };
            let request_count = u32::try_from(candidate.request_results.len())
                .map_err(|_| UserRequestError::Invalid("request count overflow".into()))?;
            let weight = candidate.estimated_weight()?;
            if weight <= max_transaction_weight {
                best = Some(candidate);
                if request_count < request_limit || request_limit == MAX_REQUESTS_PER_ROUND {
                    break;
                }
                lower_limit = request_count + 1;
            } else {
                if request_count == 1 {
                    let request_hash = candidate.request_results[0].request_hash;
                    let reason = format!(
                        "request transaction weight {weight} exceeds round limit {max_transaction_weight}"
                    );
                    if self
                        .requests
                        .mark_failed(request_hash, reason.as_bytes())
                        .await?
                    {
                        crate::monitoring::record_user_request_failed("over_weight");
                    }
                    return Err(UserRequestError::Invalid(reason));
                }
                upper_limit = request_count - 1;
            }
            request_limit = lower_limit + (upper_limit - lower_limit) / 2;
        }

        Ok(best)
    }

    async fn prepare_round_candidate(
        &self,
        block_height: u64,
        storm_eye_lane: usize,
        request_limit: u32,
        max_transaction_weight: usize,
    ) -> Result<Option<PreparedRound>, UserRequestError> {
        let mut cursor = None;
        let mut pending = self
            .requests
            .list_pending_after(PENDING_SCAN_PAGE, cursor)
            .await?;
        if pending.is_empty() {
            return Ok(None);
        }
        let storm_eye = self.asset(STORM_EYE_KIND).await?;
        let network = self.network()?;
        let rpc = self.client()?;
        let storm_eye_utxo = find_contract_utxo(
            &rpc,
            &storm_eye.contract_script,
            Some(storm_eye.asset_id),
            StormEyePool::UserRequests(storm_eye_lane),
        )?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UserRequestError::Clock)?
            .as_secs();
        let mut decoded = Vec::with_capacity(pending.len());
        let mut issued_count = 0usize;
        // One round is issued at one feed; batches naming another wait.
        let mut instructed: Option<PriceFeedData> = None;
        // The queue is walked in pages, not taken as one window, so a run of
        // requests this round cannot issue delays only those requests. Taking a
        // window would let a page of them empty the round and stop issuance for
        // everyone behind them. The scan is still bounded, since every row read
        // costs a signature check.
        let mut scanned = 0usize;
        'fill: loop {
            for stored in pending {
                cursor = Some((stored.block_height, stored.request_hash));
                scanned += 1;
                let (request, fee_utxos, named_feed) =
                    validate_encoded_request(&stored.request).map_err(UserRequestError::Invalid)?;
                // A priced request is held up by more than a missing local price: a
                // signer that refuses the rate fails the whole round, and the same
                // batch returns every block. Age it out whatever held it up, so its
                // fees come back and the requests queued behind it can issue.
                if let Some(feed) = named_feed
                    && waited_too_long(block_height, stored.block_height)
                {
                    let waited = block_height.saturating_sub(stored.block_height);
                    let reason = format!("feed {feed} was not issued in {waited} blocks");
                    if self
                        .requests
                        .mark_failed(stored.request_hash, reason.as_bytes())
                        .await?
                    {
                        crate::monitoring::record_user_request_failed("unpriced_feed");
                    }
                    tracing::warn!(
                        request_hash = %hex::encode(stored.request_hash),
                        %reason,
                        "failed a user request no round could issue"
                    );
                    continue;
                }
                // A rate the issued Tick outlives cannot be spent beside it, so the
                // round waits for a fresher one rather than minting the pair.
                let own = match named_feed {
                    Some(feed) if instructed.is_none() => self
                        .prices
                        .value(feed)
                        .await
                        .filter(|rate| usable_for_round(rate, timestamp)),
                    _ => None,
                };
                // The rate this batch would have the round carry. It is committed
                // below, once the batch itself is in: a batch dropped after this
                // point must not leave the round issued at a feed that no included
                // batch names, which carries the rate beside none of them and
                // leaves the round signing a price its own message does not hold.
                let carried = match round_rate(instructed, named_feed, own) {
                    RoundRate::Carries(rate) => rate,
                    RoundRate::AnotherFeed => continue,
                    RoundRate::NoLocalPrice => {
                        tracing::debug!(
                            request_hash = %hex::encode(stored.request_hash),
                            feed = named_feed,
                            "deferred a user request to a round that can price it"
                        );
                        continue;
                    }
                };
                let account = AccountProgram::new(&AccountArguments {
                    storm_eye_asset_id: storm_eye.asset_id,
                    account_owner_pubkey: decode_array(&request.header.public_key)?,
                });
                let account_script = account.get_script_pubkey(&network);
                let mut resolved_fee_utxos = Vec::with_capacity(fee_utxos.len());
                let mut unavailable = None;
                for fee_utxo in fee_utxos {
                    let outpoint =
                        format!("{}:{}", hex::encode(fee_utxo.txid), fee_utxo.output_index);
                    if self
                        .monitored_utxos
                        .is_reserved_for_burning(fee_utxo.txid, fee_utxo.output_index)
                        .await?
                    {
                        unavailable = Some(format!(
                            "fee UTXO '{outpoint}' is reserved for burning issued UTXOs"
                        ));
                        break;
                    }
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
                    if self
                        .requests
                        .mark_failed(stored.request_hash, reason.as_bytes())
                        .await?
                    {
                        crate::monitoring::record_user_request_failed("fee_utxo_unavailable");
                    }
                    tracing::warn!(
                        request_hash = %hex::encode(stored.request_hash),
                        %reason,
                        "rejected pending user request before issuance"
                    );
                    continue;
                }

                if issued_count + request.requests.len() > MAX_ISSUED_DESCRIPTORS {
                    break 'fill;
                }
                issued_count += request.requests.len();
                instructed = carried;
                decoded.push((stored, request, resolved_fee_utxos, named_feed));
                if decoded.len() >= request_limit as usize {
                    break 'fill;
                }
            }
            if scanned >= MAX_PENDING_SCAN {
                tracing::debug!(
                    scanned,
                    accepted = decoded.len(),
                    "stopped scanning pending user requests at the round's bound"
                );
                break;
            }
            pending = self
                .requests
                .list_pending_after(PENDING_SCAN_PAGE, cursor)
                .await?;
            if pending.is_empty() {
                break;
            }
        }
        if decoded.is_empty() {
            return Ok(None);
        }
        let verifier_count = decoded
            .iter()
            .flat_map(|(_, request, _, _)| &request.requests)
            .filter(|user_request| issues_verifier(&user_request.kind))
            .count();
        let tick_count = issued_count - verifier_count;
        // Each token reissues the sum of its asset's outputs.
        let mut tokens = Vec::with_capacity(2);
        let mut tick_asset_id = None;
        let mut verifier_asset_id = None;
        if tick_count > 0 {
            let asset = self.asset(TICK_ASSET_KIND).await?;
            tick_asset_id = Some(asset_id(asset.asset_id)?);
            let amount = timestamp
                .checked_mul(tick_count as u64)
                .ok_or_else(|| UserRequestError::Invalid("Tick issuance amount overflow".into()))?;
            tokens.push(RoundToken::find(&rpc, asset, amount)?);
        }
        if verifier_count > 0 {
            let asset = self.asset(ORACLE_VERIFIER_KIND).await?;
            verifier_asset_id = Some(asset_id(asset.asset_id)?);
            tokens.push(RoundToken::find(&rpc, asset, verifier_count as u64)?);
        }

        let mut final_transaction = FinalTransaction::new();
        let auth_program = storm_eye_program(&storm_eye)?;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
                UserRequestError::Invalid("Storm Eye contract data is missing".into())
            })?)?;
        elements::add_storm_eye_input(
            &mut final_transaction,
            &storm_eye_utxo,
            &auth_program,
            elements::placeholder_storm_eye_witness(&contract_data, Either::Left(0)),
        );
        let treasury = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        });
        for token in &tokens {
            final_transaction.add_program_issuance_input(
                PartialInput::new(token.utxo.clone()),
                ProgramInput::new(
                    Box::new(treasury.as_ref().clone()),
                    TreasuryWitness {
                        storm_eye_input_index: 0,
                    },
                ),
                IssuanceInput::new_reissuance(
                    token.issuance_amount,
                    token.asset.entropy.ok_or_else(|| {
                        UserRequestError::Invalid(format!(
                            "{} entropy is missing",
                            token.asset.name
                        ))
                    })?,
                ),
                RequiredSignature::None,
            );
        }

        let policy_asset = network.policy_asset();
        let mut spent_utxo_secrets = vec![explicit_txout_secrets(&storm_eye_utxo.txout)?];
        spent_utxo_secrets.extend(token_input_secrets(&tokens)?);
        let mut spent_utxos = vec![storm_eye_utxo.txout.clone()];
        spent_utxos.extend(tokens.iter().map(|token| token.utxo.txout.clone()));
        let mut account_balances = Vec::with_capacity(decoded.len());
        for (_, request, fee_utxos, _) in &decoded {
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
                        contracts::artifacts::account::derived_account::AccountWitness {
                            storm_eye_input_index: 0,
                        },
                    ),
                    RequiredSignature::None,
                );
            }
            account_balances.push(input_total);
        }

        final_transaction.add_output(output_from_utxo(&storm_eye_utxo));
        for token in &tokens {
            final_transaction.add_output(output_from_utxo(&token.utxo));
        }
        let first_reserve_output = 1 + tokens.len() + issued_count;
        let mut request_results = Vec::with_capacity(decoded.len());
        let mut descriptors = Vec::with_capacity(issued_count);
        for (request_index, (stored, request, _, _)) in decoded.iter().enumerate() {
            let mut results = Vec::with_capacity(request.requests.len());
            let owner = decode_array(&request.header.public_key)?;
            let reserve_output_index = u32::try_from(first_reserve_output + request_index)
                .map_err(|_| UserRequestError::Invalid("reserve output index overflow".into()))?;
            for user_request in &request.requests {
                let details: TickUtxoRequestDetails = serde_json::from_str(&user_request.payload)?;
                let vout = final_transaction.n_outputs();
                let verifier = issues_verifier(&user_request.kind);
                let descriptor = IssuedUtxoDescriptor::from_request(
                    u32::try_from(vout).map_err(|_| {
                        UserRequestError::Invalid("issued output index overflow".into())
                    })?,
                    reserve_output_index,
                    owner,
                    &details.utxo_auth_method,
                    verifier.then_some(PLACEHOLDER_SIGNER),
                )
                .map_err(UserRequestError::Invalid)?;
                // Filled in once the rate is signed.
                let (amount, asset, payload) = if verifier {
                    (
                        1,
                        verifier_asset_id.expect("a round with Verifiers reissues them"),
                        String::new(),
                    )
                } else {
                    (
                        timestamp,
                        tick_asset_id.expect("a round with Ticks reissues them"),
                        serde_json::to_string(&TickUtxoDetails { timestamp })?,
                    )
                };
                final_transaction.add_output(PartialOutput::new(
                    descriptor
                        .voucher_program(storm_eye.asset_id)
                        .map_err(UserRequestError::Invalid)?
                        .get_script_pubkey(&network),
                    amount,
                    asset,
                ));
                results.push(RequestResult {
                    kind: user_request.kind.clone(),
                    vout: vout as u64,
                    auth_method: details.utxo_auth_method,
                    payload,
                });
                descriptors.push(descriptor);
            }
            request_results.push(PreparedRequestResult {
                request_hash: stored.request_hash,
                results,
            });
        }
        let account_requirements = decoded
            .iter()
            .zip(&account_balances)
            .map(|((_, request, _, _), input_total)| (request.requests.len(), *input_total))
            .collect::<Vec<_>>();
        let account_reserves = allocate_account_reserves(&account_requirements, &self.config)?;
        for ((_, request, _, _), reserve) in decoded.iter().zip(account_reserves) {
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
        let descriptor_output = final_transaction.n_outputs();
        let descriptor_script =
            IssuedUtxoDescriptor::script_pubkey(&descriptors).map_err(UserRequestError::Invalid)?;
        final_transaction.add_output(PartialOutput::new(descriptor_script, 0, policy_asset));
        final_transaction.add_output(PartialOutput::new(
            treasury.get_script_pubkey(&network),
            self.config.operational_fee_sats * issued_count as u64,
            policy_asset,
        ));
        final_transaction.add_output(PartialOutput::new(
            Script::new(),
            self.config.issuance_transaction_fee_sats,
            policy_asset,
        ));

        let (mut pset, _) = final_transaction.extract_pst();
        reblind_tokens(&mut pset, &tokens, &spent_utxo_secrets)?;
        let transaction = RoundTransaction {
            pset,
            descriptors,
            descriptor_output,
            storm_eye,
            network,
        };
        // This hash covers the transaction; the rate is the round's second
        // signed message. Fold it in here once a covenant field records it
        // on-chain, so the issuance itself commits to the price.
        let (pset, signing_hash) = transaction.for_branch(PLACEHOLDER_SIGNER)?;
        let external_requests = decoded
            .iter()
            .map(|(stored, _, _, named_feed)| ExternalRequests {
                request_hash: stored.request_hash,
                network_user_requests: stored.request.clone(),
                additional_payload: batch_payload(*named_feed, instructed.as_ref()),
            })
            .collect();
        // Placeholder branch; each attempt names its real one.
        let request = ExecuteUserRequests {
            tx: encode::serialize(&pset),
            signing_hash,
            signing_storm_tree_branch: PLACEHOLDER_SIGNER,
            external_requests,
            chain_tip: None,
        };

        Ok(Some(PreparedRound {
            request,
            transaction,
            final_transaction,
            spent_utxos,
            request_results,
            max_transaction_weight,
            instructed,
        }))
    }

    async fn asset(&self, kind: &'static str) -> Result<NetworkAsset, UserRequestError> {
        self.assets
            .require(kind, UserRequestError::MissingAsset)
            .await
    }

    pub(crate) async fn storm_eye_utxo_count(&self) -> Result<usize, UserRequestError> {
        let storm_eye = self.asset(STORM_EYE_KIND).await?;
        let client = self.client()?;

        Ok(scan_contract_utxos(
            &client,
            &storm_eye.contract_script,
            Some(storm_eye.asset_id),
        )?
        .len())
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
        // The tx for the branch that signed.
        let (mut pset, signing_hash) = prepared
            .transaction
            .for_branch(signing.signing_storm_tree_branch)?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest_slice(&signing_hash).expect("the signing hash has 32 bytes"),
                &branch_key,
            )
            .map_err(|_| {
                UserRequestError::Invalid(
                    "Storm Eye signature failed independent BIP340 verification".into(),
                )
            })?;
        let signed_price = prepared
            .instructed
            .map(|price| signed_price_bloom(&price, &signing, &proof))
            .transpose()?;
        let signature = *signature.as_ref();
        let mut transaction = prepared.final_transaction;
        let storm_eye = &prepared.transaction.storm_eye;
        let network = &prepared.transaction.network;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
                UserRequestError::Invalid("Storm Eye contract data is missing".into())
            })?)?;
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
            .witness = elements::storm_eye_witness(
            &contract_data,
            signature,
            signing.signing_storm_tree_branch,
            proof,
            Either::Left(0),
        )
        .into();

        for (index, input) in transaction.inputs().iter().enumerate() {
            let Some(program_input) = &input.program_input else {
                continue;
            };
            let final_witness = program_input
                .program
                .finalize(&pset, &program_input.witness, index, network)
                .map_err(|error| {
                    UserRequestError::Invalid(format!(
                        "failed to finalize covenant input {index}: {error}"
                    ))
                })?;
            pset.inputs_mut()[index].final_script_witness = Some(final_witness.into());
        }
        if issuance_signing_hash(&pset, storm_eye, network)? != signing_hash {
            return Err(UserRequestError::Invalid(
                "final issuance signing hash changed".into(),
            ));
        }
        let final_tx = pset
            .extract_tx()
            .map_err(|error| UserRequestError::Pset(error.to_string()))?;
        if final_tx.weight() > prepared.max_transaction_weight {
            return Err(UserRequestError::Invalid(format!(
                "final issuance transaction weight {} exceeds round limit {}",
                final_tx.weight(),
                prepared.max_transaction_weight
            )));
        }
        verify_tx_amt_proofs(&final_tx, &prepared.spent_utxos).map_err(|error| {
            UserRequestError::Invalid(format!(
                "failed to verify issuance amounts and proofs: {error}"
            ))
        })?;
        let txid = final_tx.txid().to_string();
        let final_bytes = encode::serialize(&final_tx);
        let transaction_hex = hex::encode(&final_bytes);
        tracing::debug!(%txid, "prepared issuance transaction");
        let client = self.client()?;
        let broadcast_txid: String =
            client.call("sendrawtransaction", &[transaction_hex.into()])?;
        if broadcast_txid != txid {
            return Err(UserRequestError::Invalid(
                "broadcast transaction id mismatch".into(),
            ));
        }
        crate::monitoring::record_issuance_tx_weight(final_tx.weight());

        fn verify_tx_amt_proofs(
            transaction: &simplex::simplicityhl::elements::Transaction,
            spent_utxos: &[TxOut],
        ) -> Result<(), String> {
            let mut verifiable = transaction.clone();
            verifiable.output.retain(|output| {
                output.value.explicit() != Some(0)
                    || !output.script_pubkey.is_provably_unspendable()
            });
            verifiable
                .verify_tx_amt_proofs(&Secp256k1::new(), spent_utxos)
                .map_err(|error| error.to_string())
        }
        let mut updated = 0;
        for result in prepared.request_results {
            let mut results = result.results;
            for issued in results
                .iter_mut()
                .filter(|issued| issues_verifier(&issued.kind))
            {
                // A priced batch always sets the rate.
                let (price_data, bloom) = signed_price
                    .as_ref()
                    .expect("a round issuing Verifiers carries a signed rate");
                issued.payload = serde_json::to_string(&SignedPriceDataDetails {
                    price_data: price_data.clone(),
                    storm_tree_bloom: bloom.clone(),
                })?;
            }
            let payload = serde_json::to_vec(&NetworkRequestsResult {
                txid: txid.clone(),
                results,
            })?;
            updated += usize::from(
                self.requests
                    .mark_processing(result.request_hash, &payload, &final_bytes)
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
        let tip: u64 = client.call("getblockcount", &[])?;
        let mut updated = 0;
        for request in processing {
            let Some(payload) = request.payload else {
                continue;
            };
            let result: NetworkRequestsResult = serde_json::from_slice(&payload)?;
            let confirmation = client.call::<RawTransactionInfo>(
                "getrawtransaction",
                &[result.txid.clone().into(), true.into()],
            );
            let Ok(confirmation) = confirmation else {
                self.requests.mark_orphaned(request.request_hash).await?;
                if let Some(transaction) = request.execution_tx {
                    let _: String =
                        client.call("sendrawtransaction", &[hex::encode(transaction).into()])?;
                }
                continue;
            };
            if confirmation.confirmations == 0 {
                self.requests.mark_orphaned(request.request_hash).await?;
                continue;
            }
            let block_hash = confirmation
                .block_hash
                .as_deref()
                .ok_or_else(|| {
                    UserRequestError::Invalid(
                        "confirmed issuance transaction has no block hash".into(),
                    )
                })?
                .parse::<BlockHash>()
                .map_err(|error| UserRequestError::Invalid(error.to_string()))?
                .to_byte_array();
            let included_at = tip
                .saturating_sub(confirmation.confirmations)
                .saturating_add(1);
            self.requests
                .mark_included(request.request_hash, included_at, block_hash)
                .await?;
            if confirmation.confirmations >= self.config.finality_confirmations.max(1) {
                updated += usize::from(self.requests.mark_executed(request.request_hash).await?);
            }
        }

        Ok(updated)
    }

    fn network(&self) -> Result<SimplicityNetwork, UserRequestError> {
        elements::network(
            &self.client()?,
            UserRequestError::Invalid,
            UserRequestError::UnsupportedChain,
        )
    }

    fn client(&self) -> Result<Client, UserRequestError> {
        let url = self.elements_rpc.wallet_url()?;
        Ok(crate::monitoring::elements_client(
            url.as_str(),
            self.elements_rpc.auth(),
            "issuance",
        )?)
    }
}

impl PreparedRound {
    fn estimated_weight(&self) -> Result<usize, UserRequestError> {
        finalized_dummy_weight(
            &self.final_transaction,
            &self.transaction.pset,
            &self.transaction.network,
        )
    }
}

impl RoundTransaction {
    /// The tx with Verifiers committed to `branch`, and its signing hash.
    pub(crate) fn for_branch(
        &self,
        branch: StormTreeBranch,
    ) -> Result<(PartiallySignedTransaction, [u8; 32]), UserRequestError> {
        let mut pset = self.pset.clone();
        if self
            .descriptors
            .iter()
            .any(IssuedUtxoDescriptor::is_verifier)
        {
            let descriptors = committed_to(&self.descriptors, branch);
            for descriptor in descriptors
                .iter()
                .filter(|descriptor| descriptor.is_verifier())
            {
                pset.outputs_mut()[descriptor.output_index as usize].script_pubkey = descriptor
                    .voucher_program(self.storm_eye.asset_id)
                    .map_err(UserRequestError::Invalid)?
                    .get_script_pubkey(&self.network);
            }
            pset.outputs_mut()[self.descriptor_output].script_pubkey =
                IssuedUtxoDescriptor::script_pubkey(&descriptors)
                    .map_err(UserRequestError::Invalid)?;
        }
        let signing_hash = issuance_signing_hash(&pset, &self.storm_eye, &self.network)?;

        Ok((pset, signing_hash))
    }
}

impl RoundToken {
    fn find(
        client: &Client,
        asset: NetworkAsset,
        issuance_amount: u64,
    ) -> Result<Self, UserRequestError> {
        let utxo = find_token_utxo(client, &asset)?;
        let secrets = utxo.secrets.ok_or_else(|| {
            UserRequestError::Invalid(format!("{} token secrets are missing", asset.name))
        })?;

        Ok(Self {
            asset,
            utxo,
            secrets,
            issuance_amount,
        })
    }
}

/// Sets `branch` as every Verifier's signer.
fn committed_to(
    descriptors: &[IssuedUtxoDescriptor],
    branch: StormTreeBranch,
) -> Vec<IssuedUtxoDescriptor> {
    descriptors
        .iter()
        .cloned()
        .map(|mut descriptor| {
            if descriptor.is_verifier() {
                descriptor.signer = Some(branch);
            }
            descriptor
        })
        .collect()
}

fn issuance_signing_hash(
    pset: &PartiallySignedTransaction,
    storm_eye: &NetworkAsset,
    network: &SimplicityNetwork,
) -> Result<[u8; 32], UserRequestError> {
    let env = storm_eye_program(storm_eye)?
        .as_ref()
        .get_env(pset, 0, network)
        .map_err(|error| {
            UserRequestError::Invalid(format!("cannot derive Storm Eye sighash: {error}"))
        })?;

    Ok(SigMessage::Tagged(STORM_EYE_TAG.to_string())
        .digest(env.c_tx_env().sighash_all().to_byte_array()))
}

/// `signed-price-data` issues a Verifier, anything else a Tick.
fn issues_verifier(request_kind: &str) -> bool {
    request_kind == PRICE_REQUEST_KIND
}

/// Surjection inputs of the token inputs: each token, then what it reissues,
/// in the order consensus builds the domain.
fn token_input_secrets(tokens: &[RoundToken]) -> Result<Vec<TxOutSecrets>, UserRequestError> {
    let mut secrets = Vec::with_capacity(tokens.len() * 2);
    for token in tokens {
        secrets.push(token.secrets);
        secrets.push(TxOutSecrets::new(
            asset_id(token.asset.asset_id)?,
            confidential::AssetBlindingFactor::zero(),
            token.issuance_amount,
            confidential::ValueBlindingFactor::zero(),
        ));
    }
    Ok(secrets)
}

/// Reblinds token outputs to the Treasury; the last balances them.
fn reblind_tokens(
    pset: &mut PartiallySignedTransaction,
    tokens: &[RoundToken],
    spent_utxo_secrets: &[TxOutSecrets],
) -> Result<(), UserRequestError> {
    let token_indexes = 1..=tokens.len();
    let mut output_secrets = pset
        .outputs()
        .iter()
        .enumerate()
        .filter(|(index, _)| !token_indexes.contains(index))
        .map(|(_, output)| explicit_txout_secrets(&output.to_txout()))
        .collect::<Result<Vec<_>, _>>()?;
    let secp = Secp256k1::new();
    let treasury_blinding_public_key =
        PublicKey::from_secret_key(&secp, &treasury_blinding_secret());
    for (offset, token) in tokens.iter().enumerate() {
        let index = 1 + offset;
        let name = &token.asset.name;
        let mut rng = secp256k1_zkp::rand::thread_rng();
        let script = token.utxo.txout.script_pubkey.clone();
        let token_output = if index == tokens.len() {
            let output_secret_refs = output_secrets.iter().collect::<Vec<_>>();
            TxOut::new_last_confidential(
                &mut rng,
                &secp,
                token.secrets.value,
                token.secrets.asset,
                script,
                treasury_blinding_public_key,
                spent_utxo_secrets,
                &output_secret_refs,
            )
            .map(|(output, _, _, _)| output)
        } else {
            let secrets = TxOutSecrets::new(
                token.secrets.asset,
                confidential::AssetBlindingFactor::new(&mut rng),
                token.secrets.value,
                confidential::ValueBlindingFactor::new(&mut rng),
            );
            output_secrets.push(secrets);
            let ephemeral_key = SecretKey::new(&mut rng);
            TxOut::with_txout_secrets(
                &mut rng,
                &secp,
                script,
                treasury_blinding_public_key,
                ephemeral_key,
                secrets,
                spent_utxo_secrets,
            )
        }
        .map_err(|_| UserRequestError::Invalid(format!("failed to reblind {name} token")))?;
        let mut token_pset_output =
            simplex::simplicityhl::elements::pset::Output::from_txout(token_output);
        token_pset_output.blinding_key = Some(
            simplex::simplicityhl::elements::bitcoin::PublicKey::new(treasury_blinding_public_key),
        );
        token_pset_output.blinder_index = Some(
            u32::try_from(index)
                .map_err(|_| UserRequestError::Invalid("token input index overflow".into()))?,
        );
        pset.outputs_mut()[index] = token_pset_output;

        let token_input = &mut pset.inputs_mut()[index];
        let token_asset_commitment =
            token.utxo.txout.asset.commitment().ok_or_else(|| {
                UserRequestError::Invalid(format!("{name} token asset is explicit"))
            })?;
        let token_value_commitment =
            token.utxo.txout.value.commitment().ok_or_else(|| {
                UserRequestError::Invalid(format!("{name} token value is explicit"))
            })?;
        token_input.asset = Some(token.secrets.asset);
        token_input.amount = Some(token.secrets.value);
        token_input.blind_asset_proof = Some(
            SurjectionProof::blind_asset_proof(
                &mut rng,
                &secp,
                token.secrets.asset,
                token.secrets.asset_bf,
            )
            .map_err(|_| {
                UserRequestError::Invalid(format!("failed to prove {name} token asset"))
            })?,
        );
        token_input.blind_value_proof = Some(
            RangeProof::blind_value_proof(
                &mut rng,
                &secp,
                token.secrets.value,
                token_value_commitment,
                token_asset_commitment,
                token.secrets.value_bf,
            )
            .map_err(|_| {
                UserRequestError::Invalid(format!("failed to prove {name} token value"))
            })?,
        );
    }

    Ok(())
}

fn find_token_utxo(client: &Client, asset: &NetworkAsset) -> Result<UTXO, UserRequestError> {
    let name = &asset.name;
    let token_id = asset_id(
        asset
            .reissuance_token_id
            .ok_or_else(|| UserRequestError::Invalid(format!("{name} token id is missing")))?,
    )?;
    let token_txout = token_txout(asset)?;
    let secrets = token_txout
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .map_err(|_| UserRequestError::Invalid(format!("failed to unblind {name} token")))?;
    if secrets.asset != token_id
        || token_txout.script_pubkey.as_bytes() != asset.contract_script
        || !token_txout.asset.is_confidential()
        || !token_txout.value.is_confidential()
    {
        return Err(UserRequestError::Invalid(format!(
            "invalid confidential {name} token template"
        )));
    }

    let descriptor = format!("raw({})", hex::encode(&asset.contract_script));
    let scan: ScanResult = client.call(
        "scantxoutset",
        &["start".into(), serde_json::json!([descriptor])],
    )?;
    for unspent in scan.unspents {
        let txid = Txid::from_str(&unspent.txid)
            .map_err(|_| UserRequestError::Invalid(format!("invalid {name} token txid")))?;
        let transaction = get_raw_transaction(client, txid, unspent.height)?;
        let Some(candidate) = transaction.output.get(unspent.vout as usize).cloned() else {
            continue;
        };
        if let Some(token) = token_candidate(
            OutPoint::new(txid, unspent.vout),
            candidate,
            &secrets,
            &asset.contract_script,
        ) {
            return follow_mempool_token_chain(client, token, &secrets, &asset.contract_script);
        }
    }

    Err(UserRequestError::Invalid(format!(
        "confidential {name} token UTXO is unavailable"
    )))
}

fn follow_mempool_token_chain(
    client: &Client,
    mut token: UTXO,
    expected: &TxOutSecrets,
    expected_script: &[u8],
) -> Result<UTXO, UserRequestError> {
    for _ in 0..MAX_MEMPOOL_TOKEN_CHAIN_LENGTH {
        let Some(spending_txid) = find_mempool_spender(client, token.outpoint)? else {
            return Ok(token);
        };
        let transaction = get_raw_transaction(client, spending_txid, None)?;
        if !transaction
            .input
            .iter()
            .any(|input| input.previous_output == token.outpoint)
        {
            return Err(UserRequestError::Invalid(
                "reported token transaction does not spend the current token".into(),
            ));
        }
        token = transaction
            .output
            .into_iter()
            .enumerate()
            .find_map(|(vout, candidate)| {
                let vout = u32::try_from(vout).ok()?;
                token_candidate(
                    OutPoint::new(spending_txid, vout),
                    candidate,
                    expected,
                    expected_script,
                )
            })
            .ok_or_else(|| {
                UserRequestError::Invalid(
                    "token spender does not preserve the confidential token".into(),
                )
            })?;
    }

    Err(UserRequestError::Invalid(format!(
        "unconfirmed token chain exceeds {MAX_MEMPOOL_TOKEN_CHAIN_LENGTH} transactions"
    )))
}

fn find_mempool_spender(
    client: &Client,
    outpoint: OutPoint,
) -> Result<Option<Txid>, UserRequestError> {
    match client.call::<Vec<SpendingPrevout>>(
        "gettxspendingprevout",
        &[serde_json::json!([{
            "txid": outpoint.txid.to_string(),
            "vout": outpoint.vout,
        }])],
    ) {
        Ok(results) => {
            return results
                .into_iter()
                .next()
                .and_then(|result| result.spending_txid)
                .map(|txid| {
                    Txid::from_str(&txid)
                        .map_err(|_| UserRequestError::Invalid("invalid token spender txid".into()))
                })
                .transpose();
        }
        Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
            error,
        ))) if error.code == -32601 => {}
        Err(error) => return Err(error.into()),
    }

    let mempool: Vec<String> = client.call("getrawmempool", &[])?;
    for txid in mempool {
        let txid = Txid::from_str(&txid)
            .map_err(|_| UserRequestError::Invalid("invalid mempool txid".into()))?;
        let transaction = match get_raw_transaction(client, txid, None) {
            Ok(transaction) => transaction,
            Err(UserRequestError::Rpc(bitcoincore_rpc::Error::JsonRpc(
                bitcoincore_rpc::jsonrpc::error::Error::Rpc(error),
            ))) if error.code == -5 => continue,
            Err(error) => return Err(error),
        };
        if transaction
            .input
            .iter()
            .any(|input| input.previous_output == outpoint)
        {
            return Ok(Some(txid));
        }
    }

    Ok(None)
}

fn token_candidate(
    outpoint: OutPoint,
    candidate: TxOut,
    expected: &TxOutSecrets,
    expected_script: &[u8],
) -> Option<UTXO> {
    let candidate_secrets = candidate
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .ok()?;
    if candidate_secrets.asset != expected.asset
        || candidate_secrets.value != expected.value
        || candidate.script_pubkey.as_bytes() != expected_script
        || !candidate.asset.is_confidential()
        || !candidate.value.is_confidential()
    {
        return None;
    }

    Some(UTXO {
        outpoint,
        txout: candidate,
        secrets: Some(candidate_secrets),
    })
}

/// The asset's original token output.
fn token_txout(asset: &NetworkAsset) -> Result<TxOut, UserRequestError> {
    let name = &asset.name;
    let contract_data: TickAssetContractData =
        postcard::from_bytes(asset.contract_data.as_deref().ok_or_else(|| {
            UserRequestError::Invalid(format!("{name} contract data is missing"))
        })?)?;

    let transaction: simplex::simplicityhl::elements::Transaction =
        encode::deserialize(&contract_data.issuance_tx).map_err(|_| {
            UserRequestError::Invalid(format!("invalid {name} issuance transaction"))
        })?;
    transaction
        .output
        .get(contract_data.token_output_index as usize)
        .cloned()
        .ok_or_else(|| UserRequestError::Invalid(format!("invalid {name} token output index")))
}

/// Signers sync their index to the anchor first, so every reserve at or below it is known.
async fn require_unreserved_anchored_fee_utxos(
    monitored_utxos: &MonitoredUtxoStore,
    client: &Client,
    chain_tip: Option<ChainTip>,
    fee_utxos: &[FeeUtxo],
) -> Result<(), UserRequestError> {
    let chain_tip = chain_tip
        .ok_or_else(|| UserRequestError::Invalid("issuance round has no chain anchor".into()))?;
    let outpoint =
        |fee_utxo: &FeeUtxo| format!("{}:{}", hex::encode(fee_utxo.txid), fee_utxo.output_index);

    let reserved = monitored_utxos
        .burning_reservations(
            &fee_utxos
                .iter()
                .map(|fee_utxo| (fee_utxo.txid, fee_utxo.output_index))
                .collect::<Vec<_>>(),
        )
        .await?;
    if let Some(index) = reserved.iter().position(|reserved| *reserved) {
        return Err(UserRequestError::Invalid(format!(
            "fee UTXO '{}' is reserved for burning issued UTXOs",
            outpoint(&fee_utxos[index])
        )));
    }

    let mut confirmations = Vec::with_capacity(fee_utxos.len());
    for fee_utxo in fee_utxos {
        let txid = Txid::from_str(&hex::encode(fee_utxo.txid))
            .map_err(|_| UserRequestError::Invalid("invalid fee UTXO txid".into()))?;
        let output = get_txout_optional(client, txid, fee_utxo.output_index, false)?;
        confirmations.push(output.map_or(0, |output| output.confirmations));
    }
    // Read last: a tip that moved meanwhile can only overstate an output's height.
    let tip: u64 = client.call("getblockcount", &[])?;
    for (fee_utxo, confirmations) in fee_utxos.iter().zip(confirmations) {
        if confirmations < MIN_FEE_UTXO_CONFIRMATIONS
            || (tip + 1).saturating_sub(confirmations) > chain_tip.height
        {
            return Err(UserRequestError::Invalid(format!(
                "fee UTXO '{}' is not confirmed at the round's anchored block",
                outpoint(fee_utxo)
            )));
        }
    }

    Ok(())
}

fn get_confirmed_fee_outpoint(
    client: &Client,
    outpoint: &FeeUtxo,
) -> Result<Option<UTXO>, UserRequestError> {
    let txid = Txid::from_str(&hex::encode(outpoint.txid))
        .map_err(|_| UserRequestError::Invalid("invalid UTXO txid".into()))?;
    let Some(output) = get_txout_optional(client, txid, outpoint.output_index, true)? else {
        return Ok(None);
    };
    if output.confirmations < MIN_FEE_UTXO_CONFIRMATIONS {
        return Ok(None);
    }

    explicit_outpoint(txid, outpoint.output_index, output).map(Some)
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
            .map_err(|_| UserRequestError::Invalid("invalid token transaction".into()))?,
    )
    .map_err(UserRequestError::Transaction)
}

pub(crate) fn explicit_txout_secrets(txout: &TxOut) -> Result<TxOutSecrets, UserRequestError> {
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

/// The rate the message is issued at, `None` for plain Tick requests.
fn validate_execute_request(
    request: &ExecuteUserRequests,
    storm_eye: &NetworkAsset,
    tick_asset: Option<&NetworkAsset>,
    verifier_asset: Option<&NetworkAsset>,
    config: &ProtocolConfig,
    network: &SimplicityNetwork,
) -> Result<Option<PriceFeedData>, UserRequestError> {
    if request.external_requests.is_empty() {
        return Err(UserRequestError::Invalid("no external requests".into()));
    }
    let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
    if pset.inputs().len() < 3 || pset.outputs().len() < 5 {
        return Err(UserRequestError::Invalid(
            "issuance transaction is incomplete".into(),
        ));
    }

    let storm_eye_input = witness_utxo(&pset, 0)?;
    let storm_eye_asset_id = asset_id(storm_eye.asset_id)?;
    require_explicit_utxo(
        storm_eye_input,
        storm_eye_asset_id,
        &storm_eye.contract_script,
        "Storm Eye",
    )?;
    require_preserved_output(&pset, 0, storm_eye_input, "Storm Eye")?;

    let mut batches = Vec::with_capacity(request.external_requests.len());
    let mut instructed = None;
    for external in &request.external_requests {
        let request_hash: [u8; 32] = sha2::Sha256::digest(&external.network_user_requests).into();
        if request_hash != external.request_hash {
            return Err(UserRequestError::Invalid(
                "external request hash mismatch".into(),
            ));
        }
        let (user_request, fee_utxos, named_feed) =
            validate_encoded_request(&external.network_user_requests)
                .map_err(UserRequestError::Invalid)?;
        instructed = instructed_price(
            named_feed,
            external.additional_payload.as_deref(),
            instructed,
        )?;
        let owner = secp256k1_zkp::XOnlyPublicKey::from_slice(
            &hex::decode(&user_request.header.public_key)
                .map_err(|_| UserRequestError::Invalid("invalid requester public key".into()))?,
        )
        .map_err(|_| UserRequestError::Invalid("invalid requester public key".into()))?;
        batches.push((user_request, fee_utxos, owner.serialize()));
    }

    // Token inputs follow the Storm Eye, Tick first.
    let issued_count = batches
        .iter()
        .map(|(user_request, _, _)| user_request.requests.len())
        .sum::<usize>();
    let verifier_count = batches
        .iter()
        .flat_map(|(user_request, _, _)| &user_request.requests)
        .filter(|user_request| issues_verifier(&user_request.kind))
        .count();
    let mut tokens = Vec::with_capacity(2);
    if issued_count > verifier_count {
        tokens.push(tick_asset.ok_or(UserRequestError::MissingAsset(TICK_ASSET_KIND))?);
    }
    if verifier_count > 0 {
        tokens.push(verifier_asset.ok_or(UserRequestError::MissingAsset(ORACLE_VERIFIER_KIND))?);
    }
    for (offset, asset) in tokens.iter().enumerate() {
        validate_token(&pset, 1 + offset, asset)?;
    }
    let first_fee_input = 1 + tokens.len();
    let first_issued_output = 1 + tokens.len();

    let mut expected_fee_inputs = 0usize;
    let mut expected_account_scripts = Vec::with_capacity(batches.len());
    for (user_request, fee_utxos, owner) in &batches {
        let account_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: *owner,
        })
        .get_script_pubkey(network);

        let mut input_total = 0u64;
        for fee_utxo in fee_utxos {
            let input_index = first_fee_input + expected_fee_inputs;
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
        expected_account_scripts.push((account_script, user_request.requests.len(), input_total));
    }
    if pset.inputs().len() != first_fee_input + expected_fee_inputs {
        return Err(UserRequestError::Invalid(
            "issuance transaction has unrequested inputs".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| UserRequestError::Clock)?
        .as_secs();
    let first_reserve_output = first_issued_output + issued_count;
    let first_descriptor_output = first_reserve_output + expected_account_scripts.len();
    // Verifiers commit to this message's branch.
    let signer = request.signing_storm_tree_branch;
    let mut issued_amounts = vec![0u64; tokens.len()];
    let mut descriptors = Vec::with_capacity(issued_count);
    for (request_index, (user_request, _, owner)) in batches.iter().enumerate() {
        let reserve_output_index = u32::try_from(first_reserve_output + request_index)
            .map_err(|_| UserRequestError::Invalid("reserve output index overflow".into()))?;
        for issued in &user_request.requests {
            let details: TickUtxoRequestDetails = serde_json::from_str(&issued.payload)
                .map_err(|error| UserRequestError::Invalid(error.to_string()))?;
            let output_index = first_issued_output + descriptors.len();
            let verifier = issues_verifier(&issued.kind);
            let descriptor = IssuedUtxoDescriptor::from_request(
                u32::try_from(output_index).map_err(|_| {
                    UserRequestError::Invalid("issued output index overflow".into())
                })?,
                reserve_output_index,
                *owner,
                &details.utxo_auth_method,
                verifier.then_some(signer),
            )
            .map_err(UserRequestError::Invalid)?;
            let output = pset.outputs().get(output_index).ok_or_else(|| {
                UserRequestError::Invalid("a requested issued output is missing".into())
            })?;
            let amount = output.amount.ok_or_else(|| {
                UserRequestError::Invalid("issued output amount is confidential".into())
            })?;
            let (token, asset) = if verifier {
                if amount != 1 {
                    return Err(UserRequestError::Invalid(
                        "an Oracle Verifier is issued with an amount of one".into(),
                    ));
                }
                (tokens.len() - 1, verifier_asset)
            } else {
                if amount.abs_diff(now) > MAX_TICK_TIME_SKEW_SECS {
                    return Err(UserRequestError::Invalid(
                        "Tick timestamp is outside the accepted window".into(),
                    ));
                }
                (0, tick_asset)
            };
            let asset = asset.expect("the round reissues every asset it issues");
            let expected_script = descriptor
                .voucher_program(storm_eye.asset_id)
                .map_err(UserRequestError::Invalid)?
                .get_script_pubkey(network);
            if output.asset != Some(asset_id(asset.asset_id)?)
                || output.script_pubkey != expected_script
            {
                return Err(UserRequestError::Invalid(format!(
                    "{} output does not match the request",
                    asset.name
                )));
            }
            issued_amounts[token] = issued_amounts[token].checked_add(amount).ok_or_else(|| {
                UserRequestError::Invalid(format!("{} issuance amount overflow", asset.name))
            })?;
            descriptors.push(descriptor);
        }
    }
    for (offset, (asset, issued_amount)) in tokens.iter().zip(issued_amounts).enumerate() {
        let issuance_input = &pset.inputs()[1 + offset];
        if issuance_input.issuance_value_amount != Some(issued_amount)
            || issuance_input
                .issuance_asset_entropy
                .map(|entropy| entropy.to_byte_array())
                != asset.entropy
            || issuance_input.issuance_value_comm.is_some()
            || issuance_input.issuance_value_rangeproof.is_some()
            || issuance_input.in_issuance_blind_value_proof.is_some()
        {
            return Err(UserRequestError::Invalid(format!(
                "{} reissuance metadata does not match the requested outputs",
                asset.name
            )));
        }
    }

    let policy_asset = network.policy_asset();
    let expected_descriptor_script =
        IssuedUtxoDescriptor::script_pubkey(&descriptors).map_err(UserRequestError::Invalid)?;
    let output = pset
        .outputs()
        .get(first_descriptor_output)
        .ok_or_else(|| UserRequestError::Invalid("issued UTXO descriptor is missing".into()))?;
    if output.asset != Some(policy_asset)
        || output.amount != Some(0)
        || output.script_pubkey != expected_descriptor_script
    {
        return Err(UserRequestError::Invalid(
            "invalid issued UTXO descriptor".into(),
        ));
    }
    validate_accounting_outputs(
        &pset,
        &expected_account_scripts,
        tokens.len(),
        issued_count,
        storm_eye.asset_id,
        policy_asset,
        config,
        network,
    )?;

    // The other half of the note at the coordinator's `signing_hash`: the rate
    // validated above is not in what this re-derives, so it is not signed for.
    if issuance_signing_hash(&pset, storm_eye, network)? != request.signing_hash {
        return Err(UserRequestError::Invalid("signing hash mismatch".into()));
    }

    Ok(instructed)
}

/// The token at `index` is returned unchanged.
fn validate_token(
    pset: &PartiallySignedTransaction,
    index: usize,
    asset: &NetworkAsset,
) -> Result<(), UserRequestError> {
    let name = &asset.name;
    let token_input = witness_utxo(pset, index)?;
    let expected_token = token_txout(asset)?;
    let expected_token_secrets = expected_token
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .map_err(|_| {
            UserRequestError::Invalid(format!("failed to unblind {name} token template"))
        })?;
    let token_input_map = &pset.inputs()[index];
    let token_asset_commitment = token_input
        .asset
        .commitment()
        .ok_or_else(|| UserRequestError::Invalid(format!("{name} token asset is explicit")))?;
    let token_value_commitment = token_input
        .value
        .commitment()
        .ok_or_else(|| UserRequestError::Invalid(format!("{name} token value is explicit")))?;
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
        return Err(UserRequestError::Invalid(format!(
            "invalid {name} reissuance token input"
        )));
    }
    let token_output = pset
        .outputs()
        .get(index)
        .ok_or_else(|| UserRequestError::Invalid(format!("missing {name} token output")))?
        .to_txout();
    let token_output_secrets = token_output
        .unblind(&Secp256k1::new(), treasury_blinding_secret())
        .map_err(|_| UserRequestError::Invalid(format!("failed to unblind {name} token output")))?;
    if token_output_secrets.asset != expected_token_secrets.asset
        || token_output_secrets.value != expected_token_secrets.value
        || token_output.script_pubkey != token_input.script_pubkey
        || !token_output.asset.is_confidential()
        || !token_output.value.is_confidential()
    {
        return Err(UserRequestError::Invalid(format!(
            "{name} reissuance token is not preserved"
        )));
    }

    Ok(())
}

/// What a round does with the batch it is looking at.
#[derive(Debug, PartialEq, Eq)]
enum RoundRate {
    /// It joins the round, which goes on carrying this rate.
    Carries(Option<PriceFeedData>),
    /// It waits for a round issued at the feed it names.
    AnotherFeed,
    /// This node cannot price the feed it names. A feed is unavailable after a
    /// restart and between polls, so the batch waits rather than failing and
    /// losing the fee UTXOs it reserved — but only for so long.
    NoLocalPrice,
}

/// `own` is this node's value for the feed the batch names, read only when the
/// round has no rate yet.
fn round_rate(
    instructed: Option<PriceFeedData>,
    named_feed: Option<FeedId>,
    own: Option<PriceFeedData>,
) -> RoundRate {
    let Some(feed) = named_feed else {
        return RoundRate::Carries(instructed);
    };
    match instructed {
        Some(held) if held.feed_id != feed => RoundRate::AnotherFeed,
        Some(held) => RoundRate::Carries(Some(held)),
        None => match own {
            Some(own) => RoundRate::Carries(Some(own)),
            None => RoundRate::NoLocalPrice,
        },
    }
}

/// A rate the round can still both sign and mint against. The covenant spends a
/// Tick beside a rate only while the Tick's timestamp is strictly before
/// `valid_until`, and every signer re-checks the rate against its own clock when
/// the message reaches it, so the rate has to outlast the signing session it is
/// chosen for. One that expires mid-session fails the round for every member
/// instead, and the round is rebuilt on the same rate until the feed polls again.
fn usable_for_round(rate: &PriceFeedData, timestamp: u64) -> bool {
    rate.valid_until > timestamp.saturating_add(SIGNING_SESSION_TIMEOUT.as_secs())
}

/// Whether a round prepared now would hold a rate to issue this feed at.
pub(crate) async fn has_round_rate(prices: &Prices, feed: FeedId) -> bool {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    prices
        .value(feed)
        .await
        .is_some_and(|rate| usable_for_round(&rate, now.as_secs()))
}

/// Its fee UTXOs stay reserved while it waits, so it does not wait forever. A
/// height that rewound in a reorg never ages a request early.
fn waited_too_long(block_height: u64, since: u64) -> bool {
    block_height.saturating_sub(since) > MAX_UNPRICED_REQUEST_BLOCKS
}

/// The round's second signature, checked here for the same reason the Storm Eye
/// one is: nothing else verifies it before a user is handed it.
fn signed_price_bloom(
    price: &PriceFeedData,
    signing: &SigningResult,
    proof: &storm_tree::StormTreeProof,
) -> Result<(String, StormTreeBloom), UserRequestError> {
    let signature = *signing
        .signatures
        .get(1)
        .ok_or_else(|| UserRequestError::Invalid("missing price signature".into()))?;
    let branch_key = XOnlyPublicKey::from_slice(&signing.signing_storm_tree_branch)
        .map_err(|_| UserRequestError::Invalid("invalid Storm Eye signing branch".into()))?;
    Secp256k1::verification_only()
        .verify_schnorr(
            &Signature::from_slice(&signature)
                .map_err(|_| UserRequestError::Invalid("invalid price signature".into()))?,
            &Message::from_digest_slice(&price_hash(price)).expect("the price hash has 32 bytes"),
            &branch_key,
        )
        .map_err(|_| {
            UserRequestError::Invalid(
                "price signature failed independent BIP340 verification".into(),
            )
        })?;

    Ok((
        hex::encode(price.to_bytes()),
        StormTreeBloom {
            signature: hex::encode(signature),
            branch: hex::encode(signing.signing_storm_tree_branch),
            proof: proof
                .siblings
                .iter()
                .map(|(right, hash)| BloomStep {
                    right: *right,
                    hash: hex::encode(hash),
                })
                .collect(),
        },
    ))
}

/// Only a batch issued at the round's feed carries its rate.
fn batch_payload(
    named_feed: Option<FeedId>,
    instructed: Option<&PriceFeedData>,
) -> Option<Vec<u8>> {
    named_feed
        .and(instructed)
        .map(|price| price.to_bytes().to_vec())
}

/// A batch carries a rate exactly when it names a feed, and one message
/// carries one rate, so `carried` is what the batches before it named.
fn instructed_price(
    named_feed: Option<FeedId>,
    payload: Option<&[u8]>,
    carried: Option<PriceFeedData>,
) -> Result<Option<PriceFeedData>, UserRequestError> {
    let instructed = match (named_feed, payload) {
        (None, None) => return Ok(carried),
        (None, Some(_)) => {
            return Err(UserRequestError::Invalid(
                "a batch that names no price feed carries no instructed price".into(),
            ));
        }
        (Some(_), None) => {
            return Err(UserRequestError::Invalid(
                "a batch issued at a price feed carries no instructed price".into(),
            ));
        }
        (Some(feed), Some(payload)) => {
            let instructed = PriceFeedData::from_bytes(payload)
                .map_err(|error| UserRequestError::Invalid(error.to_string()))?;
            if instructed.feed_id != feed {
                return Err(UserRequestError::Invalid(
                    "the instructed price is for another feed than the batch".into(),
                ));
            }
            instructed
        }
    };
    if carried.is_some_and(|carried| carried != instructed) {
        return Err(UserRequestError::Invalid(
            "one execute-user-requests carries one rate for one feed".into(),
        ));
    }

    Ok(Some(instructed))
}

#[allow(clippy::too_many_arguments)]
fn validate_accounting_outputs(
    pset: &PartiallySignedTransaction,
    accounts: &[(Script, usize, u64)],
    token_count: usize,
    issued_count: usize,
    storm_eye_asset_id: [u8; 32],
    policy_asset: AssetId,
    config: &ProtocolConfig,
    network: &SimplicityNetwork,
) -> Result<(), UserRequestError> {
    let expected_output_count = 1 + token_count + issued_count + accounts.len() + 1 + 2;
    if pset.outputs().len() != expected_output_count {
        return Err(UserRequestError::Invalid(
            "issuance transaction has unexpected outputs".into(),
        ));
    }
    let token_outputs = 1..=token_count;
    for (index, output) in pset.outputs().iter().enumerate() {
        if !token_outputs.contains(&index) && !is_fully_explicit_output(output) {
            return Err(UserRequestError::Invalid(format!(
                "issuance output {index} must be explicit"
            )));
        }
    }

    let treasury_script =
        TreasuryProgram::new(&TreasuryArguments { storm_eye_asset_id }).get_script_pubkey(network);
    let expected_operational = config
        .operational_fee_sats
        .checked_mul(issued_count as u64)
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
        let output = pset
            .outputs()
            .get(1 + token_count + issued_count + index)
            .ok_or_else(|| {
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
    let input_total =
        pset.inputs()[1 + token_count..]
            .iter()
            .try_fold(0u64, |total, input| {
                let utxo = input
                    .witness_utxo
                    .as_ref()
                    .ok_or_else(|| UserRequestError::Invalid("fee UTXO is missing".into()))?;
                if utxo.asset.explicit() != Some(policy_asset) {
                    return Err(UserRequestError::Invalid("fee UTXO asset mismatch".into()));
                }
                total
                    .checked_add(utxo.value.explicit().ok_or_else(|| {
                        UserRequestError::Invalid("fee UTXO must be explicit".into())
                    })?)
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

fn allocate_account_reserves(
    accounts: &[(usize, u64)],
    config: &ProtocolConfig,
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

fn decode_array(encoded: &str) -> Result<[u8; 32], UserRequestError> {
    hex::decode(encoded)
        .map_err(|_| UserRequestError::Invalid("invalid authentication data".into()))?
        .try_into()
        .map_err(|_| UserRequestError::Invalid("invalid authentication data".into()))
}

#[derive(Deserialize)]
struct SpendingPrevout {
    #[serde(rename = "spendingtxid")]
    spending_txid: Option<String>,
}

#[cfg(test)]
mod tests;
