use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use bitcoincore_rpc::{Client, RpcApi};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use contracts::voucher::VoucherSpendPath;
use secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use simplex::{
    either::Either,
    program::ProgramTrait,
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, Script, Transaction, TxOut, Txid, encode, pset::PartiallySignedTransaction,
    },
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage,
        utxo::UTXO,
    },
};

use crate::high_storm::elements;
use crate::{
    NetworkAsset,
    config::{ElementsRpcConfig, ProtocolConfig},
    db::{
        monitored_utxo::{MonitoredUtxo, MonitoredUtxoStore},
        network_asset::{NetworkAssetStore, ORACLE_VERIFIER_KIND, STORM_EYE_KIND, TICK_ASSET_KIND},
    },
};

use super::{
    SigningResult,
    assets::{StormEyeContractData, storm_eye_program},
    elements::{STORM_EYE_TAG, asset_id, finalized_dummy_weight, pack_proof},
    issuance::voucher_program,
    message::{BurnExpiredUtxos, ExpiredUtxosBurned, StormEyeUtxo},
    signing::SigningError,
    utxo::{
        StormEyePool, find_contract_utxo, get_explicit_outpoint, get_optional_explicit_outpoint,
        output_from_utxo, require_explicit_utxo, require_preserved_output, witness_utxo,
    },
};

const MAX_TICKS_PER_BURN: usize = 100;
/// Elements' standardness limit; a lane's weight share is only a scheduling budget.
const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
/// Elements' default `-minrelaytxfee`, in satoshis per 1,000 virtual bytes.
const BURN_FEE_RATE_SAT_PER_KVB: u64 = 100;
/// Upper bounds on finalized burn weight, above `measures_burn_transaction_weight`.
const BURN_BASE_WEIGHT: u64 = 3_900;
const BURN_ITEM_WEIGHT: u64 = 500;
const BURN_RESERVE_WEIGHT: u64 = 750;

#[derive(Debug, thiserror::Error)]
pub enum BurningError {
    #[error("burn reserves cannot cover the burn fee")]
    ReserveShortfall,
    #[error("burn database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid burning request: {0}")]
    Invalid(String),
    #[error("failed to decode burning transaction: {0}")]
    Transaction(#[from] encode::Error),
    #[error("failed to reconstruct network covenant: {0}")]
    Asset(#[from] super::assets::AssetError),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("unsupported Elements chain '{0}'")]
    UnsupportedChain(String),
    #[error("distributed signing failed: {0}")]
    Signing(#[from] SigningError),
    #[error("failed to finalize covenant input: {0}")]
    Program(#[from] simplex::program::ProgramError),
    #[error("failed to extract final transaction: {0}")]
    Pset(String),
    #[error("shared transaction helper failed: {0}")]
    TransactionHelper(#[from] super::elements::TransactionHelperError),
}

pub(crate) struct PreparedBurn {
    pub(crate) request: BurnExpiredUtxos,
    final_transaction: FinalTransaction,
    pset: PartiallySignedTransaction,
    spent_utxos: Vec<TxOut>,
    selected: Vec<([u8; 32], u32)>,
    network: SimplicityNetwork,
    storm_eye: NetworkAsset,
    group_count: usize,
    max_transaction_weight: usize,
}

#[derive(Clone)]
pub(crate) struct Burning {
    store: MonitoredUtxoStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    config: ProtocolConfig,
}

/// Asset ids a burn can spend.
struct BurnAssets {
    tick: Option<AssetId>,
    verifier: Option<AssetId>,
}

#[derive(Debug)]
struct BurnGroup {
    reserve: ([u8; 32], u32),
    owner: [u8; 32],
    ticks: Vec<MonitoredUtxo>,
}

impl Burning {
    pub(crate) fn new(
        store: MonitoredUtxoStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        config: ProtocolConfig,
    ) -> Self {
        Self {
            store,
            assets,
            elements_rpc,
            config,
        }
    }

    pub(crate) async fn prepare_round(
        &self,
        block_height: u64,
        storm_eye_lane: usize,
        max_transaction_weight: usize,
    ) -> Result<Option<PreparedBurn>, BurningError> {
        let mut lower_limit = 1usize;
        let mut upper_limit = MAX_TICKS_PER_BURN;
        let mut group_limit = upper_limit;
        let mut best = None;

        while lower_limit <= upper_limit {
            let candidate = match self
                .prepare_round_candidate(
                    block_height,
                    storm_eye_lane,
                    group_limit,
                    max_transaction_weight,
                )
                .await
            {
                Ok(Some(candidate)) => candidate,
                Ok(None) => return Ok(best),
                Err(BurningError::ReserveShortfall) if group_limit > 1 => {
                    upper_limit = group_limit - 1;
                    group_limit = lower_limit + (upper_limit - lower_limit) / 2;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let weight = candidate.estimated_weight()?;
            if weight <= max_transaction_weight {
                let group_count = candidate.group_count;
                best = Some(candidate);
                if group_count < group_limit || group_limit == MAX_TICKS_PER_BURN {
                    break;
                }
                lower_limit = group_count + 1;
            } else {
                if candidate.group_count == 1 {
                    if weight > MAX_STANDARD_TX_WEIGHT {
                        return Err(BurningError::Invalid(format!(
                            "one burn group transaction weight {weight} exceeds the standard limit"
                        )));
                    }
                    // An unsplittable group would otherwise block every round behind it.
                    tracing::info!(
                        weight,
                        max_transaction_weight,
                        "burning one group alone beyond its lane weight budget"
                    );
                    let mut candidate = candidate;
                    candidate.max_transaction_weight = MAX_STANDARD_TX_WEIGHT;
                    return Ok(Some(candidate));
                }
                upper_limit = candidate.group_count - 1;
            }
            group_limit = lower_limit + (upper_limit - lower_limit) / 2;
        }

        Ok(best)
    }

    /// The group's still unspent items with their UTXOs; `None` if none remain.
    async fn available_ticks(
        &self,
        client: &Client,
        mut group: BurnGroup,
        block_height: u64,
    ) -> Result<Option<(BurnGroup, Vec<UTXO>)>, BurningError> {
        let mut tick_utxos = Vec::with_capacity(group.ticks.len());
        let mut available = Vec::with_capacity(group.ticks.len());
        for tick in group.ticks {
            let outpoint = (tick.txid, tick.output_index);
            if let Some(tick_utxo) = get_optional_explicit_outpoint(
                client,
                Txid::from_byte_array(tick.txid),
                tick.output_index,
            )? {
                tick_utxos.push(tick_utxo);
                available.push(tick);
                continue;
            }
            // Spent since reconciliation: leave it out rather than fail the round.
            if let Some(spending_txid) = mempool_spender(client, outpoint)? {
                self.store
                    .mark_burning(&[outpoint], spending_txid.to_byte_array(), block_height)
                    .await?;
            }
            tracing::info!(
                txid = %Txid::from_byte_array(tick.txid),
                output_index = tick.output_index,
                "left an already spent issued UTXO out of the burn round"
            );
        }
        if available.is_empty() {
            return Ok(None);
        }
        group.ticks = available;
        Ok(Some((group, tick_utxos)))
    }

    /// Takes a group that can never be burned out of the queue so it cannot block later groups.
    async fn quarantine_group(
        &self,
        reserve: ([u8; 32], u32),
        items: &[MonitoredUtxo],
        block_height: u64,
        reason: &str,
    ) -> Result<(), BurningError> {
        let outpoints = items
            .iter()
            .map(|item| (item.txid, item.output_index))
            .collect::<Vec<_>>();
        let quarantined = self
            .store
            .quarantine_unburnable(&outpoints, block_height)
            .await?;
        if quarantined != outpoints.len() as u64 {
            return Err(BurningError::Invalid(
                "expired item state changed while quarantining a burn group".into(),
            ));
        }
        tracing::warn!(
            reserve_txid = %Txid::from_byte_array(reserve.0),
            reserve_output_index = reserve.1,
            item_count = outpoints.len(),
            %reason,
            "quarantined an unburnable burn group"
        );
        Ok(())
    }

    async fn prepare_round_candidate(
        &self,
        block_height: u64,
        storm_eye_lane: usize,
        group_limit: usize,
        max_transaction_weight: usize,
    ) -> Result<Option<PreparedBurn>, BurningError> {
        let expired = self.store.list_expired(u32::MAX).await?;
        let (expired, conflicting) = split_conflicting_reserves(expired);
        for (reserve, items) in conflicting {
            self.quarantine_group(
                reserve,
                &items,
                block_height,
                "one burn reserve has conflicting Account owners",
            )
            .await?;
        }
        let groups = select_groups(expired, group_limit)?;
        if groups.is_empty() {
            return Ok(None);
        }

        let storm_eye = self.asset(STORM_EYE_KIND).await?;
        let burn_assets = self.burn_assets().await?;
        let network = self.network()?;
        let client = self.client()?;
        let policy_asset = network.policy_asset();
        let mut burnable_groups = Vec::with_capacity(groups.len());
        for group in groups {
            let reserve_txid = Txid::from_byte_array(group.reserve.0);
            let Some(reserve) =
                get_optional_explicit_outpoint(&client, reserve_txid, group.reserve.1)?
            else {
                if let Some(spending_txid) =
                    mempool_spender(&client, (group.reserve.0, group.reserve.1))?
                {
                    tracing::info!(
                        %spending_txid,
                        reserve_txid = %reserve_txid,
                        reserve_output_index = group.reserve.1,
                        "skipping a burn group whose reserve is already spent in the mempool"
                    );
                    continue;
                }
                let ticks = group
                    .ticks
                    .iter()
                    .map(|tick| (tick.txid, tick.output_index))
                    .collect::<Vec<_>>();
                let quarantined = self
                    .store
                    .quarantine_unburnable(&ticks, block_height)
                    .await?;
                if quarantined != ticks.len() as u64 {
                    return Err(BurningError::Invalid(
                        "expired Tick state changed while quarantining a missing reserve".into(),
                    ));
                }
                tracing::warn!(
                    reserve_txid = %reserve_txid,
                    reserve_output_index = group.reserve.1,
                    tick_count = ticks.len(),
                    "quarantined expired Ticks with a missing burn reserve"
                );
                continue;
            };
            let account = AccountProgram::new(&AccountArguments {
                storm_eye_asset_id: storm_eye.asset_id,
                account_owner_pubkey: group.owner,
            });
            if reserve.asset() != policy_asset
                || reserve.txout.script_pubkey != account.get_script_pubkey(&network)
            {
                self.quarantine_group(
                    group.reserve,
                    &group.ticks,
                    block_height,
                    "burn reserve is not controlled by its Account",
                )
                .await?;
                continue;
            }
            let Some((group, tick_utxos)) =
                self.available_ticks(&client, group, block_height).await?
            else {
                continue;
            };
            match validate_group_items(storm_eye.asset_id, &burn_assets, &group, &tick_utxos) {
                Ok(()) => {}
                Err(BurningError::Invalid(reason)) => {
                    self.quarantine_group(group.reserve, &group.ticks, block_height, &reason)
                        .await?;
                    continue;
                }
                Err(error) => return Err(error),
            }
            burnable_groups.push((group, reserve, account, tick_utxos));
        }
        if burnable_groups.is_empty() {
            return Ok(None);
        }

        let storm_eye_utxo = find_contract_utxo(
            &client,
            &storm_eye.contract_script,
            Some(storm_eye.asset_id),
            StormEyePool::NetworkLeader(storm_eye_lane),
        )?;
        let BuiltBurn {
            final_transaction,
            spent_utxos,
            selected,
            signing_branch,
        } = build_burn_transaction(
            &storm_eye,
            &storm_eye_utxo,
            &burnable_groups,
            &burn_assets,
            &network,
            self.config.burn_transaction_fee_sats,
        )?;

        let (pset, _) = final_transaction.extract_pst();
        let signing_hash = signing_hash(&pset, &storm_eye, &network)?;
        let request = BurnExpiredUtxos {
            tx: encode::serialize(&pset),
            signing_hash,
            signing_storm_tree_branch: signing_branch,
            block_height,
            chain_tip: None,
        };

        Ok(Some(PreparedBurn {
            request,
            final_transaction,
            pset,
            spent_utxos,
            selected,
            network,
            storm_eye,
            group_count: burnable_groups.len(),
            max_transaction_weight,
        }))
    }

    pub(crate) async fn validate_request(
        &self,
        request: &BurnExpiredUtxos,
    ) -> Result<(), BurningError> {
        let storm_eye = self.asset(STORM_EYE_KIND).await?;
        let burn_assets = self.burn_assets().await?;
        let expired = self.store.list_expired(u32::MAX).await?;
        let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
        let client = self.client()?;
        for (index, input) in pset.inputs().iter().enumerate() {
            let actual =
                get_explicit_outpoint(&client, input.previous_txid, input.previous_output_index)?;
            if witness_utxo(&pset, index)? != &actual.txout {
                return Err(BurningError::Invalid(format!(
                    "burn input {index} does not match the live UTXO"
                )));
            }
        }
        validate_layout(
            &pset,
            request,
            &expired,
            &storm_eye,
            &burn_assets,
            &self.network()?,
            self.config.burn_transaction_fee_sats,
        )
    }

    /// Either asset may not be issued yet.
    async fn burn_assets(&self) -> Result<BurnAssets, BurningError> {
        Ok(BurnAssets {
            tick: self
                .assets
                .get(TICK_ASSET_KIND)
                .await?
                .map(|asset| AssetId::from_byte_array(asset.asset_id)),
            verifier: self
                .assets
                .get(ORACLE_VERIFIER_KIND)
                .await?
                .map(|asset| AssetId::from_byte_array(asset.asset_id)),
        })
    }

    pub(crate) async fn observe_broadcast(
        &self,
        notification: &ExpiredUtxosBurned,
    ) -> Result<usize, BurningError> {
        if notification.utxos.is_empty() || notification.utxos.len() > MAX_TICKS_PER_BURN {
            return Err(BurningError::Invalid(
                "burn notification has an invalid Tick count".into(),
            ));
        }
        let notified = notification
            .utxos
            .iter()
            .map(|utxo| (utxo.txid, utxo.output_index))
            .collect::<BTreeSet<_>>();
        if notified.len() != notification.utxos.len() {
            return Err(BurningError::Invalid(
                "burn notification contains duplicate Tick outpoints".into(),
            ));
        }

        let client = self.client()?;
        let txid = Txid::from_byte_array(notification.txid);
        let mempool: Vec<String> = client.call("getrawmempool", &[])?;
        if !mempool
            .iter()
            .any(|candidate| candidate == &txid.to_string())
        {
            return Err(BurningError::Invalid(
                "notified burn transaction is not in the local mempool".into(),
            ));
        }
        let transaction = raw_transaction(&client, txid)?;
        let spent = spent_outpoints(&transaction);
        if !notified.iter().all(|outpoint| spent.contains(outpoint)) {
            return Err(BurningError::Invalid(
                "burn notification contains an outpoint not spent by its transaction".into(),
            ));
        }

        let updated = self
            .store
            .mark_burning(
                &notified.iter().copied().collect::<Vec<_>>(),
                notification.txid,
                notification.block_height,
            )
            .await?;
        if updated != notified.len() as u64 {
            return Err(BurningError::Invalid(
                "notified Tick state does not match the local burn queue".into(),
            ));
        }

        Ok(notified.len())
    }

    /// Returns items to the queue once their recorded spend is neither pending nor confirmed.
    pub(crate) async fn release_vanished_burns(
        &self,
        block_height: u64,
    ) -> Result<u64, BurningError> {
        let burn_txids = self.store.burning_txids().await?;
        if burn_txids.is_empty() {
            return Ok(0);
        }
        let client = self.client()?;
        let mempool: Vec<String> = client.call("getrawmempool", &[])?;
        let mut released = 0;
        for burn_txid in burn_txids {
            let txid = Txid::from_byte_array(burn_txid);
            if mempool.contains(&txid.to_string()) {
                continue;
            }
            // Looked up after the mempool, so a spend mined meanwhile is still found.
            match client.call::<serde_json::Value>(
                "getrawtransaction",
                &[txid.to_string().into(), true.into()],
            ) {
                Ok(_) => continue,
                Err(bitcoincore_rpc::Error::JsonRpc(
                    bitcoincore_rpc::jsonrpc::error::Error::Rpc(error),
                )) if error.code == -5 => {}
                Err(error) => return Err(error.into()),
            }
            released += self.store.release_burning(burn_txid, block_height).await?;
        }

        Ok(released)
    }

    pub(crate) async fn reconcile_mempool(&self, block_height: u64) -> Result<usize, BurningError> {
        let expired = self.store.list_expired(u32::MAX).await?;
        if expired.is_empty() {
            return Ok(0);
        }
        let expired = expired
            .into_iter()
            .map(|tick| (tick.txid, tick.output_index))
            .collect::<BTreeSet<_>>();
        let client = self.client()?;
        let mempool: Vec<String> = client.call("getrawmempool", &[])?;
        let mut updated = 0usize;
        for encoded_txid in mempool {
            let txid = Txid::from_str(&encoded_txid)
                .map_err(|_| BurningError::Invalid("invalid mempool transaction id".into()))?;
            let transaction = raw_transaction(&client, txid)?;
            let selected = spent_outpoints(&transaction)
                .intersection(&expired)
                .copied()
                .collect::<Vec<_>>();
            if selected.is_empty() {
                continue;
            }
            let marked = self
                .store
                .mark_burning(&selected, txid.to_byte_array(), block_height)
                .await?;
            if marked != selected.len() as u64 {
                return Err(BurningError::Invalid(
                    "expired Tick state changed during mempool reconciliation".into(),
                ));
            }
            updated += selected.len();
        }

        Ok(updated)
    }

    pub(crate) async fn finalize_and_broadcast(
        &self,
        prepared: PreparedBurn,
        signing: SigningResult,
        proof: storm_tree::StormTreeProof,
        block_height: u64,
    ) -> Result<ExpiredUtxosBurned, BurningError> {
        let signature = *signing
            .signatures
            .first()
            .ok_or_else(|| BurningError::Invalid("missing Storm Eye signature".into()))?;
        let branch_key = XOnlyPublicKey::from_slice(&signing.signing_storm_tree_branch)
            .map_err(|_| BurningError::Invalid("invalid Storm Eye signing branch".into()))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| BurningError::Invalid("invalid Storm Eye signature".into()))?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest_slice(&prepared.request.signing_hash)
                    .expect("the signing hash has 32 bytes"),
                &branch_key,
            )
            .map_err(|_| BurningError::Invalid("Storm Eye signature verification failed".into()))?;

        let contract_data: StormEyeContractData =
            postcard::from_bytes(prepared.storm_eye.contract_data.as_deref().ok_or_else(|| {
                BurningError::Invalid("Storm Eye contract data is missing".into())
            })?)
            .map_err(|error| BurningError::Invalid(error.to_string()))?;
        if !storm_tree::StormTree::verify_branch(
            &contract_data.storm_tree_root,
            &signing.signing_storm_tree_branch,
            &proof,
        ) {
            return Err(BurningError::Invalid(
                "signing branch is not included in the Storm Eye root".into(),
            ));
        }

        let mut transaction = prepared.final_transaction;
        transaction.inputs_mut()[0]
            .program_input
            .as_mut()
            .expect("Storm Eye is a program input")
            .witness = elements::storm_eye_witness(
            &contract_data,
            *signature.as_ref(),
            signing.signing_storm_tree_branch,
            pack_proof(&proof)?,
            Either::Left(0),
        )
        .into();
        let mut pset = prepared.pset;
        for (index, input) in transaction.inputs().iter().enumerate() {
            let Some(program_input) = &input.program_input else {
                continue;
            };
            let final_witness = program_input
                .program
                .finalize(&pset, &program_input.witness, index, &prepared.network)
                .map_err(|error| {
                    BurningError::Invalid(format!(
                        "failed to finalize burn covenant input {index}: {error}"
                    ))
                })?;
            pset.inputs_mut()[index].final_script_witness = Some(final_witness.into());
        }
        if signing_hash(&pset, &prepared.storm_eye, &prepared.network)?
            != prepared.request.signing_hash
        {
            return Err(BurningError::Invalid(
                "final burn signing hash changed".into(),
            ));
        }
        let final_tx = pset
            .extract_tx()
            .map_err(|error| BurningError::Pset(error.to_string()))?;
        if final_tx.weight() > prepared.max_transaction_weight {
            return Err(BurningError::Invalid(format!(
                "final burn transaction weight {} exceeds round limit {}",
                final_tx.weight(),
                prepared.max_transaction_weight
            )));
        }
        final_tx
            .verify_tx_amt_proofs(&Secp256k1::new(), &prepared.spent_utxos)
            .map_err(|error| {
                BurningError::Invalid(format!("failed to verify burn amounts: {error}"))
            })?;
        let txid = final_tx.txid();
        let broadcast_txid =
            send_burn_transaction(&self.client()?, hex::encode(encode::serialize(&final_tx)))?;
        if broadcast_txid != txid.to_string() {
            return Err(BurningError::Invalid(
                "broadcast transaction id mismatch".into(),
            ));
        }
        let count = usize::try_from(
            self.store
                .mark_burning(&prepared.selected, txid.to_byte_array(), block_height)
                .await?,
        )
        .map_err(|_| BurningError::Invalid("burning record count overflow".into()))?;
        if count != prepared.selected.len() {
            return Err(BurningError::Invalid(
                "expired Tick state changed while signing".into(),
            ));
        }

        let chain_tip = prepared.request.chain_tip;
        Ok(ExpiredUtxosBurned {
            txid: txid.to_byte_array(),
            utxos: prepared
                .selected
                .into_iter()
                .map(|(txid, output_index)| StormEyeUtxo { txid, output_index })
                .collect(),
            block_height,
            chain_tip,
        })
    }

    fn network(&self) -> Result<SimplicityNetwork, BurningError> {
        let client = self.client()?;
        elements::network(
            &client,
            BurningError::Invalid,
            BurningError::UnsupportedChain,
        )
    }

    async fn asset(&self, kind: &'static str) -> Result<crate::NetworkAsset, BurningError> {
        self.assets.require(kind, BurningError::MissingAsset).await
    }

    fn client(&self) -> Result<Client, BurningError> {
        let url = self.elements_rpc.wallet_url()?;
        Ok(crate::monitoring::elements_client(
            url.as_str(),
            self.elements_rpc.auth(),
            "burn",
        )?)
    }
}

impl PreparedBurn {
    fn estimated_weight(&self) -> Result<usize, BurningError> {
        finalized_dummy_weight(&self.final_transaction, &self.pset, &self.network)
            .map_err(BurningError::TransactionHelper)
    }
}

fn raw_transaction(client: &Client, txid: Txid) -> Result<Transaction, BurningError> {
    let encoded: String = client.call(
        "getrawtransaction",
        &[txid.to_string().into(), false.into()],
    )?;
    Ok(encode::deserialize(&hex::decode(encoded).map_err(
        |_| BurningError::Invalid("invalid mempool transaction encoding".into()),
    )?)?)
}

fn spent_outpoints(transaction: &Transaction) -> BTreeSet<([u8; 32], u32)> {
    transaction
        .input
        .iter()
        .map(|input| {
            (
                input.previous_output.txid.to_byte_array(),
                input.previous_output.vout,
            )
        })
        .collect()
}

fn mempool_spender(
    client: &Client,
    outpoint: ([u8; 32], u32),
) -> Result<Option<Txid>, BurningError> {
    let mempool: Vec<String> = client.call("getrawmempool", &[])?;
    for encoded_txid in mempool {
        let txid = Txid::from_str(&encoded_txid)
            .map_err(|_| BurningError::Invalid("invalid mempool transaction id".into()))?;
        if spent_outpoints(&raw_transaction(client, txid)?).contains(&outpoint) {
            return Ok(Some(txid));
        }
    }

    Ok(None)
}

/// A burn group with its reserve, its Account covenant and its items' live UTXOs.
type BurnableGroup = (BurnGroup, UTXO, AccountProgram, Vec<UTXO>);

struct BuiltBurn {
    final_transaction: FinalTransaction,
    spent_utxos: Vec<TxOut>,
    selected: Vec<([u8; 32], u32)>,
    signing_branch: [u8; 32],
}

fn build_burn_transaction(
    storm_eye: &NetworkAsset,
    storm_eye_utxo: &UTXO,
    burnable_groups: &[BurnableGroup],
    burn_assets: &BurnAssets,
    network: &SimplicityNetwork,
    burn_fee_sats: u64,
) -> Result<BuiltBurn, BurningError> {
    let item_count = burnable_groups
        .iter()
        .map(|(group, _, _, _)| group.ticks.len())
        .sum();
    let burn_fee_sats = burn_fee(burn_fee_sats, item_count, burnable_groups.len())?;
    let auth_program = storm_eye_program(storm_eye)?;
    let contract_data: StormEyeContractData = postcard::from_bytes(
        storm_eye
            .contract_data
            .as_deref()
            .ok_or_else(|| BurningError::Invalid("Storm Eye contract data is missing".into()))?,
    )
    .map_err(|error| BurningError::Invalid(error.to_string()))?;
    let signing_branch = contract_data.storm_tree_root;

    let mut final_transaction = FinalTransaction::new();
    elements::add_storm_eye_input(
        &mut final_transaction,
        storm_eye_utxo,
        &auth_program,
        elements::placeholder_storm_eye_witness(&contract_data, Either::Left(0)),
    );

    let mut spent_utxos = vec![storm_eye_utxo.txout.clone()];
    let mut selected = Vec::new();
    for (group, _, _, tick_utxos) in burnable_groups {
        for (tick, tick_utxo) in group.ticks.iter().zip(tick_utxos) {
            if tick_utxo.asset() != burn_assets.of(tick)?
                || tick_utxo.amount() != tick.amount
                || tick_utxo.txout.script_pubkey.as_bytes() != tick.script_pubkey
            {
                return Err(BurningError::Invalid("indexed issued UTXO changed".into()));
            }
            final_transaction.add_program_input(
                PartialInput::new(tick_utxo.clone()),
                issued_network_input(storm_eye.asset_id, tick, network)?,
                RequiredSignature::None,
            );
            spent_utxos.push(tick_utxo.txout.clone());
            selected.push((tick.txid, tick.output_index));
        }
    }
    let burns = burn_outputs(
        burnable_groups
            .iter()
            .flat_map(|(group, _, _, _)| &group.ticks),
        burn_assets,
    )?;

    let policy_asset = network.policy_asset();
    for (_, reserve, account, _) in burnable_groups {
        final_transaction.add_program_input(
            PartialInput::new(reserve.clone()),
            ProgramInput::new(
                Box::new(account.as_ref().clone()),
                contracts::artifacts::account::derived_account::AccountWitness {
                    storm_eye_input_index: 0,
                },
            ),
            RequiredSignature::None,
        );
        spent_utxos.push(reserve.txout.clone());
    }

    final_transaction.add_output(output_from_utxo(storm_eye_utxo));
    for (asset, amount) in burns {
        final_transaction.add_output(PartialOutput::new(
            Script::new_op_return(&[]),
            amount,
            asset,
        ));
    }
    for (index, (_, reserve, account, _)) in burnable_groups.iter().enumerate() {
        let fee_share = fee_share(burn_fee_sats, burnable_groups.len(), index)?;
        let remaining = reserve
            .amount()
            .checked_sub(fee_share)
            .filter(|remaining| *remaining > 0)
            .ok_or(BurningError::ReserveShortfall)?;
        final_transaction.add_output(PartialOutput::new(
            account.get_script_pubkey(network),
            remaining,
            policy_asset,
        ));
    }
    final_transaction.add_output(PartialOutput::new(
        Script::new(),
        burn_fee_sats,
        policy_asset,
    ));

    Ok(BuiltBurn {
        final_transaction,
        spent_utxos,
        selected,
        signing_branch,
    })
}

type ItemsByReserve = BTreeMap<([u8; 32], u32), Vec<MonitoredUtxo>>;

/// Expired items whose reserve all name one owner, and per reserve the items that do not.
fn split_conflicting_reserves(expired: Vec<MonitoredUtxo>) -> (Vec<MonitoredUtxo>, ItemsByReserve) {
    let mut owners = BTreeMap::<([u8; 32], u32), BTreeSet<[u8; 32]>>::new();
    for item in &expired {
        owners
            .entry((item.burning_fee_txid, item.burning_fee_output_index))
            .or_default()
            .insert(item.account_owner_pubkey);
    }
    let mut conflicting = BTreeMap::<_, Vec<_>>::new();
    let mut consistent = Vec::with_capacity(expired.len());
    for item in expired {
        let reserve = (item.burning_fee_txid, item.burning_fee_output_index);
        if owners[&reserve].len() > 1 {
            conflicting.entry(reserve).or_default().push(item);
        } else {
            consistent.push(item);
        }
    }
    (consistent, conflicting)
}

/// Persistent faults in a group's items, checked before the round so one group cannot fail it.
fn validate_group_items(
    storm_eye_asset_id: [u8; 32],
    burn_assets: &BurnAssets,
    group: &BurnGroup,
    tick_utxos: &[UTXO],
) -> Result<(), BurningError> {
    for (tick, tick_utxo) in group.ticks.iter().zip(tick_utxos) {
        if tick_utxo.asset() != burn_assets.of(tick)?
            || tick_utxo.amount() != tick.amount
            || tick_utxo.txout.script_pubkey.as_bytes() != tick.script_pubkey
        {
            return Err(BurningError::Invalid("indexed issued UTXO changed".into()));
        }
        issued_program(storm_eye_asset_id, tick, voucher_program)?;
    }
    Ok(())
}

fn select_groups(
    expired: Vec<MonitoredUtxo>,
    max_groups: usize,
) -> Result<Vec<BurnGroup>, BurningError> {
    let mut grouped = BTreeMap::<([u8; 32], u32), BurnGroup>::new();
    for tick in expired {
        let reserve = (tick.burning_fee_txid, tick.burning_fee_output_index);
        let group = grouped.entry(reserve).or_insert_with(|| BurnGroup {
            reserve,
            owner: tick.account_owner_pubkey,
            ticks: Vec::new(),
        });
        if group.owner != tick.account_owner_pubkey {
            return Err(BurningError::Invalid(
                "one burn reserve has conflicting Account owners".into(),
            ));
        }
        group.ticks.push(tick);
    }

    // Oldest first, so no reserve outpoint can starve or jump ahead of older work.
    let mut groups = grouped.into_values().collect::<Vec<_>>();
    groups.sort_by_key(|group| {
        let oldest = group.ticks.iter().map(|tick| tick.block_height).min();
        (oldest, group.reserve)
    });

    let mut selected = Vec::new();
    let mut tick_count = 0usize;
    for group in groups {
        if selected.len() == max_groups {
            break;
        }
        if tick_count + group.ticks.len() > MAX_TICKS_PER_BURN {
            continue;
        }
        tick_count += group.ticks.len();
        selected.push(group);
    }
    Ok(selected)
}

impl BurnAssets {
    fn of(&self, utxo: &MonitoredUtxo) -> Result<AssetId, BurningError> {
        let asset = match utxo.asset_kind.as_str() {
            TICK_ASSET_KIND => self.tick,
            ORACLE_VERIFIER_KIND => self.verifier,
            _ => None,
        };
        asset.ok_or_else(|| {
            BurningError::Invalid(format!(
                "cannot burn an issued UTXO of kind '{}'",
                utxo.asset_kind
            ))
        })
    }
}

/// One empty OP_RETURN per asset, Ticks first.
fn burn_outputs<'a>(
    utxos: impl IntoIterator<Item = &'a MonitoredUtxo>,
    assets: &BurnAssets,
) -> Result<Vec<(AssetId, u64)>, BurningError> {
    let mut burns = BTreeMap::<bool, (AssetId, u64)>::new();
    for utxo in utxos {
        let asset = assets.of(utxo)?;
        let (_, amount) = burns
            .entry(utxo.asset_kind == ORACLE_VERIFIER_KIND)
            .or_insert((asset, 0));
        *amount = amount
            .checked_add(utxo.amount)
            .ok_or_else(|| BurningError::Invalid("burn amount overflow".into()))?;
    }
    Ok(burns.into_values().collect())
}

/// Covenant of an issued UTXO, with a Verifier's internal key.
fn issued_network_input(
    storm_eye_asset_id: [u8; 32],
    utxo: &MonitoredUtxo,
    network: &SimplicityNetwork,
) -> Result<ProgramInput, BurningError> {
    let program = issued_program(storm_eye_asset_id, utxo, voucher_program)?;
    if program.get_script_pubkey(network).as_bytes() != utxo.script_pubkey {
        return Err(BurningError::Invalid(
            "issued UTXO does not match the voucher covenant".into(),
        ));
    }
    Ok(ProgramInput::new(
        Box::new(program.as_ref().clone()),
        VoucherSpendPath::NetworkAuth {
            storm_eye_input_index: 0,
        }
        .build_witness(),
    ))
}

fn issued_program<P>(
    storm_eye_asset_id: [u8; 32],
    utxo: &MonitoredUtxo,
    create: impl FnOnce([u8; 32], u8, [u8; 32], Option<[u8; 32]>) -> Result<P, String>,
) -> Result<P, BurningError> {
    let auth_kind = match utxo.auth_method.as_str() {
        "asset-id-auth" => 0,
        "scriptPubKey-auth" => 1,
        "signature-auth" => 2,
        _ => {
            return Err(BurningError::Invalid(
                "unsupported issued UTXO authentication method".into(),
            ));
        }
    };
    let signer = match utxo.asset_kind.as_str() {
        ORACLE_VERIFIER_KIND => Some(utxo.internal_key.ok_or_else(|| {
            BurningError::Invalid("indexed Oracle Verifier has no internal key".into())
        })?),
        _ => None,
    };
    create(
        storm_eye_asset_id,
        auth_kind,
        decode_32(&utxo.auth_data)?,
        signer,
    )
    .map_err(BurningError::Invalid)
}

/// At least `minimum_sats`, and enough for the relay floor at the burn's bounded weight.
fn burn_fee(minimum_sats: u64, items: usize, reserves: usize) -> Result<u64, BurningError> {
    let overflow = || BurningError::Invalid("burn fee overflow".into());
    let items = u64::try_from(items).map_err(|_| overflow())?;
    let reserves = u64::try_from(reserves).map_err(|_| overflow())?;
    let weight = BURN_ITEM_WEIGHT
        .checked_mul(items)
        .zip(BURN_RESERVE_WEIGHT.checked_mul(reserves))
        .and_then(|(items, reserves)| items.checked_add(reserves))
        .and_then(|weight| weight.checked_add(BURN_BASE_WEIGHT))
        .ok_or_else(overflow)?;
    let floor = weight
        .div_ceil(4)
        .checked_mul(BURN_FEE_RATE_SAT_PER_KVB)
        .ok_or_else(overflow)?
        .div_ceil(1_000);
    Ok(minimum_sats.max(floor))
}

fn fee_share(total: u64, groups: usize, index: usize) -> Result<u64, BurningError> {
    let groups = u64::try_from(groups)
        .map_err(|_| BurningError::Invalid("burn group count overflow".into()))?;
    if groups == 0 {
        return Err(BurningError::Invalid(
            "burn transaction has no reserve groups".into(),
        ));
    }
    let index = u64::try_from(index)
        .map_err(|_| BurningError::Invalid("burn group index overflow".into()))?;
    Ok(total / groups + u64::from(index < total % groups))
}

fn signing_hash(
    pset: &PartiallySignedTransaction,
    storm_eye: &NetworkAsset,
    network: &SimplicityNetwork,
) -> Result<[u8; 32], BurningError> {
    let program = storm_eye_program(storm_eye)?;
    let env = program.as_ref().get_env(pset, 0, network)?;
    Ok(SigMessage::Tagged(STORM_EYE_TAG.to_string())
        .digest(env.c_tx_env().sighash_all().to_byte_array()))
}

fn validate_layout(
    pset: &PartiallySignedTransaction,
    request: &BurnExpiredUtxos,
    expired: &[MonitoredUtxo],
    storm_eye: &NetworkAsset,
    burn_assets: &BurnAssets,
    network: &SimplicityNetwork,
    minimum_fee: u64,
) -> Result<(), BurningError> {
    if pset.inputs().len() < 3 || pset.outputs().len() < 4 {
        return Err(BurningError::Invalid(
            "burn transaction is incomplete".into(),
        ));
    }

    let storm_eye_input = witness_utxo(pset, 0)?;
    require_explicit_utxo(
        storm_eye_input,
        asset_id(storm_eye.asset_id)?,
        &storm_eye.contract_script,
        "Storm Eye",
    )?;
    require_preserved_output(pset, 0, storm_eye_input, "Storm Eye")?;

    let expired_by_outpoint = expired
        .iter()
        .map(|tick| ((tick.txid, tick.output_index), tick))
        .collect::<BTreeMap<_, _>>();
    let mut ticks = Vec::new();
    for input in pset.inputs().iter().skip(1) {
        let outpoint = (
            input.previous_txid.to_byte_array(),
            input.previous_output_index,
        );
        let Some(tick) = expired_by_outpoint.get(&outpoint) else {
            break;
        };
        ticks.push((*tick).clone());
    }
    if ticks.is_empty() || ticks.len() > MAX_TICKS_PER_BURN {
        return Err(BurningError::Invalid(
            "burn transaction has an invalid Tick count".into(),
        ));
    }

    for (offset, tick) in ticks.iter().enumerate() {
        let index = 1 + offset;
        let input = witness_utxo(pset, index)?;
        require_explicit_utxo(
            input,
            burn_assets.of(tick)?,
            &tick.script_pubkey,
            "issued UTXO",
        )?;
        issued_network_input(storm_eye.asset_id, tick, network)?;
        if input.value.explicit() != Some(tick.amount) {
            return Err(BurningError::Invalid(
                "issued UTXO input does not match indexed state".into(),
            ));
        }
    }

    let burns = burn_outputs(&ticks, burn_assets)?;
    for (offset, (asset, amount)) in burns.iter().enumerate() {
        let burn_output = pset
            .outputs()
            .get(1 + offset)
            .ok_or_else(|| BurningError::Invalid("burn output is missing".into()))?;
        if burn_output.asset != Some(*asset)
            || burn_output.amount != Some(*amount)
            || burn_output.script_pubkey != Script::new_op_return(&[])
        {
            return Err(BurningError::Invalid(
                "issued UTXOs are not aggregated into one empty OP_RETURN per asset".into(),
            ));
        }
    }

    let groups = select_groups(ticks, MAX_TICKS_PER_BURN)?;
    let item_count = groups.iter().map(|group| group.ticks.len()).sum::<usize>();
    let fee = burn_fee(minimum_fee, item_count, groups.len())?;
    if pset.inputs().len()
        != 1 + groups.iter().map(|group| group.ticks.len()).sum::<usize>() + groups.len()
        || pset.outputs().len() != 2 + burns.len() + groups.len()
    {
        return Err(BurningError::Invalid(
            "burn transaction has unexpected inputs or outputs".into(),
        ));
    }

    let first_reserve_input = 1 + groups.iter().map(|group| group.ticks.len()).sum::<usize>();
    let first_reserve_output = 1 + burns.len();
    let policy_asset = network.policy_asset();
    for (offset, group) in groups.iter().enumerate() {
        let input_map = &pset.inputs()[first_reserve_input + offset];
        if input_map.previous_txid.to_byte_array() != group.reserve.0
            || input_map.previous_output_index != group.reserve.1
        {
            return Err(BurningError::Invalid(
                "burn reserve input does not match indexed state".into(),
            ));
        }
        let account_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: group.owner,
        })
        .get_script_pubkey(network);
        let reserve = witness_utxo(pset, first_reserve_input + offset)?;
        require_explicit_utxo(
            reserve,
            policy_asset,
            account_script.as_bytes(),
            "Account reserve",
        )?;
        let share = fee_share(fee, groups.len(), offset)?;
        let expected_remaining = reserve
            .value
            .explicit()
            .and_then(|amount| amount.checked_sub(share))
            .filter(|amount| *amount > 0)
            .ok_or_else(|| {
                BurningError::Invalid("burn reserve cannot cover its fee share".into())
            })?;
        let output = &pset.outputs()[first_reserve_output + offset];
        if output.asset != Some(policy_asset)
            || output.amount != Some(expected_remaining)
            || output.script_pubkey != account_script
        {
            return Err(BurningError::Invalid(
                "remaining burn reserve is not returned to its Account".into(),
            ));
        }
    }

    let miner_fee = pset.outputs().last().expect("burn transaction has outputs");
    if miner_fee.asset != Some(policy_asset)
        || miner_fee.amount != Some(fee)
        || !miner_fee.script_pubkey.is_empty()
    {
        return Err(BurningError::Invalid(
            "invalid burn miner fee output".into(),
        ));
    }
    if signing_hash(pset, storm_eye, network)? != request.signing_hash {
        return Err(BurningError::Invalid("burn signing hash mismatch".into()));
    }

    Ok(())
}

fn send_burn_transaction(
    client: &Client,
    transaction_hex: String,
) -> Result<String, bitcoincore_rpc::Error> {
    client.call(
        "sendrawtransaction",
        &[transaction_hex.into(), "0.10".into()],
    )
}

fn decode_32(bytes: &[u8]) -> Result<[u8; 32], BurningError> {
    bytes
        .try_into()
        .map_err(|_| BurningError::Invalid("invalid 32-byte covenant argument".into()))
}

#[cfg(test)]
mod tests;
