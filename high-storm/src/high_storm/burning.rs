use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::{
    account::{AccountProgram, derived_account::AccountArguments},
    auth::derived_auth::AuthWitness,
    voucher::{VoucherProgram, derived_voucher::VoucherWitness},
};
use secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::Deserialize;
use simplex::{
    either::Either,
    program::ProgramTrait,
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, BlockHash, Script, Transaction, TxOut, Txid, encode,
        pset::PartiallySignedTransaction,
    },
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage,
        utxo::UTXO,
    },
};
use url::Url;

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
    issuance::voucher_program,
    message::{BurnExpiredUtxos, ExpiredUtxosBurned, StormEyeUtxo},
    signing::SigningError,
    user_requests::{
        STORM_EYE_TAG, StormEyePool, UserRequestError, asset_id, finalized_dummy_weight,
        find_contract_utxo, get_explicit_outpoint, get_optional_explicit_outpoint,
        output_from_utxo, pack_proof, require_explicit_utxo, require_preserved_output,
        witness_utxo,
    },
};

const MAX_TICKS_PER_BURN: usize = 100;
/// Elements' standardness limit; a lane's weight share is only a scheduling budget.
const MAX_STANDARD_TX_WEIGHT: usize = 400_000;
/// Elements' default `-minrelaytxfee`, in satoshis per 1,000 virtual bytes.
const BURN_FEE_RATE_SAT_PER_KVB: u64 = 100;
/// Upper bounds on finalized burn weight, above `measures_burn_transaction_weight`.
const BURN_BASE_WEIGHT: u64 = 3_900;
const BURN_ITEM_WEIGHT: u64 = 450;
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
    TransactionHelper(#[from] UserRequestError),
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

        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(BurningError::MissingAsset(STORM_EYE_KIND))?;
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
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(BurningError::MissingAsset(STORM_EYE_KIND))?;
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
            .witness = AuthWitness {
            path: Either::Left((
                (contract_data.storm_tree_root, contract_data.rescue_height),
                (
                    *signature.as_ref(),
                    signing.signing_storm_tree_branch,
                    pack_proof(&proof)?,
                ),
                Either::Left(0),
            )),
        }
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
        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
        match chain.chain.as_str() {
            "liquidv1" => Ok(SimplicityNetwork::Liquid),
            "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
            "elementsregtest" => {
                let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
                let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
                Ok(SimplicityNetwork::ElementsCustom {
                    policy_asset: AssetId::from_str(&sidechain.pegged_asset).map_err(|_| {
                        BurningError::Invalid("invalid regtest policy asset".into())
                    })?,
                    genesis_hash: BlockHash::from_str(&genesis_hash).map_err(|_| {
                        BurningError::Invalid("invalid regtest genesis hash".into())
                    })?,
                })
            }
            _ => Err(BurningError::UnsupportedChain(chain.chain)),
        }
    }

    fn client(&self) -> Result<Client, BurningError> {
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
    final_transaction.add_program_input(
        PartialInput::new(storm_eye_utxo.clone()),
        ProgramInput::new(
            Box::new(auth_program.as_ref().clone()),
            AuthWitness {
                path: Either::Left((
                    (contract_data.storm_tree_root, contract_data.rescue_height),
                    (
                        [0; 64],
                        signing_branch,
                        std::array::from_fn(|_| Either::Left(())),
                    ),
                    Either::Left(0),
                )),
            },
        ),
        RequiredSignature::witness_tagged("PATH", ["Left", "1", "0"], STORM_EYE_TAG),
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
            let program = issued_program(storm_eye.asset_id, tick)?;
            final_transaction.add_program_input(
                PartialInput::new(tick_utxo.clone()),
                ProgramInput::new(
                    Box::new(program.as_ref().clone()),
                    VoucherWitness {
                        path: Either::Right(Either::Right(0)),
                    },
                ),
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
        issued_program(storm_eye_asset_id, tick)?;
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
fn issued_program(
    storm_eye_asset_id: [u8; 32],
    utxo: &MonitoredUtxo,
) -> Result<VoucherProgram, BurningError> {
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
    voucher_program(
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
        if input.value.explicit() != Some(tick.amount)
            || issued_program(storm_eye.asset_id, tick)?.get_script_pubkey(network)
                != input.script_pubkey
        {
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

#[derive(Deserialize)]
struct ChainInfo {
    chain: String,
}

#[derive(Deserialize)]
struct SidechainInfo {
    pegged_asset: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{external_api::users::UtxoAuthMethod, high_storm::issuance::IssuedUtxoDescriptor};

    /// x of the secp256k1 generator, a valid signing branch.
    const SIGNER: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn verifier(txid: u8, output_index: u32, reserve: u8, owner: u8) -> MonitoredUtxo {
        MonitoredUtxo {
            asset_kind: ORACLE_VERIFIER_KIND.into(),
            amount: 1,
            internal_key: Some(SIGNER),
            ..tick(txid, output_index, reserve, owner)
        }
    }

    fn tick(txid: u8, output_index: u32, reserve: u8, owner: u8) -> MonitoredUtxo {
        MonitoredUtxo {
            txid: [txid; 32],
            output_index,
            asset_kind: TICK_ASSET_KIND.into(),
            amount: 1_700_000_000,
            script_pubkey: vec![0x51],
            auth_method: "signature-auth".into(),
            auth_data: vec![2; 32],
            account_owner_pubkey: [owner; 32],
            internal_key: None,
            burning_fee_txid: [reserve; 32],
            burning_fee_output_index: 7,
            block_height: 1,
            status: "expired".into(),
            status_block_height: 61,
            burn_txid: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn burn_broadcast_uses_elements_23_3_4_rpc_without_retries() {
        use std::sync::{Arc, Mutex};

        for error in [
            None,
            Some(serde_json::json!({
                "code": -1, "message": "sendrawtransaction \"hexstring\" ( maxfeerate )",
            })),
            Some(serde_json::json!({"code": -26, "message": "min relay fee not met"})),
            Some(serde_json::json!({"code": -1, "message": "unrelated failure"})),
        ] {
            let accepted = error.is_none();
            let calls = Arc::new(Mutex::new(Vec::new()));
            let observed = calls.clone();
            let app = axum::Router::new().route(
                "/",
                axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                    assert_eq!(request["method"], "sendrawtransaction");
                    let mut calls = observed.lock().unwrap();
                    calls.push(request["params"].clone());
                    let response = if calls.len() == 1 && error.is_some() {
                        serde_json::json!({"id": request["id"], "result": null, "error": error})
                    } else {
                        serde_json::json!({"id": request["id"], "result": "txid", "error": null})
                    };
                    async move { axum::Json(response) }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = tokio::task::spawn_blocking(move || {
                let client =
                    Client::new(&format!("http://{address}"), bitcoincore_rpc::Auth::None).unwrap();
                send_burn_transaction(&client, "raw".into())
            })
            .await
            .unwrap();

            assert_eq!(result.is_ok(), accepted);
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0], serde_json::json!(["raw", "0.10"]));
            server.abort();
        }
    }

    #[test]
    fn selects_ticks_from_different_users_in_deterministic_order() {
        let groups = select_groups(
            vec![tick(3, 1, 2, 4), tick(1, 1, 1, 3), tick(2, 1, 2, 4)],
            MAX_TICKS_PER_BURN,
        )
        .unwrap();

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].reserve, ([1; 32], 7));
        assert_eq!(groups[0].ticks.len(), 1);
        assert_eq!(groups[1].reserve, ([2; 32], 7));
        assert_eq!(groups[1].ticks.len(), 2);
    }

    #[test]
    fn burns_the_oldest_group_first_whatever_its_reserve_txid() {
        let aged = |txid: u8, reserve: u8, block_height: u64| MonitoredUtxo {
            block_height,
            ..tick(txid, 1, reserve, reserve)
        };
        // A full round of newer groups whose reserves sort before the old one.
        let mut expired = (1..=100)
            .map(|reserve| aged(reserve, reserve, 50))
            .collect::<Vec<_>>();
        expired.push(aged(200, 255, 10));

        let groups = select_groups(expired, MAX_TICKS_PER_BURN).unwrap();

        assert_eq!(groups.len(), 100);
        assert_eq!(groups[0].reserve, ([255; 32], 7));
        assert!(!groups.iter().any(|group| group.reserve == ([100; 32], 7)));
    }

    #[test]
    fn fills_a_round_past_a_group_that_does_not_fit() {
        let group = |reserve: u8, count: u8, block_height: u64| {
            (0..count).map(move |index| MonitoredUtxo {
                block_height,
                ..tick(reserve, u32::from(index), reserve, reserve)
            })
        };
        let expired = group(1, 60, 1)
            .chain(group(2, 50, 2))
            .chain(group(3, 40, 3))
            .collect();

        let groups = select_groups(expired, MAX_TICKS_PER_BURN).unwrap();

        assert_eq!(
            groups
                .iter()
                .map(|group| group.reserve.0[0])
                .collect::<Vec<_>>(),
            vec![1, 3]
        );
        assert_eq!(
            groups.iter().map(|group| group.ticks.len()).sum::<usize>(),
            100
        );
    }

    #[tokio::test]
    async fn reconciliation_excludes_observed_spends_and_keeps_other_expired_items() {
        use crate::db::{Database, monitored_utxo::IndexedBlock};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let spent = tick(1, 2, 3, 4);
        let available = tick(2, 2, 5, 6);
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 61,
                    hash: [61; 32],
                },
                &[spent.clone(), available.clone()],
                &[],
                60,
            )
            .await
            .unwrap();

        let transaction = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![simplex::simplicityhl::elements::TxIn {
                previous_output: simplex::simplicityhl::elements::OutPoint {
                    txid: Txid::from_byte_array(spent.txid),
                    vout: spent.output_index,
                },
                ..Default::default()
            }],
            output: vec![],
        };
        let txid = transaction.txid();
        let encoded = hex::encode(encode::serialize(&transaction));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = calls.clone();
        let app = axum::Router::new().route(
            "/wallet/test",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                let result = match request["method"].as_str().unwrap() {
                    "getrawmempool" => serde_json::json!([txid]),
                    "getrawtransaction" => {
                        assert_eq!(request["params"], serde_json::json!([txid, false]));
                        serde_json::json!(encoded)
                    }
                    method => panic!("unexpected RPC method: {method}"),
                };
                async move {
                    axum::Json(serde_json::json!({
                        "id": request["id"], "result": result, "error": null,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let burning = Burning::new(
            store.clone(),
            database.network_assets(),
            ElementsRpcConfig {
                url: format!("http://{address}"),
                username: String::new(),
                password: String::new(),
                wallet: "test".into(),
            },
            ProtocolConfig {
                operational_fee_sats: 1_000,
                tick_burn_reserve_sats: 1_000,
                issuance_transaction_fee_sats: 500,
                burn_transaction_fee_sats: 500,
                exchange_transaction_fee_sats: 500,
                tick_lifetime_blocks: 60,
                finality_confirmations: 2,
            },
        );

        let result = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async {
                let first = burning.reconcile_mempool(61).await?;
                let second = burning.reconcile_mempool(61).await?;
                Ok::<_, BurningError>((first, second))
            })
        })
        .await;
        server.abort();

        assert_eq!(result.unwrap().unwrap(), (1, 0));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        let expired = store.list_expired(10).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].txid, available.txid);
        assert!(
            store
                .is_reserved_for_burning(spent.burning_fee_txid, spent.burning_fee_output_index)
                .await
                .unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn releases_only_items_whose_burning_transaction_vanished() {
        use crate::db::{Database, monitored_utxo::IndexedBlock};
        use serde_json::json;

        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let items = (1..=4).map(|txid| tick(txid, 0, 9, 4)).collect::<Vec<_>>();
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 61,
                    hash: [61; 32],
                },
                &items,
                &[],
                60,
            )
            .await
            .unwrap();
        let pending = [10; 32];
        let confirmed = [11; 32];
        let vanished = [12; 32];
        for (burn_txid, batch) in [
            (pending, &items[..1]),
            (confirmed, &items[1..2]),
            (vanished, &items[2..]),
        ] {
            let outpoints = batch
                .iter()
                .map(|item| (item.txid, item.output_index))
                .collect::<Vec<_>>();
            store.mark_burning(&outpoints, burn_txid, 61).await.unwrap();
        }

        let pending_txid = Txid::from_byte_array(pending).to_string();
        let confirmed_txid = Txid::from_byte_array(confirmed).to_string();
        let app = axum::Router::new().route(
            "/wallet/test",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                let (result, error) = match request["method"].as_str().unwrap() {
                    "getrawmempool" => (json!([pending_txid]), json!(null)),
                    "getrawtransaction" if request["params"][0] == confirmed_txid => {
                        (json!({ "confirmations": 1 }), json!(null))
                    }
                    "getrawtransaction" => (
                        json!(null),
                        json!({ "code": -5, "message": "No such mempool or blockchain transaction" }),
                    ),
                    method => panic!("unexpected RPC method: {method}"),
                };
                async move {
                    axum::Json(json!({ "id": request["id"], "result": result, "error": error }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let burning = Burning::new(
            store.clone(),
            database.network_assets(),
            ElementsRpcConfig {
                url: format!("http://{address}"),
                username: String::new(),
                password: String::new(),
                wallet: "test".into(),
            },
            ProtocolConfig {
                operational_fee_sats: 1_000,
                tick_burn_reserve_sats: 1_000,
                issuance_transaction_fee_sats: 500,
                burn_transaction_fee_sats: 500,
                exchange_transaction_fee_sats: 500,
                tick_lifetime_blocks: 60,
                finality_confirmations: 2,
            },
        );

        assert_eq!(burning.release_vanished_burns(62).await.unwrap(), 2);
        assert_eq!(burning.release_vanished_burns(62).await.unwrap(), 0);
        server.abort();

        let expired = store.list_expired(10).await.unwrap();
        assert_eq!(
            expired.iter().map(|item| item.txid).collect::<Vec<_>>(),
            vec![items[2].txid, items[3].txid]
        );
        assert!(
            expired
                .iter()
                .all(|item| item.burn_txid.is_none() && item.status_block_height == 62)
        );
        assert_eq!(
            store.burning_txids().await.unwrap(),
            vec![pending, confirmed]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_round_leaves_out_items_spent_after_reconciliation() {
        use crate::db::{Database, monitored_utxo::IndexedBlock};
        use serde_json::json;

        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let unspent = tick(1, 0, 9, 4);
        let spent_in_mempool = tick(2, 0, 9, 4);
        let spent_in_block = tick(3, 0, 9, 4);
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 61,
                    hash: [61; 32],
                },
                &[
                    unspent.clone(),
                    spent_in_mempool.clone(),
                    spent_in_block.clone(),
                ],
                &[],
                60,
            )
            .await
            .unwrap();

        let spender = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![simplex::simplicityhl::elements::TxIn {
                previous_output: simplex::simplicityhl::elements::OutPoint {
                    txid: Txid::from_byte_array(spent_in_mempool.txid),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![],
        };
        let spender_txid = spender.txid();
        let spender_hex = hex::encode(encode::serialize(&spender));
        let unspent_txid = Txid::from_byte_array(unspent.txid).to_string();
        let tick_asset = AssetId::from_byte_array([5; 32]);
        let app = axum::Router::new().route(
            "/wallet/test",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                let result = match request["method"].as_str().unwrap() {
                    "gettxout" if request["params"][0] == unspent_txid => json!({
                        "confirmations": 2,
                        "asset": tick_asset.to_string(),
                        "value": 17,
                        "scriptPubKey": { "hex": "51" },
                    }),
                    "gettxout" => json!(null),
                    "getrawmempool" => json!([spender_txid]),
                    "getrawtransaction" => json!(spender_hex),
                    method => panic!("unexpected RPC method: {method}"),
                };
                async move {
                    axum::Json(json!({ "id": request["id"], "result": result, "error": null }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let burning = Burning::new(
            store.clone(),
            database.network_assets(),
            ElementsRpcConfig {
                url: format!("http://{address}"),
                username: String::new(),
                password: String::new(),
                wallet: "test".into(),
            },
            ProtocolConfig {
                operational_fee_sats: 1_000,
                tick_burn_reserve_sats: 1_000,
                issuance_transaction_fee_sats: 500,
                burn_transaction_fee_sats: 500,
                exchange_transaction_fee_sats: 500,
                tick_lifetime_blocks: 60,
                finality_confirmations: 2,
            },
        );
        let group = select_groups(store.list_expired(10).await.unwrap(), MAX_TICKS_PER_BURN)
            .unwrap()
            .remove(0);

        let client = burning.client().unwrap();
        let (group, utxos) = burning
            .available_ticks(&client, group, 61)
            .await
            .unwrap()
            .unwrap();
        server.abort();

        assert_eq!(
            group.ticks.iter().map(|tick| tick.txid).collect::<Vec<_>>(),
            vec![unspent.txid]
        );
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount(), 1_700_000_000);
        // The mempool spend is tracked; the block spend waits for indexing to delete it.
        let expired = store.list_expired(10).await.unwrap();
        assert_eq!(
            expired.iter().map(|tick| tick.txid).collect::<Vec<_>>(),
            vec![unspent.txid, spent_in_block.txid]
        );
    }

    #[test]
    fn collects_transaction_inputs_for_burn_observation() {
        let transaction = Transaction {
            version: 2,
            lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
            input: vec![simplex::simplicityhl::elements::TxIn {
                previous_output: simplex::simplicityhl::elements::OutPoint {
                    txid: Txid::from_byte_array([3; 32]),
                    vout: 7,
                },
                ..Default::default()
            }],
            output: vec![],
        };

        assert_eq!(
            spent_outpoints(&transaction),
            BTreeSet::from([([3; 32], 7)])
        );
    }

    #[test]
    fn splits_the_configured_fee_exactly_across_reserves() {
        let shares = (0..3)
            .map(|index| fee_share(500, 3, index).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(shares, vec![167, 167, 166]);
        assert_eq!(shares.into_iter().sum::<u64>(), 500);
    }

    #[test]
    fn rejects_conflicting_owners_for_one_reserve() {
        let error = select_groups(vec![tick(1, 1, 3, 4), tick(2, 1, 3, 5)], MAX_TICKS_PER_BURN)
            .unwrap_err();

        assert!(matches!(error, BurningError::Invalid(_)));
    }

    #[test]
    fn reconstructs_descriptor_covenant_for_every_authentication_mode() {
        let authentication = [
            ("asset-id-auth", hex::encode([1; 32])),
            ("scriptPubKey-auth", hex::encode([0x51])),
            ("signature-auth", hex::encode([2; 32])),
        ];
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset: AssetId::from_byte_array([8; 32]),
            genesis_hash: BlockHash::from_byte_array([9; 32]),
        };

        for (kind, auth_data) in authentication {
            for signer in [None, Some(SIGNER)] {
                let descriptor = IssuedUtxoDescriptor::from_request(
                    2,
                    3,
                    [4; 32],
                    &UtxoAuthMethod {
                        kind: kind.into(),
                        auth_data: auth_data.clone(),
                    },
                    signer,
                )
                .unwrap();
                let mut monitored = if signer.is_some() {
                    verifier(1, 2, 3, 4)
                } else {
                    tick(1, 2, 3, 4)
                };
                monitored.auth_method = descriptor.auth_method_name().into();
                monitored.auth_data = descriptor.auth_data.to_vec();

                assert_eq!(
                    issued_program([7; 32], &monitored)
                        .unwrap()
                        .get_script_pubkey(&network),
                    descriptor
                        .voucher_program([7; 32])
                        .unwrap()
                        .get_script_pubkey(&network)
                );
            }
        }
    }
    /// Production-shaped burn inputs on Liquid, without a node.
    struct BurnFixture {
        network: SimplicityNetwork,
        assets: BurnAssets,
        storm_eye: NetworkAsset,
        storm_eye_utxo: UTXO,
    }

    impl BurnFixture {
        const STORM_EYE_ID: [u8; 32] = [7; 32];

        fn new() -> Self {
            let network = SimplicityNetwork::Liquid;
            let mut storm_eye = NetworkAsset {
                kind: STORM_EYE_KIND.into(),
                name: "Storm Eye".into(),
                asset_id: Self::STORM_EYE_ID,
                reissuance_token_id: None,
                entropy: None,
                issuance_txid: [0; 32],
                contract_script: Vec::new(),
                contract_data: Some(
                    postcard::to_stdvec(&StormEyeContractData {
                        storm_tree_root: SIGNER,
                        rescue_height: 1_000_000,
                        rescue_output_script_hash: [3; 32],
                    })
                    .unwrap(),
                ),
                supply: 1,
                created_at_block: 1,
            };
            let script = storm_eye_program(&storm_eye)
                .unwrap()
                .get_script_pubkey(&network);
            storm_eye.contract_script = script.as_bytes().to_vec();
            let storm_eye_utxo = Self::utxo(
                200,
                0,
                AssetId::from_byte_array(Self::STORM_EYE_ID),
                1,
                script,
            );
            Self {
                network,
                assets: BurnAssets {
                    tick: Some(AssetId::from_byte_array([1; 32])),
                    verifier: Some(AssetId::from_byte_array([2; 32])),
                },
                storm_eye,
                storm_eye_utxo,
            }
        }

        fn utxo(txid: u8, vout: u32, asset: AssetId, amount: u64, script: Script) -> UTXO {
            use simplex::simplicityhl::elements::{OutPoint, confidential};

            UTXO {
                outpoint: OutPoint::new(Txid::from_byte_array([txid; 32]), vout),
                txout: TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: confidential::Value::Explicit(amount),
                    script_pubkey: script,
                    ..Default::default()
                },
                secrets: None,
            }
        }

        fn group(
            &self,
            reserve: u8,
            items: usize,
            verifiers: bool,
            reserve_sats: u64,
        ) -> BurnableGroup {
            let owner = [reserve; 32];
            let account = AccountProgram::new(&AccountArguments {
                storm_eye_asset_id: Self::STORM_EYE_ID,
                account_owner_pubkey: owner,
            });
            let mut ticks = Vec::with_capacity(items);
            let mut tick_utxos = Vec::with_capacity(items);
            for index in 0..items as u32 {
                let mut item = if verifiers {
                    verifier(reserve, index, reserve, reserve)
                } else {
                    tick(reserve, index, reserve, reserve)
                };
                let script = issued_program(Self::STORM_EYE_ID, &item)
                    .unwrap()
                    .get_script_pubkey(&self.network);
                item.script_pubkey = script.as_bytes().to_vec();
                item.burning_fee_txid = [reserve; 32];
                item.burning_fee_output_index = 1_000;
                tick_utxos.push(Self::utxo(
                    reserve,
                    index,
                    self.assets.of(&item).unwrap(),
                    item.amount,
                    script,
                ));
                ticks.push(item);
            }
            let reserve_utxo = Self::utxo(
                reserve,
                1_000,
                self.network.policy_asset(),
                reserve_sats,
                account.get_script_pubkey(&self.network),
            );
            (
                BurnGroup {
                    reserve: ([reserve; 32], 1_000),
                    owner,
                    ticks,
                },
                reserve_utxo,
                account,
                tick_utxos,
            )
        }

        fn build(
            &self,
            groups: &[BurnableGroup],
            minimum_fee: u64,
        ) -> Result<BuiltBurn, BurningError> {
            build_burn_transaction(
                &self.storm_eye,
                &self.storm_eye_utxo,
                groups,
                &self.assets,
                &self.network,
                minimum_fee,
            )
        }
    }

    #[test]
    fn sizes_the_burn_fee_to_the_relay_floor_above_the_minimum() {
        assert_eq!(burn_fee(500, 1, 1).unwrap(), 500);
        assert_eq!(burn_fee(500, 34, 1).unwrap(), 500);
        assert_eq!(burn_fee(500, 35, 1).unwrap(), 510);
        // 3,900 + 450 * 50 + 750 = 27,150 WU -> 6,788 vB -> 679 sats at 0.1 sat/vB.
        assert_eq!(burn_fee(500, 50, 1).unwrap(), 679);
        assert_eq!(burn_fee(500, 100, 100).unwrap(), 3_098);
        assert_eq!(burn_fee(5_000, 100, 100).unwrap(), 5_000);
    }

    #[test]
    fn signers_recompute_the_sized_fee_of_a_large_burn() {
        let fixture = BurnFixture::new();
        let groups = [fixture.group(1, 50, false, 100_000)];
        let built = fixture.build(&groups, 500).unwrap();
        let (pset, _) = built.final_transaction.extract_pst();
        let fee_output = pset.outputs().last().unwrap();
        assert_eq!(fee_output.amount, Some(679));
        assert_eq!(
            pset.outputs()[pset.outputs().len() - 2].amount,
            Some(100_000 - 679)
        );

        let request = BurnExpiredUtxos {
            tx: encode::serialize(&pset),
            signing_hash: signing_hash(&pset, &fixture.storm_eye, &fixture.network).unwrap(),
            signing_storm_tree_branch: built.signing_branch,
            block_height: 61,
            chain_tip: None,
        };
        let validate = |minimum_fee| {
            validate_layout(
                &pset,
                &request,
                &groups[0].0.ticks,
                &fixture.storm_eye,
                &fixture.assets,
                &fixture.network,
                minimum_fee,
            )
        };
        validate(500).unwrap();
        assert!(validate(700).is_err());
    }

    #[test]
    fn reports_a_reserve_shortfall_so_the_round_can_shrink() {
        let fixture = BurnFixture::new();
        let groups = [
            fixture.group(1, 1, false, 200),
            fixture.group(2, 1, false, 200),
        ];

        assert!(matches!(
            fixture.build(&groups, 500),
            Err(BurningError::ReserveShortfall)
        ));
        fixture.build(&groups, 300).unwrap();
    }

    #[test]
    fn separates_reserves_claimed_by_conflicting_owners() {
        let (consistent, conflicting) = split_conflicting_reserves(vec![
            tick(1, 0, 5, 1),
            tick(2, 0, 5, 2),
            tick(3, 0, 6, 3),
            tick(4, 0, 6, 3),
        ]);

        assert_eq!(
            consistent
                .iter()
                .map(|item| item.txid[0])
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(conflicting.len(), 1);
        assert_eq!(conflicting[&([5; 32], 7)].len(), 2);
        select_groups(consistent, MAX_TICKS_PER_BURN).unwrap();
    }

    #[test]
    fn finds_persistent_faults_in_a_groups_items() {
        let fixture = BurnFixture::new();
        let validate = |(group, _, _, utxos): &BurnableGroup| {
            validate_group_items(BurnFixture::STORM_EYE_ID, &fixture.assets, group, utxos)
        };
        validate(&fixture.group(1, 3, false, 1_000)).unwrap();
        validate(&fixture.group(1, 3, true, 1_000)).unwrap();

        let mut changed = fixture.group(1, 3, false, 1_000);
        changed.3[1].txout.value =
            simplex::simplicityhl::elements::confidential::Value::Explicit(1);
        assert!(matches!(validate(&changed), Err(BurningError::Invalid(_))));

        let mut keyless = fixture.group(1, 3, true, 1_000);
        keyless.0.ticks[2].internal_key = None;
        assert!(matches!(validate(&keyless), Err(BurningError::Invalid(_))));
    }

    #[tokio::test]
    async fn quarantining_a_group_leaves_the_rest_of_the_queue() {
        use crate::db::{Database, monitored_utxo::IndexedBlock};

        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let faulty = [tick(1, 0, 5, 1), tick(2, 0, 5, 1)];
        let healthy = tick(3, 0, 6, 3);
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 61,
                    hash: [61; 32],
                },
                &[faulty[0].clone(), faulty[1].clone(), healthy.clone()],
                &[],
                60,
            )
            .await
            .unwrap();
        let burning = Burning::new(
            store.clone(),
            database.network_assets(),
            ElementsRpcConfig {
                url: "http://127.0.0.1:9".into(),
                username: String::new(),
                password: String::new(),
                wallet: "test".into(),
            },
            ProtocolConfig {
                operational_fee_sats: 1_000,
                tick_burn_reserve_sats: 1_000,
                issuance_transaction_fee_sats: 500,
                burn_transaction_fee_sats: 500,
                exchange_transaction_fee_sats: 500,
                tick_lifetime_blocks: 60,
                finality_confirmations: 2,
            },
        );

        burning
            .quarantine_group(([5; 32], 7), &faulty, 61, "indexed issued UTXO changed")
            .await
            .unwrap();

        let expired = store.list_expired(10).await.unwrap();
        assert_eq!(
            expired.iter().map(|item| item.txid).collect::<Vec<_>>(),
            vec![healthy.txid]
        );
        assert!(
            burning
                .quarantine_group(([5; 32], 7), &faulty, 62, "again")
                .await
                .is_err()
        );
    }

    /// Finalized weight of production burn transactions; the Storm Eye witness is the
    /// fixed template the round limit already uses.
    #[test]
    #[ignore = "measurement taking about a minute; run with --ignored --nocapture"]
    fn measures_burn_transaction_weight() {
        let fixture = BurnFixture::new();
        let weight = |groups: &[BurnableGroup]| {
            let built = fixture.build(groups, 500).unwrap();
            let (pset, _) = built.final_transaction.extract_pst();
            let weight =
                finalized_dummy_weight(&built.final_transaction, &pset, &fixture.network).unwrap();
            let items = groups.iter().map(|(group, _, _, _)| group.ticks.len());
            let bound = BURN_BASE_WEIGHT
                + BURN_ITEM_WEIGHT * items.sum::<usize>() as u64
                + BURN_RESERVE_WEIGHT * groups.len() as u64;
            assert!(
                weight as u64 <= bound,
                "{weight} WU exceeds the fee bound {bound}"
            );
            weight
        };

        let mut previous = 0;
        for items in [1, 2, 10, 20, 50, 100] {
            let tick_weight = weight(&[fixture.group(1, items, false, 100_000)]);
            let verifier_weight = weight(&[fixture.group(1, items, true, 100_000)]);
            let spread = (1..=items as u8)
                .map(|reserve| fixture.group(reserve, 1, false, 100_000))
                .collect::<Vec<_>>();
            let spread_weight = weight(&spread);
            println!(
                "items={items} one_reserve_ticks_wu={tick_weight} \
                 one_reserve_verifiers_wu={verifier_weight} one_reserve_each_wu={spread_weight}"
            );
            assert!(tick_weight > previous);
            assert!(spread_weight >= tick_weight);
            previous = tick_weight;
        }
    }

    #[test]
    fn refuses_to_burn_a_verifier_without_its_internal_key() {
        let mut monitored = verifier(1, 2, 3, 4);
        monitored.internal_key = None;

        assert!(issued_program([7; 32], &monitored).is_err());
    }

    #[test]
    fn burns_each_asset_into_an_op_return_of_its_own() {
        let assets = BurnAssets {
            tick: Some(AssetId::from_byte_array([1; 32])),
            verifier: Some(AssetId::from_byte_array([2; 32])),
        };
        let utxos = [
            verifier(1, 1, 1, 1),
            tick(2, 1, 1, 1),
            verifier(3, 1, 1, 1),
            tick(4, 1, 1, 1),
        ];

        assert_eq!(
            burn_outputs(&utxos, &assets).unwrap(),
            vec![
                (AssetId::from_byte_array([1; 32]), 3_400_000_000),
                (AssetId::from_byte_array([2; 32]), 2),
            ]
        );
        assert_eq!(
            burn_outputs(&utxos[..1], &assets).unwrap(),
            vec![(AssetId::from_byte_array([2; 32]), 1)]
        );
        assert!(
            burn_outputs(
                &utxos,
                &BurnAssets {
                    verifier: None,
                    ..assets
                }
            )
            .is_err()
        );
    }
}
