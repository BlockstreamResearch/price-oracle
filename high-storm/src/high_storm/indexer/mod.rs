use std::{
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bitcoincore_rpc::{Client, RpcApi};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use contracts::artifacts::treasury::{TreasuryProgram, derived_treasury::TreasuryArguments};
use secp256k1_zkp::Secp256k1;
use serde::Deserialize;
use simplex::{
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, Block, BlockHash, Transaction, TxOut, Txid, encode,
        pset::PartiallySignedTransaction,
    },
};
use storm_tree::StormTree;
use tokio::sync::Mutex;

use crate::high_storm::elements;
use crate::{
    NetworkAsset,
    config::{ElementsRpcConfig, ProtocolConfig},
    db::{
        chain::{CanonicalBlock, ChainStore, FinalizedMemberMigration},
        droplet::{DropletBalance, DropletError, DropletStore, TreasuryTransaction},
        monitored_utxo::{IndexedBlock, MonitoredUtxo, MonitoredUtxoStore},
        network_asset::{NetworkAssetStore, ORACLE_VERIFIER_KIND, STORM_EYE_KIND, TICK_ASSET_KIND},
    },
};

use super::{
    ChainTip,
    assets::{
        initial_members_from_script, migrated_members_proposer_from_script, renewed_storm_eye,
        storm_eye_contract_data, treasury_blinding_secret,
    },
    droplets::member_from_script,
    elements::asset_id,
    issuance::IssuedUtxoDescriptor,
};

const ISSUED_UTXO_RULE_SET: &str = "issued-utxo-burning-v1";
const DROPLETS_RULE_SET: &str = "droplets-v1";

#[derive(Debug, PartialEq, Eq)]
enum ExchangeRecovery {
    Keep,
    Unlock,
    Rebroadcast { transaction: Vec<u8>, txid: String },
}

/// Where a locked exchange's transaction stands on chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExchangeChainState {
    /// In the mempool or confirmed; indexing settles it.
    Known,
    /// An input is spent by another confirmed transaction, so it can never confirm.
    Conflicted,
    Pending,
}

#[derive(Deserialize)]
struct ConfirmationInfo {
    #[serde(default)]
    confirmations: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    #[error("indexer database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Droplets(#[from] DropletError),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("failed to decode indexed block: {0}")]
    Block(#[from] encode::Error),
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid indexed data: {0}")]
    Invalid(String),
    #[error("chain reorganization detected at block {height}")]
    Reorganization { height: u64 },
    #[error("chain safety halt requires operator intervention: {0}")]
    SafetyHalt(String),
}

#[derive(Clone)]
pub(crate) struct Indexer {
    chain: ChainStore,
    store: MonitoredUtxoStore,
    droplets: DropletStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    tick_lifetime_blocks: u64,
    initial_members: Vec<[u8; 32]>,
    recovering: Arc<AtomicBool>,
    sync_lock: Arc<Mutex<()>>,
}

impl Indexer {
    pub(crate) fn new(
        chain: ChainStore,
        store: MonitoredUtxoStore,
        droplets: DropletStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        protocol: &ProtocolConfig,
        initial_members: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            chain,
            store,
            droplets,
            assets,
            elements_rpc,
            tick_lifetime_blocks: protocol.tick_lifetime_blocks,
            initial_members,
            recovering: Arc::new(AtomicBool::new(true)),
            sync_lock: Arc::new(Mutex::new(())),
        }
    }

    pub(crate) async fn sync(&self) -> Result<u64, IndexerError> {
        let _guard = self.sync_lock.lock().await;
        let mut storm_eye = self.asset(STORM_EYE_KIND).await?;
        let tick_asset = self.asset(TICK_ASSET_KIND).await?;
        // Required, or a Verifier-only issuance would be skipped.
        let verifier_asset = self.asset(ORACLE_VERIFIER_KIND).await?;
        let issued_assets = [&tick_asset, &verifier_asset];
        let client = self.client()?;
        let network = network(&client)?;
        let tip: u64 = client.call("getblockcount", &[])?;
        let target_tip_hash = block_hash(&client, tip)?;
        let mut issued_cursor = self.store.cursor(ISSUED_UTXO_RULE_SET).await?;
        let mut droplets_cursor = self.droplets.cursor(DROPLETS_RULE_SET).await?;
        let persisted_recovery = self.chain.recovery_state().await?;
        if persisted_recovery.safe_halted {
            self.recovering.store(true, Ordering::Release);
            return Err(IndexerError::SafetyHalt(
                persisted_recovery
                    .halt_reason
                    .unwrap_or_else(|| "persisted chain safety halt".into()),
            ));
        }
        let member_migrations = self.chain.finalized_member_migrations().await?;
        for migration in &member_migrations {
            if migration.block_height > tip {
                self.recovering.store(true, Ordering::Release);
                return Err(IndexerError::Reorganization {
                    height: migration.block_height,
                });
            }
            if block_hash(&client, migration.block_height)? != migration.block_hash {
                let reason = format!(
                    "finalized member migration {} at block {} is no longer canonical",
                    hex::encode(migration.request_hash),
                    migration.block_height
                );
                self.chain.safe_halt(&reason).await?;
                self.recovering.store(true, Ordering::Release);
                return Err(IndexerError::SafetyHalt(reason));
            }
        }
        let journal = self.chain.blocks_descending().await?;
        let missing_journal =
            journal.is_empty() && (issued_cursor.is_some() || droplets_cursor.is_some());
        let journal_mismatch = if let Some(journal_tip) = journal.first() {
            journal_tip.height > tip || block_hash(&client, journal_tip.height)? != journal_tip.hash
        } else {
            false
        };
        let mut cursor_mismatch = false;
        for cursor in [&issued_cursor, &droplets_cursor].into_iter().flatten() {
            if cursor.height > tip || block_hash(&client, cursor.height)? != cursor.hash {
                cursor_mismatch = true;
                break;
            }
        }

        let migration_ahead_of_cursor = member_migration_requires_replay(
            &storm_eye,
            &member_migrations,
            issued_cursor.as_ref().map(|cursor| cursor.height),
            droplets_cursor.as_ref().map(|cursor| cursor.height),
            self.droplets.ledger_halt().await?.is_some(),
        );
        if journal_mismatch || cursor_mismatch {
            crate::monitoring::record_chain_reorg();
        }
        let mut recovered_locks = Vec::new();
        let recovering = persisted_recovery.recovering
            || missing_journal
            || journal_mismatch
            || cursor_mismatch
            || migration_ahead_of_cursor;
        if recovering {
            self.recovering.store(true, Ordering::Release);
            let ancestor = common_ancestor(&client, tip, &journal)?;
            let fork_height = ancestor.map_or(0, |height| height.saturating_add(1));
            self.chain.set_recovering(fork_height).await?;
            recovered_locks = self.chain.reset_projections().await?;
            storm_eye = self.asset(STORM_EYE_KIND).await?;
            issued_cursor = None;
            droplets_cursor = None;
            tracing::warn!(
                fork_height,
                common_ancestor = ancestor,
                "rebuilding chain-derived state after a reorganization"
            );
        }

        let issued_height = issued_cursor
            .as_ref()
            .map_or(tick_asset.created_at_block, |cursor| cursor.height + 1);
        // A halted ledger stops Droplets accounting only; vouchers keep being indexed.
        let mut droplets_height = if let Some((height, reason)) =
            self.droplets.ledger_halt().await?
        {
            tracing::warn!(height, %reason, "Droplets ledger is halted; indexing issued UTXOs only");
            None
        } else {
            Some(
                droplets_cursor
                    .as_ref()
                    .map_or(storm_eye.created_at_block, |cursor| cursor.height + 1),
            )
        };
        let first_height =
            droplets_height.map_or(issued_height, |height| height.min(issued_height));
        let mut active_members = member_migrations.first().map_or_else(
            || self.initial_members.clone(),
            |migration| migration.previous_members.clone(),
        );
        for migration in member_migrations
            .iter()
            .filter(|migration| migration.block_height < first_height)
        {
            active_members.clone_from(&migration.next_members);
        }
        let treasury_script = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        })
        .get_script_pubkey(&network);
        let mut indexed = 0;
        let mut previous_hash = if recovering {
            None
        } else {
            journal.first().map(|block| block.hash)
        };
        for height in first_height..=tip {
            let hash = block_hash(&client, height)?;
            let block = get_block(&client, hash)?;
            require_parent_hash(
                previous_hash,
                block.header.prev_blockhash.to_byte_array(),
                height,
            )?;
            let indexed_block = IndexedBlock { height, hash };
            let canonical_block = CanonicalBlock {
                height,
                hash,
                parent_hash: block.header.prev_blockhash.to_byte_array(),
            };
            let renewal = indexed_storm_eye_renewal(&client, &block.txdata, &storm_eye, &network)?;
            let member_migration = member_migrations
                .iter()
                .find(|migration| migration.block_height == height);
            if renewal.is_some() && member_migration.is_some() {
                return Err(IndexerError::Invalid(
                    "Storm Eye renewal and member migration share one block".into(),
                ));
            }
            let migrated_storm_eye = member_migration
                .map(|migration| {
                    if migration.asset_kind != storm_eye.kind
                        || migration.previous_script != storm_eye.contract_script
                        || migration.previous_data != storm_eye.contract_data
                    {
                        return Err(IndexerError::Invalid(
                            "member migration does not match replayed Storm Eye state".into(),
                        ));
                    }
                    let mut migrated = storm_eye.clone();
                    migrated.contract_script.clone_from(&migration.next_script);
                    migrated.contract_data.clone_from(&migration.next_data);
                    Ok(migrated)
                })
                .transpose()?;
            let block_storm_eye = renewal.as_ref().map_or(&storm_eye, |(_, renewed)| renewed);
            let issued = if height >= issued_height {
                Some(issued_utxos(
                    &client,
                    &block.txdata,
                    height,
                    block_storm_eye,
                    &issued_assets,
                    &network,
                )?)
            } else {
                None
            };
            let spent = issued
                .as_ref()
                .map(|_| spent_monitored_outpoints(&block.txdata));
            let treasury_transactions = if droplets_height.is_some_and(|start| height >= start) {
                verify_initial_members(&block.txdata, block_storm_eye, &active_members)?;
                Some(treasury_transactions(
                    &block.txdata,
                    &treasury_script,
                    network.policy_asset(),
                )?)
            } else {
                None
            };

            let mut transaction = self.chain.begin().await?;
            if let Some((_, renewed)) = &renewal
                && !NetworkAssetStore::index_storm_eye_renewal_in(
                    &mut transaction,
                    &storm_eye,
                    renewed,
                )
                .await?
            {
                return Err(IndexerError::Invalid(
                    "indexed Storm Eye renewal does not match active state".into(),
                ));
            }
            if let Some((_, renewed)) = &renewal {
                ChainStore::record_asset_transition(
                    &mut transaction,
                    &canonical_block,
                    &storm_eye,
                    renewed,
                )
                .await?;
            }
            if let Some(migrated) = &migrated_storm_eye
                && !NetworkAssetStore::index_storm_eye_renewal_in(
                    &mut transaction,
                    &storm_eye,
                    migrated,
                )
                .await?
            {
                return Err(IndexerError::Invalid(
                    "replayed member migration does not match active state".into(),
                ));
            }
            let mut reverted_burns = 0;
            if let (Some(issued), Some(spent)) = (&issued, &spent) {
                reverted_burns = MonitoredUtxoStore::apply_block_in(
                    &mut transaction,
                    &indexed_block,
                    issued,
                    spent,
                    self.tick_lifetime_blocks,
                )
                .await?;
                MonitoredUtxoStore::record_cursor(
                    &mut transaction,
                    ISSUED_UTXO_RULE_SET,
                    &indexed_block,
                )
                .await?;
            }
            if let Some(treasury_transactions) = &treasury_transactions {
                let mut savepoint = sqlx::Acquire::begin(&mut transaction).await?;
                match DropletStore::apply_block_in(
                    &mut savepoint,
                    &indexed_block,
                    treasury_transactions,
                    &active_members,
                )
                .await
                {
                    Ok(()) => {
                        savepoint.commit().await?;
                        MonitoredUtxoStore::record_cursor(
                            &mut transaction,
                            DROPLETS_RULE_SET,
                            &indexed_block,
                        )
                        .await?;
                    }
                    Err(DropletError::Invalid(reason)) => {
                        savepoint.rollback().await?;
                        DropletStore::halt_ledger_in(&mut transaction, height, &reason).await?;
                        tracing::error!(
                            height,
                            %reason,
                            "halted the Droplets ledger; issued UTXOs and burns continue"
                        );
                        droplets_height = None;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            ChainStore::record_block(&mut transaction, &canonical_block).await?;
            transaction.commit().await?;
            // Replaying history while recovering would count past reverts again.
            if reverted_burns > 0 && !recovering {
                crate::monitoring::record_burns_reverted(reverted_burns);
            }

            if let Some((txid, renewed)) = renewal {
                tracing::info!(%txid, height, "indexed Storm Eye timelock renewal");
                storm_eye = renewed;
            }
            if let Some(migrated) = migrated_storm_eye {
                storm_eye = migrated;
            }
            if let Some(migration) = member_migration {
                active_members.clone_from(&migration.next_members);
            }
            previous_hash = Some(hash);
            indexed += 1;
        }

        let current_tip: u64 = client.call("getblockcount", &[])?;
        if !target_tip_is_canonical(current_tip, tip, block_hash(&client, tip)?, target_tip_hash) {
            return Err(IndexerError::Reorganization { height: tip });
        }

        if recovering {
            for lock in recovered_locks {
                if !self
                    .droplets
                    .lock_exchange(
                        lock.member,
                        lock.amount,
                        lock.block_height,
                        &lock.transaction,
                    )
                    .await?
                {
                    tracing::warn!(
                        member = %hex::encode(lock.member),
                        "could not restore a pending Droplets lock after reorganization"
                    );
                }
            }
            self.chain.finish_recovery().await?;
        }
        self.recovering.store(false, Ordering::Release);

        Ok(indexed)
    }

    pub(crate) fn is_recovering(&self) -> bool {
        self.recovering.load(Ordering::Acquire)
    }

    /// Stands in for the first sync, which needs an Elements node.
    #[cfg(test)]
    pub(crate) fn mark_synced(&self) {
        self.recovering.store(false, Ordering::Release);
    }

    pub(crate) async fn cursor(&self) -> Result<Option<IndexedBlock>, IndexerError> {
        Ok(self.store.cursor(ISSUED_UTXO_RULE_SET).await?)
    }

    pub(crate) async fn chain_tip(&self) -> Result<ChainTip, IndexerError> {
        let block = self
            .chain
            .tip()
            .await?
            .ok_or_else(|| IndexerError::Invalid("canonical chain is not indexed".into()))?;
        Ok(ChainTip {
            height: block.height,
            hash: block.hash,
        })
    }

    pub(crate) fn hash_at(&self, height: u64) -> Result<[u8; 32], IndexerError> {
        block_hash(&self.client()?, height)
    }

    pub(crate) fn tip(&self) -> Result<u64, IndexerError> {
        Ok(self.client()?.call("getblockcount", &[])?)
    }

    pub(crate) async fn recover_droplet_exchanges(
        &self,
        block_height: u64,
        is_leader: bool,
    ) -> Result<(), IndexerError> {
        let client = self.client()?;
        let mempool: Vec<String> = client.call("getrawmempool", &[])?;
        for balance in self.droplets.locked().await? {
            let exchange = balance.last_tx.as_deref().and_then(locked_exchange);
            let chain = match &exchange {
                Some((transaction, _)) => {
                    match exchange_chain_state(&client, transaction, &mempool) {
                        Ok(chain) => chain,
                        Err(error) => {
                            tracing::warn!(%error, "could not check a locked Droplets exchange");
                            continue;
                        }
                    }
                }
                None => ExchangeChainState::Pending,
            };
            match exchange_recovery(&balance, block_height, is_leader, exchange.as_ref(), chain) {
                ExchangeRecovery::Keep => {}
                ExchangeRecovery::Unlock => {
                    self.droplets
                        .unlock_exchange(balance.xonly_pubkey, block_height)
                        .await?;
                    tracing::info!(
                        member = %hex::encode(balance.xonly_pubkey),
                        "released a Droplets exchange that can no longer confirm"
                    );
                }
                ExchangeRecovery::Rebroadcast { transaction, txid } => {
                    match client
                        .call::<String>("sendrawtransaction", &[hex::encode(transaction).into()])
                    {
                        Ok(broadcast_txid) if broadcast_txid == txid => {}
                        Ok(broadcast_txid) => {
                            tracing::warn!(%txid, %broadcast_txid, "rebroadcast Droplets transaction id mismatch");
                        }
                        Err(error) => {
                            tracing::warn!(%txid, %error, "recovered Droplets rebroadcast failed");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn asset(&self, kind: &'static str) -> Result<crate::NetworkAsset, IndexerError> {
        self.assets.require(kind, IndexerError::MissingAsset).await
    }

    fn client(&self) -> Result<Client, IndexerError> {
        let url = url::Url::parse(&self.elements_rpc.url)?;
        Ok(crate::monitoring::elements_client(
            url.as_str(),
            self.elements_rpc.auth(),
            "rebroadcast",
        )?)
    }
}

fn common_ancestor(
    client: &Client,
    tip: u64,
    journal: &[CanonicalBlock],
) -> Result<Option<u64>, IndexerError> {
    for block in journal {
        if block.height <= tip && block_hash(client, block.height)? == block.hash {
            return Ok(Some(block.height));
        }
    }
    Ok(None)
}

fn indexed_storm_eye_renewal(
    client: &Client,
    transactions: &[Transaction],
    current: &crate::NetworkAsset,
    network: &SimplicityNetwork,
) -> Result<Option<(Txid, crate::NetworkAsset)>, IndexerError> {
    let renewed = renewed_storm_eye(current, network)
        .map_err(|error| IndexerError::Invalid(error.to_string()))?;
    let mut matched = None;
    for transaction in transactions {
        if !matches_storm_eye_supply(&transaction.output, &renewed)? {
            continue;
        }
        let spent = transaction
            .input
            .iter()
            .filter(|input| !input.is_pegin)
            .map(|input| previous_output(client, input.previous_output))
            .collect::<Result<Vec<_>, _>>()?;
        if !matches_storm_eye_supply(&spent, current)? {
            continue;
        }
        if matched.is_some() {
            return Err(IndexerError::Invalid(
                "block contains multiple Storm Eye renewal transactions".into(),
            ));
        }
        matched = Some((transaction.txid(), renewed.clone()));
    }
    Ok(matched)
}

fn matches_storm_eye_supply(
    outputs: &[TxOut],
    storm_eye: &crate::NetworkAsset,
) -> Result<bool, IndexerError> {
    let asset =
        asset_id(storm_eye.asset_id).map_err(|error| IndexerError::Invalid(error.to_string()))?;
    let mut amount = 0u64;
    let mut found = false;
    for output in outputs {
        if output.asset.explicit() != Some(asset) {
            continue;
        }
        found = true;
        if output.script_pubkey.as_bytes() != storm_eye.contract_script {
            return Ok(false);
        }
        let Some(output_amount) = output.value.explicit() else {
            return Ok(false);
        };
        amount = amount
            .checked_add(output_amount)
            .ok_or_else(|| IndexerError::Invalid("Storm Eye amount overflow".into()))?;
    }
    Ok(found && amount == storm_eye.supply)
}

/// The locked transaction and whether it is final: signers hold only the unsigned PSET
/// until the leader announces the broadcast.
fn locked_exchange(bytes: &[u8]) -> Option<(Transaction, bool)> {
    if let Ok(transaction) = encode::deserialize::<Transaction>(bytes) {
        return Some((transaction, true));
    }
    let pset: PartiallySignedTransaction = encode::deserialize(bytes).ok()?;
    pset.extract_tx()
        .ok()
        .map(|transaction| (transaction, false))
}

fn exchange_chain_state(
    client: &Client,
    transaction: &Transaction,
    mempool: &[String],
) -> Result<ExchangeChainState, IndexerError> {
    let mut conflicted = false;
    for input in &transaction.input {
        let unspent: Option<serde_json::Value> = client.call(
            "gettxout",
            &[
                input.previous_output.txid.to_string().into(),
                input.previous_output.vout.into(),
                false.into(),
            ],
        )?;
        conflicted |= unspent.is_none();
    }
    // Checked after the inputs, so an exchange confirming meanwhile is not taken for a conflict.
    let txid = transaction.txid().to_string();
    if mempool.contains(&txid) {
        return Ok(ExchangeChainState::Known);
    }
    match client.call::<ConfirmationInfo>("getrawtransaction", &[txid.into(), true.into()]) {
        Ok(info) if info.confirmations > 0 => return Ok(ExchangeChainState::Known),
        Ok(_) => {}
        Err(bitcoincore_rpc::Error::JsonRpc(bitcoincore_rpc::jsonrpc::error::Error::Rpc(
            error,
        ))) if error.code == -5 => {}
        Err(error) => return Err(error.into()),
    }

    Ok(if conflicted {
        ExchangeChainState::Conflicted
    } else {
        ExchangeChainState::Pending
    })
}

fn exchange_recovery(
    balance: &DropletBalance,
    block_height: u64,
    is_leader: bool,
    exchange: Option<&(Transaction, bool)>,
    chain: ExchangeChainState,
) -> ExchangeRecovery {
    let Some(last_tx) = balance.last_tx.as_ref() else {
        return ExchangeRecovery::Unlock;
    };
    let Some((transaction, is_final)) = exchange else {
        return if balance.block_height < block_height {
            ExchangeRecovery::Unlock
        } else {
            ExchangeRecovery::Keep
        };
    };
    match chain {
        ExchangeChainState::Known => ExchangeRecovery::Keep,
        ExchangeChainState::Conflicted => ExchangeRecovery::Unlock,
        ExchangeChainState::Pending if *is_final && is_leader => ExchangeRecovery::Rebroadcast {
            transaction: last_tx.clone(),
            txid: transaction.txid().to_string(),
        },
        ExchangeChainState::Pending => ExchangeRecovery::Keep,
    }
}

fn verify_initial_members(
    transactions: &[Transaction],
    storm_eye: &crate::NetworkAsset,
    expected_members: &[[u8; 32]],
) -> Result<(), IndexerError> {
    let Some(transaction) = transactions
        .iter()
        // `issuance_txid` is stored in display byte order.
        .find(|transaction| transaction.txid().to_string() == hex::encode(storm_eye.issuance_txid))
    else {
        return Ok(());
    };
    let markers = transaction
        .output
        .iter()
        .filter_map(|output| {
            initial_members_from_script(&output.script_pubkey)
                .map_err(|error| IndexerError::Invalid(error.to_string()))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?;
    if markers.len() != 1 {
        return Err(IndexerError::Invalid(
            "Storm Eye issuance must contain one initial-members marker".into(),
        ));
    }
    let marker_root = StormTree::new(markers[0].clone())
        .map_err(|error| IndexerError::Invalid(error.to_string()))?
        .root();
    let replayed_root = storm_eye_contract_data(storm_eye)
        .map_err(|error| IndexerError::Invalid(error.to_string()))?
        .storm_tree_root;
    if replayed_root != marker_root {
        tracing::warn!(
            "skipped the initial-members check: this node has no history of a later member migration"
        );
        return Ok(());
    }
    let mut expected_members = expected_members.to_vec();
    expected_members.sort_unstable();
    expected_members.dedup();
    if markers[0] != expected_members {
        return Err(IndexerError::Invalid(
            "Storm Eye initial members do not match the configured network".into(),
        ));
    }
    Ok(())
}

fn treasury_transactions(
    transactions: &[Transaction],
    treasury_script: &simplex::simplicityhl::elements::Script,
    policy_asset: AssetId,
) -> Result<Vec<TreasuryTransaction>, IndexerError> {
    transactions
        .iter()
        .map(|transaction| {
            let outputs = transaction
                .output
                .iter()
                .enumerate()
                .filter_map(|(index, output)| {
                    treasury_output_amount(output, treasury_script, policy_asset)
                        .transpose()
                        .map(|result| {
                            result.and_then(|amount| {
                                u32::try_from(index)
                                    .map(|index| (index, amount))
                                    .map_err(|_| {
                                        IndexerError::Invalid(
                                            "Treasury output index overflow".into(),
                                        )
                                    })
                            })
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let markers = transaction
                .output
                .iter()
                .filter_map(|output| {
                    member_from_script(&output.script_pubkey)
                        .or_else(|| migrated_members_proposer_from_script(&output.script_pubkey))
                })
                .collect::<std::collections::BTreeSet<_>>();
            let exchange_member = (markers.len() == 1)
                .then(|| markers.first().copied())
                .flatten();
            let deposit_member = outputs.iter().find_map(|(index, _)| {
                transaction
                    .output
                    .get(*index as usize + 1)
                    .and_then(|output| member_from_script(&output.script_pubkey))
            });

            Ok(TreasuryTransaction {
                txid: transaction.txid().to_byte_array(),
                inputs: transaction
                    .input
                    .iter()
                    .map(|input| {
                        (
                            input.previous_output.txid.to_byte_array(),
                            input.previous_output.vout,
                        )
                    })
                    .collect(),
                outputs,
                deposit_member,
                exchange_member,
            })
        })
        .collect()
}

fn treasury_output_amount(
    output: &TxOut,
    treasury_script: &simplex::simplicityhl::elements::Script,
    policy_asset: AssetId,
) -> Result<Option<u64>, IndexerError> {
    if output.script_pubkey != *treasury_script {
        return Ok(None);
    }
    if let (Some(asset), Some(value)) = (output.asset.explicit(), output.value.explicit()) {
        return Ok((asset == policy_asset).then_some(value));
    }
    Ok(None)
}

fn issued_utxos(
    client: &Client,
    transactions: &[Transaction],
    height: u64,
    storm_eye: &crate::NetworkAsset,
    issued_assets: &[&crate::NetworkAsset],
    network: &SimplicityNetwork,
) -> Result<Vec<MonitoredUtxo>, IndexerError> {
    let mut issued = Vec::new();
    for transaction in transactions {
        let Some(tokens) = issuance_tokens(client, transaction, storm_eye, issued_assets)? else {
            continue;
        };
        issued.extend(indexed_issued_outputs(
            transaction,
            height,
            storm_eye,
            &tokens,
            network,
        )?);
    }
    Ok(issued)
}

/// `tokens`: reissued assets, in input order.
fn indexed_issued_outputs(
    transaction: &Transaction,
    height: u64,
    storm_eye: &crate::NetworkAsset,
    tokens: &[&crate::NetworkAsset],
    network: &SimplicityNetwork,
) -> Result<Vec<MonitoredUtxo>, IndexerError> {
    let txid = transaction.txid();
    let mut descriptors = None;
    for output in &transaction.output {
        let Some(output_descriptors) = IssuedUtxoDescriptor::from_script(&output.script_pubkey)
            .map_err(IndexerError::Invalid)?
        else {
            continue;
        };
        if descriptors.is_some() {
            return Err(IndexerError::Invalid(
                "issuance has multiple descriptor outputs".into(),
            ));
        }
        if output.asset.explicit() != Some(network.policy_asset())
            || output.value.explicit() != Some(0)
        {
            return Err(IndexerError::Invalid(
                "issued UTXO descriptor output must have zero policy-asset value".into(),
            ));
        }
        descriptors = Some(output_descriptors);
    }
    let descriptors = descriptors
        .ok_or_else(|| IndexerError::Invalid("issuance descriptor output is missing".into()))?;
    // Token index of a descriptor's asset.
    let token_of = |descriptor: &IssuedUtxoDescriptor| {
        let kind = if descriptor.is_verifier() {
            ORACLE_VERIFIER_KIND
        } else {
            TICK_ASSET_KIND
        };
        tokens
            .iter()
            .position(|asset| asset.kind == kind)
            .ok_or_else(|| {
                IndexerError::Invalid(format!("issuance describes {kind} it does not reissue"))
            })
    };
    for (position, asset) in tokens.iter().enumerate() {
        let asset_id = AssetId::from_byte_array(asset.asset_id);
        let output_count = transaction
            .output
            .iter()
            .filter(|output| output.asset.explicit() == Some(asset_id))
            .count();
        let described = descriptors
            .iter()
            .map(token_of)
            .filter(|token| token.as_ref().is_ok_and(|token| *token == position))
            .count();
        if described != output_count {
            return Err(IndexerError::Invalid(format!(
                "issuance descriptors do not match {} outputs",
                asset.name
            )));
        }
    }

    let mut issued = Vec::with_capacity(descriptors.len());
    let mut described_outputs = std::collections::BTreeSet::new();
    let mut issued_amounts = vec![0u64; tokens.len()];
    for descriptor in descriptors {
        if !described_outputs.insert(descriptor.output_index) {
            return Err(IndexerError::Invalid(
                "issued output has duplicate descriptors".into(),
            ));
        }
        let token = token_of(&descriptor)?;
        let asset = tokens[token];
        let output = transaction
            .output
            .get(descriptor.output_index as usize)
            .ok_or_else(|| IndexerError::Invalid("indexed issued output is missing".into()))?;
        let amount = output
            .value
            .explicit()
            .ok_or_else(|| IndexerError::Invalid("indexed issued output is confidential".into()))?;
        issued_amounts[token] = issued_amounts[token]
            .checked_add(amount)
            .ok_or_else(|| IndexerError::Invalid("indexed issued amount overflow".into()))?;
        if output.asset.explicit() != Some(AssetId::from_byte_array(asset.asset_id))
            || (descriptor.is_verifier() && amount != 1)
            || !descriptor.matches_script(storm_eye.asset_id, network, &output.script_pubkey)
        {
            return Err(IndexerError::Invalid(format!(
                "indexed {} output does not match its descriptor",
                asset.name
            )));
        }
        let reserve = transaction
            .output
            .get(descriptor.reserve_output_index as usize)
            .ok_or_else(|| IndexerError::Invalid("indexed burn reserve is missing".into()))?;
        let account_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: descriptor.account_owner_pubkey,
        })
        .get_script_pubkey(network);
        if reserve.asset.explicit() != Some(network.policy_asset())
            || reserve.value.explicit().is_none_or(|value| value == 0)
            || reserve.script_pubkey != account_script
        {
            return Err(IndexerError::Invalid(
                "indexed burn reserve does not match its descriptor".into(),
            ));
        }

        issued.push(MonitoredUtxo {
            txid: txid.to_byte_array(),
            output_index: descriptor.output_index,
            asset_kind: asset.kind.clone(),
            amount,
            script_pubkey: output.script_pubkey.as_bytes().to_vec(),
            auth_method: descriptor.auth_method_name().into(),
            auth_data: descriptor.auth_data.to_vec(),
            account_owner_pubkey: descriptor.account_owner_pubkey,
            internal_key: descriptor.signer,
            burning_fee_txid: txid.to_byte_array(),
            burning_fee_output_index: descriptor.reserve_output_index,
            block_height: height,
            status: "active".into(),
            status_block_height: height,
            burn_txid: None,
        });
    }
    for (position, (asset, issued_amount)) in tokens.iter().zip(issued_amounts).enumerate() {
        if transaction.input[1 + position]
            .asset_issuance
            .amount
            .explicit()
            != Some(issued_amount)
        {
            return Err(IndexerError::Invalid(format!(
                "{} reissuance amount does not match described outputs",
                asset.name
            )));
        }
    }
    Ok(issued)
}

/// Assets an issuance reissues, in input order; `None` if not an issuance.
fn issuance_tokens<'a>(
    client: &Client,
    transaction: &Transaction,
    storm_eye: &crate::NetworkAsset,
    issued_assets: &[&'a crate::NetworkAsset],
) -> Result<Option<Vec<&'a crate::NetworkAsset>>, IndexerError> {
    if transaction.input.len() < 2 || transaction.output.len() < 2 {
        return Ok(None);
    }
    let txid = transaction.txid();
    // Peg-ins have no previous Liquid transaction to look up; network issuances never use them.
    if transaction.input.iter().any(|input| input.is_pegin) {
        tracing::debug!(%txid, "rejected issuance candidate: spends a peg-in");
        return Ok(None);
    }
    let mut tokens: Vec<&crate::NetworkAsset> = Vec::with_capacity(issued_assets.len());
    for input in transaction.input.iter().skip(1) {
        let issuance = input.asset_issuance;
        if issuance.is_null() {
            break;
        }
        // A null nonce is a new issuance, whose entropy field is a free contract hash.
        if issuance.asset_blinding_nonce.is_null() {
            tracing::debug!(%txid, "rejected issuance candidate: not a reissuance");
            return Ok(None);
        }
        let Some(asset) = issued_assets
            .iter()
            .find(|asset| asset.entropy == Some(issuance.asset_entropy.to_byte_array()))
        else {
            tracing::debug!(
                %txid,
                actual = %hex::encode(issuance.asset_entropy.to_byte_array()),
                "rejected issuance candidate: entropy of no network asset"
            );
            return Ok(None);
        };
        if tokens.iter().any(|token| token.kind == asset.kind) {
            tracing::debug!(%txid, asset = %asset.name, "rejected issuance candidate: asset reissued twice");
            return Ok(None);
        }
        if !issuance.inflation_keys.is_null() {
            tracing::debug!(%txid, "rejected issuance candidate: inflation keys are not null");
            return Ok(None);
        }
        tokens.push(asset);
    }
    if tokens.is_empty() {
        return Ok(None);
    }
    let storm_eye_input = previous_output(client, transaction.input[0].previous_output)?;
    let storm_eye_asset =
        asset_id(storm_eye.asset_id).map_err(|error| IndexerError::Invalid(error.to_string()))?;
    if storm_eye_input.asset.explicit() != Some(storm_eye_asset)
        || storm_eye_input.script_pubkey.as_bytes() != storm_eye.contract_script
        || transaction.output[0] != storm_eye_input
    {
        tracing::debug!(%txid, "rejected issuance candidate: Storm Eye is not preserved");
        return Ok(None);
    }
    for (offset, asset) in tokens.iter().enumerate() {
        if !preserves_token(client, transaction, 1 + offset, asset)? {
            return Ok(None);
        }
    }

    Ok(Some(tokens))
}

/// The token at `index` is returned unchanged.
fn preserves_token(
    client: &Client,
    transaction: &Transaction,
    index: usize,
    asset: &crate::NetworkAsset,
) -> Result<bool, IndexerError> {
    let txid = transaction.txid();
    let name = &asset.name;
    let token_input = previous_output(client, transaction.input[index].previous_output)?;
    let Ok(token_input_secrets) =
        token_input.unblind(&Secp256k1::new(), treasury_blinding_secret())
    else {
        tracing::debug!(%txid, %name, "rejected issuance candidate: token input cannot be unblinded");
        return Ok(false);
    };
    let token_id = asset_id(
        asset
            .reissuance_token_id
            .ok_or_else(|| IndexerError::Invalid(format!("{name} token id is missing")))?,
    )
    .map_err(|error| IndexerError::Invalid(error.to_string()))?;
    if token_input_secrets.asset != token_id
        || token_input.script_pubkey.as_bytes() != asset.contract_script
    {
        tracing::debug!(%txid, %name, "rejected issuance candidate: token input does not match its asset");
        return Ok(false);
    }
    let Some(token_output) = transaction.output.get(index) else {
        tracing::debug!(%txid, %name, "rejected issuance candidate: token output is missing");
        return Ok(false);
    };
    let Ok(token_output_secrets) =
        token_output.unblind(&Secp256k1::new(), treasury_blinding_secret())
    else {
        tracing::debug!(%txid, %name, "rejected issuance candidate: token output cannot be unblinded");
        return Ok(false);
    };
    let preserved = token_output_secrets.asset == token_input_secrets.asset
        && token_output_secrets.value == token_input_secrets.value
        && token_output.script_pubkey == token_input.script_pubkey;
    if !preserved {
        tracing::debug!(%txid, %name, "rejected issuance candidate: token is not preserved");
    }
    Ok(preserved)
}

fn previous_output(
    client: &Client,
    outpoint: simplex::simplicityhl::elements::OutPoint,
) -> Result<TxOut, IndexerError> {
    let encoded: String = client.call(
        "getrawtransaction",
        &[outpoint.txid.to_string().into(), false.into()],
    )?;
    let transaction: Transaction = encode::deserialize(
        &hex::decode(encoded)
            .map_err(|_| IndexerError::Invalid("invalid previous transaction encoding".into()))?,
    )?;
    transaction
        .output
        .get(outpoint.vout as usize)
        .cloned()
        .ok_or_else(|| IndexerError::Invalid("previous transaction output is missing".into()))
}

fn network(client: &Client) -> Result<SimplicityNetwork, IndexerError> {
    elements::network(client, IndexerError::Invalid, |chain| {
        IndexerError::Invalid(format!("unsupported Elements chain '{chain}'"))
    })
}

fn spent_monitored_outpoints(transactions: &[Transaction]) -> Vec<([u8; 32], u32, [u8; 32])> {
    transactions
        .iter()
        .flat_map(|transaction| {
            let spending_txid = transaction.txid().to_byte_array();
            transaction.input.iter().map(move |input| {
                (
                    input.previous_output.txid.to_byte_array(),
                    input.previous_output.vout,
                    spending_txid,
                )
            })
        })
        .collect()
}

fn block_hash(client: &Client, height: u64) -> Result<[u8; 32], IndexerError> {
    let encoded: String = client.call("getblockhash", &[height.into()])?;
    BlockHash::from_str(&encoded)
        .map(|hash| hash.to_byte_array())
        .map_err(|_| IndexerError::Invalid("invalid block hash".into()))
}

fn require_parent_hash(
    expected_parent: Option<[u8; 32]>,
    actual_parent: [u8; 32],
    height: u64,
) -> Result<(), IndexerError> {
    if expected_parent.is_some_and(|expected| expected != actual_parent) {
        return Err(IndexerError::Reorganization { height });
    }
    Ok(())
}

fn member_migration_requires_replay(
    storm_eye: &NetworkAsset,
    migrations: &[FinalizedMemberMigration],
    issued_cursor: Option<u64>,
    droplets_cursor: Option<u64>,
    droplets_halted: bool,
) -> bool {
    migrations.iter().any(|migration| {
        migration.asset_kind == storm_eye.kind
            && migration.next_script == storm_eye.contract_script
            && migration.next_data == storm_eye.contract_data
            && (issued_cursor.is_none_or(|height| height < migration.block_height)
                || (!droplets_halted
                    && droplets_cursor.is_none_or(|height| height < migration.block_height)))
    })
}

fn target_tip_is_canonical(
    current_tip: u64,
    target_tip: u64,
    current_target_hash: [u8; 32],
    expected_target_hash: [u8; 32],
) -> bool {
    current_tip >= target_tip && current_target_hash == expected_target_hash
}

fn get_block(client: &Client, hash: [u8; 32]) -> Result<Block, IndexerError> {
    let hash = BlockHash::from_byte_array(hash).to_string();
    let encoded: String = client.call("getblock", &[hash.into(), 0.into()])?;
    let bytes =
        hex::decode(encoded).map_err(|_| IndexerError::Invalid("invalid block encoding".into()))?;
    Ok(encode::deserialize(&bytes)?)
}

#[cfg(test)]
mod tests;
