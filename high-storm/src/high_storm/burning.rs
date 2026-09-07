use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use bitcoin::{Amount, Denomination};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::{
    account::{AccountProgram, derived_account::AccountArguments},
    auth::derived_auth::AuthWitness,
    tick_asset::{
        TickAssetProgram,
        derived_tick_asset::{TickAssetArguments, TickAssetWitness},
    },
};
use secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::Deserialize;
use simplex::{
    either::Either,
    program::ProgramTrait,
    provider::SimplicityNetwork,
    simplicityhl::{
        elements::{
            AssetId, BlockHash, Script, Transaction, TxOut, Txid, encode,
            pset::PartiallySignedTransaction,
        },
        simplicity::hashes::Hash,
    },
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, SigMessage,
    },
};
use url::Url;

use crate::{
    NetworkAsset,
    config::{ElementsRpcConfig, UserRequestsConfig},
    db::{
        monitored_utxo::{MonitoredUtxo, MonitoredUtxoStore},
        network_asset::{NetworkAssetStore, STORM_EYE_KIND, TICK_ASSET_KIND},
    },
};

use super::{
    SigningResult,
    assets::{StormEyeContractData, storm_eye_program},
    message::{BurnExpiredUtxos, ExpiredUtxosBurned, StormEyeUtxo},
    signing::SigningError,
    user_requests::{
        STORM_EYE_TAG, UserRequestError, asset_id, find_contract_utxo, get_explicit_outpoint,
        get_optional_explicit_outpoint, output_from_utxo, pack_proof, require_explicit_utxo,
        require_preserved_output, witness_utxo,
    },
};

const MAX_TICKS_PER_BURN: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum BurningError {
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
}

#[derive(Clone)]
pub(crate) struct Burning {
    store: MonitoredUtxoStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    config: UserRequestsConfig,
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
        config: UserRequestsConfig,
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
    ) -> Result<Option<PreparedBurn>, BurningError> {
        let expired = self.store.list_expired(u32::MAX).await?;
        let groups = select_groups(expired)?;
        if groups.is_empty() {
            return Ok(None);
        }

        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(BurningError::MissingAsset(STORM_EYE_KIND))?;
        let tick_asset = self
            .assets
            .get(TICK_ASSET_KIND)
            .await?
            .ok_or(BurningError::MissingAsset(TICK_ASSET_KIND))?;
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
                return Err(BurningError::Invalid(
                    "burn reserve is not controlled by its Account".into(),
                ));
            }
            burnable_groups.push((group, reserve, account));
        }
        if burnable_groups.is_empty() {
            return Ok(None);
        }

        let storm_eye_utxo = find_contract_utxo(
            &client,
            &storm_eye.contract_script,
            Some(storm_eye.asset_id),
        )?;
        let auth_program = storm_eye_program(&storm_eye)?;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
                BurningError::Invalid("Storm Eye contract data is missing".into())
            })?)
            .map_err(|error| BurningError::Invalid(error.to_string()))?;
        let signing_branch = contract_data.storm_tree_root;

        let mut final_transaction = FinalTransaction::new();
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

        let tick_asset_id = asset_id(tick_asset.asset_id)?;
        let mut spent_utxos = vec![storm_eye_utxo.txout.clone()];
        let mut selected = Vec::new();
        let mut burn_amount = 0u64;
        for (group, _, _) in &burnable_groups {
            for tick in &group.ticks {
                let tick_utxo = get_explicit_outpoint(
                    &client,
                    Txid::from_byte_array(tick.txid),
                    tick.output_index,
                )?;
                if tick_utxo.asset() != tick_asset_id
                    || tick_utxo.amount() != tick.amount
                    || tick_utxo.txout.script_pubkey.as_bytes() != tick.script_pubkey
                {
                    return Err(BurningError::Invalid("indexed Tick UTXO changed".into()));
                }
                let program = tick_program(storm_eye.asset_id, tick)?;
                final_transaction.add_program_input(
                    PartialInput::new(tick_utxo.clone()),
                    ProgramInput::new(
                        Box::new(program.as_ref().clone()),
                        Box::new(TickAssetWitness {
                            path: Either::Right(Either::Right(0)),
                        }),
                    ),
                    RequiredSignature::None,
                );
                spent_utxos.push(tick_utxo.txout);
                selected.push((tick.txid, tick.output_index));
                burn_amount = burn_amount
                    .checked_add(tick.amount)
                    .ok_or_else(|| BurningError::Invalid("burn amount overflow".into()))?;
            }
        }

        let policy_asset = network.policy_asset();
        for (_, reserve, account) in &burnable_groups {
            final_transaction.add_program_input(
                PartialInput::new(reserve.clone()),
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
            spent_utxos.push(reserve.txout.clone());
        }

        final_transaction.add_output(output_from_utxo(&storm_eye_utxo));
        final_transaction.add_output(PartialOutput::new(
            Script::new_op_return(&[]),
            burn_amount,
            tick_asset_id,
        ));
        for (index, (_, reserve, account)) in burnable_groups.iter().enumerate() {
            let fee_share = fee_share(
                self.config.burn_transaction_fee_sats,
                burnable_groups.len(),
                index,
            )?;
            let remaining = reserve
                .amount()
                .checked_sub(fee_share)
                .filter(|remaining| *remaining > 0)
                .ok_or_else(|| {
                    BurningError::Invalid("burn reserve cannot cover its fee share".into())
                })?;
            final_transaction.add_output(PartialOutput::new(
                account.get_script_pubkey(&network),
                remaining,
                policy_asset,
            ));
        }
        final_transaction.add_output(PartialOutput::new(
            Script::new(),
            self.config.burn_transaction_fee_sats,
            policy_asset,
        ));

        let (pset, _) = final_transaction.extract_pst();
        let signing_hash = signing_hash(&pset, &storm_eye, &network)?;
        let request = BurnExpiredUtxos {
            tx: encode::serialize(&pset),
            signing_hash,
            signing_storm_tree_branch: signing_branch,
            block_height,
        };

        Ok(Some(PreparedBurn {
            request,
            final_transaction,
            pset,
            spent_utxos,
            selected,
            network,
            storm_eye,
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
        let tick_asset = self
            .assets
            .get(TICK_ASSET_KIND)
            .await?
            .ok_or(BurningError::MissingAsset(TICK_ASSET_KIND))?;
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
            &tick_asset,
            &self.network()?,
            self.config.burn_transaction_fee_sats,
        )
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
            .witness = Box::new(AuthWitness {
            path: Either::Left((
                (contract_data.storm_tree_root, contract_data.rescue_height),
                (
                    *signature.as_ref(),
                    signing.signing_storm_tree_branch,
                    pack_proof(&proof)?,
                ),
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
                    BurningError::Invalid(format!(
                        "failed to finalize burn covenant input {index}: {error}"
                    ))
                })?;
            pset.inputs_mut()[index].final_script_witness = Some(final_witness);
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
        final_tx
            .verify_tx_amt_proofs(&Secp256k1::new(), &prepared.spent_utxos)
            .map_err(|error| {
                BurningError::Invalid(format!("failed to verify burn amounts: {error}"))
            })?;
        let txid = final_tx.txid();
        let burn_amount = final_tx
            .output
            .iter()
            .filter(|output| output.script_pubkey == Script::new_op_return(&[]))
            .try_fold(0u64, |total, output| {
                output
                    .value
                    .explicit()
                    .and_then(|value| total.checked_add(value))
            })
            .ok_or_else(|| BurningError::Invalid("invalid explicit burn amount".into()))?;
        let max_burn_amount = Amount::from_sat(burn_amount).to_string_in(Denomination::Bitcoin);
        let broadcast_txid: String = self.client()?.call(
            "sendrawtransaction",
            &[
                hex::encode(encode::serialize(&final_tx)).into(),
                "0.10".into(),
                max_burn_amount.into(),
            ],
        )?;
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

        Ok(ExpiredUtxosBurned {
            txid: txid.to_byte_array(),
            utxos: prepared
                .selected
                .into_iter()
                .map(|(txid, output_index)| StormEyeUtxo { txid, output_index })
                .collect(),
            block_height,
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

fn select_groups(expired: Vec<MonitoredUtxo>) -> Result<Vec<BurnGroup>, BurningError> {
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

    let mut selected = Vec::new();
    let mut tick_count = 0usize;
    for group in grouped.into_values() {
        if tick_count + group.ticks.len() > MAX_TICKS_PER_BURN {
            break;
        }
        tick_count += group.ticks.len();
        selected.push(group);
    }
    Ok(selected)
}

fn tick_program(
    storm_eye_asset_id: [u8; 32],
    tick: &MonitoredUtxo,
) -> Result<TickAssetProgram, BurningError> {
    let mut arguments = TickAssetArguments {
        storm_eye_asset_id,
        auth_method: 0,
        auth_asset_id: [0; 32],
        auth_script_hash: [0; 32],
        auth_pubkey: [0; 32],
    };
    match tick.auth_method.as_str() {
        "asset-id-auth" => arguments.auth_asset_id = decode_32(&tick.auth_data)?,
        "scriptPubKey-auth" => {
            arguments.auth_method = 1;
            arguments.auth_script_hash = decode_32(&tick.auth_data)?;
        }
        "signature-auth" => {
            arguments.auth_method = 2;
            arguments.auth_pubkey = decode_32(&tick.auth_data)?;
        }
        _ => {
            return Err(BurningError::Invalid(
                "unsupported Tick authentication method".into(),
            ));
        }
    }
    Ok(TickAssetProgram::new(&arguments))
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
    tick_asset: &NetworkAsset,
    network: &SimplicityNetwork,
    fee: u64,
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

    let tick_asset_id = asset_id(tick_asset.asset_id)?;
    let mut expected_burn_amount = 0u64;
    for (offset, tick) in ticks.iter().enumerate() {
        let index = 1 + offset;
        let input = witness_utxo(pset, index)?;
        require_explicit_utxo(input, tick_asset_id, &tick.script_pubkey, "Tick")?;
        if input.value.explicit() != Some(tick.amount)
            || tick_program(storm_eye.asset_id, tick)?.get_script_pubkey(network)
                != input.script_pubkey
        {
            return Err(BurningError::Invalid(
                "Tick input does not match indexed state".into(),
            ));
        }
        expected_burn_amount = expected_burn_amount
            .checked_add(tick.amount)
            .ok_or_else(|| BurningError::Invalid("burn amount overflow".into()))?;
    }

    let burn_output = pset
        .outputs()
        .get(1)
        .ok_or_else(|| BurningError::Invalid("Tick burn output is missing".into()))?;
    if burn_output.asset != Some(tick_asset_id)
        || burn_output.amount != Some(expected_burn_amount)
        || burn_output.script_pubkey != Script::new_op_return(&[])
    {
        return Err(BurningError::Invalid(
            "Ticks are not aggregated into one empty OP_RETURN".into(),
        ));
    }

    let groups = select_groups(ticks)?;
    if pset.inputs().len()
        != 1 + groups.iter().map(|group| group.ticks.len()).sum::<usize>() + groups.len()
        || pset.outputs().len() != 3 + groups.len()
    {
        return Err(BurningError::Invalid(
            "burn transaction has unexpected inputs or outputs".into(),
        ));
    }

    let first_reserve_input = 1 + groups.iter().map(|group| group.ticks.len()).sum::<usize>();
    let first_reserve_output = 2;
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
    use crate::{external_api::users::UtxoAuthMethod, high_storm::issuance::IssuedTickDescriptor};

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
            burning_fee_txid: [reserve; 32],
            burning_fee_output_index: 7,
            block_height: 1,
            status: "expired".into(),
            status_block_height: 61,
            burn_txid: None,
        }
    }

    #[test]
    fn selects_ticks_from_different_users_in_deterministic_order() {
        let groups =
            select_groups(vec![tick(3, 1, 2, 4), tick(1, 1, 1, 3), tick(2, 1, 2, 4)]).unwrap();

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].reserve, ([1; 32], 7));
        assert_eq!(groups[0].ticks.len(), 1);
        assert_eq!(groups[1].reserve, ([2; 32], 7));
        assert_eq!(groups[1].ticks.len(), 2);
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
        let error = select_groups(vec![tick(1, 1, 3, 4), tick(2, 1, 3, 5)]).unwrap_err();

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
            let descriptor = IssuedTickDescriptor::from_request(
                2,
                3,
                [4; 32],
                &UtxoAuthMethod {
                    kind: kind.into(),
                    auth_data,
                },
            )
            .unwrap();
            let mut monitored = tick(1, 2, 3, 4);
            monitored.auth_method = descriptor.auth_method_name().into();
            monitored.auth_data = descriptor.auth_data.to_vec();

            assert_eq!(
                tick_program([7; 32], &monitored)
                    .unwrap()
                    .get_script_pubkey(&network),
                descriptor.tick_program([7; 32]).get_script_pubkey(&network)
            );
        }
    }
}
