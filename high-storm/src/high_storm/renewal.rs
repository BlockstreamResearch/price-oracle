use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::{
    auth::derived_auth::AuthWitness,
    treasury::{
        TreasuryProgram,
        derived_treasury::{TreasuryArguments, TreasuryWitness},
    },
};
use secp256k1_zkp::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::Deserialize;
use simplex::{
    either::Either,
    provider::SimplicityNetwork,
    simplicityhl::{
        elements::{BlockHash, Script, TxOut, Txid, encode, pset::PartiallySignedTransaction},
        simplicity::hashes::Hash,
    },
    transaction::{
        FinalTransaction, PartialInput, PartialOutput, ProgramInput, RequiredSignature, UTXO,
    },
};
use storm::{PeerStatus, StormHandle};
use url::Url;

use crate::{
    NetworkAsset,
    config::ElementsRpcConfig,
    db::{
        droplet::{DropletStore, TreasuryUtxo},
        network_asset::{NetworkAssetStore, PendingStormEyeRenewal, STORM_EYE_KIND},
    },
};

use super::{
    SigningResult,
    assets::{
        StormEyeContractData, next_storm_eye_rescue_height, renewed_storm_eye,
        storm_eye_contract_data, storm_eye_program,
    },
    droplets::member_script,
    message::{NodeMessage, NodeMessageKind, RenewStormUtxos},
    signing::SigningError,
    user_requests::{STORM_EYE_TAG, asset_id, pack_proof},
    voting_execution::{
        VotingExecutionError, network, scan_storm_eye_utxos, scan_storm_eye_utxos_ignoring_mempool,
        signing_hashes, verify_voting_amounts,
    },
};

pub(crate) const RENEWAL_LEAD_BLOCKS: u64 = 30 * 24 * 60;

#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid Storm Eye renewal: {0}")]
    Invalid(String),
    #[error("network asset database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("failed to decode renewal transaction: {0}")]
    Transaction(#[from] encode::Error),
    #[error("failed to encode renewal message: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("failed to reconstruct the Storm Eye covenant: {0}")]
    Asset(#[from] super::assets::AssetError),
    #[error("failed to evaluate the Storm Eye covenant: {0}")]
    Program(#[from] simplex::program::ProgramError),
    #[error("shared transaction validation failed: {0}")]
    TransactionHelper(#[from] super::user_requests::UserRequestError),
    #[error("shared voting transaction validation failed: {0}")]
    VotingTransaction(#[from] VotingExecutionError),
    #[error("distributed signing failed: {0}")]
    Signing(#[from] SigningError),
    #[error("Storm message encoding failed: {0}")]
    StormMessage(#[from] storm::MessageError),
    #[error("Storm transport failed: {0}")]
    Storm(#[from] storm::Error),
    #[error("failed to extract final renewal transaction: {0}")]
    Pset(String),
}

pub(crate) struct PreparedRenewal {
    pub(crate) request: RenewStormUtxos,
    transaction: FinalTransaction,
    pset: PartiallySignedTransaction,
    spent_utxos: Vec<TxOut>,
    storm_eye_inputs: usize,
    old_storm_eye: NetworkAsset,
    network: SimplicityNetwork,
}

#[derive(Clone, Copy)]
struct CoordinatorFee {
    amount: u64,
    member: [u8; 32],
}

#[derive(Clone)]
pub(crate) struct Renewal {
    assets: NetworkAssetStore,
    droplets: DropletStore,
    elements_rpc: ElementsRpcConfig,
    transaction_fee_sats: u64,
    coordinator_member: [u8; 32],
    finality_confirmations: u64,
}

impl Renewal {
    pub(crate) fn new(
        assets: NetworkAssetStore,
        droplets: DropletStore,
        elements_rpc: ElementsRpcConfig,
        transaction_fee_sats: u64,
        coordinator_member: [u8; 32],
        finality_confirmations: u64,
    ) -> Self {
        Self {
            assets,
            droplets,
            elements_rpc,
            transaction_fee_sats,
            coordinator_member,
            finality_confirmations: finality_confirmations.max(1),
        }
    }

    pub(crate) async fn prepare(
        &self,
        block_height: u64,
    ) -> Result<Option<PreparedRenewal>, RenewalError> {
        if self.assets.pending_storm_eye_renewal().await?.is_some() {
            return Ok(None);
        }
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(RenewalError::MissingAsset(STORM_EYE_KIND))?;
        let data = storm_eye_contract_data(&storm_eye)?;
        if !renewal_due(block_height, data.rescue_height) {
            return Ok(None);
        }

        self.prepare_transaction(block_height, storm_eye, true)
            .await
            .map(Some)
    }

    pub(crate) async fn validate_request(
        &self,
        request: &RenewStormUtxos,
    ) -> Result<(), RenewalError> {
        if request.final_tx.is_some() {
            return Err(RenewalError::Invalid(
                "signing request unexpectedly contains a final transaction".into(),
            ));
        }
        if request.block_height != self.block_height()? {
            return Err(RenewalError::Invalid(
                "renewal does not target the current Liquid block".into(),
            ));
        }
        self.validate_transaction(request, true).await
    }

    async fn validate_transaction(
        &self,
        request: &RenewStormUtxos,
        include_mempool: bool,
    ) -> Result<(), RenewalError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(RenewalError::MissingAsset(STORM_EYE_KIND))?;
        let expected = self
            .prepare_transaction(request.block_height, storm_eye, include_mempool)
            .await?;
        if expected.request.tx != request.tx
            || expected.request.signing_hashes != request.signing_hashes
            || expected.request.block_height != request.block_height
            || expected.request.new_rescue_height != request.new_rescue_height
        {
            return Err(RenewalError::Invalid(
                "renewal transaction does not match the complete live Storm Eye inventory".into(),
            ));
        }

        Ok(())
    }

    pub(crate) fn finalize(
        &self,
        mut prepared: PreparedRenewal,
        signing: SigningResult,
        proof: storm_tree::StormTreeProof,
    ) -> Result<RenewStormUtxos, RenewalError> {
        if signing.signatures.len() != prepared.storm_eye_inputs
            || signing.signatures.len() != prepared.request.signing_hashes.len()
        {
            return Err(RenewalError::Invalid(
                "renewal requires one signature per Storm Eye input".into(),
            ));
        }
        let data = storm_eye_contract_data(&prepared.old_storm_eye)?;
        if !storm_tree::StormTree::verify_branch(
            &data.storm_tree_root,
            &signing.signing_storm_tree_branch,
            &proof,
        ) {
            return Err(RenewalError::Invalid(
                "signing branch is not included in the Storm Eye root".into(),
            ));
        }
        let branch_key = XOnlyPublicKey::from_slice(&signing.signing_storm_tree_branch)
            .map_err(|_| RenewalError::Invalid("invalid Storm Eye signing branch".into()))?;
        for (index, (signature, signing_hash)) in signing
            .signatures
            .iter()
            .zip(&prepared.request.signing_hashes)
            .enumerate()
        {
            let signature = Signature::from_slice(signature)
                .map_err(|_| RenewalError::Invalid("invalid Storm Eye signature".into()))?;
            Secp256k1::verification_only()
                .verify_schnorr(
                    &signature,
                    &Message::from_digest_slice(signing_hash)
                        .expect("the signing hash has 32 bytes"),
                    &branch_key,
                )
                .map_err(|_| {
                    RenewalError::Invalid("Storm Eye signature verification failed".into())
                })?;
            prepared.transaction.inputs_mut()[index]
                .program_input
                .as_mut()
                .expect("Storm Eye is a program input")
                .witness = Box::new(renewal_witness(
                &data,
                prepared.request.new_rescue_height,
                index as u32,
                *signature.as_ref(),
                signing.signing_storm_tree_branch,
                pack_proof(&proof)?,
            ));
        }
        for (index, input) in prepared.transaction.inputs().iter().enumerate() {
            let program_input = input
                .program_input
                .as_ref()
                .expect("all renewal inputs are covenant inputs");
            prepared.pset.inputs_mut()[index].final_script_witness =
                Some(program_input.program.finalize(
                    &prepared.pset,
                    &program_input.witness.build_witness(),
                    index,
                    &prepared.network,
                )?);
        }
        if signing_hashes(
            &prepared.pset,
            &prepared.old_storm_eye,
            &prepared.network,
            prepared.storm_eye_inputs,
        )? != prepared.request.signing_hashes
        {
            return Err(RenewalError::Invalid(
                "final renewal signing hashes changed".into(),
            ));
        }
        let final_tx = prepared
            .pset
            .extract_tx()
            .map_err(|error| RenewalError::Pset(error.to_string()))?;
        verify_voting_amounts(&final_tx, &prepared.spent_utxos)?;
        prepared.request.final_tx = Some(encode::serialize(&final_tx));
        prepared.request.signing_storm_tree_branch = signing.signing_storm_tree_branch;

        Ok(prepared.request)
    }

    pub(crate) async fn record_and_broadcast(
        &self,
        request: &RenewStormUtxos,
    ) -> Result<[u8; 32], RenewalError> {
        let (txid, final_tx) = finalized_transaction(request)?;
        let current = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(RenewalError::MissingAsset(STORM_EYE_KIND))?;
        let renewed = renewed_storm_eye(&current, &network(&self.client()?)?)?;
        if storm_eye_contract_data(&renewed)?.rescue_height != request.new_rescue_height {
            return Err(RenewalError::Invalid(
                "renewal rescue height does not match the next covenant state".into(),
            ));
        }
        let encoded_request = postcard::to_stdvec(request)?;
        let pending = PendingStormEyeRenewal {
            txid,
            request: encoded_request,
            contract_script: renewed.contract_script,
            contract_data: renewed.contract_data.ok_or_else(|| {
                RenewalError::Invalid("renewed Storm Eye contract data is missing".into())
            })?,
            block_height: request.block_height,
        };
        if let Some(existing) = self.assets.pending_storm_eye_renewal().await? {
            if existing != pending {
                return Err(RenewalError::Invalid(
                    "a different Storm Eye renewal is already pending".into(),
                ));
            }
        } else if !self.assets.record_storm_eye_renewal(&pending).await? {
            return Err(RenewalError::Invalid(
                "Storm Eye renewal state changed while recording broadcast".into(),
            ));
        }
        self.broadcast(txid, &final_tx)?;

        Ok(txid)
    }

    pub(crate) async fn observe_broadcast(
        &self,
        request: &RenewStormUtxos,
    ) -> Result<[u8; 32], RenewalError> {
        let mut signing_request = request.clone();
        signing_request.final_tx = None;
        if request.block_height > self.block_height()? {
            return Err(RenewalError::Invalid(
                "renewal targets a future Liquid block".into(),
            ));
        }
        self.validate_transaction(&signing_request, false).await?;
        let (txid, _final_tx) = finalized_transaction(request)?;
        self.record_and_broadcast(request).await?;
        Ok(txid)
    }

    pub(crate) async fn reconcile(&self) -> Result<bool, RenewalError> {
        let Some(pending) = self.assets.pending_storm_eye_renewal().await? else {
            return Ok(false);
        };
        let request: RenewStormUtxos = postcard::from_bytes(&pending.request)?;
        let (txid, final_tx) = finalized_transaction(&request)?;
        if txid != pending.txid {
            return Err(RenewalError::Invalid(
                "persisted renewal transaction id does not match its request".into(),
            ));
        }
        let Some(confirmation) = self.transaction_confirmation(txid)? else {
            self.assets.mark_storm_eye_renewal_orphaned(txid).await?;
            self.broadcast(txid, &final_tx)?;
            return Ok(false);
        };
        let tip = self.block_height()?;
        let included_at = tip
            .saturating_sub(confirmation.confirmations)
            .saturating_add(1);
        self.assets
            .mark_storm_eye_renewal_included(txid, included_at, confirmation.block_hash)
            .await?;
        if confirmation.confirmations >= self.finality_confirmations {
            if !self.assets.confirm_storm_eye_renewal(txid).await? {
                return Err(RenewalError::Invalid(
                    "pending renewal changed while confirming".into(),
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) async fn pending_request(&self) -> Result<Option<RenewStormUtxos>, RenewalError> {
        self.assets
            .pending_storm_eye_renewal()
            .await?
            .map(|pending| postcard::from_bytes(&pending.request).map_err(Into::into))
            .transpose()
    }

    async fn prepare_transaction(
        &self,
        block_height: u64,
        storm_eye: NetworkAsset,
        include_mempool: bool,
    ) -> Result<PreparedRenewal, RenewalError> {
        let data = storm_eye_contract_data(&storm_eye)?;
        if !renewal_due(block_height, data.rescue_height) {
            return Err(RenewalError::Invalid(
                "Storm Eye rescue height is outside the one-month renewal window".into(),
            ));
        }
        let new_rescue_height = next_storm_eye_rescue_height(data.rescue_height)?;
        if new_rescue_height <= data.rescue_height {
            return Err(RenewalError::Invalid(
                "renewal must push the Storm Eye rescue height forward".into(),
            ));
        }
        let client = self.client()?;
        let network = network(&client)?;
        let storm_eye_utxos = if include_mempool {
            scan_storm_eye_utxos(&client, &storm_eye)?
        } else {
            scan_storm_eye_utxos_ignoring_mempool(&client, &storm_eye)?
        };
        let treasury_utxos = self
            .select_treasury_utxos(&client, &network, include_mempool)
            .await?;
        build_transaction(
            block_height,
            new_rescue_height,
            storm_eye,
            storm_eye_utxos,
            treasury_utxos,
            network,
            CoordinatorFee {
                amount: self.transaction_fee_sats,
                member: self.coordinator_member,
            },
        )
    }

    async fn select_treasury_utxos(
        &self,
        client: &Client,
        network: &SimplicityNetwork,
        include_mempool: bool,
    ) -> Result<Vec<UTXO>, RenewalError> {
        let policy_asset = network.policy_asset();
        let mut selected = Vec::new();
        let mut total = 0u64;
        for indexed in self.droplets.treasury_utxos().await? {
            let Some(utxo) = live_treasury_utxo(client, &indexed, include_mempool)? else {
                continue;
            };
            if utxo.asset() != policy_asset || utxo.amount() != indexed.amount {
                continue;
            }
            total = total
                .checked_add(utxo.amount())
                .ok_or_else(|| RenewalError::Invalid("Treasury input overflow".into()))?;
            selected.push(utxo);
            if total >= self.transaction_fee_sats {
                return Ok(selected);
            }
        }
        Err(RenewalError::Invalid(
            "Treasury cannot cover the Storm Eye renewal fee".into(),
        ))
    }

    fn client(&self) -> Result<Client, RenewalError> {
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

    fn block_height(&self) -> Result<u64, RenewalError> {
        Ok(self.client()?.call("getblockcount", &[])?)
    }

    fn broadcast(
        &self,
        txid: [u8; 32],
        final_tx: &simplex::simplicityhl::elements::Transaction,
    ) -> Result<(), RenewalError> {
        let expected = Txid::from_byte_array(txid);
        let client = self.client()?;
        match client.call::<String>(
            "sendrawtransaction",
            &[hex::encode(encode::serialize(final_tx)).into()],
        ) {
            Ok(actual) if actual == expected.to_string() => Ok(()),
            Ok(_) => Err(RenewalError::Invalid(
                "broadcast renewal transaction id mismatch".into(),
            )),
            Err(_error) if self.require_known_transaction(txid).is_ok() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn require_known_transaction(&self, txid: [u8; 32]) -> Result<(), RenewalError> {
        let txid = Txid::from_byte_array(txid);
        let client = self.client()?;
        let mempool: Vec<String> = client.call("getrawmempool", &[])?;
        if mempool.iter().any(|known| known == &txid.to_string())
            || client
                .call::<RawTransactionInfo>(
                    "getrawtransaction",
                    &[txid.to_string().into(), true.into()],
                )
                .is_ok()
        {
            return Ok(());
        }
        Err(RenewalError::Invalid(
            "renewal transaction is absent from the local mempool and chain".into(),
        ))
    }

    fn transaction_confirmation(
        &self,
        txid: [u8; 32],
    ) -> Result<Option<RenewalConfirmation>, RenewalError> {
        let txid = Txid::from_byte_array(txid);
        let transaction = self.client()?.call::<RawTransactionInfo>(
            "getrawtransaction",
            &[txid.to_string().into(), true.into()],
        );
        let Ok(transaction) = transaction else {
            return Ok(None);
        };
        if transaction.confirmations == 0 {
            return Ok(None);
        }
        let block_hash = transaction
            .block_hash
            .as_deref()
            .ok_or_else(|| RenewalError::Invalid("confirmed renewal has no block hash".into()))?
            .parse::<BlockHash>()
            .map_err(|error| RenewalError::Invalid(error.to_string()))?
            .to_byte_array();
        Ok(Some(RenewalConfirmation {
            confirmations: transaction.confirmations,
            block_hash,
        }))
    }
}

struct RenewalConfirmation {
    confirmations: u64,
    block_hash: [u8; 32],
}

fn build_transaction(
    block_height: u64,
    new_rescue_height: u32,
    storm_eye: NetworkAsset,
    storm_eye_utxos: Vec<UTXO>,
    treasury_utxos: Vec<UTXO>,
    network: SimplicityNetwork,
    coordinator_fee: CoordinatorFee,
) -> Result<PreparedRenewal, RenewalError> {
    let data = storm_eye_contract_data(&storm_eye)?;
    if storm_eye_utxos.is_empty() {
        return Err(RenewalError::Invalid(
            "there are no live Storm Eyes to renew".into(),
        ));
    }
    let renewed_storm_eye = renewed_storm_eye(&storm_eye, &network)?;
    if storm_eye_contract_data(&renewed_storm_eye)?.rescue_height != new_rescue_height {
        return Err(RenewalError::Invalid(
            "renewal rescue height does not match the next covenant state".into(),
        ));
    }
    let auth_program = storm_eye_program(&storm_eye)?;
    let storm_eye_inputs = storm_eye_utxos.len();
    let treasury_amount = treasury_utxos.iter().try_fold(0u64, |total, utxo| {
        total
            .checked_add(utxo.amount())
            .ok_or_else(|| RenewalError::Invalid("Treasury amount overflow".into()))
    })?;
    let treasury_change = treasury_amount
        .checked_sub(coordinator_fee.amount)
        .ok_or_else(|| RenewalError::Invalid("Treasury cannot cover the renewal fee".into()))?;

    let mut transaction = FinalTransaction::new();
    for (output_index, utxo) in storm_eye_utxos.iter().enumerate() {
        transaction.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(auth_program.as_ref().clone()),
                Box::new(placeholder_witness(
                    &data,
                    new_rescue_height,
                    output_index as u32,
                )),
            ),
            RequiredSignature::witness_tagged("PATH", ["Left", "1", "0"], STORM_EYE_TAG),
        );
    }
    let treasury = TreasuryProgram::new(&TreasuryArguments {
        storm_eye_asset_id: storm_eye.asset_id,
    });
    for utxo in &treasury_utxos {
        transaction.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(treasury.as_ref().clone()),
                Box::new(TreasuryWitness {
                    storm_eye_input_index: 0,
                }),
            ),
            RequiredSignature::None,
        );
    }
    let storm_eye_asset = asset_id(storm_eye.asset_id)?;
    let renewed_script = Script::from(renewed_storm_eye.contract_script.clone());
    for utxo in &storm_eye_utxos {
        transaction.add_output(PartialOutput::new(
            renewed_script.clone(),
            utxo.amount(),
            storm_eye_asset,
        ));
    }
    if treasury_change > 0 {
        transaction.add_output(PartialOutput::new(
            treasury.get_script_pubkey(&network),
            treasury_change,
            network.policy_asset(),
        ));
    }
    transaction.add_output(PartialOutput::new(
        member_script(coordinator_fee.member),
        0,
        network.policy_asset(),
    ));
    transaction.add_output(PartialOutput::new(
        Script::new(),
        coordinator_fee.amount,
        network.policy_asset(),
    ));

    let spent_utxos = storm_eye_utxos
        .iter()
        .chain(&treasury_utxos)
        .map(|utxo| utxo.txout.clone())
        .collect();
    let (pset, _) = transaction.extract_pst();
    let request = RenewStormUtxos {
        tx: encode::serialize(&pset),
        final_tx: None,
        signing_hashes: signing_hashes(&pset, &storm_eye, &network, storm_eye_inputs)?,
        signing_storm_tree_branch: data.storm_tree_root,
        block_height,
        chain_tip: None,
        new_rescue_height,
    };

    Ok(PreparedRenewal {
        request,
        transaction,
        pset,
        spent_utxos,
        storm_eye_inputs,
        old_storm_eye: storm_eye,
        network,
    })
}

fn placeholder_witness(
    data: &StormEyeContractData,
    new_rescue_height: u32,
    output_index: u32,
) -> AuthWitness {
    renewal_witness(
        data,
        new_rescue_height,
        output_index,
        [0; 64],
        data.storm_tree_root,
        std::array::from_fn(|_| Either::Left(())),
    )
}

fn renewal_witness(
    data: &StormEyeContractData,
    new_rescue_height: u32,
    output_index: u32,
    signature: [u8; 64],
    branch: [u8; 32],
    proof: [Either<(), (bool, [u8; 32])>; storm_tree::TREE_DEPTH as usize],
) -> AuthWitness {
    AuthWitness {
        path: Either::Left((
            (data.storm_tree_root, data.rescue_height),
            (signature, branch, proof),
            Either::Right(Either::Left(Either::Right((
                new_rescue_height,
                output_index,
            )))),
        )),
    }
}

fn renewal_due(block_height: u64, rescue_height: u32) -> bool {
    block_height.saturating_add(RENEWAL_LEAD_BLOCKS) >= u64::from(rescue_height)
}

fn finalized_transaction(
    request: &RenewStormUtxos,
) -> Result<([u8; 32], simplex::simplicityhl::elements::Transaction), RenewalError> {
    let final_bytes = request
        .final_tx
        .as_deref()
        .ok_or_else(|| RenewalError::Invalid("final renewal transaction is missing".into()))?;
    let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
    let unsigned = pset
        .extract_tx()
        .map_err(|error| RenewalError::Pset(error.to_string()))?;
    let final_tx: simplex::simplicityhl::elements::Transaction = encode::deserialize(final_bytes)?;
    if final_tx.txid() != unsigned.txid() {
        return Err(RenewalError::Invalid(
            "final transaction does not match the signed renewal".into(),
        ));
    }
    Ok((final_tx.txid().to_byte_array(), final_tx))
}

fn live_treasury_utxo(
    client: &Client,
    indexed: &TreasuryUtxo,
    include_mempool: bool,
) -> Result<Option<UTXO>, RenewalError> {
    let txid = Txid::from_byte_array(indexed.txid);
    if include_mempool {
        Ok(super::user_requests::get_optional_explicit_outpoint(
            client,
            txid,
            indexed.output_index,
        )?)
    } else {
        Ok(
            super::user_requests::get_optional_explicit_outpoint_ignoring_mempool(
                client,
                txid,
                indexed.output_index,
            )?,
        )
    }
}

#[derive(Deserialize)]
struct RawTransactionInfo {
    #[serde(default)]
    confirmations: u64,
    #[serde(default, rename = "blockhash")]
    block_hash: Option<String>,
}

pub(crate) async fn announce(
    storm: &StormHandle,
    request: &RenewStormUtxos,
) -> Result<(), RenewalError> {
    let recipients = storm
        .peers()
        .await
        .into_iter()
        .filter(|peer| peer.status == PeerStatus::Active)
        .map(|peer| {
            secp256k1_zkp::PublicKey::from_slice(&peer.compressed_public_key)
                .map_err(|_| RenewalError::Invalid("invalid renewal recipient".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if recipients.is_empty() {
        return Ok(());
    }
    let message =
        NodeMessage::new(NodeMessageKind::RenewStormUtxos, None, request)?.into_storm_message()?;
    storm.send_message(message, &recipients).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_starts_exactly_one_month_before_rescue() {
        let rescue_height = 1_576_800u32;
        assert!(!renewal_due(
            u64::from(rescue_height - RENEWAL_LEAD_BLOCKS as u32 - 1),
            rescue_height,
        ));
        assert!(renewal_due(
            u64::from(rescue_height - RENEWAL_LEAD_BLOCKS as u32),
            rescue_height,
        ));
    }

    #[test]
    fn renewal_pushes_rescue_three_years_from_current_rescue_height() {
        assert_eq!(next_storm_eye_rescue_height(1_576_800).unwrap(), 3_153_600);
    }
}
