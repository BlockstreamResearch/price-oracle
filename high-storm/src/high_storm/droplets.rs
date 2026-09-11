use std::str::FromStr;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::{
    auth::derived_auth::AuthWitness,
    treasury::{
        TreasuryProgram,
        derived_treasury::{TreasuryArguments, TreasuryWitness},
    },
};
use secp256k1_zkp::{Message, PublicKey, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use simplex::simplicityhl::elements::{opcodes, script::Instruction};
use simplex::{
    either::Either,
    program::{ProgramTrait, WitnessTrait},
    provider::SimplicityNetwork,
    simplicityhl::{
        elements::{
            Address, AddressParams, AssetId, BlockHash, Script, TxOut, Txid, encode,
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
    config::ElementsRpcConfig,
    db::{
        droplet::{DropletBalance, DropletExchangeRequest, DropletStore, TreasuryUtxo},
        network_asset::{NetworkAssetStore, STORM_EYE_KIND},
    },
};

use super::{
    SigningResult,
    assets::{StormEyeContractData, storm_eye_program},
    message::ExchangeRewards,
    signing::SigningError,
    user_requests::{
        STORM_EYE_TAG, StormEyePool, asset_id, find_contract_utxo, get_optional_explicit_outpoint,
        is_fully_explicit_output, output_from_utxo, pack_proof, require_explicit_utxo,
        require_preserved_output, witness_utxo,
    },
};

const MEMBER_MAGIC: [u8; 2] = *b"OD";
const MEMBER_VERSION: u8 = 1;
const MEMBER_DATA_LEN: usize = 35;

#[derive(Debug, thiserror::Error)]
pub enum DropletsError {
    #[error("Droplets database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("network asset is not initialized: {0}")]
    MissingAsset(&'static str),
    #[error("invalid Droplets exchange: {0}")]
    Invalid(String),
    #[error("failed to decode Droplets exchange transaction: {0}")]
    Transaction(#[from] encode::Error),
    #[error("Elements RPC operation failed: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("invalid Elements RPC URL: {0}")]
    RpcUrl(#[from] url::ParseError),
    #[error("failed to reconstruct network covenant: {0}")]
    Asset(#[from] super::assets::AssetError),
    #[error("failed to evaluate network covenant: {0}")]
    Program(#[from] simplex::program::ProgramError),
    #[error("shared transaction validation failed: {0}")]
    TransactionHelper(#[from] super::user_requests::UserRequestError),
    #[error("distributed signing failed: {0}")]
    Signing(#[from] SigningError),
    #[error("failed to extract final Droplets exchange transaction: {0}")]
    Pset(String),
}

impl DropletsError {
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Signing(SigningError::NoAvailableBranch | SigningError::SigningFailed)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedExchange {
    pub(crate) member: [u8; 32],
    pub(crate) amount: u64,
}

#[derive(Clone)]
pub(crate) struct Droplets {
    store: DropletStore,
    assets: NetworkAssetStore,
    elements_rpc: ElementsRpcConfig,
    transaction_fee_sats: u64,
}

impl Droplets {
    pub(crate) fn new(
        store: DropletStore,
        assets: NetworkAssetStore,
        elements_rpc: ElementsRpcConfig,
        transaction_fee_sats: u64,
    ) -> Self {
        Self {
            store,
            assets,
            elements_rpc,
            transaction_fee_sats,
        }
    }

    pub(crate) async fn validate_request(
        &self,
        request: &ExchangeRewards,
        expected_leader: [u8; 33],
    ) -> Result<ValidatedExchange, DropletsError> {
        self.validate_transaction(&request.tx, request.signing_hash, expected_leader)
            .await
    }

    pub(crate) fn transaction_fee_sats(&self) -> u64 {
        self.transaction_fee_sats
    }

    pub(crate) async fn state(
        &self,
        member: [u8; 32],
    ) -> Result<(Option<DropletBalance>, Option<DropletExchangeRequest>), DropletsError> {
        Ok((
            self.store.balance(member).await?,
            self.store.exchange_request(member).await?,
        ))
    }

    pub(crate) async fn history(
        &self,
        member: [u8; 32],
    ) -> Result<Vec<DropletExchangeRequest>, DropletsError> {
        Ok(self.store.exchange_history(member).await?)
    }

    pub(crate) async fn queue_exchange(
        &self,
        transaction: &[u8],
        signing_hash: [u8; 32],
        expected_member: [u8; 33],
        block_height: u64,
    ) -> Result<DropletExchangeRequest, DropletsError> {
        let exchange = self
            .validate_transaction(transaction, signing_hash, expected_member)
            .await?;
        let balance = self
            .store
            .balance(exchange.member)
            .await?
            .ok_or_else(|| DropletsError::Invalid("network member has no Droplets".into()))?;
        if balance.exchange_locked {
            return Err(DropletsError::Invalid(
                "Droplets exchange is already in progress".into(),
            ));
        }

        self.store
            .queue_exchange(exchange.member, transaction, signing_hash, block_height)
            .await?;
        self.store
            .exchange_request(exchange.member)
            .await?
            .ok_or_else(|| DropletsError::Invalid("queued exchange disappeared".into()))
    }

    pub(crate) async fn prepare_and_queue_exchange(
        &self,
        amount: u64,
        destination: &str,
        expected_member: [u8; 33],
        block_height: u64,
    ) -> Result<DropletExchangeRequest, DropletsError> {
        if amount == 0 {
            return Err(DropletsError::Invalid(
                "exchange amount must be positive".into(),
            ));
        }
        let required = amount
            .checked_add(self.transaction_fee_sats)
            .ok_or_else(|| DropletsError::Invalid("exchange amount overflow".into()))?;
        Address::from_str(destination)
            .map_err(|_| DropletsError::Invalid("invalid destination address".into()))?;

        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(DropletsError::MissingAsset(STORM_EYE_KIND))?;
        let indexed_utxos = self.store.treasury_utxos().await?;
        let (transaction, signing_hash) = self.prepare_exchange_transaction(
            amount,
            destination,
            expected_member,
            required,
            &storm_eye,
            &indexed_utxos,
        )?;
        self.queue_exchange(&transaction, signing_hash, expected_member, block_height)
            .await
    }

    fn prepare_exchange_transaction(
        &self,
        amount: u64,
        destination: &str,
        expected_member: [u8; 33],
        required: u64,
        storm_eye: &NetworkAsset,
        indexed_utxos: &[TreasuryUtxo],
    ) -> Result<(Vec<u8>, [u8; 32]), DropletsError> {
        let client = self.client()?;
        let network = self.network(&client)?;
        let destination = Address::from_str(destination)
            .map_err(|_| DropletsError::Invalid("invalid destination address".into()))?;
        if destination.params != address_params(&network) {
            return Err(DropletsError::Invalid(
                "destination address belongs to a different network".into(),
            ));
        }
        if destination.is_blinded() {
            return Err(DropletsError::Invalid(
                "destination must be an unconfidential address".into(),
            ));
        }

        let policy_asset = network.policy_asset();
        let treasury = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        });
        let treasury_script = treasury.get_script_pubkey(&network);
        let mut selected = Vec::new();
        let mut selected_amount = 0u64;
        for indexed in indexed_utxos {
            let txid = Txid::from_byte_array(indexed.txid);
            let Some(utxo) = get_optional_explicit_outpoint(&client, txid, indexed.output_index)?
            else {
                continue;
            };
            if utxo.asset() != policy_asset
                || utxo.amount() != indexed.amount
                || utxo.txout.script_pubkey != treasury_script
            {
                return Err(DropletsError::Invalid(
                    "indexed Treasury UTXO does not match Elements".into(),
                ));
            }
            selected_amount = selected_amount
                .checked_add(utxo.amount())
                .ok_or_else(|| DropletsError::Invalid("Treasury input overflow".into()))?;
            selected.push(utxo);
            if selected_amount >= required {
                break;
            }
        }
        if selected_amount < required {
            return Err(DropletsError::Invalid(
                "Treasury does not have enough available LBTC".into(),
            ));
        }

        let storm_eye_utxo = find_contract_utxo(
            &client,
            &storm_eye.contract_script,
            Some(storm_eye.asset_id),
            StormEyePool::NetworkLeader(0),
        )?;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
                DropletsError::Invalid("Storm Eye contract data is missing".into())
            })?)
            .map_err(|error| DropletsError::Invalid(error.to_string()))?;
        let auth_program = storm_eye_program(storm_eye)?;
        let mut transaction = FinalTransaction::new();
        transaction.add_program_input(
            PartialInput::new(storm_eye_utxo.clone()),
            ProgramInput::new(
                Box::new(auth_program.as_ref().clone()),
                Box::new(AuthWitness {
                    path: Either::Left((
                        (contract_data.storm_tree_root, contract_data.rescue_height),
                        (
                            [0; 64],
                            contract_data.storm_tree_root,
                            std::array::from_fn(|_| Either::Left(())),
                        ),
                        Either::Left(0),
                    )),
                }),
            ),
            RequiredSignature::witness_tagged("PATH", ["Left", "1", "0"], STORM_EYE_TAG),
        );
        for utxo in &selected {
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

        transaction.add_output(output_from_utxo(&storm_eye_utxo));
        transaction.add_output(PartialOutput::new(
            destination.script_pubkey(),
            amount,
            policy_asset,
        ));
        let change = selected_amount - required;
        if change > 0 {
            transaction.add_output(PartialOutput::new(treasury_script, change, policy_asset));
        }
        let member = PublicKey::from_slice(&expected_member)
            .map_err(|_| DropletsError::Invalid("invalid local public key".into()))?
            .x_only_public_key()
            .0
            .serialize();
        transaction.add_output(PartialOutput::new(member_script(member), 0, policy_asset));
        transaction.add_output(PartialOutput::new(
            Script::new(),
            self.transaction_fee_sats,
            policy_asset,
        ));

        let (pset, _) = transaction.extract_pst();
        let signing_hash = signing_hash(&pset, storm_eye, &network)?;
        Ok((encode::serialize(&pset), signing_hash))
    }

    pub(crate) async fn complete_request(
        &self,
        request: &DropletExchangeRequest,
        txid: [u8; 32],
    ) -> Result<(), DropletsError> {
        self.store.complete_exchange_request(request, txid).await?;
        Ok(())
    }

    pub(crate) async fn fail_request(
        &self,
        request: &DropletExchangeRequest,
        error: &str,
    ) -> Result<(), DropletsError> {
        self.store.fail_exchange_request(request, error).await?;
        Ok(())
    }

    pub(crate) async fn observe_broadcast(
        &self,
        request: &ExchangeRewards,
        expected_leader: [u8; 33],
    ) -> Result<(), DropletsError> {
        let exchange = self
            .validate_transaction(&request.tx, request.signing_hash, expected_leader)
            .await?;
        let final_bytes = request
            .final_tx
            .as_deref()
            .ok_or_else(|| DropletsError::Invalid("final transaction is missing".into()))?;
        let pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
        let unsigned_tx = pset
            .extract_tx()
            .map_err(|error| DropletsError::Pset(error.to_string()))?;
        let final_tx: simplex::simplicityhl::elements::Transaction =
            encode::deserialize(final_bytes)?;
        if final_tx.txid() != unsigned_tx.txid() {
            return Err(DropletsError::Invalid(
                "final transaction does not match the exchange request".into(),
            ));
        }

        let client = self.client()?;
        let mempool: Vec<String> = client.call("getrawmempool", &[])?;
        if !mempool
            .iter()
            .any(|txid| txid == &final_tx.txid().to_string())
        {
            let txid: String =
                client.call("sendrawtransaction", &[hex::encode(final_bytes).into()])?;
            if txid != final_tx.txid().to_string() {
                return Err(DropletsError::Invalid(
                    "completion transaction id mismatch".into(),
                ));
            }
        }
        if !self
            .store
            .update_locked_transaction(exchange.member, &request.tx, final_bytes)
            .await?
        {
            return Err(DropletsError::Invalid(
                "matching Droplets exchange is not locked locally".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn validate_transaction(
        &self,
        transaction: &[u8],
        signing_hash: [u8; 32],
        expected_leader: [u8; 33],
    ) -> Result<ValidatedExchange, DropletsError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(DropletsError::MissingAsset(STORM_EYE_KIND))?;
        let pset: PartiallySignedTransaction = encode::deserialize(transaction)?;
        let client = self.client()?;
        for (index, input) in pset.inputs().iter().enumerate() {
            let live = previous_output(&client, input.previous_txid, input.previous_output_index)?;
            if witness_utxo(&pset, index)? != &live {
                return Err(DropletsError::Invalid(format!(
                    "input {index} does not match the live UTXO"
                )));
            }
        }

        let network = self.network(&client)?;
        let validated =
            validate_layout(&pset, signing_hash, expected_leader, &storm_eye, &network)?;
        let balance = self
            .store
            .balance(validated.member)
            .await?
            .ok_or_else(|| DropletsError::Invalid("network leader has no Droplets".into()))?;
        if balance.amount < validated.amount {
            return Err(DropletsError::Invalid(
                "Droplets exchange exceeds the network leader balance".into(),
            ));
        }
        Ok(validated)
    }

    pub(crate) async fn lock_exchange(
        &self,
        exchange: &ValidatedExchange,
        block_height: u64,
        transaction: &[u8],
    ) -> Result<(), DropletsError> {
        if !self
            .store
            .lock_exchange(exchange.member, exchange.amount, block_height, transaction)
            .await?
        {
            return Err(DropletsError::Invalid(
                "Droplets balance is insufficient or already locked".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn unlock_exchange(
        &self,
        member: [u8; 32],
        block_height: u64,
    ) -> Result<(), DropletsError> {
        self.store.unlock_exchange(member, block_height).await?;
        Ok(())
    }

    pub(crate) async fn finalize_and_broadcast(
        &self,
        request: &ExchangeRewards,
        signing: SigningResult,
        proof: storm_tree::StormTreeProof,
        exchange: &ValidatedExchange,
    ) -> Result<([u8; 32], Vec<u8>), DropletsError> {
        let storm_eye = self
            .assets
            .get(STORM_EYE_KIND)
            .await?
            .ok_or(DropletsError::MissingAsset(STORM_EYE_KIND))?;
        let network = self.network(&self.client()?)?;
        let contract_data: StormEyeContractData =
            postcard::from_bytes(storm_eye.contract_data.as_deref().ok_or_else(|| {
                DropletsError::Invalid("Storm Eye contract data is missing".into())
            })?)
            .map_err(|error| DropletsError::Invalid(error.to_string()))?;
        if !storm_tree::StormTree::verify_branch(
            &contract_data.storm_tree_root,
            &signing.signing_storm_tree_branch,
            &proof,
        ) {
            return Err(DropletsError::Invalid(
                "signing branch is not included in the Storm Eye root".into(),
            ));
        }
        let signature = *signing
            .signatures
            .first()
            .ok_or_else(|| DropletsError::Invalid("missing Storm Eye signature".into()))?;
        let branch_key = XOnlyPublicKey::from_slice(&signing.signing_storm_tree_branch)
            .map_err(|_| DropletsError::Invalid("invalid Storm Eye signing branch".into()))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| DropletsError::Invalid("invalid Storm Eye signature".into()))?;
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest_slice(&request.signing_hash)
                    .expect("the signing hash has 32 bytes"),
                &branch_key,
            )
            .map_err(|_| {
                DropletsError::Invalid("Storm Eye signature verification failed".into())
            })?;

        let mut pset: PartiallySignedTransaction = encode::deserialize(&request.tx)?;
        let auth_program = storm_eye_program(&storm_eye)?;
        let auth_witness = AuthWitness {
            path: Either::Left((
                (contract_data.storm_tree_root, contract_data.rescue_height),
                (
                    *signature.as_ref(),
                    signing.signing_storm_tree_branch,
                    pack_proof(&proof)?,
                ),
                Either::Left(0),
            )),
        };
        pset.inputs_mut()[0].final_script_witness = Some(auth_program.as_ref().finalize(
            &pset,
            &auth_witness.build_witness(),
            0,
            &network,
        )?);
        let treasury = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        });
        for index in 1..pset.inputs().len() {
            pset.inputs_mut()[index].final_script_witness = Some(
                treasury.as_ref().finalize(
                    &pset,
                    &TreasuryWitness {
                        storm_eye_input_index: 0,
                    }
                    .build_witness(),
                    index,
                    &network,
                )?,
            );
        }
        if signing_hash(&pset, &storm_eye, &network)? != request.signing_hash {
            return Err(DropletsError::Invalid(
                "final exchange signing hash changed".into(),
            ));
        }
        let final_tx = pset
            .extract_tx()
            .map_err(|error| DropletsError::Pset(error.to_string()))?;
        let client = self.client()?;
        let spent_utxos = final_tx
            .input
            .iter()
            .map(|input| {
                previous_output(
                    &client,
                    input.previous_output.txid,
                    input.previous_output.vout,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        verify_exchange_amounts(&final_tx, &spent_utxos)?;
        let final_bytes = encode::serialize(&final_tx);
        if !self
            .store
            .update_locked_transaction(exchange.member, &request.tx, &final_bytes)
            .await?
        {
            return Err(DropletsError::Invalid(
                "Droplets exchange lock disappeared before broadcast".into(),
            ));
        }
        let txid = final_tx.txid();
        let broadcast_txid: String =
            client.call("sendrawtransaction", &[hex::encode(&final_bytes).into()])?;
        if broadcast_txid != txid.to_string() {
            return Err(DropletsError::Invalid(
                "broadcast transaction id mismatch".into(),
            ));
        }
        Ok((txid.to_byte_array(), final_bytes))
    }

    fn client(&self) -> Result<Client, DropletsError> {
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

    fn network(&self, client: &Client) -> Result<SimplicityNetwork, DropletsError> {
        #[derive(serde::Deserialize)]
        struct ChainInfo {
            chain: String,
        }
        #[derive(serde::Deserialize)]
        struct SidechainInfo {
            pegged_asset: String,
        }

        let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
        match chain.chain.as_str() {
            "liquidv1" => Ok(SimplicityNetwork::Liquid),
            "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
            "elementsregtest" => {
                let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
                let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
                Ok(SimplicityNetwork::ElementsCustom {
                    policy_asset: AssetId::from_str(&sidechain.pegged_asset).map_err(|_| {
                        DropletsError::Invalid("invalid regtest policy asset".into())
                    })?,
                    genesis_hash: BlockHash::from_str(&genesis_hash).map_err(|_| {
                        DropletsError::Invalid("invalid regtest genesis hash".into())
                    })?,
                })
            }
            _ => Err(DropletsError::Invalid(format!(
                "unsupported Elements chain '{}'",
                chain.chain
            ))),
        }
    }
}

pub(crate) fn member_script(member: [u8; 32]) -> Script {
    let mut data = Vec::with_capacity(MEMBER_DATA_LEN);
    data.extend_from_slice(&MEMBER_MAGIC);
    data.push(MEMBER_VERSION);
    data.extend_from_slice(&member);
    Script::new_op_return(&data)
}

fn address_params(network: &SimplicityNetwork) -> &'static AddressParams {
    match network {
        SimplicityNetwork::Liquid => &AddressParams::LIQUID,
        SimplicityNetwork::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
        SimplicityNetwork::ElementsRegtest { .. } | SimplicityNetwork::ElementsCustom { .. } => {
            &AddressParams::ELEMENTS
        }
    }
}

pub(crate) fn member_from_script(script: &Script) -> Option<[u8; 32]> {
    let mut instructions = script.instructions_minimal();
    if !matches!(
        instructions.next(),
        Some(Ok(Instruction::Op(opcodes::all::OP_RETURN)))
    ) {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
        return None;
    };
    if instructions.next().is_some()
        || data.len() != MEMBER_DATA_LEN
        || data[..2] != MEMBER_MAGIC
        || data[2] != MEMBER_VERSION
    {
        return None;
    }
    data[3..].try_into().ok()
}

pub(crate) fn exchange_recipient_amount(transaction: &[u8]) -> Result<u64, DropletsError> {
    let pset: PartiallySignedTransaction = encode::deserialize(transaction)?;
    let treasury_script = witness_utxo(&pset, 1)?.script_pubkey.clone();
    let mut recipient_amount = 0u64;
    for output in pset.outputs().iter().skip(1) {
        if output.script_pubkey.is_empty()
            || output.script_pubkey == treasury_script
            || member_from_script(&output.script_pubkey).is_some()
        {
            continue;
        }
        recipient_amount = recipient_amount
            .checked_add(output.amount.ok_or_else(|| {
                DropletsError::Invalid("exchange recipient amount is missing".into())
            })?)
            .ok_or_else(|| DropletsError::Invalid("recipient amount overflow".into()))?;
    }
    if recipient_amount == 0 {
        return Err(DropletsError::Invalid(
            "exchange has no recipient amount".into(),
        ));
    }
    Ok(recipient_amount)
}

fn validate_layout(
    pset: &PartiallySignedTransaction,
    request_signing_hash: [u8; 32],
    expected_leader: [u8; 33],
    storm_eye: &crate::NetworkAsset,
    network: &SimplicityNetwork,
) -> Result<ValidatedExchange, DropletsError> {
    if pset.inputs().len() < 2 || pset.outputs().len() < 3 {
        return Err(DropletsError::Invalid("transaction is incomplete".into()));
    }
    let storm_eye_input = witness_utxo(pset, 0)?;
    require_explicit_utxo(
        storm_eye_input,
        asset_id(storm_eye.asset_id)?,
        &storm_eye.contract_script,
        "Storm Eye",
    )?;
    require_preserved_output(pset, 0, storm_eye_input, "Storm Eye")?;

    let policy_asset = network.policy_asset();
    let treasury_script = TreasuryProgram::new(&TreasuryArguments {
        storm_eye_asset_id: storm_eye.asset_id,
    })
    .get_script_pubkey(network);
    let mut treasury_inputs = 0u64;
    for index in 1..pset.inputs().len() {
        let input = witness_utxo(pset, index)?;
        if input.script_pubkey != treasury_script {
            return Err(DropletsError::Invalid(
                "transaction contains a non-Treasury funding input".into(),
            ));
        }
        let secrets = txout_secrets(input)?;
        if secrets.asset != policy_asset {
            return Err(DropletsError::Invalid("Treasury input is not LBTC".into()));
        }
        treasury_inputs = treasury_inputs
            .checked_add(secrets.value)
            .ok_or_else(|| DropletsError::Invalid("Treasury input overflow".into()))?;
    }

    let expected_member = PublicKey::from_slice(&expected_leader)
        .map_err(|_| DropletsError::Invalid("invalid leader public key".into()))?
        .x_only_public_key()
        .0
        .serialize();
    let mut marker_count = 0usize;
    let mut treasury_return = 0u64;
    let mut total_outputs = 0u64;
    let mut recipient_amount = 0u64;
    for output in pset.outputs().iter().skip(1) {
        if !is_fully_explicit_output(output) {
            return Err(DropletsError::Invalid(
                "exchange LBTC output must be explicit".into(),
            ));
        }
        if output.asset != Some(policy_asset) {
            return Err(DropletsError::Invalid("exchange output is not LBTC".into()));
        }
        let amount = output
            .amount
            .ok_or_else(|| DropletsError::Invalid("exchange output amount is missing".into()))?;
        total_outputs = total_outputs
            .checked_add(amount)
            .ok_or_else(|| DropletsError::Invalid("exchange output overflow".into()))?;
        if let Some(member) = member_from_script(&output.script_pubkey) {
            marker_count += 1;
            if member != expected_member || amount != 0 {
                return Err(DropletsError::Invalid(
                    "exchange member marker is invalid".into(),
                ));
            }
        } else if output.script_pubkey == treasury_script {
            treasury_return = treasury_return
                .checked_add(amount)
                .ok_or_else(|| DropletsError::Invalid("Treasury change overflow".into()))?;
        } else if !output.script_pubkey.is_empty() {
            recipient_amount = recipient_amount
                .checked_add(amount)
                .ok_or_else(|| DropletsError::Invalid("recipient amount overflow".into()))?;
        }
    }
    if marker_count != 1 || recipient_amount == 0 || total_outputs != treasury_inputs {
        return Err(DropletsError::Invalid(
            "exchange outputs do not conserve Treasury value or identify one recipient".into(),
        ));
    }
    let amount = treasury_inputs
        .checked_sub(treasury_return)
        .filter(|amount| *amount > 0)
        .ok_or_else(|| DropletsError::Invalid("exchange removes no Treasury value".into()))?;
    if signing_hash(pset, storm_eye, network)? != request_signing_hash {
        return Err(DropletsError::Invalid(
            "exchange signing hash mismatch".into(),
        ));
    }
    Ok(ValidatedExchange {
        member: expected_member,
        amount,
    })
}

fn txout_secrets(
    output: &TxOut,
) -> Result<simplex::simplicityhl::elements::TxOutSecrets, DropletsError> {
    let asset = output
        .asset
        .explicit()
        .ok_or_else(|| DropletsError::Invalid("Treasury input asset must be explicit".into()))?;
    let value = output
        .value
        .explicit()
        .ok_or_else(|| DropletsError::Invalid("Treasury input value must be explicit".into()))?;
    Ok(simplex::simplicityhl::elements::TxOutSecrets::new(
        asset,
        simplex::simplicityhl::elements::confidential::AssetBlindingFactor::zero(),
        value,
        simplex::simplicityhl::elements::confidential::ValueBlindingFactor::zero(),
    ))
}

fn signing_hash(
    pset: &PartiallySignedTransaction,
    storm_eye: &crate::NetworkAsset,
    network: &SimplicityNetwork,
) -> Result<[u8; 32], DropletsError> {
    let program = storm_eye_program(storm_eye)?;
    let env = program.as_ref().get_env(pset, 0, network)?;
    Ok(SigMessage::Tagged(STORM_EYE_TAG.to_string())
        .digest(env.c_tx_env().sighash_all().to_byte_array()))
}

fn previous_output(
    client: &Client,
    txid: simplex::simplicityhl::elements::Txid,
    vout: u32,
) -> Result<TxOut, DropletsError> {
    let encoded: String = client.call(
        "getrawtransaction",
        &[txid.to_string().into(), false.into()],
    )?;
    let transaction: simplex::simplicityhl::elements::Transaction =
        encode::deserialize(&hex::decode(encoded).map_err(|_| {
            DropletsError::Invalid("invalid previous transaction encoding".into())
        })?)?;
    transaction
        .output
        .get(vout as usize)
        .cloned()
        .ok_or_else(|| DropletsError::Invalid("previous transaction output is missing".into()))
}

fn verify_exchange_amounts(
    transaction: &simplex::simplicityhl::elements::Transaction,
    spent_utxos: &[TxOut],
) -> Result<(), DropletsError> {
    let mut verifiable = transaction.clone();
    verifiable.output.retain(|output| {
        output.value.explicit() != Some(0) || !output.script_pubkey.is_provably_unspendable()
    });
    verifiable
        .verify_tx_amt_proofs(&Secp256k1::new(), spent_utxos)
        .map_err(|error| {
            DropletsError::Invalid(format!("failed to verify exchange amounts: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use crate::NetworkAsset;
    use secp256k1_zkp::SecretKey;
    use simplex::simplicityhl::elements::{
        LockTime, OutPoint, Transaction, TxIn, TxOut, TxOutSecrets, Txid,
        confidential::{self, AssetBlindingFactor, ValueBlindingFactor},
    };

    use super::*;

    #[test]
    fn retries_temporary_signer_branch_failures() {
        assert!(DropletsError::Signing(SigningError::NoAvailableBranch).is_retryable());
        assert!(DropletsError::Signing(SigningError::SigningFailed).is_retryable());
    }

    #[test]
    fn does_not_retry_invalid_exchange_requests() {
        assert!(!DropletsError::Invalid("invalid transaction".into()).is_retryable());
    }

    fn exchange_fixture() -> (
        PartiallySignedTransaction,
        NetworkAsset,
        SimplicityNetwork,
        [u8; 33],
    ) {
        let policy_asset = AssetId::from_byte_array([8; 32]);
        let network = SimplicityNetwork::ElementsCustom {
            policy_asset,
            genesis_hash: BlockHash::from_byte_array([6; 32]),
        };
        let contract_data = StormEyeContractData {
            storm_tree_root: [3; 32],
            rescue_height: 100,
            rescue_output_script_hash: [4; 32],
        };
        let mut storm_eye = NetworkAsset {
            kind: STORM_EYE_KIND.into(),
            name: "Storm Eye".into(),
            asset_id: [7; 32],
            reissuance_token_id: None,
            entropy: Some([1; 32]),
            issuance_txid: [2; 32],
            contract_script: vec![],
            contract_data: Some(postcard::to_stdvec(&contract_data).unwrap()),
            supply: 10_000,
            created_at_block: 1,
        };
        storm_eye.contract_script = storm_eye_program(&storm_eye)
            .unwrap()
            .get_script_pubkey(&network)
            .into_bytes();
        let treasury_script = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        })
        .get_script_pubkey(&network);
        let leader = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[1; 32]).unwrap(),
        );
        let member = leader.x_only_public_key().0.serialize();
        let explicit_output = |asset, value, script_pubkey| TxOut {
            asset: confidential::Asset::Explicit(asset),
            value: confidential::Value::Explicit(value),
            nonce: confidential::Nonce::Null,
            script_pubkey,
            witness: Default::default(),
        };
        let storm_eye_utxo = explicit_output(
            AssetId::from_byte_array(storm_eye.asset_id),
            1,
            Script::from(storm_eye.contract_script.clone()),
        );
        let treasury_utxo = explicit_output(policy_asset, 1_000, treasury_script.clone());
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([10; 32]),
                        vout: 0,
                    },
                    ..Default::default()
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([11; 32]),
                        vout: 1,
                    },
                    ..Default::default()
                },
            ],
            output: vec![
                storm_eye_utxo.clone(),
                explicit_output(policy_asset, 600, Script::from(vec![0x51])),
                explicit_output(policy_asset, 400, treasury_script),
                explicit_output(policy_asset, 0, member_script(member)),
            ],
        };
        let mut pset = PartiallySignedTransaction::from_tx(transaction);
        pset.inputs_mut()[0].witness_utxo = Some(storm_eye_utxo);
        pset.inputs_mut()[1].witness_utxo = Some(treasury_utxo);

        (pset, storm_eye, network, leader.serialize())
    }

    #[test]
    fn member_marker_round_trips() {
        let member = [7; 32];

        assert_eq!(member_from_script(&member_script(member)), Some(member));
        assert_eq!(member_from_script(&Script::new_op_return(b"other")), None);
    }

    #[test]
    fn rejects_malformed_member_markers() {
        let mut wrong_version = Vec::from(MEMBER_MAGIC);
        wrong_version.push(MEMBER_VERSION + 1);
        wrong_version.extend_from_slice(&[7; 32]);
        let mut trailing_instruction = member_script([7; 32]).into_bytes();
        trailing_instruction.push(0x00);

        assert_eq!(
            member_from_script(&Script::new_op_return(&wrong_version)),
            None
        );
        assert_eq!(
            member_from_script(&Script::new_op_return(&wrong_version[..34])),
            None
        );
        assert_eq!(
            member_from_script(&Script::from(trailing_instruction)),
            None
        );
    }

    #[test]
    fn validates_exchange_with_treasury_change() {
        let (pset, storm_eye, network, leader) = exchange_fixture();
        let request_hash = signing_hash(&pset, &storm_eye, &network).unwrap();

        let exchange = validate_layout(&pset, request_hash, leader, &storm_eye, &network).unwrap();

        assert_eq!(exchange.amount, 600);
        assert_eq!(
            exchange.member,
            PublicKey::from_slice(&leader)
                .unwrap()
                .x_only_public_key()
                .0
                .serialize()
        );
    }

    #[test]
    fn reads_recipient_amount_from_queued_exchange() {
        let (pset, _, _, _) = exchange_fixture();

        assert_eq!(
            exchange_recipient_amount(&encode::serialize(&pset)).unwrap(),
            600
        );
    }

    #[test]
    fn verifies_exchange_amounts_with_zero_value_member_marker() {
        let (pset, _, _, _) = exchange_fixture();
        let spent_utxos = pset
            .inputs()
            .iter()
            .map(|input| input.witness_utxo.clone().unwrap())
            .collect::<Vec<_>>();
        let transaction = pset.extract_tx().unwrap();

        verify_exchange_amounts(&transaction, &spent_utxos).unwrap();
    }

    #[test]
    fn rejects_exchange_for_a_different_member() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        pset.outputs_mut()[3].script_pubkey = member_script([9; 32]);

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("member marker is invalid"));
    }

    #[test]
    fn rejects_exchange_without_one_member_marker() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        pset.outputs_mut()[3].script_pubkey = Script::new_op_return(b"unrelated");

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("identify one recipient"));
    }

    #[test]
    fn rejects_non_lbtc_exchange_outputs() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        pset.outputs_mut()[1].asset = Some(AssetId::from_byte_array([9; 32]));

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("output is not LBTC"));
    }

    #[test]
    fn rejects_confidential_exchange_outputs_with_disclosed_metadata() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        let policy_asset = network.policy_asset();
        let secp = Secp256k1::new();
        let blinding_public_key =
            PublicKey::from_secret_key(&secp, &super::super::assets::treasury_blinding_secret());
        let input_secrets = [TxOutSecrets::new(
            policy_asset,
            AssetBlindingFactor::zero(),
            600,
            ValueBlindingFactor::zero(),
        )];
        let (confidential_output, _, _, _) = TxOut::new_last_confidential(
            &mut secp256k1_zkp::rand::thread_rng(),
            &secp,
            600,
            policy_asset,
            Script::from(vec![0x51]),
            blinding_public_key,
            &input_secrets,
            &[],
        )
        .unwrap();
        let mut output =
            simplex::simplicityhl::elements::pset::Output::from_txout(confidential_output);
        output.asset = Some(policy_asset);
        output.amount = Some(600);
        pset.outputs_mut()[1] = output;

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("LBTC output must be explicit"));
    }

    #[test]
    fn rejects_non_treasury_funding_inputs() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        pset.inputs_mut()[1]
            .witness_utxo
            .as_mut()
            .unwrap()
            .script_pubkey = Script::from(vec![0x51]);

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("non-Treasury funding input"));
    }

    #[test]
    fn rejects_confidential_treasury_funding_inputs() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        let treasury_utxo = pset.inputs()[1].witness_utxo.as_ref().unwrap();
        let policy_asset = treasury_utxo.asset.explicit().unwrap();
        let treasury_script = treasury_utxo.script_pubkey.clone();
        let secp = Secp256k1::new();
        let blinding_public_key =
            PublicKey::from_secret_key(&secp, &super::super::assets::treasury_blinding_secret());
        let input_secrets = [TxOutSecrets::new(
            policy_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        )];
        let (confidential_utxo, _, _, _) = TxOut::new_last_confidential(
            &mut secp256k1_zkp::rand::thread_rng(),
            &secp,
            1_000,
            policy_asset,
            treasury_script,
            blinding_public_key,
            &input_secrets,
            &[],
        )
        .unwrap();
        pset.inputs_mut()[1].witness_utxo = Some(confidential_utxo);

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("input asset must be explicit"));
    }

    #[test]
    fn rejects_exchange_that_does_not_conserve_value() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        pset.outputs_mut()[1].amount = Some(601);

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("do not conserve Treasury value"));
    }

    #[test]
    fn rejects_exchange_without_a_recipient() {
        let (mut pset, storm_eye, network, leader) = exchange_fixture();
        pset.outputs_mut()[1].script_pubkey = Script::new();

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("identify one recipient"));
    }

    #[test]
    fn rejects_exchange_with_an_invalid_leader_key() {
        let (pset, storm_eye, network, _) = exchange_fixture();

        let error = validate_layout(&pset, [0; 32], [0; 33], &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("invalid leader public key"));
    }

    #[test]
    fn rejects_exchange_with_a_tampered_signing_hash() {
        let (pset, storm_eye, network, leader) = exchange_fixture();

        let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

        assert!(error.to_string().contains("signing hash mismatch"));
    }
}
