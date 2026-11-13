use std::str::FromStr;

use bitcoincore_rpc::{Client, RpcApi};
use contracts::artifacts::{
    auth::{AuthProgram, derived_auth::AuthWitness},
    treasury::{TreasuryProgram, derived_treasury::TreasuryWitness},
};
use serde::Deserialize;
use simplex::{
    either::Either,
    program::ProgramError,
    provider::SimplicityNetwork,
    simplicityhl::elements::{
        AssetId, BlockHash, Script, opcodes, pset::PartiallySignedTransaction, script::Instruction,
    },
    transaction::{FinalTransaction, PartialInput, ProgramInput, RequiredSignature, UTXO},
};

use super::{
    assets::StormEyeContractData,
    user_requests::{PackedStormTreeProof, STORM_EYE_TAG},
};

#[derive(Deserialize)]
pub(crate) struct ChainInfo {
    pub(crate) chain: String,
}

#[derive(Deserialize)]
pub(crate) struct SidechainInfo {
    pub(crate) pegged_asset: String,
}

#[derive(Deserialize)]
pub(crate) struct RawTransactionInfo {
    #[serde(default)]
    pub(crate) confirmations: u64,
    #[serde(default, rename = "blockhash")]
    pub(crate) block_hash: Option<String>,
}

/// Adds each of `utxos` as a Treasury input that defers to the Storm Eye at input 0.
/// The spend arm of a Storm Eye witness, as `AuthKind` in `auth.simf`.
pub(crate) type StormEyeSpend =
    Either<u32, Either<Either<([u8; 32], u32), (u32, u32)>, Either<u8, u8>>>;

/// A Storm Eye witness for the authorized spend `kind`, signed by `branch`.
pub(crate) fn storm_eye_witness(
    data: &StormEyeContractData,
    signature: [u8; 64],
    branch: [u8; 32],
    proof: PackedStormTreeProof,
    kind: StormEyeSpend,
) -> AuthWitness {
    AuthWitness {
        path: Either::Left((
            (data.storm_tree_root, data.rescue_height),
            (signature, branch, proof),
            kind,
        )),
    }
}

/// The witness a Storm Eye input carries until it is signed: a zero
/// signature, the root as branch and an empty proof.
pub(crate) fn placeholder_storm_eye_witness(
    data: &StormEyeContractData,
    kind: StormEyeSpend,
) -> AuthWitness {
    storm_eye_witness(
        data,
        [0; 64],
        data.storm_tree_root,
        std::array::from_fn(|_| Either::Left(())),
        kind,
    )
}

/// Adds a Storm Eye input signed through the tagged `PATH` witness.
pub(crate) fn add_storm_eye_input(
    transaction: &mut FinalTransaction,
    utxo: &UTXO,
    program: &AuthProgram,
    witness: AuthWitness,
) {
    transaction.add_program_input(
        PartialInput::new(utxo.clone()),
        ProgramInput::new(Box::new(program.as_ref().clone()), witness),
        RequiredSignature::witness_tagged("PATH", ["Left", "1", "0"], STORM_EYE_TAG),
    );
}

pub(crate) fn add_treasury_inputs<'a>(
    transaction: &mut FinalTransaction,
    treasury: &TreasuryProgram,
    utxos: impl IntoIterator<Item = &'a UTXO>,
) {
    for utxo in utxos {
        transaction.add_program_input(
            PartialInput::new(utxo.clone()),
            ProgramInput::new(
                Box::new(treasury.as_ref().clone()),
                TreasuryWitness {
                    storm_eye_input_index: 0,
                },
            ),
            RequiredSignature::None,
        );
    }
}

/// Sets the final witness of every input of `pset` from the program that
/// `transaction` spends it with; `all_programs` is the panic message for an
/// input without one.
pub(crate) fn finalize_program_inputs(
    pset: &mut PartiallySignedTransaction,
    transaction: &FinalTransaction,
    network: &SimplicityNetwork,
    all_programs: &str,
) -> Result<(), ProgramError> {
    for (index, input) in transaction.inputs().iter().enumerate() {
        let program_input = input.program_input.as_ref().expect(all_programs);
        pset.inputs_mut()[index].final_script_witness = Some(
            program_input
                .program
                .finalize(pset, &program_input.witness, index, network)?
                .into(),
        );
    }
    Ok(())
}

/// The data of `script` when it is exactly `OP_RETURN <one data push>`.
pub(crate) fn op_return_data(script: &Script) -> Option<&[u8]> {
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
    instructions.next().is_none().then_some(data)
}

/// The network of the Elements node behind `client`. A regtest policy asset or
/// genesis hash that does not parse becomes `invalid(message)`, and any chain
/// but Liquid, Liquid Testnet and regtest becomes `unsupported(chain)`.
pub(crate) fn network<E: From<bitcoincore_rpc::Error>>(
    client: &Client,
    invalid: fn(String) -> E,
    unsupported: impl FnOnce(String) -> E,
) -> Result<SimplicityNetwork, E> {
    let chain: ChainInfo = client.call("getblockchaininfo", &[])?;
    match chain.chain.as_str() {
        "liquidv1" => Ok(SimplicityNetwork::Liquid),
        "liquidtestnet" => Ok(SimplicityNetwork::LiquidTestnet),
        "elementsregtest" => {
            let sidechain: SidechainInfo = client.call("getsidechaininfo", &[])?;
            let genesis_hash: String = client.call("getblockhash", &[0.into()])?;
            Ok(SimplicityNetwork::ElementsCustom {
                policy_asset: AssetId::from_str(&sidechain.pegged_asset)
                    .map_err(|_| invalid("invalid regtest policy asset".into()))?,
                genesis_hash: BlockHash::from_str(&genesis_hash)
                    .map_err(|_| invalid("invalid regtest genesis hash".into()))?,
            })
        }
        _ => Err(unsupported(chain.chain)),
    }
}
