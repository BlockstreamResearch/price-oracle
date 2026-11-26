//! Runs a program on one input of an in-memory transaction, without a node.

use simplex::program::{Program, ProgramError, ProgramTrait};
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::WitnessValues;
use simplex::simplicityhl::elements::{AssetId, OutPoint, Script, Sequence, Txid};
use simplex::simplicityhl::simplicity::bit_machine::ExecutionError;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, ProgramInput, UTXO};

/// What the program's input holds, in the network's policy asset.
pub const AMOUNT: u64 = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// The spend succeeds.
    Ok,
    /// A failed `assert!` or jet in the contract.
    AssertFailed,
    /// Execution reached a pruned branch (e.g. `unwrap(None)`).
    PrunedBranch,
}

/// Whether signature checks run. `Skipped` passes every `bip_0340_verify`, for cases that
/// test what surrounds a signature without signing the unit transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signatures {
    Checked,
    Skipped,
}

/// What a case changes in the unit transaction. By default it spends the program's
/// input alone into one `OP_TRUE` output.
#[derive(Clone, Debug, Default)]
pub struct UnitTx {
    /// Outputs placed before the default one, so the first sits at index 0.
    pub leading_outputs: Vec<PartialOutput>,
    /// Inputs placed after the program's.
    pub trailing_inputs: Vec<PartialInput>,
    /// The program input's sequence.
    pub sequence: Option<Sequence>,
    /// The transaction version.
    pub version: Option<u32>,
}

pub fn asset() -> AssetId {
    SimplicityNetwork::default_regtest().policy_asset()
}

pub fn run_in(
    program: &Program,
    witness: impl Into<WitnessValues>,
    signatures: Signatures,
    tx: UnitTx,
) -> Result<(), ProgramError> {
    let network = SimplicityNetwork::default_regtest();
    let witness = witness.into();
    let version = tx.version;

    let (mut pst, _) = unit_transaction(program, witness.clone(), network, tx)
        .extract_pst()
        .expect("the unit transaction is explicit");
    if let Some(version) = version {
        pst.global.tx_data.version = version;
    }

    match signatures {
        Signatures::Checked => program.finalize(&pst, &witness, 0, &network),
        Signatures::Skipped => program.finalize_unverified(&pst, &witness, 0, &network),
    }
    .map(|_| ())
}

/// A case that fails before the program runs (e.g. a malformed witness) panics instead of
/// matching `expect`.
#[track_caller]
pub fn check_in(
    program: &Program,
    witness: impl Into<WitnessValues>,
    signatures: Signatures,
    tx: UnitTx,
    expect: Expect,
) {
    match outcome(run_in(program, witness, signatures, tx)) {
        Ok(actual) => assert_eq!(actual, expect, "unexpected program outcome"),
        Err(error) => panic!("the case failed before the program ran: {error}"),
    }
}

/// The outcome of a run, or the error when the case failed before the program ran.
///
/// # Errors
/// Returns the [`ProgramError`] that is not an execution failure of the program.
pub fn outcome(result: Result<(), ProgramError>) -> Result<Expect, ProgramError> {
    let execution = match result {
        Ok(()) => return Ok(Expect::Ok),
        Err(ProgramError::Pruning(execution)) => execution,
        Err(other) => return Err(other),
    };

    match execution {
        ExecutionError::JetFailed(_) => Ok(Expect::AssertFailed),
        ExecutionError::ReachedPrunedBranch(_) => Ok(Expect::PrunedBranch),
        other => Err(ProgramError::Pruning(other)),
    }
}

fn unit_transaction(
    program: &Program,
    witness: WitnessValues,
    network: SimplicityNetwork,
    tx: UnitTx,
) -> FinalTransaction {
    let asset = network.policy_asset();
    let utxo = UTXO::explicit(
        OutPoint::new(Txid::from_byte_array([0xf0; 32]), 0),
        program.get_script_pubkey(&network),
        AMOUNT,
        asset,
    );
    let input = match tx.sequence {
        Some(sequence) => PartialInput::new(utxo).with_sequence(sequence),
        None => PartialInput::new(utxo),
    };

    let mut ft = FinalTransaction::new();
    ft.add_program_input(
        input,
        ProgramInput::new(Box::new(program.clone()), witness),
        None,
    );
    for input in tx.trailing_inputs {
        ft.add_input(input, None);
    }
    for output in tx.leading_outputs {
        ft.add_output(output);
    }
    ft.add_output(PartialOutput::new(Script::from(vec![0x51]), AMOUNT, asset));

    ft
}
