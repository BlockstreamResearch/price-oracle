//! Fuzz tests of the Storm Eye covenant's spending paths, run with `simplex test --fuzz`.
//!
//! Each test assembles a valid spend, lets the engine mutate it (amounts, assets,
//! timelocks, attacker inputs and outputs, reordering) and asks `model` what the
//! covenant must decide. On every accepted case the engine also redirects the outputs
//! the covenant locks and re-signs with an attacker key, and both must be refused.

use std::collections::BTreeSet;

use simplex::constants::DUMMY_SIGNATURE;
use simplex::either::Either;
use simplex::fuzz::proptest::collection::vec;
use simplex::fuzz::proptest::prelude::{Just, any};
use simplex::fuzz::proptest::prop_oneof;
use simplex::fuzz::proptest::sample::select;
use simplex::fuzz::proptest::strategy::Strategy;
use simplex::fuzz::{FuzzCase, FuzzProgramValues, Mutations, Scenario};
use simplex::simplicityhl::WitnessValues;
use simplex::simplicityhl::elements::{AssetId, LockTime, OutPoint, Script, Sequence, Txid};
use simplex::transaction::utxo::UTXO;
use simplex::transaction::{FinalTransaction, PartialInput, PartialOutput, ProgramInput};
use simplex::utils::hash_script;
use simplex::{FuzzMode, TestContext};

use contracts::artifacts::auth::AuthProgram;
use contracts::artifacts::auth::derived_auth::{AuthArguments, AuthWitness};
use contracts::auth::{AuthSpendPath, Branch, build_tree, witness_proof};

use super::fixtures::{MAX_MERGE_UTXOS_COUNT, MAX_SPLIT_UTXOS_COUNT, STORM_EYE_SUPPLY};
use super::model::{
    self, AUTH, Bloom, Bytes32, Kind, RESCUE_EXTENSION, Storage, program_storage, storage_slots,
};

const STORM_EYE_ASSET: [u8; 32] = [0x5e; 32];

/// The template's locktime on the rescue path; the generated rescue heights sit around it.
const RESCUE_LOCKTIME: u32 = 1_000;

/// Every template also pays a fee from a plain input after the Storm Eyes, so a single
/// swap can move a Storm Eye off the index its path expects.
const FEE_ASSET: [u8; 32] = [0xfe; 32];
const FEE: u64 = 500;

fn rescue_script() -> Script {
    Script::from(vec![0x51, 0x51])
}

fn attacker_script() -> Script {
    Script::from(vec![0x51])
}

fn change_script() -> Script {
    Script::from(vec![0x52])
}

fn arguments() -> AuthArguments {
    AuthArguments {
        max_split_utxos_count: MAX_SPLIT_UTXOS_COUNT,
        max_merge_utxos_count: MAX_MERGE_UTXOS_COUNT,
        rescue_output_script_hash: hash_script(&rescue_script()),
    }
}

// Transactions. The engine replaces each covenant input's program and witness, and each
// locked output's script, with the case's.

fn storm_eye_utxo(vout: u32, amount: u64) -> UTXO {
    UTXO::explicit(
        OutPoint::new(Txid::from_byte_array([0x5e; 32]), vout),
        Script::new(),
        amount,
        AssetId::from_byte_array(STORM_EYE_ASSET),
    )
}

/// Covenant inputs on paths 1-5, each signed by the network at `PATH`'s bloom.
fn authorized_inputs(amounts: &[u64]) -> FinalTransaction {
    let placeholder = AuthProgram::new(arguments()).as_ref().clone();
    let mut transaction = FinalTransaction::new();

    for (vout, &amount) in (0..).zip(amounts) {
        transaction.add_program_input(
            PartialInput::new(storm_eye_utxo(vout, amount)),
            ProgramInput::new(Box::new(placeholder.clone()), WitnessValues::default()),
            AuthSpendPath::required_signature(),
        );
    }
    add_fee_input(&mut transaction);

    transaction
}

/// Covenant inputs on the rescue path: unsigned, with the locktime enabled.
fn rescue_inputs(amounts: &[u64]) -> FinalTransaction {
    let mut transaction = FinalTransaction::new();

    for (vout, &amount) in (0..).zip(amounts) {
        transaction.add_input(
            PartialInput::new(storm_eye_utxo(vout, amount))
                .with_sequence(Sequence::ENABLE_LOCKTIME_NO_RBF),
            None,
        );
    }
    add_fee_input(&mut transaction);
    transaction.set_locktime(LockTime::from_height(RESCUE_LOCKTIME).expect("a block height"));

    transaction
}

fn add_fee_input(transaction: &mut FinalTransaction) {
    let utxo = UTXO::explicit(
        OutPoint::new(Txid::from_byte_array([0xfe; 32]), 0),
        Script::new(),
        FEE,
        AssetId::from_byte_array(FEE_ASSET),
    );

    transaction.add_input(PartialInput::new(utxo), None);
}

/// The Storm Eye outputs, then the fee input's change.
fn with_outputs(mut transaction: FinalTransaction, outputs: &[(Script, u64)]) -> FinalTransaction {
    for (script, amount) in outputs {
        transaction.add_output(PartialOutput::new(
            script.clone(),
            *amount,
            AssetId::from_byte_array(STORM_EYE_ASSET),
        ));
    }
    transaction.add_output(PartialOutput::new(
        change_script(),
        FEE,
        AssetId::from_byte_array(FEE_ASSET),
    ));

    transaction
}

/// `total` in `count` parts, the remainder on the last.
fn parts(total: u64, count: usize) -> Vec<u64> {
    let part = total / count as u64;
    let mut parts = vec![part; count];
    parts[count - 1] = total - part * (count as u64 - 1);
    parts
}

// Values. Every scenario generates the storage and the witness itself, so the Storm Tree
// root in storage is one the default signer's branch can prove.

fn arb_u32() -> impl Strategy<Value = u32> {
    prop_oneof![select(vec![0, 1, u32::MAX - 1, u32::MAX]), any::<u32>()]
}

fn arb_u8() -> impl Strategy<Value = u8> {
    prop_oneof![select(vec![0, 1, 2, u8::MAX]), any::<u8>()]
}

fn arb_bytes32() -> impl Strategy<Value = Bytes32> {
    prop_oneof![select(vec![[0; 32], [u8::MAX; 32]]), any::<Bytes32>()]
}

/// Heights around the template's locktime, the locktime threshold and the overflow of
/// a rescue block update.
fn arb_rescue_block_number() -> impl Strategy<Value = u32> {
    prop_oneof![
        4 => select(vec![0, RESCUE_LOCKTIME - 1, RESCUE_LOCKTIME, RESCUE_LOCKTIME + 1]),
        2 => select(vec![
            499_999_999,
            500_000_000,
            u32::MAX - RESCUE_EXTENSION,
            u32::MAX - RESCUE_EXTENSION + 1,
            u32::MAX,
        ]),
        1 => any::<u32>(),
    ]
}

/// A Storm Tree holding `signer` among up to eight other branches, with `signer`'s proof.
fn arb_network(signer: Branch) -> impl Strategy<Value = (Bytes32, Bloom)> {
    vec(any::<Branch>(), 0..=8).prop_map(move |others| {
        let mut leaves: BTreeSet<Branch> = others.into_iter().collect();
        leaves.insert(signer);
        let tree = build_tree(&leaves.into_iter().collect::<Vec<_>>());
        let proof = witness_proof(&tree, &signer).expect("a small tree fits the covenant");

        // The engine signs at `PATH`'s bloom in place of the dummy.
        (tree.root(), (DUMMY_SIGNATURE, signer, proof))
    })
}

/// The program's values: storage from the strategy, a witness whose storage is random
/// until `require_storage` sets it, so the engine also tries the wrong one.
fn values(storage: Storage, witness: impl FnOnce(Storage) -> AuthWitness) -> FuzzProgramValues {
    FuzzProgramValues {
        arguments: arguments().into(),
        witness: witness(storage).into(),
        storage: storage_slots(storage),
    }
}

/// Values of a path 1-5 spend taking `kind`.
fn authorized_values(
    signer: Branch,
    kind: impl Strategy<Value = Kind>,
) -> impl Strategy<Value = FuzzProgramValues> {
    (
        arb_network(signer),
        arb_rescue_block_number(),
        any::<Storage>(),
        kind,
    )
        .prop_map(
            |((merkle_root, bloom), rescue_block_number, claimed, kind)| {
                values((merkle_root, rescue_block_number), |_| AuthWitness {
                    path: Either::Left((claimed, bloom, kind)),
                })
            },
        )
}

/// Values of a rescue spend to `output_index`.
fn rescue_values(
    output_index: impl Strategy<Value = u32>,
) -> impl Strategy<Value = FuzzProgramValues> {
    (
        arb_bytes32(),
        arb_rescue_block_number(),
        any::<Storage>(),
        output_index,
    )
        .prop_map(
            |(merkle_root, rescue_block_number, claimed, output_index)| {
                values((merkle_root, rescue_block_number), |_| AuthWitness {
                    path: Either::Right((claimed, output_index)),
                })
            },
        )
}

/// The only storage the covenant may accept: the one it is spent with.
fn require_storage(witness: &mut AuthWitness, case: &FuzzCase<'_>) {
    let storage = program_storage(&case.program::<AuthProgram>(AUTH));

    match &mut witness.path {
        Either::Left((claimed, _, _)) | Either::Right((claimed, _)) => *claimed = storage,
    }
}

fn kind_mut(witness: &mut AuthWitness) -> &mut Kind {
    match &mut witness.path {
        Either::Left((_, _, kind)) => kind,
        Either::Right(_) => unreachable!("the scenario takes an authorized path"),
    }
}

fn signer_branch(context: &TestContext<FuzzMode>) -> Branch {
    context
        .get_default_signer()
        .get_schnorr_public_key()
        .serialize()
}

/// Everything the engine can change, on every UTXO of the transaction.
fn every_mutation() -> Mutations {
    Mutations::default().layout().everywhere()
}

/// Runs `scenario` against the model. `spendable` is false when no case may be accepted.
fn run(context: &TestContext<FuzzMode>, scenario: Scenario, spendable: bool) {
    let engine = context
        .engine(scenario)
        .mutations(every_mutation())
        .spec(model::expected);

    if spendable {
        engine.run();
    } else {
        engine.allow_unspendable().run();
    }
}

// 1. Inclusion without a storage update

#[simplex::fuzz]
fn inclusion_moves_the_whole_storm_eye_to_itself(context: TestContext<FuzzMode>) {
    let transaction = with_outputs(
        authorized_inputs(&[STORM_EYE_SUPPLY]),
        &[(Script::new(), STORM_EYE_SUPPLY)],
    );
    let kind = arb_u32().prop_map(Either::Left);

    let mut scenario = Scenario::new(transaction);
    scenario
        .add::<AuthProgram>(AUTH)
        .spends(0)
        .locks(0)
        .storage_capacity(2)
        .custom_strategy(authorized_values(signer_branch(&context), kind))
        .requires_witness(|witness, case| {
            require_storage(witness, case);
            *kind_mut(witness) = Either::Left(0);
        });

    run(&context, scenario, true);
}

// 2. Storm Tree root update

#[simplex::fuzz]
fn root_update_moves_the_whole_storm_eye_to_the_new_root(context: TestContext<FuzzMode>) {
    let transaction = with_outputs(
        authorized_inputs(&[STORM_EYE_SUPPLY]),
        &[(Script::new(), STORM_EYE_SUPPLY)],
    );
    let kind = (arb_bytes32(), arb_u32())
        .prop_map(|update| Either::Right(Either::Left(Either::Left(update))));

    let mut scenario = Scenario::new(transaction);
    scenario
        .add::<AuthProgram>(AUTH)
        .spends(0)
        .storage_capacity(2)
        .recursive(0, |auth| {
            let (_, rescue_block_number) = program_storage(auth);
            let Either::Left((_, _, Either::Right(Either::Left(Either::Left((new_root, _)))))) =
                auth.witness().path
            else {
                unreachable!("the scenario takes the root update path")
            };

            storage_slots((new_root, rescue_block_number))
        })
        .custom_strategy(authorized_values(signer_branch(&context), kind))
        .requires_witness(|witness, case| {
            require_storage(witness, case);
            if let Either::Right(Either::Left(Either::Left((_, output_index)))) = kind_mut(witness)
            {
                *output_index = 0;
            }
        });

    run(&context, scenario, true);
}

// 3. Rescue block number update

#[simplex::fuzz]
fn rescue_block_update_moves_the_rescue_height_three_years_ahead(context: TestContext<FuzzMode>) {
    let transaction = with_outputs(
        authorized_inputs(&[STORM_EYE_SUPPLY]),
        &[(Script::new(), STORM_EYE_SUPPLY)],
    );
    let kind = (arb_u32(), arb_u32())
        .prop_map(|update| Either::Right(Either::Left(Either::Right(update))));

    let mut scenario = Scenario::new(transaction);
    scenario
        .add::<AuthProgram>(AUTH)
        .spends(0)
        .storage_capacity(2)
        .recursive(0, |auth| {
            let (merkle_root, _) = program_storage(auth);
            let Either::Left((_, _, Either::Right(Either::Left(Either::Right((new_height, _)))))) =
                auth.witness().path
            else {
                unreachable!("the scenario takes the rescue block update path")
            };

            storage_slots((merkle_root, new_height))
        })
        .custom_strategy(authorized_values(signer_branch(&context), kind))
        .requires_witness(|witness, case| {
            let (_, rescue_block_number) = program_storage(&case.program::<AuthProgram>(AUTH));
            require_storage(witness, case);

            if let Either::Right(Either::Left(Either::Right((new_height, output_index)))) =
                kind_mut(witness)
            {
                // Past `u32::MAX` no height is right, and the generated one stays.
                if let Some(extended) = rescue_block_number.checked_add(RESCUE_EXTENSION) {
                    *new_height = extended;
                }
                *output_index = 0;
            }
        });

    run(&context, scenario, true);
}

// 4. Split

/// Input 0 split evenly into `count` outputs, and the witness asking for `count`.
fn split(context: &TestContext<FuzzMode>, count: u8) {
    let outputs: Vec<(Script, u64)> = parts(STORM_EYE_SUPPLY, count.into())
        .into_iter()
        .map(|amount| (Script::new(), amount))
        .collect();
    let transaction = with_outputs(authorized_inputs(&[STORM_EYE_SUPPLY]), &outputs);
    let kind = arb_u8().prop_map(|count| Either::Right(Either::Right(Either::Left(count))));

    let mut scenario = Scenario::new(transaction);
    let mut auth = scenario
        .add::<AuthProgram>(AUTH)
        .spends(0)
        .storage_capacity(2)
        .custom_strategy(authorized_values(signer_branch(context), kind))
        .requires_witness(move |witness, case| {
            require_storage(witness, case);
            *kind_mut(witness) = Either::Right(Either::Right(Either::Left(count)));
        });
    for output in 0..count.into() {
        auth = auth.locks(output);
    }

    run(
        context,
        scenario,
        count > 1 && count < MAX_SPLIT_UTXOS_COUNT,
    );
}

/// The smallest and the largest split, `2..MAX_SPLIT_UTXOS_COUNT` being exclusive.
#[simplex::fuzz]
fn split_spreads_the_whole_storm_eye_over_its_outputs(context: TestContext<FuzzMode>) {
    split(&context, 2);
    split(&context, MAX_SPLIT_UTXOS_COUNT - 1);
}

#[simplex::fuzz]
fn split_refuses_one_output_and_the_maximum(context: TestContext<FuzzMode>) {
    split(&context, 1);
    split(&context, MAX_SPLIT_UTXOS_COUNT);
}

// 5. Merge

/// `count` covenant inputs in uneven amounts into output 0, and the witness asking for `count`.
fn merge(context: &TestContext<FuzzMode>, count: u8) {
    let amounts: Vec<u64> = (1..=u64::from(count)).map(|n| n * 1_000 + n).collect();
    let transaction = with_outputs(
        authorized_inputs(&amounts),
        &[(Script::new(), amounts.iter().sum())],
    );
    let kind = arb_u8().prop_map(|count| Either::Right(Either::Right(Either::Right(count))));

    let mut scenario = Scenario::new(transaction);
    let mut auth = scenario
        .add::<AuthProgram>(AUTH)
        .locks(0)
        .storage_capacity(2)
        .custom_strategy(authorized_values(signer_branch(context), kind))
        .requires_witness(move |witness, case| {
            require_storage(witness, case);
            *kind_mut(witness) = Either::Right(Either::Right(Either::Right(count)));
        });
    for input in 0..count.into() {
        auth = auth.spends(input);
    }

    run(
        context,
        scenario,
        count > 1 && count < MAX_MERGE_UTXOS_COUNT,
    );
}

/// The smallest and the largest merge, `2..MAX_MERGE_UTXOS_COUNT` being exclusive.
#[simplex::fuzz]
fn merge_gathers_every_storm_eye_into_output_zero(context: TestContext<FuzzMode>) {
    merge(&context, 2);
    merge(&context, MAX_MERGE_UTXOS_COUNT - 1);
}

#[simplex::fuzz]
fn merge_refuses_one_input_and_the_maximum(context: TestContext<FuzzMode>) {
    merge(&context, 1);
    merge(&context, MAX_MERGE_UTXOS_COUNT);
}

// 6. Rescue

#[simplex::fuzz]
fn rescue_pays_the_rescue_script_from_the_rescue_height(context: TestContext<FuzzMode>) {
    let transaction = with_outputs(
        rescue_inputs(&[STORM_EYE_SUPPLY]),
        &[(rescue_script(), STORM_EYE_SUPPLY)],
    );

    let mut scenario = Scenario::new(transaction);
    scenario
        .add::<AuthProgram>(AUTH)
        .spends(0)
        .storage_capacity(2)
        .custom_strategy(rescue_values(arb_u32()))
        .requires_witness(|witness, case| {
            require_storage(witness, case);
            if let Either::Right((_, output_index)) = &mut witness.path {
                *output_index = 0;
            }
        });

    run(&context, scenario, true);
}

// Two Storm Eyes, one output

/// Two rescued Storm Eyes name the same rescue output, which holds only one of them; the
/// other goes to an attacker output. The model refuses it.
#[simplex::fuzz]
#[ignore = "auth.simf does not tie the named output to the input, so both rescues pass"]
fn two_rescues_cannot_share_one_output(context: TestContext<FuzzMode>) {
    let transaction = with_outputs(
        rescue_inputs(&[STORM_EYE_SUPPLY, STORM_EYE_SUPPLY]),
        &[
            (rescue_script(), STORM_EYE_SUPPLY),
            (attacker_script(), STORM_EYE_SUPPLY),
        ],
    );

    let mut scenario = Scenario::new(transaction);
    scenario
        .add::<AuthProgram>(AUTH)
        .spends(0)
        .spends(1)
        .storage_capacity(2)
        .custom_strategy(rescue_values(Just(0)))
        .requires_witness(require_storage);

    run(&context, scenario, false);
}
