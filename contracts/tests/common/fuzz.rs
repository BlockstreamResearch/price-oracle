use std::fmt::Debug;

use simplex::fuzz::proptest::strategy::Strategy;
use simplex::fuzz::proptest::test_runner::{TestCaseError, TestRunner};
use simplex::fuzz::{Expect, FuzzProgramValues, Scenario};
use simplex::simplicityhl::{Arguments, WitnessValues};
use simplex::transaction::{FinalTransaction, PartialInput, ProgramInput, ProgramSignature};
use simplex::{FuzzMode, TestContext};

use super::case::DispatchCase;
use super::unit::{self, Signatures};

const DEFAULT_SPENT_INPUT: usize = 0;

pub fn accepts<C, T>(
    context: &TestContext<FuzzMode>,
    inputs: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> C + 'static,
) where
    C: DispatchCase,
    T: Debug + 'static,
{
    check(context, inputs, build, None, Expect::Accept);
}

pub fn rejects<C, T>(
    context: &TestContext<FuzzMode>,
    inputs: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> C + 'static,
) where
    C: DispatchCase,
    T: Debug + 'static,
{
    check(context, inputs, build, None, Expect::Reject);
}

/// As [`accepts`], with the engine signing at `signature` for the default signer. The
/// engine then also checks that an attacker's key or a replayed signature is refused.
pub fn accepts_signed<C, T>(
    context: &TestContext<FuzzMode>,
    inputs: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> C + 'static,
    signature: ProgramSignature,
) where
    C: DispatchCase,
    T: Debug + 'static,
{
    check(context, inputs, build, Some(signature), Expect::Accept);
}

/// As [`rejects`], with a valid signature at `signature`, so the rejection comes from
/// something other than the signature.
pub fn rejects_signed<C, T>(
    context: &TestContext<FuzzMode>,
    inputs: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> C + 'static,
    signature: ProgramSignature,
) where
    C: DispatchCase,
    T: Debug + 'static,
{
    check(context, inputs, build, Some(signature), Expect::Reject);
}

pub fn check<C, T>(
    context: &TestContext<FuzzMode>,
    inputs: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> C + 'static,
    signature: Option<ProgramSignature>,
    expect: Expect,
) where
    C: DispatchCase,
    T: Debug + 'static,
{
    let scenario = Scenario::new(spending_transaction::<C>(signature));

    check_scenario(context, scenario, inputs, build, expect);
}

/// Runs the cases on `scenario`'s transaction, the program spending its input 0.
pub fn check_scenario<C, T>(
    context: &TestContext<FuzzMode>,
    mut scenario: Scenario,
    inputs: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> C + 'static,
    expect: Expect,
) where
    C: DispatchCase,
    T: Debug + 'static,
{
    let arguments: Arguments = C::arguments().into();
    let values = inputs.prop_map(move |input| {
        FuzzProgramValues::from((arguments.clone(), build(input).into_witness().into()))
    });

    scenario
        .add::<C::Program>(C::PROGRAM_NAME)
        .spends(DEFAULT_SPENT_INPUT)
        .custom_strategy(values);

    run_scenario(context, scenario, expect);
}

pub fn run_scenario(context: &TestContext<FuzzMode>, scenario: Scenario, expect: Expect) {
    let engine = context.engine(scenario).spec(move |_| expect);

    // Negative scenarios deliberately generate no accepting witness.
    let engine = if expect == Expect::Reject {
        engine.allow_unspendable()
    } else {
        engine
    };

    engine.run();
}

/// Runs unit cases under the fuzz config, for what the engine cannot vary: each input
/// builds a case and the outcome it must have in its own unit transaction.
pub fn check_units<C, T>(
    context: &TestContext<FuzzMode>,
    inputs: impl Strategy<Value = T>,
    build: impl Fn(T) -> (C, unit::Expect),
) where
    C: DispatchCase,
    T: Debug,
{
    let mut runner = TestRunner::new(context.get_fuzz_config().clone());

    runner
        .run(&inputs, |input| {
            let (case, expect) = build(input);
            let tx = case.unit_tx();
            let result = unit::run_in(&C::program(), case.into_witness(), Signatures::Checked, tx);

            match unit::outcome(result) {
                Ok(actual) if actual == expect => Ok(()),
                Ok(actual) => Err(TestCaseError::fail(format!(
                    "expected {expect:?}, the program ended with {actual:?}"
                ))),
                Err(error) => Err(TestCaseError::fail(format!(
                    "the case failed before the program ran: {error}"
                ))),
            }
        })
        .unwrap_or_else(|error| panic!("{error}"));
}

/// `Scenario::default()`'s one input, carrying `signature` when the case verifies one.
fn spending_transaction<C: DispatchCase>(signature: Option<ProgramSignature>) -> FinalTransaction {
    let mut transaction = FinalTransaction::new();

    match signature {
        // The engine replaces the program and the witness with the case's.
        Some(signature) => {
            transaction.add_program_input(
                PartialInput::default(),
                ProgramInput::new(Box::new(C::program()), WitnessValues::default()),
                Some(signature),
            );
        }
        None => {
            transaction.add_input(PartialInput::default(), None);
        }
    }

    transaction
}
