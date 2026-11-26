use std::fmt::Debug;

use simplex::fuzz::proptest::prelude::{Just, any};
use simplex::fuzz::proptest::prop_oneof;
use simplex::fuzz::proptest::strategy::Strategy;
use simplex::fuzz::{Expect, Mutations, Scenario};
use simplex::simplicityhl::elements::Sequence;
use simplex::transaction::FinalTransaction;
use simplex::{FuzzMode, TestContext};

use contracts::artifacts::voucher::VoucherProgram;
use contracts::voucher::VoucherSpendPath;

use super::case::{self, PERMISSIONLESS_PATH, VOUCHER};
use super::common::fuzz::{check_scenario, check_units};
use super::common::unit;

const SEQUENCE_FLAGS: u32 = 0x8040_0000;
const TIME_FLAG: u32 = 0x0040_0000;
const UNUSED_BITS: u32 = 0x7fbf_0000;

fn check<T: Debug + 'static>(
    context: &TestContext<FuzzMode>,
    transaction: FinalTransaction,
    output_indices: impl Strategy<Value = T> + 'static,
    build: impl Fn(T) -> case::Case + 'static,
    expect: Expect,
) {
    check_scenario(
        context,
        Scenario::new(transaction),
        output_indices,
        build,
        expect,
    );
}

fn arb_non_zero_u32() -> impl Strategy<Value = u32> {
    any::<u32>().prop_filter("output index should not be zero", |index| *index != 0)
}

/// Sequences around every bit the burn reads: the disable flag, the time flag and the
/// 16-bit value around the nine-interval minimum, with the unused bits as noise.
fn arb_sequence() -> impl Strategy<Value = u32> {
    let value = prop_oneof![
        4 => 8u32..=10,
        2 => 0u32..=20,
        1 => any::<u16>().prop_map(u32::from),
        1 => Just(0xffff),
    ];
    let flags = prop_oneof![
        4 => Just(TIME_FLAG),
        1 => Just(0),
        1 => Just(SEQUENCE_FLAGS),
        1 => Just(SEQUENCE_FLAGS & !TIME_FLAG),
    ];
    let noise = prop_oneof![Just(0), any::<u32>().prop_map(|bits| bits & UNUSED_BITS)];

    prop_oneof![
        4 => (flags, noise, value).prop_map(|(flags, noise, value)| flags | noise | value),
        1 => any::<u32>(),
    ]
}

/// Versions around the accepted range `2..=0x7fffffff`.
fn arb_version() -> impl Strategy<Value = u32> {
    prop_oneof![
        4 => Just(2u32),
        1 => prop_oneof![0u32..=3, 0x7fff_fffe..=0x8000_0001u32, Just(u32::MAX)],
        1 => any::<u32>(),
    ]
}

// Burn output

#[simplex::fuzz]
fn permissionless_burn_rejects_another_output(context: TestContext<FuzzMode>) {
    check(
        &context,
        case::permissionless_transaction(),
        arb_non_zero_u32(),
        case::permissionless_burn,
        Expect::Reject,
    );
}

// Delay and version

/// The engine draws only block-based sequences and keeps the version, so these run as
/// unit cases. A second input with a valid delay must not help a voucher whose own is wrong.
#[simplex::fuzz]
fn permissionless_burn_follows_bip68(context: TestContext<FuzzMode>) {
    check_units(
        &context,
        (arb_sequence(), arb_version(), any::<bool>()),
        |(sequence, version, with_valid_neighbour)| {
            let mut case = case::permissionless_burn(0)
                .sequence(sequence)
                .version(version);
            if with_valid_neighbour {
                case = case.neighbour(Sequence::from_512_second_intervals(9));
            }

            let allowed =
                case::sequence_allows_burn(sequence) && case::version_allows_burn(version);
            let expect = if allowed {
                unit::Expect::Ok
            } else {
                unit::Expect::AssertFailed
            };

            (case, expect)
        },
    );
}

// The whole transaction

/// Everything the engine can change: amounts, assets, sequences, extra attacker inputs
/// and outputs, reordering. `expected_permissionless_burn` says when the burn still holds.
#[simplex::fuzz]
fn permissionless_burn_survives_transaction_mutations(context: TestContext<FuzzMode>) {
    let mut scenario = Scenario::new(case::permissionless_transaction());
    scenario
        .add::<VoucherProgram>(VOUCHER)
        .spends(0)
        .bind_arguments(|arguments, _| {
            *arguments = case::voucher().get_parameters().build_arguments()
        })
        .spending_path("PATH", PERMISSIONLESS_PATH)
        // The only output index the contract may accept; the engine also tries others.
        .requires_witness(|witness, _| {
            *witness = VoucherSpendPath::PermissionlessBurn {
                voucher_output_index: 0,
            }
            .build_witness();
        });

    context
        .engine(scenario)
        .mutations(Mutations::default().layout().everywhere())
        .spec(case::expected_permissionless_burn)
        .run();
}
