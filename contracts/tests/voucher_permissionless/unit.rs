use simplex::simplicityhl::elements::Sequence;

use super::case;
use super::common::case::DispatchCase;
use super::common::unit::Expect::{AssertFailed, PrunedBranch};

/// Bits 31 and 22 of a sequence: relative lock disabled, and time-based.
const DISABLE_FLAG: u32 = 0x8000_0000;
const TIME_FLAG: u32 = 0x0040_0000;

/// The sequence bits BIP68 leaves free: neither flag nor the 16-bit value.
const UNUSED_BITS: u32 = 0x7fbf_0000;

// Delay

#[test]
fn accepts_the_minimum_delay() {
    case::permissionless_burn(0).accepts();
}

#[test]
fn accepts_the_longest_delay() {
    case::permissionless_burn(0)
        .sequence(TIME_FLAG | 0xffff)
        .accepts();
}

#[test]
fn rejects_one_interval_short() {
    case::permissionless_burn(0)
        .sequence(TIME_FLAG | 8)
        .rejects(AssertFailed);
}

#[test]
fn rejects_a_delay_in_blocks() {
    case::permissionless_burn(0)
        .sequence(9)
        .rejects(AssertFailed);
}

#[test]
fn rejects_a_disabled_relative_lock() {
    case::permissionless_burn(0)
        .sequence(DISABLE_FLAG | TIME_FLAG | 9)
        .rejects(AssertFailed);
}

#[test]
fn ignores_the_unused_sequence_bits() {
    case::permissionless_burn(0)
        .sequence(UNUSED_BITS | TIME_FLAG | 9)
        .accepts();
}

/// The contract reads its own sequence, so another input's valid delay does not count.
#[test]
fn rejects_a_delay_lent_by_another_input() {
    case::permissionless_burn(0)
        .sequence(TIME_FLAG | 8)
        .neighbour(Sequence::from_512_second_intervals(9))
        .rejects(AssertFailed);
}

// Version

#[test]
fn rejects_version_1() {
    case::permissionless_burn(0)
        .version(1)
        .rejects(AssertFailed);
}

#[test]
fn accepts_the_highest_version() {
    case::permissionless_burn(0).version(0x7fff_ffff).accepts();
}

#[test]
fn rejects_a_negative_version() {
    case::permissionless_burn(0)
        .version(0x8000_0000)
        .rejects(AssertFailed);
}

// Burn output

#[test]
fn rejects_a_burn_tagged_for_another_input() {
    case::permissionless_burn(0)
        .burn_tagged_for(1)
        .rejects(AssertFailed);
}

#[test]
fn rejects_a_burn_of_another_amount() {
    case::permissionless_burn(0)
        .burn_amount(super::common::unit::AMOUNT - 1)
        .rejects(AssertFailed);
}

#[test]
fn rejects_an_output_that_is_not_a_burn() {
    case::permissionless_burn(0)
        .without_burn()
        .rejects(PrunedBranch);
}

#[test]
fn rejects_a_missing_output() {
    case::permissionless_burn(u32::MAX).rejects(PrunedBranch);
}
