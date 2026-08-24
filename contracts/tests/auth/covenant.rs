//! Turns a Storm Tree inclusion proof into the shape `auth.simf` can verify.

use monotree::hasher::Sha2;
use monotree::{Hash, Hasher};
use thiserror::Error;

use storm_tree::{StormTreeBranch, StormTreeProof, StormTreeRoot};

/// Slot widths, in the order the covenant hashes them. Selected slots, taken in order,
/// reproduce the cut contiguously.
///
/// The total is 111 and every length is `32a + 16b + (0..15)` with `a, b <= 2`, so the
/// reachable lengths tile `0..=111` without gaps and greedy largest-first selection always
/// lands exactly. Two slots of each wide size are needed: one 16 would only reach 95, and
/// three 32s with no 16 would leave holes at 16..31, 48..63 and 80..95.
pub const SLOT_SIZES: [usize; 8] = [32, 32, 16, 16, 8, 4, 2, 1];

/// Number of slots, and the width of a [`CutMask`].
pub const SLOTS: usize = SLOT_SIZES.len();

/// The longest cut monotree can emit.
///
/// A Hard node is `32 + (4 + path_L) + (4 + path_R) + 32 + 1` bytes with each path at most
/// 32, so at most 137; a cut drops one 32-byte hash. Soft nodes top out at 37.
pub const MAX_CUT: usize = 105;

/// Which slots carry part of this cut. The chosen set spells the cut's length in
/// [`SLOT_SIZES`].
pub type CutMask = [bool; SLOTS];

/// A cut split across [`SLOT_SIZES`], in the Rust types the generated witness expects.
///
/// Unused slots are zero and are never hashed; they only occupy witness space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CutSlots {
    /// 32 bytes.
    pub wide_a: [u8; 32],
    /// 32 bytes.
    pub wide_b: [u8; 32],
    /// 16 bytes.
    pub half_a: u128,
    /// 16 bytes.
    pub half_b: u128,
    /// 8 bytes.
    pub eight: u64,
    /// 4 bytes.
    pub four: u32,
    /// 2 bytes.
    pub two: u16,
    /// 1 byte.
    pub one: u8,
}

/// One level of the covenant's fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// Which child the proof descended into, and therefore where the running hash goes:
    /// `false` puts it at the front, `true` just before the node's trailing type flag.
    pub right: bool,
    /// The cut, split across the slots.
    pub slots: CutSlots,
    /// Which slots are in use.
    pub mask: CutMask,
}

/// A padded fold step. `None` is an unused level, which leaves the accumulator alone.
pub type PaddedStep = Option<ProofStep>;

/// Errors from packing a proof for on-chain verification.
#[derive(Debug, Error)]
pub enum CovenantError {
    /// A cut was longer than the slots can hold, which the node format should forbid.
    #[error("cut of {actual} bytes exceeds the {capacity}-byte slot capacity")]
    CutTooLong {
        /// Length of the offending cut.
        actual: usize,
        /// Total width of all slots.
        capacity: usize,
    },
    /// The proof needs more levels than the covenant was compiled for.
    #[error("proof of {actual} steps exceeds the covenant's depth of {depth}")]
    ProofTooDeep {
        /// Number of steps in the proof.
        actual: usize,
        /// Fixed depth the covenant folds over.
        depth: usize,
    },
}

/// Splits one cut across [`SLOT_SIZES`].
///
/// # Errors
/// Returns [`CovenantError::CutTooLong`] if the cut does not fit in the slots.
pub fn pack_cut(cut: &[u8]) -> Result<(CutSlots, CutMask), CovenantError> {
    let capacity: usize = SLOT_SIZES.iter().sum();
    if cut.len() > capacity {
        return Err(CovenantError::CutTooLong {
            actual: cut.len(),
            capacity,
        });
    }

    // Greedy largest-first is exact for these widths, so the selected slots sum to the
    // cut's length and, taken in order, hold its bytes contiguously.
    let mut remainder = cut.len();
    let mut mask = [false; SLOTS];
    for (index, size) in SLOT_SIZES.iter().enumerate() {
        if remainder >= *size {
            mask[index] = true;
            remainder -= size;
        }
    }
    debug_assert_eq!(remainder, 0, "slot widths must decompose every length exactly");

    let mut pieces: [&[u8]; SLOTS] = [&[]; SLOTS];
    let mut offset = 0;
    for (index, size) in SLOT_SIZES.iter().enumerate() {
        if mask[index] {
            pieces[index] = &cut[offset..offset + size];
            offset += size;
        }
    }
    debug_assert_eq!(offset, cut.len(), "every byte of the cut must land in a slot");

    Ok((
        CutSlots {
            wide_a: wide(pieces[0]),
            wide_b: wide(pieces[1]),
            half_a: u128::from_be_bytes(fixed(pieces[2])),
            half_b: u128::from_be_bytes(fixed(pieces[3])),
            eight: u64::from_be_bytes(fixed(pieces[4])),
            four: u32::from_be_bytes(fixed(pieces[5])),
            two: u16::from_be_bytes(fixed(pieces[6])),
            one: pieces[7].first().copied().unwrap_or(0),
        },
        mask,
    ))
}

/// Packs a proof into exactly `depth` fold steps, reversed and padded.
///
/// The reversal happens here, not in the covenant: monotree stores a proof root-first
/// while `array_fold` walks left to right. The trailing `0x01` type flag is also stripped
/// from right-hand cuts, because the covenant re-adds it as a constant.
///
/// # Errors
/// Returns [`CovenantError::ProofTooDeep`] if the proof needs more than `depth` levels, or
/// [`CovenantError::CutTooLong`] if a cut does not fit the slots.
pub fn pack_proof(
    proof: &StormTreeProof,
    depth: usize,
) -> Result<Vec<PaddedStep>, CovenantError> {
    if proof.len() > depth {
        return Err(CovenantError::ProofTooDeep {
            actual: proof.len(),
            depth,
        });
    }

    let mut steps: Vec<PaddedStep> = Vec::with_capacity(depth);
    for (right, cut) in proof.iter().rev() {
        let payload = if *right { &cut[..cut.len() - 1] } else { &cut[..] };
        let (slots, mask) = pack_cut(payload)?;
        steps.push(Some(ProofStep {
            right: *right,
            slots,
            mask,
        }));
    }
    steps.resize(depth, None);

    Ok(steps)
}

/// Recomputes the root from packed steps, exactly as the covenant's fold does.
///
/// Use it to check a witness before handing it to a contract: if this does not return the
/// stored root, neither will the covenant.
#[must_use]
pub fn fold(branch: &StormTreeBranch, steps: &[PaddedStep]) -> StormTreeRoot {
    let hasher = Sha2::new();
    let mut hash: Hash = *branch;

    for step in steps.iter().flatten() {
        let mut node = Vec::with_capacity(MAX_CUT + 33);
        if step.right {
            append_cut(&mut node, step);
            node.extend_from_slice(&hash);
            node.push(0x01);
        } else {
            node.extend_from_slice(&hash);
            append_cut(&mut node, step);
        }
        hash = hasher.digest(&node);
    }

    hash
}

/// Writes the selected slots, in order, reproducing the original cut.
fn append_cut(node: &mut Vec<u8>, step: &ProofStep) {
    let slots = &step.slots;
    let widths: [&[u8]; SLOTS] = [
        &slots.wide_a,
        &slots.wide_b,
        &slots.half_a.to_be_bytes(),
        &slots.half_b.to_be_bytes(),
        &slots.eight.to_be_bytes(),
        &slots.four.to_be_bytes(),
        &slots.two.to_be_bytes(),
        std::slice::from_ref(&slots.one),
    ];

    for (index, bytes) in widths.iter().enumerate() {
        if step.mask[index] {
            node.extend_from_slice(bytes);
        }
    }
}

fn wide(piece: &[u8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if !piece.is_empty() {
        bytes.copy_from_slice(piece);
    }
    bytes
}

fn fixed<const N: usize>(piece: &[u8]) -> [u8; N] {
    let mut bytes = [0u8; N];
    if !piece.is_empty() {
        bytes.copy_from_slice(piece);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_widths_reach_every_cut_length() {
        let capacity: usize = SLOT_SIZES.iter().sum();
        assert!(MAX_CUT <= capacity);

        for length in 0..=capacity {
            let cut: Vec<u8> = (0..length).map(|byte| byte as u8).collect();
            let (slots, mask) = pack_cut(&cut).expect("every length must pack");

            let selected: usize = SLOT_SIZES
                .iter()
                .zip(&mask)
                .filter(|(_, used)| **used)
                .map(|(size, _)| *size)
                .sum();
            assert_eq!(selected, length, "slots must sum to the cut length");

            // Round-trip: the selected slots, concatenated, are the cut again.
            let mut rebuilt = Vec::new();
            append_cut(
                &mut rebuilt,
                &ProofStep {
                    right: false,
                    slots,
                    mask,
                },
            );
            assert_eq!(rebuilt, cut, "packing must be lossless");
        }
    }

    #[test]
    fn rejects_a_cut_that_does_not_fit() {
        let capacity: usize = SLOT_SIZES.iter().sum();
        assert!(matches!(
            pack_cut(&vec![0u8; capacity + 1]),
            Err(CovenantError::CutTooLong { .. })
        ));
    }
}
