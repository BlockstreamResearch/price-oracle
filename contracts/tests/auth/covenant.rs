//! Turns a Storm Tree inclusion proof into the shape `auth.simf` can verify.

use thiserror::Error;

use storm_tree::smt::{Hasher, Proof, Sha256, LEAF_MARKER, key_bit};

/// One level of the covenant's fold: which child the walk descended into, and the sibling
/// hash at that level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// `true` when the running hash is the right child, so the sibling is hashed first.
    pub right: bool,
    /// The sibling's node hash.
    pub sibling: [u8; 32],
}

/// A padded fold step. `None` is a level past the leaf's depth, which leaves the
/// accumulator alone.
pub type PaddedStep = Option<ProofStep>;

/// Errors from packing a proof for on-chain verification.
#[derive(Debug, Error)]
pub enum CovenantError {
    /// The proof needs more levels than the covenant was compiled for.
    #[error("proof of {actual} steps exceeds the covenant's depth of {depth}")]
    ProofTooDeep {
        /// Number of live levels in the proof.
        actual: u32,
        /// Fixed depth the covenant folds over.
        depth: u32,
    },
    /// The proof does not show the key present, so it cannot authorize anything.
    #[error("proof is not an inclusion proof")]
    NotAnInclusionProof,
}

/// The leaf a branch hashes to.
///
/// A Storm Tree stores each branch under itself, so its key and value are both the
/// branch. This must stay identical to `get_storm_tree_leaf` in `network.simf`.
#[must_use]
pub fn leaf_hash(branch: &[u8; 32]) -> [u8; 32] {
    Sha256::hash3(branch, branch, &LEAF_MARKER)
}

/// The number of levels a proof really spans, with the zero padding past the leaf's depth
/// trimmed off.
///
/// A zero sibling *within* those levels is a genuinely empty subtree and is kept: the
/// covenant still has to hash against it.
fn live_depth(proof: &Proof) -> u32 {
    let mut depth = proof.siblings.len();
    while depth > 0 && proof.siblings[depth - 1] == [0u8; 32] {
        depth -= 1;
    }

    depth as u32
}

/// Packs a proof into exactly `depth` fold steps, reversed and padded.
///
/// The reversal happens here, not in the covenant: `siblings` is indexed by depth from the
/// root, while the fold starts at the leaf and works upwards.
///
/// # Errors
/// Returns [`CovenantError::NotAnInclusionProof`] for an exclusion proof, or
/// [`CovenantError::ProofTooDeep`] if the proof needs more than `depth` levels.
pub fn pack_proof(proof: &Proof, depth: u32) -> Result<Vec<PaddedStep>, CovenantError> {
    if !proof.existence {
        return Err(CovenantError::NotAnInclusionProof);
    }

    let live = live_depth(proof);
    if live > depth {
        return Err(CovenantError::ProofTooDeep {
            actual: live,
            depth,
        });
    }

    let mut steps: Vec<PaddedStep> = (0..live)
        .rev()
        .map(|level| {
            Some(ProofStep {
                right: key_bit(&proof.key, level),
                sibling: proof.siblings[level as usize],
            })
        })
        .collect();
    steps.resize(depth as usize, None);

    Ok(steps)
}

/// Recomputes the root from packed steps, exactly as the covenant's fold does.
///
/// Use it to check a witness before handing it to a contract: if this does not return the
/// stored root, neither will the covenant.
#[must_use]
pub fn fold(branch: &[u8; 32], steps: &[PaddedStep]) -> [u8; 32] {
    let mut hash = leaf_hash(branch);

    for step in steps.iter().flatten() {
        hash = if step.right {
            Sha256::hash2(&step.sibling, &hash)
        } else {
            Sha256::hash2(&hash, &step.sibling)
        };
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use storm_tree::TREE_DEPTH;
    use storm_tree::smt::SparseMerkleTree;

    type Tree = SparseMerkleTree<Sha256>;

    fn branch(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn tree_of(branches: &[[u8; 32]]) -> Tree {
        let mut tree = Tree::new(TREE_DEPTH).expect("TREE_DEPTH is valid");
        for entry in branches {
            tree.add(*entry, *entry).expect("branches are distinct");
        }

        tree
    }

    #[test]
    fn packed_steps_fold_back_to_the_root() {
        let branches: Vec<[u8; 32]> = (1..=8).map(branch).collect();
        let tree = tree_of(&branches);

        for entry in &branches {
            let proof = tree.proof(*entry);
            let steps = pack_proof(&proof, TREE_DEPTH).expect("proof fits");

            assert_eq!(steps.len(), TREE_DEPTH as usize);
            assert_eq!(
                fold(entry, &steps),
                tree.root(),
                "packed witness for {entry:02x?} must fold to the root"
            );
        }
    }

    #[test]
    fn padding_never_replaces_a_live_level() {
        let branches: Vec<[u8; 32]> = (1..=8).map(branch).collect();
        let tree = tree_of(&branches);
        let proof = tree.proof(branches[0]);
        let steps = pack_proof(&proof, TREE_DEPTH).unwrap();

        // Every live level is packed first, and the padding is all trailing.
        let live = steps.iter().filter(|step| step.is_some()).count();
        assert_eq!(live as u32, live_depth(&proof));
        assert!(steps[..live].iter().all(Option::is_some));
        assert!(steps[live..].iter().all(Option::is_none));
    }

    #[test]
    fn a_tampered_witness_folds_somewhere_else() {
        let branches: Vec<[u8; 32]> = (1..=8).map(branch).collect();
        let tree = tree_of(&branches);
        let proof = tree.proof(branches[0]);
        let steps = pack_proof(&proof, TREE_DEPTH).unwrap();

        let mut flipped = steps.clone();
        let level = flipped
            .iter()
            .position(|step| step.is_some_and(|step| step.sibling != [0u8; 32]))
            .expect("the proof has a live sibling");
        flipped[level].as_mut().unwrap().sibling[0] ^= 1;
        assert_ne!(fold(&branches[0], &flipped), tree.root());

        let mut swapped = steps;
        swapped[level].as_mut().unwrap().right ^= true;
        assert_ne!(fold(&branches[0], &swapped), tree.root());
    }

    #[test]
    fn rejects_an_exclusion_proof() {
        let tree = tree_of(&[branch(1), branch(2)]);

        assert!(matches!(
            pack_proof(&tree.proof(branch(9)), TREE_DEPTH),
            Err(CovenantError::NotAnInclusionProof)
        ));
    }

    #[test]
    fn rejects_a_proof_deeper_than_the_covenant() {
        let tree = tree_of(&[branch(1), branch(2)]);
        let proof = tree.proof(branch(1));

        assert!(matches!(
            pack_proof(&proof, 0),
            Err(CovenantError::ProofTooDeep { .. })
        ));
    }
}
