//! Builds Storm Trees for the covenant tests and packs their proofs into witness shape.

use simplex::either::Either;
use thiserror::Error;

use storm_tree::TREE_DEPTH;
use storm_tree::smt::{MerkleTree, Proof, hash_leaf, hash_node};

/// Fold length the covenant is compiled for.
pub const WITNESS_DEPTH: usize = TREE_DEPTH as usize;

/// A MuSig2 aggregate key for one signer combination.
pub type Branch = [u8; 32];

/// One fold step, in the shape `AuthWitness` expects. `Left` is an unused level.
pub type WitnessStep = Either<(), (bool, [u8; 32])>;

type StormTreeBloomArray = Vec<Option<(bool, [u8; 32])>>;

/// Errors from packing a proof for on-chain verification.
#[derive(Debug, Error)]
pub enum CovenantError {
    /// The proof needs more levels than the covenant was compiled for.
    #[error("proof of {actual} steps exceeds the covenant's depth of {depth}")]
    ProofTooDeep {
        /// Number of levels in the proof.
        actual: usize,
        /// Fixed depth the covenant folds over.
        depth: usize,
    },
    /// Building the tree failed.
    #[error("tree operation failed: {0}")]
    Tree(#[from] storm_tree::smt::Error),
}

/// Builds a Storm Tree over arbitrary branches, through the same recipe the network uses.
///
/// # Panics
/// Panics if the branches contain a duplicate or need a deeper tree than the covenant.
pub fn build_tree(branches: &[Branch]) -> MerkleTree {
    MerkleTree::from_leaves(branches).expect("branches are distinct and fit a tree")
}

/// Packs a proof into exactly `depth` fold steps, padding the levels the tree never
/// reached.
///
/// # Errors
/// Returns [`CovenantError::ProofTooDeep`] if the proof needs more than `depth` levels.
pub fn pack_proof(proof: &Proof, depth: usize) -> Result<StormTreeBloomArray, CovenantError> {
    if proof.siblings.len() > depth {
        return Err(CovenantError::ProofTooDeep {
            actual: proof.siblings.len(),
            depth,
        });
    }

    let mut steps: StormTreeBloomArray = proof.siblings.iter().copied().map(Some).collect();
    steps.resize(depth, None);

    Ok(steps)
}

/// Recomputes the root from packed steps, exactly as the covenant's fold does.
#[must_use]
pub fn fold(branch: &Branch, steps: &[Option<(bool, [u8; 32])>]) -> [u8; 32] {
    let mut hash = hash_leaf(branch);

    for (is_right, sibling) in steps.iter().flatten() {
        hash = if *is_right {
            hash_node(sibling, &hash)
        } else {
            hash_node(&hash, sibling)
        };
    }

    hash
}

/// Packs a branch's proof into the covenant's witness shape.
///
/// # Panics
/// Panics if the branch is absent, the proof is deeper than the covenant allows, or the
/// packed steps do not fold back to the tree's root.
pub fn witness_proof(tree: &MerkleTree, branch: &Branch) -> [WitnessStep; WITNESS_DEPTH] {
    let proof = tree.proof(branch).expect("branch is in the tree");
    let steps = pack_proof(&proof, WITNESS_DEPTH).expect("proof fits the covenant depth");

    assert_eq!(
        fold(branch, &steps),
        tree.root(),
        "packed witness must fold to the tree's root"
    );

    steps
        .iter()
        .map(|step| match step {
            None => Either::Left(()),
            Some((is_right, sibling)) => Either::Right((*is_right, *sibling)),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("pack_proof returns exactly WITNESS_DEPTH steps")
}
