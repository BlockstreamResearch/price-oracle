use simplex::either::Either;
use thiserror::Error;

use storm_tree::TREE_DEPTH;
use storm_tree::smt::{MerkleTree, hash_leaf, hash_node};

/// Fold length the covenant is compiled for.
pub const WITNESS_DEPTH: usize = TREE_DEPTH as usize;

/// A MuSig2 aggregate key for one signer combination.
pub type Branch = [u8; 32];

/// One fold step, in the shape the covenant's witness expects. `Left` is an unused level.
pub type WitnessStep = Either<(), (bool, [u8; 32])>;

/// The network's authorization proof for a Storm Eye spend: the aggregate signature, the
/// signing combination's key, and its inclusion proof under the stored Storm Tree root.
#[derive(Debug, Clone, Copy)]
pub struct StormTreeBloom {
    pub signature: [u8; 64],
    pub branch: Branch,
    pub proof: [WitnessStep; WITNESS_DEPTH],
}

/// Errors packing a Storm Tree proof into the covenant's fixed-depth witness shape.
#[derive(Debug, Error)]
pub enum StormTreeWitnessError {
    /// The proof needs more levels than the covenant was compiled for.
    #[error("proof of {actual} steps exceeds the covenant's depth of {depth}")]
    ProofTooDeep { actual: usize, depth: usize },
}

/// Builds a Storm Tree over arbitrary branches, through the same recipe the network uses.
///
/// # Panics
/// Panics if the branches contain a duplicate or need a deeper tree than the covenant.
#[must_use]
pub fn build_tree(branches: &[Branch]) -> MerkleTree {
    MerkleTree::from_leaves(branches).expect("branches are distinct and fit a tree")
}

/// Packs `branch`'s proof under `tree` into exactly [`WITNESS_DEPTH`] fold steps, padding
/// the levels the tree never reached.
///
/// # Errors
/// Returns [`StormTreeWitnessError::ProofTooDeep`] if the proof needs more levels than
/// the covenant was compiled for — a real possibility once the network has enough nodes
/// that a signer combination's branch sits deeper than [`WITNESS_DEPTH`].
///
/// # Panics
/// Panics if `branch` is not in `tree`, or if the packed steps do not fold back to the
/// tree's root — both are internal consistency checks, not caller-input validation.
pub fn witness_proof(
    tree: &MerkleTree,
    branch: &Branch,
) -> Result<[WitnessStep; WITNESS_DEPTH], StormTreeWitnessError> {
    let proof = tree.proof(branch).expect("branch is in the tree");

    if proof.siblings.len() > WITNESS_DEPTH {
        return Err(StormTreeWitnessError::ProofTooDeep {
            actual: proof.siblings.len(),
            depth: WITNESS_DEPTH,
        });
    }

    let mut steps: Vec<Option<(bool, [u8; 32])>> =
        proof.siblings.iter().copied().map(Some).collect();
    steps.resize(WITNESS_DEPTH, None);

    assert_eq!(
        fold(branch, &steps),
        tree.root(),
        "packed witness must fold to the tree's root"
    );

    Ok(steps
        .iter()
        .map(|step| match step {
            None => Either::Left(()),
            Some((is_right, sibling)) => Either::Right((*is_right, *sibling)),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("packed exactly WITNESS_DEPTH steps"))
}

/// Recomputes the root from packed steps, exactly as the covenant's fold does.
fn fold(branch: &Branch, steps: &[Option<(bool, [u8; 32])>]) -> [u8; 32] {
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
