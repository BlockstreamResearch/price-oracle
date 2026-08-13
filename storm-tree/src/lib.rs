#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

use std::collections::BTreeMap;

use itertools::Itertools;
use monotree::database::MemoryDB;
use monotree::hasher::Sha2;
use monotree::{Hash, Hasher, Monotree, Proof, verify_proof};
use secp256k1::musig::KeyAggCache;
use secp256k1::{Parity, PublicKey, XOnlyPublicKey};
use thiserror::Error;

/// The serialized 32-byte X-only secp256k1 public key of a network node.
pub type NodePublicKey = [u8; 32];
/// The serialized 32-byte X-only MuSig2 aggregate key for one signer combination.
pub type StormTreeBranch = [u8; 32];
/// The SHA-256 root of a Storm Tree.
pub type StormTreeRoot = [u8; 32];
/// A sparse Merkle inclusion proof for a [`StormTreeBranch`].
pub type StormTreeProof = Proof;

const MIN_NODES: usize = 3;
/// Maximum number of signer combinations accepted by [`StormTree::new`].
///
/// This bounds initialization time and memory use when node lists come from an
/// untrusted or incorrectly configured source. With the two-thirds threshold,
/// the default supports up to 20 nodes.
pub const MAX_BRANCHES: usize = 100_000;

/// Errors returned while constructing or querying a [`StormTree`].
#[derive(Debug, Error)]
pub enum StormTreeError {
    /// The participant set contains fewer than three nodes.
    #[error("a Storm Tree requires at least {minimum} nodes, got {actual}")]
    TooFewNodes {
        /// Minimum participant count required by the Storm Tree protocol.
        minimum: usize,
        /// Number of node keys supplied by the caller.
        actual: usize,
    },
    /// A byte array does not encode a valid X-only secp256k1 public key.
    #[error("node public key at index {index} is invalid")]
    InvalidNodePublicKey {
        /// Position of the invalid key in the caller's input.
        index: usize,
        #[source]
        /// The secp256k1 parsing error.
        source: secp256k1::Error,
    },
    /// The same node public key occurs more than once.
    #[error("duplicate node public key: {0:02x?}")]
    DuplicateNodePublicKey(NodePublicKey),
    /// The participant set would generate more than [`MAX_BRANCHES`].
    #[error("Storm Tree exceeds the limit of {maximum} signer combinations")]
    TooManyBranches {
        /// Maximum number of branches accepted by this implementation.
        maximum: usize,
    },
    /// Distinct participant sets unexpectedly generated the same aggregate key.
    #[error("two participant combinations produced the same MuSig2 key: {0:02x?}")]
    DuplicateBranch(StormTreeBranch),
    /// The requested aggregate key is not a branch in this tree.
    #[error("unknown Storm Tree branch: {0:02x?}")]
    UnknownBranch(StormTreeBranch),
    /// The underlying sparse Merkle tree operation failed.
    #[error("sparse Merkle tree operation failed: {0}")]
    SparseMerkleTree(#[from] monotree::Errors),
}

/// A deterministic sparse Merkle tree of minimum-threshold MuSig2 keys.
///
/// Node keys are validated, sorted lexicographically, and treated as a set.
/// Every size-`threshold` subset appears exactly once; permutations of a subset
/// are never separate branches. Each branch is both the sparse-tree key and leaf.
pub struct StormTree {
    nodes: Vec<NodePublicKey>,
    threshold: usize,
    branches: BTreeMap<StormTreeBranch, Vec<NodePublicKey>>,
    tree: Monotree<MemoryDB, Sha2>,
    root: StormTreeRoot,
}

impl StormTree {
    /// Builds a tree from serialized X-only secp256k1 node public keys.
    ///
    /// The input order does not affect the branch keys or root. Construction
    /// fails for duplicate or invalid node keys, colliding aggregate keys, or a
    /// participant set requiring more than [`MAX_BRANCHES`] combinations.
    pub fn new(nodes: Vec<NodePublicKey>) -> Result<Self, StormTreeError> {
        if nodes.len() < MIN_NODES {
            return Err(StormTreeError::TooFewNodes {
                minimum: MIN_NODES,
                actual: nodes.len(),
            });
        }

        for (index, node) in nodes.iter().enumerate() {
            XOnlyPublicKey::from_byte_array(*node)
                .map_err(|source| StormTreeError::InvalidNodePublicKey { index, source })?;
        }

        let mut nodes = nodes;
        nodes.sort_unstable();
        if let Some(duplicate) = nodes.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(StormTreeError::DuplicateNodePublicKey(duplicate[0]));
        }

        let threshold = Self::minimum_threshold(nodes.len());
        let branch_count = combination_count(nodes.len(), threshold, MAX_BRANCHES).ok_or(
            StormTreeError::TooManyBranches {
                maximum: MAX_BRANCHES,
            },
        )?;
        let mut branches = BTreeMap::new();
        for participants in nodes.iter().copied().combinations(threshold) {
            let public_keys: Vec<PublicKey> = participants
                .iter()
                .map(|key| {
                    XOnlyPublicKey::from_byte_array(*key)
                        .expect("node keys were validated")
                        .public_key(Parity::Even)
                })
                .collect();
            let public_key_refs: Vec<&PublicKey> = public_keys.iter().collect();
            let branch = KeyAggCache::new(&public_key_refs).agg_pk().serialize();

            if branches.insert(branch, participants).is_some() {
                return Err(StormTreeError::DuplicateBranch(branch));
            }
        }
        debug_assert_eq!(branches.len(), branch_count);

        let branch_keys: Vec<Hash> = branches.keys().copied().collect();
        let mut tree = Monotree::<MemoryDB, Sha2>::new("storm-tree");
        let root = tree
            .inserts(None, &branch_keys, &branch_keys)?
            .expect("a valid Storm Tree has at least one branch");

        Ok(Self {
            nodes,
            threshold,
            branches,
            tree,
            root,
        })
    }

    /// Returns the minimum signer count: two-thirds of `node_count`, rounded up.
    pub const fn minimum_threshold(node_count: usize) -> usize {
        node_count - node_count / 3
    }

    /// Returns all node keys in canonical lexicographic order.
    pub fn nodes(&self) -> &[NodePublicKey] {
        &self.nodes
    }

    /// Returns the number of signers in every branch.
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the SHA-256 sparse Merkle root.
    pub const fn root(&self) -> StormTreeRoot {
        self.root
    }

    /// Iterates over aggregate branch keys in lexicographic order.
    pub fn branches(&self) -> impl ExactSizeIterator<Item = StormTreeBranch> + '_ {
        self.branches.keys().copied()
    }

    /// Returns the canonical node set represented by an aggregate MuSig2 key.
    ///
    /// The returned keys are sorted lexicographically and contain no duplicates.
    pub fn nodes_for_branch(
        &self,
        branch: &StormTreeBranch,
    ) -> Result<&[NodePublicKey], StormTreeError> {
        self.branches
            .get(branch)
            .map(Vec::as_slice)
            .ok_or(StormTreeError::UnknownBranch(*branch))
    }

    /// Returns an inclusion proof for an aggregate MuSig2 branch key.
    ///
    /// The tree is borrowed mutably because `monotree`'s in-memory database API
    /// uses mutable access for reads.
    pub fn proof(&mut self, branch: &StormTreeBranch) -> Result<StormTreeProof, StormTreeError> {
        if !self.branches.contains_key(branch) {
            return Err(StormTreeError::UnknownBranch(*branch));
        }

        self.tree
            .get_merkle_proof(Some(&self.root), branch)?
            .ok_or(StormTreeError::UnknownBranch(*branch))
    }

    /// Verifies that an aggregate key is included under a Storm Tree root.
    ///
    /// This verifies only Merkle inclusion. Callers must separately validate the
    /// root against the authoritative network state.
    pub fn verify_branch(
        root: &StormTreeRoot,
        branch: &StormTreeBranch,
        proof: &StormTreeProof,
    ) -> bool {
        verify_proof(&Sha2::new(), Some(root), branch, Some(proof))
    }
}

fn combination_count(node_count: usize, threshold: usize, limit: usize) -> Option<usize> {
    let selected = threshold.min(node_count - threshold);
    let mut count = 1usize;

    for divisor in 1..=selected {
        count = count
            .checked_mul(node_count - selected + divisor)?
            .checked_div(divisor)?;
        if count > limit {
            return None;
        }
    }

    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SecretKey};
    use std::collections::BTreeSet;

    fn node_keys(count: usize) -> Vec<NodePublicKey> {
        (1..=count)
            .map(|value| {
                let secret_key = SecretKey::from_secret_bytes([value as u8; 32]).unwrap();
                let keypair = Keypair::from_secret_key(&secret_key);
                XOnlyPublicKey::from_keypair(&keypair).0.serialize()
            })
            .collect()
    }

    #[test]
    fn computes_two_thirds_threshold_rounded_up() {
        assert_eq!(StormTree::minimum_threshold(3), 2);
        assert_eq!(StormTree::minimum_threshold(4), 3);
        assert_eq!(StormTree::minimum_threshold(5), 4);
        assert_eq!(StormTree::minimum_threshold(6), 4);
        assert_eq!(StormTree::minimum_threshold(7), 5);
    }

    #[test]
    fn builds_every_combination_and_recovers_its_nodes() {
        let input = node_keys(4);
        let tree = StormTree::new(input.clone()).unwrap();

        assert_eq!(tree.threshold(), 3);
        assert_eq!(tree.branches().len(), 4);
        assert_eq!(tree.nodes().len(), input.len());
        for branch in tree.branches() {
            let participants = tree.nodes_for_branch(&branch).unwrap();
            assert_eq!(participants.len(), tree.threshold());
            assert!(participants.windows(2).all(|pair| pair[0] < pair[1]));
        }
    }

    #[test]
    fn emits_each_participant_set_once_without_permutations() {
        let mut nodes = node_keys(5);
        nodes.reverse();
        let tree = StormTree::new(nodes).unwrap();

        let actual: BTreeSet<Vec<NodePublicKey>> = tree
            .branches()
            .map(|branch| tree.nodes_for_branch(&branch).unwrap().to_vec())
            .collect();
        let expected: BTreeSet<Vec<NodePublicKey>> = tree
            .nodes()
            .iter()
            .copied()
            .combinations(tree.threshold())
            .collect();

        assert_eq!(actual.len(), 5);
        assert_eq!(actual, expected);
    }

    #[test]
    fn creates_verifiable_sha256_inclusion_proofs() {
        let mut tree = StormTree::new(node_keys(5)).unwrap();
        let branch = tree.branches().next().unwrap();
        let proof = tree.proof(&branch).unwrap();

        assert!(StormTree::verify_branch(&tree.root(), &branch, &proof));

        let other_branch = StormTree::new(node_keys(3))
            .unwrap()
            .branches()
            .next()
            .unwrap();
        assert!(!StormTree::verify_branch(
            &tree.root(),
            &other_branch,
            &proof
        ));
    }

    #[test]
    fn input_order_does_not_change_the_tree() {
        let nodes = node_keys(5);
        let mut reversed = nodes.clone();
        reversed.reverse();

        let tree = StormTree::new(nodes).unwrap();
        let reversed_tree = StormTree::new(reversed).unwrap();

        assert_eq!(tree.root(), reversed_tree.root());
        assert!(tree.branches().eq(reversed_tree.branches()));
    }

    #[test]
    fn rejects_duplicate_nodes() {
        let mut nodes = node_keys(3);
        nodes[2] = nodes[0];

        assert!(matches!(
            StormTree::new(nodes),
            Err(StormTreeError::DuplicateNodePublicKey(_))
        ));
    }

    #[test]
    fn rejects_excessive_combination_counts() {
        assert_eq!(combination_count(20, 14, MAX_BRANCHES), Some(38_760));
        assert_eq!(combination_count(21, 14, MAX_BRANCHES), None);
    }
}
