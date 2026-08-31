//! A complete binary Merkle tree over a sorted set of leaves, held in a heap array.
//!
//! Every leaf sits at a fixed depth and its position is its rank in the sorted input, so a
//! proof is always exactly [`MerkleTree::depth`] steps and nothing about the shape depends
//! on the leaf values. That is the whole difference from a key-addressed sparse tree, and
//! it is what lets `N` leaves fit in `ceil(log2(N))` levels.

use std::collections::BTreeMap;

use sha2::Digest;
use thiserror::Error;

/// The largest depth a tree can be built at.
///
/// This is a guard against an accidental allocation, not a protocol limit.
pub const MAX_DEPTH: u32 = 20;

/// A leaf's value. For a Storm Tree this is a MuSig2 aggregate key.
pub type Leaf = [u8; 32];
/// The hash of a node, and of the tree itself when taken at the root.
pub type NodeHash = [u8; 32];

/// The hash of an empty subtree, at every level.
pub const ZERO_HASH: NodeHash = [0u8; 32];

/// Separates a leaf preimage from an internal node's.
pub const LEAF_MARKER: u8 = 0x01;

/// Hashes a leaf: `sha256(leaf || 0x01)`.
#[must_use]
pub fn hash_leaf(leaf: &Leaf) -> NodeHash {
    let mut hasher = sha2::Sha256::new();
    hasher.update(leaf);
    hasher.update([LEAF_MARKER]);

    hasher.finalize().into()
}

/// Hashes an internal node: `sha256(left || right)`.
#[must_use]
pub fn hash_node(left: &NodeHash, right: &NodeHash) -> NodeHash {
    let mut hasher = sha2::Sha256::new();
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

/// An inclusion proof: the sibling at each level, deepest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The leaf being proven.
    pub leaf: Leaf,
    /// The root the proof was taken against.
    pub root: NodeHash,
    /// One `(this node is the right child, sibling hash)` per level, leaf to root.
    pub siblings: Vec<(bool, NodeHash)>,
}

/// Everything that can go wrong building or querying a tree.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// A depth of zero was requested.
    #[error("depth must be greater than zero")]
    DepthIsZero,
    /// The requested depth is above [`MAX_DEPTH`].
    #[error("depth {0} exceeds the maximum of {MAX_DEPTH}")]
    DepthExceedsMaximum(u32),
    /// Every leaf slot is taken.
    #[error("tree is full at {capacity} leaves")]
    TreeIsFull {
        /// How many leaves the tree can hold.
        capacity: usize,
    },
    /// [`MerkleTree::add`] was called with a leaf that does not sort after the last one.
    ///
    /// This also catches duplicates, since a repeated leaf is not strictly greater.
    #[error(
        "leaves must be added in strictly ascending order: {leaf:02x?} does not follow {last:02x?}"
    )]
    OutOfOrder {
        /// The leaf that was offered.
        leaf: Leaf,
        /// The last leaf already in the tree.
        last: Leaf,
    },
    /// The requested leaf is not in the tree.
    #[error("unknown leaf: {0:02x?}")]
    UnknownLeaf(Leaf),
}

/// A complete binary Merkle tree over a sorted set of leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    depth: u32,
    /// 1-based heap array of `2^(depth+1)` hashes; index 0 is unused.
    nodes: Vec<NodeHash>,
    /// Leaf value to its node index, kept ordered so the last entry is the ordering guard.
    positions: BTreeMap<Leaf, usize>,
}

impl MerkleTree {
    /// Creates an empty tree with `2^depth` leaf slots.
    ///
    /// # Errors
    /// Returns [`Error::DepthIsZero`] or [`Error::DepthExceedsMaximum`] for a depth outside
    /// `1..=`[`MAX_DEPTH`].
    pub fn new(depth: u32) -> Result<Self, Error> {
        if depth == 0 {
            return Err(Error::DepthIsZero);
        }
        if depth > MAX_DEPTH {
            return Err(Error::DepthExceedsMaximum(depth));
        }

        Ok(Self {
            depth,
            nodes: vec![ZERO_HASH; 1usize << (depth + 1)],
            positions: BTreeMap::new(),
        })
    }

    /// The shallowest depth that holds `leaves` leaves, or `None` if that is above
    /// [`MAX_DEPTH`].
    ///
    /// This is `ceil(log2(leaves))`, floored at 1.
    #[must_use]
    pub fn depth_for(leaves: usize) -> Option<u32> {
        let depth = leaves.max(2).checked_next_power_of_two()?.trailing_zeros();

        (depth <= MAX_DEPTH).then_some(depth)
    }

    /// Builds a tree sized to `leaves`, which are sorted first.
    ///
    /// # Errors
    /// Returns [`Error::TreeIsFull`] if `leaves` needs a deeper tree than [`MAX_DEPTH`],
    /// or [`Error::OutOfOrder`] if it contains duplicates.
    pub fn from_leaves(leaves: &[Leaf]) -> Result<Self, Error> {
        let mut sorted = leaves.to_vec();
        sorted.sort_unstable();

        let depth = Self::depth_for(sorted.len()).ok_or(Error::TreeIsFull {
            capacity: 1usize << MAX_DEPTH,
        })?;
        let mut tree = Self::new(depth)?;
        for leaf in sorted {
            tree.add(leaf)?;
        }

        Ok(tree)
    }

    /// Appends a leaf and rehashes the path to the root.
    ///
    /// # Errors
    /// Returns [`Error::OutOfOrder`] unless `leaf` sorts strictly after every leaf already
    /// present, or [`Error::TreeIsFull`] once every slot is taken.
    pub fn add(&mut self, leaf: Leaf) -> Result<(), Error> {
        if let Some((last, _)) = self.positions.last_key_value()
            && leaf <= *last
        {
            return Err(Error::OutOfOrder { leaf, last: *last });
        }
        if self.positions.len() == self.capacity() {
            return Err(Error::TreeIsFull {
                capacity: self.capacity(),
            });
        }

        let index = self.first_leaf_index() + self.positions.len();
        self.nodes[index] = hash_leaf(&leaf);
        self.positions.insert(leaf, index);
        self.rehash_path(index);

        Ok(())
    }

    /// The tree's root, which is [`ZERO_HASH`] while the tree is empty.
    #[must_use]
    pub fn root(&self) -> NodeHash {
        self.nodes[1]
    }

    /// Builds an inclusion proof for `leaf`.
    ///
    /// # Errors
    /// Returns [`Error::UnknownLeaf`] if the leaf was never added.
    pub fn proof(&self, leaf: &Leaf) -> Result<Proof, Error> {
        let mut index = *self.positions.get(leaf).ok_or(Error::UnknownLeaf(*leaf))?;

        let mut siblings = Vec::with_capacity(self.depth as usize);
        while index > 1 {
            siblings.push((index & 1 == 1, self.nodes[index ^ 1]));
            index >>= 1;
        }

        Ok(Proof {
            leaf: *leaf,
            root: self.root(),
            siblings,
        })
    }

    /// How many leaves the tree can hold.
    const fn capacity(&self) -> usize {
        1usize << self.depth
    }

    /// The index of the leftmost leaf slot.
    const fn first_leaf_index(&self) -> usize {
        1usize << self.depth
    }

    /// Recomputes every node between `index` and the root.
    fn rehash_path(&mut self, index: usize) {
        let mut parent = index >> 1;
        while parent >= 1 {
            self.nodes[parent] = hash_node(&self.nodes[parent * 2], &self.nodes[parent * 2 + 1]);
            parent >>= 1;
        }
    }
}

/// Checks a proof against the root it carries.
#[must_use]
pub fn verify_proof(proof: &Proof) -> bool {
    process_proof(&proof.leaf, &proof.siblings) == proof.root
}

/// Recomputes the root a proof implies, exactly as the covenant's fold does.
#[must_use]
pub fn process_proof(leaf: &Leaf, siblings: &[(bool, NodeHash)]) -> NodeHash {
    let mut hash = hash_leaf(leaf);

    for (is_right, sibling) in siblings {
        hash = if *is_right {
            hash_node(sibling, &hash)
        } else {
            hash_node(&hash, sibling)
        };
    }

    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(byte: u8) -> Leaf {
        [byte; 32]
    }

    fn tree_of(depth: u32, count: u8) -> MerkleTree {
        let mut tree = MerkleTree::new(depth).unwrap();
        for byte in 1..=count {
            tree.add(leaf(byte)).unwrap();
        }

        tree
    }

    #[test]
    fn rejects_out_of_range_depth() {
        assert_eq!(MerkleTree::new(0).unwrap_err(), Error::DepthIsZero);
        assert_eq!(
            MerkleTree::new(MAX_DEPTH + 1).unwrap_err(),
            Error::DepthExceedsMaximum(MAX_DEPTH + 1)
        );
    }

    #[test]
    fn sizes_the_tree_to_the_leaf_count() {
        assert_eq!(MerkleTree::depth_for(1), Some(1));
        assert_eq!(MerkleTree::depth_for(2), Some(1));
        assert_eq!(MerkleTree::depth_for(3), Some(2));
        assert_eq!(MerkleTree::depth_for(4), Some(2));
        assert_eq!(MerkleTree::depth_for(5), Some(3));
        // The Storm Tree's real size: 38,760 branches fit in 16 levels.
        assert_eq!(MerkleTree::depth_for(38_760), Some(16));
        assert_eq!(MerkleTree::depth_for(65_536), Some(16));
        assert_eq!(MerkleTree::depth_for(65_537), Some(17));
        assert_eq!(MerkleTree::depth_for(100_000), Some(17));
        assert_eq!(MerkleTree::depth_for(usize::MAX), None);
    }

    /// Pins the exact hash formula. Nothing else here would notice a wrong leaf marker or
    /// a swapped `hash_node` argument order.
    #[test]
    fn builds_known_roots_by_hand() {
        // Empty.
        let mut tree = MerkleTree::new(2).unwrap();
        assert_eq!(tree.root(), ZERO_HASH);

        // One leaf, at the leftmost slot. Its sibling and uncle are empty.
        tree.add(leaf(1)).unwrap();
        let left = hash_node(&hash_leaf(&leaf(1)), &ZERO_HASH);
        assert_eq!(tree.root(), hash_node(&left, &ZERO_HASH));

        // A second leaf becomes the first one's sibling, so only the left subtree changes.
        tree.add(leaf(2)).unwrap();
        let left = hash_node(&hash_leaf(&leaf(1)), &hash_leaf(&leaf(2)));
        assert_eq!(tree.root(), hash_node(&left, &ZERO_HASH));

        // A third starts the right subtree.
        tree.add(leaf(3)).unwrap();
        let right = hash_node(&hash_leaf(&leaf(3)), &ZERO_HASH);
        assert_eq!(tree.root(), hash_node(&left, &right));
    }

    #[test]
    fn a_leaf_never_hashes_like_a_node_or_an_empty_slot() {
        // The domain separator is what stops an internal node being replayed as a leaf.
        let node = hash_node(&hash_leaf(&leaf(1)), &hash_leaf(&leaf(2)));

        assert_ne!(hash_leaf(&node), node);
        assert_ne!(hash_leaf(&ZERO_HASH), ZERO_HASH);
        assert!((0u8..=255).all(|byte| hash_leaf(&leaf(byte)) != ZERO_HASH));
    }

    #[test]
    fn requires_strictly_ascending_leaves() {
        let mut tree = MerkleTree::new(4).unwrap();
        tree.add(leaf(5)).unwrap();

        assert!(matches!(tree.add(leaf(4)), Err(Error::OutOfOrder { .. })));
        assert!(matches!(tree.add(leaf(5)), Err(Error::OutOfOrder { .. })));
        tree.add(leaf(6)).unwrap();
    }

    #[test]
    fn rejects_leaves_past_capacity() {
        // Depth 2 holds exactly four leaves.
        let mut tree = tree_of(2, 4);

        assert_eq!(
            tree.add(leaf(5)).unwrap_err(),
            Error::TreeIsFull { capacity: 4 }
        );
    }

    #[test]
    fn proves_every_leaf_it_holds() {
        let tree = tree_of(5, 20);

        for byte in 1..=20 {
            let proof = tree.proof(&leaf(byte)).unwrap();

            assert_eq!(proof.siblings.len(), 5, "every proof spans the full depth");
            assert_eq!(proof.root, tree.root());
            assert!(verify_proof(&proof), "proof for leaf {byte} must verify");
        }
    }

    #[test]
    fn rejects_an_unknown_leaf() {
        let tree = tree_of(4, 3);

        assert_eq!(
            tree.proof(&leaf(9)).unwrap_err(),
            Error::UnknownLeaf(leaf(9))
        );
    }

    #[test]
    fn rejects_a_tampered_proof() {
        let tree = tree_of(4, 9);
        let good = tree.proof(&leaf(4)).unwrap();
        assert!(verify_proof(&good));

        let mut wrong_leaf = good.clone();
        wrong_leaf.leaf = leaf(5);
        assert!(!verify_proof(&wrong_leaf));

        let mut wrong_root = good.clone();
        wrong_root.root[0] ^= 1;
        assert!(!verify_proof(&wrong_root));

        let mut wrong_sibling = good.clone();
        wrong_sibling.siblings[0].1[0] ^= 1;
        assert!(!verify_proof(&wrong_sibling));

        // Flipping a direction bit reorders one hash, which the root notices.
        let mut wrong_direction = good;
        wrong_direction.siblings[0].0 ^= true;
        assert!(!verify_proof(&wrong_direction));
    }

    /// An internal node presented as a leaf must not verify. This is the attack the leaf
    /// marker exists to stop, and the only test that would catch its removal.
    #[test]
    fn an_internal_node_cannot_be_passed_off_as_a_leaf() {
        let tree = tree_of(3, 4);

        // The node covering leaves 1 and 2, and the proof that node's parent would need.
        let internal = hash_node(&hash_leaf(&leaf(1)), &hash_leaf(&leaf(2)));
        let upper = tree.proof(&leaf(1)).unwrap().siblings[1..].to_vec();

        assert!(!verify_proof(&Proof {
            leaf: internal,
            root: tree.root(),
            siblings: upper,
        }));
    }

    #[test]
    fn the_root_is_a_function_of_the_leaf_set() {
        let leaves: Vec<Leaf> = (1..=10).map(leaf).collect();

        let mut tree = MerkleTree::new(4).unwrap();
        for entry in &leaves {
            tree.add(*entry).unwrap();
        }

        // Same set, same depth, rebuilt from scratch.
        let mut again = MerkleTree::new(4).unwrap();
        for entry in &leaves {
            again.add(*entry).unwrap();
        }

        assert_eq!(tree.root(), again.root());
        assert_ne!(tree.root(), ZERO_HASH);

        // A deeper tree over the same leaves is a different commitment.
        let mut deeper = MerkleTree::new(5).unwrap();
        for entry in &leaves {
            deeper.add(*entry).unwrap();
        }
        assert_ne!(tree.root(), deeper.root());
    }

    #[test]
    fn heap_indexing_holds() {
        let tree = tree_of(4, 5);
        let index = tree.positions[&leaf(1)];

        assert_eq!(index, tree.first_leaf_index());
        assert_eq!(tree.positions[&leaf(2)], index + 1);
        // Siblings share a parent, and the low bit is the direction.
        assert_eq!(index >> 1, (index ^ 1) >> 1);
        assert_eq!(index & 1, 0, "the leftmost leaf is a left child");
    }
}
