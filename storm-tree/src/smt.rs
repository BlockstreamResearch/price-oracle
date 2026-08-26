//! A Sparse Merkle Tree, ported from [`SparseMerkleTree.sol`].
//!
//! [`SparseMerkleTree.sol`]: https://github.com/dl-solarity/solidity-lib/blob/master/contracts/libs/data-structures/SparseMerkleTree.sol

use std::marker::PhantomData;

use sha2::Digest;
use thiserror::Error;

/// The largest depth the tree can be configured for.
pub const MAX_DEPTH_HARD_CAP: u32 = 256;

/// The identifier of the sentinel empty node, which every absent child points at.
const ZERO_IDX: u64 = 0;

/// The hash of an empty subtree.
const ZERO_HASH: [u8; 32] = [0u8; 32];

/// The 32-byte big-endian word `1`, hashed into every leaf as a domain separator.
const LEAF_MARKER: [u8; 32] = {
    let mut marker = [0u8; 32];
    marker[31] = 1;
    marker
};

/// A 256-bit tree key.
pub type Key = [u8; 32];
/// A 256-bit value stored under a [`Key`].
pub type Value = [u8; 32];
/// The hash of a node, and of the tree itself when taken at the root.
pub type NodeHash = [u8; 32];

/// The two hash functions that define a tree's shape.
pub trait Hasher {
    /// Hashes a middle node from its two child hashes.
    fn hash2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32];

    /// Hashes a leaf from its key, its value and the leaf marker.
    fn hash3(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32];
}

/// SHA-256 over the concatenated arguments.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256;

impl Hasher for Sha256 {
    fn hash2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.finalize().into()
    }

    fn hash3(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.update(c);
        hasher.finalize().into()
    }
}

/// One node of the tree.
///
/// The Solidity carries a `nodeType` tag alongside fields that are meaningful for only
/// one tag; here the payload is the tag. Nodes are always constructed with their hash
/// already computed, so no node ever exists holding a placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Node {
    /// An absent node. Slot [`ZERO_IDX`] is permanently empty and deleted slots revert
    /// to it.
    #[default]
    Empty,
    /// A key-value pair.
    Leaf {
        /// The key this leaf is addressed by.
        key: Key,
        /// The value stored under it.
        value: Value,
        /// `hash3(key, value, 1)`.
        hash: NodeHash,
    },
    /// An interior node with at least one non-empty child.
    Middle {
        /// Arena index of the left child, or [`ZERO_IDX`] when absent.
        left: u64,
        /// Arena index of the right child, or [`ZERO_IDX`] when absent.
        right: u64,
        /// `hash2(left, right)`.
        hash: NodeHash,
    },
}

impl Node {
    /// The node's hash. An empty subtree hashes to a flat zero at every depth, which is
    /// where this port departs from a textbook sparse Merkle tree's per-level defaults.
    pub const fn hash(&self) -> NodeHash {
        match self {
            Self::Empty => ZERO_HASH,
            Self::Leaf { hash, .. } | Self::Middle { hash, .. } => *hash,
        }
    }
}

/// A proof that a key is, or is not, in the tree under [`Proof::root`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The root the proof was taken against.
    pub root: NodeHash,
    /// One sibling hash per level, indexed by depth from the root, zero-padded to the
    /// tree's maximum depth.
    pub siblings: Vec<NodeHash>,
    /// Whether the key is present.
    pub existence: bool,
    /// The key being proven.
    pub key: Key,
    /// The value at `key` when `existence`, otherwise the auxiliary leaf's value.
    pub value: Value,
    /// Whether an auxiliary leaf blocks the key's position. Only meaningful when
    /// `existence` is false.
    pub aux_existence: bool,
    /// The auxiliary leaf's key.
    pub aux_key: Key,
    /// The auxiliary leaf's value.
    pub aux_value: Value,
}

/// Everything that can go wrong operating on the tree.
///
/// The variants mirror the Solidity errors one for one, so fixture replays can compare
/// failures and not just successful roots.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// [`SparseMerkleTree::add`] was called with a key already in the tree.
    #[error("key already exists: {0:02x?}")]
    KeyAlreadyExists(Key),
    /// The walk reached a leaf holding a different key.
    #[error("leaf key {current_key:02x?} does not match {key:02x?}")]
    LeafDoesNotMatch {
        /// The key found at the leaf.
        current_key: Key,
        /// The key that was being looked for.
        key: Key,
    },
    /// The requested maximum depth is above [`MAX_DEPTH_HARD_CAP`].
    #[error("max depth {0} exceeds the hard cap of {MAX_DEPTH_HARD_CAP}")]
    MaxDepthExceedsHardCap(u32),
    /// A maximum depth of zero was requested.
    #[error("max depth must be greater than zero")]
    MaxDepthIsZero,
    /// Two keys share a prefix longer than the tree's maximum depth, so the leaf that
    /// would separate them has nowhere to go.
    #[error("max depth reached")]
    MaxDepthReached,
    /// [`SparseMerkleTree::set_max_depth`] was called with a depth that is not an
    /// increase.
    #[error("new max depth {new} must be larger than the current {current}")]
    NewMaxDepthMustBeLarger {
        /// The tree's current maximum depth.
        current: u32,
        /// The requested maximum depth.
        new: u32,
    },
    /// The walk ran into an empty subtree where a node was required.
    #[error("node {0} does not exist")]
    NodeDoesNotExist(u64),
}

/// A sparse Merkle tree over 256-bit keys.
///
/// Nodes live in an arena indexed from 1; slot 0 is the permanently empty sentinel that
/// every absent child points at.
#[derive(Debug, Clone)]
pub struct SparseMerkleTree<H: Hasher> {
    nodes: Vec<Node>,
    merkle_root_id: u64,
    deleted_nodes_count: u64,
    max_depth: u32,
    hasher: PhantomData<H>,
}

impl<H: Hasher> SparseMerkleTree<H> {
    /// Creates an empty tree that can hold leaves down to `max_depth`.
    ///
    /// This is the Solidity's `initialize`. Two keys sharing more than `max_depth` leading
    /// bits cannot both be inserted, so `max_depth` bounds which key sets the tree
    /// accepts; see [`Error::MaxDepthReached`].
    ///
    /// # Errors
    /// Returns [`Error::MaxDepthIsZero`] or [`Error::MaxDepthExceedsHardCap`] for a depth
    /// outside `1..=`[`MAX_DEPTH_HARD_CAP`].
    pub fn new(max_depth: u32) -> Result<Self, Error> {
        let mut tree = Self {
            // Slot 0 is the empty sentinel and is never handed out.
            nodes: vec![Node::default()],
            merkle_root_id: ZERO_IDX,
            deleted_nodes_count: 0,
            max_depth: 0,
            hasher: PhantomData,
        };
        tree.set_max_depth(max_depth)?;

        Ok(tree)
    }

    /// Raises the maximum depth.
    ///
    /// # Errors
    /// Returns [`Error::NewMaxDepthMustBeLarger`] if `max_depth` does not exceed the
    /// current depth, or the range errors of [`SparseMerkleTree::new`].
    pub fn set_max_depth(&mut self, max_depth: u32) -> Result<(), Error> {
        if max_depth == 0 {
            return Err(Error::MaxDepthIsZero);
        }
        if max_depth <= self.max_depth {
            return Err(Error::NewMaxDepthMustBeLarger {
                current: self.max_depth,
                new: max_depth,
            });
        }
        if max_depth > MAX_DEPTH_HARD_CAP {
            return Err(Error::MaxDepthExceedsHardCap(max_depth));
        }
        self.max_depth = max_depth;

        Ok(())
    }

    /// # Errors
    /// Returns [`Error::KeyAlreadyExists`] if the key is present, or
    /// [`Error::MaxDepthReached`] if separating it from an existing key would need a
    /// deeper tree.
    pub fn add(&mut self, key: Key, value: Value) -> Result<(), Error> {
        self.merkle_root_id = self.add_at(key, value, self.merkle_root_id, 0)?;

        Ok(())
    }

    /// # Errors
    /// Returns [`Error::NodeDoesNotExist`] or [`Error::LeafDoesNotMatch`] if the key is
    /// not in the tree.
    pub fn remove(&mut self, key: Key) -> Result<(), Error> {
        self.merkle_root_id = self.remove_at(key, self.merkle_root_id, 0)?;

        Ok(())
    }

    /// # Errors
    /// Returns [`Error::NodeDoesNotExist`] or [`Error::LeafDoesNotMatch`] if the key is
    /// not in the tree.
    pub fn update(&mut self, key: Key, new_value: Value) -> Result<(), Error> {
        self.update_at(key, new_value, self.merkle_root_id, 0)
    }

    /// Returns the tree's root hash, which is [`ZERO_HASH`] when the tree is empty.
    pub fn root(&self) -> NodeHash {
        self.node(self.merkle_root_id).hash()
    }

    /// Returns the tree's maximum depth.
    pub const fn max_depth(&self) -> u32 {
        self.max_depth
    }

    /// Returns the number of live nodes, leaves and middle nodes together.
    pub fn nodes_count(&self) -> u64 {
        self.nodes_allocated() - self.deleted_nodes_count
    }

    /// Returns a node by arena index, or an empty node if the index is unused.
    pub fn node(&self, node_id: u64) -> Node {
        // Solidity reads a mapping, which yields a zeroed struct for any absent key. An
        // out-of-range index is treated the same way here rather than panicking.
        usize::try_from(node_id)
            .ok()
            .and_then(|index| self.nodes.get(index))
            .copied()
            .unwrap_or_default()
    }

    /// Returns the leaf stored under `key`, or an empty node if the key is absent.
    pub fn node_by_key(&self, key: Key) -> Node {
        let mut next_node_id = self.merkle_root_id;

        for depth in 0..=self.max_depth {
            let node = self.node(next_node_id);

            match node {
                Node::Empty => break,
                // The walk stops at the first leaf either way: paths end at divergence,
                // so if this leaf is not the key, no leaf below it could be.
                Node::Leaf { key: leaf_key, .. } => {
                    return if leaf_key == key { node } else { Node::Empty };
                }
                Node::Middle { left, right, .. } => {
                    next_node_id = if key_bit(&key, depth) { right } else { left };
                }
            }
        }

        Node::Empty
    }

    /// Builds an inclusion or exclusion proof for `key` against the current root.
    ///
    /// [`Proof::siblings`] is always [`SparseMerkleTree::max_depth`] entries long, padded
    /// with [`ZERO_HASH`] past the leaf's depth. [`SparseMerkleTree::process_proof`]
    /// recovers the real depth by trimming that padding, which is why a middle node is
    /// never allowed to keep a lone leaf child; see [`SparseMerkleTree::remove_at`].
    pub fn proof(&self, key: Key) -> Proof {
        let max_depth = self.max_depth as usize;
        let mut proof = Proof {
            root: self.root(),
            siblings: vec![ZERO_HASH; max_depth],
            existence: false,
            key,
            value: ZERO_HASH,
            aux_existence: false,
            aux_key: ZERO_HASH,
            aux_value: ZERO_HASH,
        };

        let mut next_node_id = self.merkle_root_id;

        for depth in 0..=self.max_depth {
            let node = self.node(next_node_id);

            match node {
                Node::Empty => break,
                Node::Leaf { key, value, .. } => {
                    if key == proof.key {
                        proof.existence = true;
                    } else {
                        proof.aux_existence = true;
                        proof.aux_key = key;
                        proof.aux_value = value;
                    }
                    // The Solidity assigns the leaf's value in both branches, so an
                    // exclusion proof carries the auxiliary leaf's value here too.
                    proof.value = value;
                    break;
                }
                Node::Middle { left, right, .. } => {
                    let sibling = proof
                        .siblings
                        .get_mut(depth as usize)
                        .expect("a middle node cannot sit at max depth: add() rejects it");

                    if key_bit(&proof.key, depth) {
                        next_node_id = right;
                        *sibling = self.node(left).hash();
                    } else {
                        next_node_id = left;
                        *sibling = self.node(right).hash();
                    }
                }
            }
        }

        proof
    }

    /// Checks a proof against the root it carries.
    ///
    /// This needs no tree: the hasher is a type parameter, so the caller only has to name
    /// the same `H` the proof was produced under.
    pub fn verify_proof(proof: &Proof) -> bool {
        // An exclusion proof whose auxiliary leaf holds the very key being excluded is
        // self-contradictory.
        if !proof.existence && proof.aux_existence && proof.key == proof.aux_key {
            return false;
        }

        Self::process_proof(proof) == proof.root
    }

    /// Recomputes the root a proof implies, without comparing it to anything.
    pub fn process_proof(proof: &Proof) -> NodeHash {
        let mut computed_hash = if proof.existence {
            H::hash3(&proof.key, &proof.value, &LEAF_MARKER)
        } else if proof.aux_existence {
            H::hash3(&proof.aux_key, &proof.aux_value, &LEAF_MARKER)
        } else {
            ZERO_HASH
        };

        // Trailing zero siblings are padding past the leaf's depth, not real levels. A
        // zero sibling *within* the path is a genuine empty subtree and is kept.
        let mut depth = proof.siblings.len();
        while depth > 0 && proof.siblings[depth - 1] == ZERO_HASH {
            depth -= 1;
        }

        for level in (0..depth).rev() {
            let sibling = &proof.siblings[level];
            let level = u32::try_from(level).expect("depth is bounded by MAX_DEPTH_HARD_CAP");

            computed_hash = if key_bit(&proof.key, level) {
                H::hash2(sibling, &computed_hash)
            } else {
                H::hash2(&computed_hash, sibling)
            };
        }

        computed_hash
    }

    /// Inserts `new_leaf` into the subtree rooted at `node_id`, returning that subtree's
    /// new root identifier.
    ///
    /// The Solidity omits a depth check here: the recursion only descends through middle
    /// nodes, which by construction never sit at the maximum depth, so only
    /// [`SparseMerkleTree::push_leaf`] can exceed it.
    fn add_at(
        &mut self,
        key: Key,
        value: Value,
        node_id: u64,
        current_depth: u32,
    ) -> Result<u64, Error> {
        match self.node(node_id) {
            Node::Empty => Ok(self.alloc_leaf(key, value)),
            Node::Leaf { key: old_key, .. } => {
                if old_key == key {
                    return Err(Error::KeyAlreadyExists(key));
                }

                self.push_leaf(key, value, old_key, node_id, current_depth)
            }
            Node::Middle { left, right, .. } => {
                let (left, right) = if key_bit(&key, current_depth) {
                    (left, self.add_at(key, value, right, current_depth + 1)?)
                } else {
                    (self.add_at(key, value, left, current_depth + 1)?, right)
                };
                self.nodes[node_id as usize] = self.new_middle(left, right);

                Ok(node_id)
            }
        }
    }

    /// Removes `key` from the subtree rooted at `node_id`, returning that subtree's new
    /// root identifier.
    ///
    /// The collapsing below maintains the invariant [`SparseMerkleTree::process_proof`]
    /// depends on: a middle node never keeps a single leaf child and no other. Without it
    /// a leaf could end up with a zero sibling at its own depth, which the trailing-zero
    /// trim would mistake for padding.
    fn remove_at(&mut self, key: Key, node_id: u64, current_depth: u32) -> Result<u64, Error> {
        match self.node(node_id) {
            Node::Empty => Err(Error::NodeDoesNotExist(node_id)),
            Node::Leaf {
                key: current_key, ..
            } => {
                if current_key != key {
                    return Err(Error::LeafDoesNotMatch { current_key, key });
                }
                self.delete_node(node_id);

                Ok(ZERO_IDX)
            }
            Node::Middle {
                mut left,
                mut right,
                ..
            } => {
                let next_node_id = if key_bit(&key, current_depth) {
                    self.remove_at(key, right, current_depth + 1)?
                } else {
                    self.remove_at(key, left, current_depth + 1)?
                };

                let right_node = self.node(right);
                let left_node = self.node(left);

                // Both children are gone: this middle node has nothing left to hold.
                if right_node == Node::Empty && left_node == Node::Empty {
                    self.delete_node(node_id);

                    return Ok(next_node_id);
                }

                let next_node = self.node(next_node_id);
                let one_side_empty = right_node == Node::Empty || left_node == Node::Empty;

                if one_side_empty && !matches!(next_node, Node::Middle { .. }) {
                    // The removal emptied one side and the other side is a lone leaf, so
                    // pull that leaf up in place of this node. Leaving it here would give
                    // it a zero sibling at its own depth, which `process_proof` would
                    // trim away as padding.
                    if next_node == Node::Empty {
                        if let Node::Leaf { .. } = right_node {
                            self.delete_node(node_id);
                            return Ok(right);
                        }
                        if let Node::Leaf { .. } = left_node {
                            self.delete_node(node_id);
                            return Ok(left);
                        }
                    }

                    if right_node == Node::Empty {
                        right = next_node_id;
                    } else {
                        left = next_node_id;
                    }
                }

                self.nodes[node_id as usize] = self.new_middle(left, right);

                Ok(node_id)
            }
        }
    }

    /// Overwrites the value of the leaf holding `key`, rehashing the path back up.
    fn update_at(
        &mut self,
        key: Key,
        new_value: Value,
        node_id: u64,
        current_depth: u32,
    ) -> Result<(), Error> {
        match self.node(node_id) {
            Node::Empty => Err(Error::NodeDoesNotExist(node_id)),
            Node::Leaf {
                key: current_key, ..
            } => {
                if current_key != key {
                    return Err(Error::LeafDoesNotMatch { current_key, key });
                }
                self.nodes[node_id as usize] = self.new_leaf(key, new_value);

                Ok(())
            }
            // The child indices do not change, so rehashing from them picks up whatever
            // the recursive call wrote below.
            Node::Middle { left, right, .. } => {
                if key_bit(&key, current_depth) {
                    self.update_at(key, new_value, right, current_depth + 1)?;
                } else {
                    self.update_at(key, new_value, left, current_depth + 1)?;
                }
                self.nodes[node_id as usize] = self.new_middle(left, right);

                Ok(())
            }
        }
    }

    /// Separates two leaves that share a prefix, descending one level per shared bit.
    ///
    /// Returns the identifier of the middle node now standing where `old_leaf` was.
    fn push_leaf(
        &mut self,
        key: Key,
        value: Value,
        old_key: Key,
        old_leaf_id: u64,
        current_depth: u32,
    ) -> Result<u64, Error> {
        if current_depth >= self.max_depth {
            return Err(Error::MaxDepthReached);
        }

        let new_leaf_bit = key_bit(&key, current_depth);
        let old_leaf_bit = key_bit(&old_key, current_depth);

        // Still on a shared bit, so this level gets a middle node with one empty child.
        if new_leaf_bit == old_leaf_bit {
            let next_node_id =
                self.push_leaf(key, value, old_key, old_leaf_id, current_depth + 1)?;

            return Ok(if new_leaf_bit {
                self.alloc_middle(ZERO_IDX, next_node_id)
            } else {
                self.alloc_middle(next_node_id, ZERO_IDX)
            });
        }

        // The keys diverge here, so both leaves become children of one middle node.
        let new_leaf_id = self.alloc_leaf(key, value);

        Ok(if new_leaf_bit {
            self.alloc_middle(old_leaf_id, new_leaf_id)
        } else {
            self.alloc_middle(new_leaf_id, old_leaf_id)
        })
    }

    /// Builds a leaf with its hash already computed.
    fn new_leaf(&self, key: Key, value: Value) -> Node {
        Node::Leaf {
            key,
            value,
            hash: H::hash3(&key, &value, &LEAF_MARKER),
        }
    }

    /// Builds a middle node, hashing the children's *current* hashes out of the arena.
    fn new_middle(&self, left: u64, right: u64) -> Node {
        Node::Middle {
            left,
            right,
            hash: H::hash2(&self.node(left).hash(), &self.node(right).hash()),
        }
    }

    /// Appends a leaf to the arena and returns its identifier.
    fn alloc_leaf(&mut self, key: Key, value: Value) -> u64 {
        let node = self.new_leaf(key, value);
        self.nodes.push(node);

        self.nodes_allocated()
    }

    /// Appends a middle node to the arena and returns its identifier.
    fn alloc_middle(&mut self, left: u64, right: u64) -> u64 {
        let node = self.new_middle(left, right);
        self.nodes.push(node);

        self.nodes_allocated()
    }

    /// Clears a slot without reusing it, keeping every other identifier valid.
    fn delete_node(&mut self, node_id: u64) {
        self.nodes[node_id as usize] = Node::Empty;
        self.deleted_nodes_count += 1;
    }

    /// The number of identifiers handed out so far, including deleted ones. This is the
    /// Solidity's `nodesCount` field, derived here from the arena instead of stored.
    fn nodes_allocated(&self) -> u64 {
        self.nodes.len() as u64 - 1
    }
}

/// Returns bit `depth` of `key`, counting from the least significant bit of the
/// big-endian encoding.
///
/// This is the Solidity's `(uint256(key) >> depth) & 1 == 1`.
///
/// # Panics
/// Panics if `depth` is 256 or more, which no caller can reach: every walk is bounded by
/// the tree's maximum depth, itself capped at [`MAX_DEPTH_HARD_CAP`].
fn key_bit(key: &Key, depth: u32) -> bool {
    assert!(
        depth < MAX_DEPTH_HARD_CAP,
        "bit index {depth} is out of range"
    );

    let depth = depth as usize;

    (key[31 - depth / 8] >> (depth % 8)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    type Tree = SparseMerkleTree<Sha256>;

    /// A key whose low bits are `bits`, so that tree paths are readable in tests.
    fn key(bits: u32) -> Key {
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&bits.to_be_bytes());
        key
    }

    fn value(byte: u8) -> Value {
        [byte; 32]
    }

    fn leaf_hash(key: Key, value: Value) -> NodeHash {
        Sha256::hash3(&key, &value, &LEAF_MARKER)
    }

    #[test]
    fn reads_key_bits_least_significant_first() {
        // 0b1010 in the low byte.
        let key = key(0b1010);

        assert!(!key_bit(&key, 0));
        assert!(key_bit(&key, 1));
        assert!(!key_bit(&key, 2));
        assert!(key_bit(&key, 3));

        // Bit 255 is the high bit of the first byte.
        let mut high = [0u8; 32];
        high[0] = 0b1000_0000;
        assert!(key_bit(&high, 255));
    }

    #[test]
    fn rejects_out_of_range_max_depth() {
        assert_eq!(Tree::new(0).unwrap_err(), Error::MaxDepthIsZero);
        assert_eq!(
            Tree::new(MAX_DEPTH_HARD_CAP + 1).unwrap_err(),
            Error::MaxDepthExceedsHardCap(MAX_DEPTH_HARD_CAP + 1)
        );
        assert_eq!(
            Tree::new(8).unwrap().set_max_depth(8).unwrap_err(),
            Error::NewMaxDepthMustBeLarger { current: 8, new: 8 }
        );
    }

    /// Pins the exact hash formula against roots computed by hand. Nothing else here
    /// would notice a wrong leaf marker, a swapped `hash_branch` argument order, or an empty
    /// subtree that hashes to something other than a flat zero.
    #[test]
    fn builds_known_roots_by_hand() {
        // Empty.
        let mut tree = Tree::new(8).unwrap();
        assert_eq!(tree.root(), ZERO_HASH);
        assert_eq!(tree.nodes_count(), 0);

        // One leaf: the root is the leaf itself, with no middle node above it.
        tree.add(key(0b000), value(0xaa)).unwrap();
        assert_eq!(tree.root(), leaf_hash(key(0b000), value(0xaa)));
        assert_eq!(tree.nodes_count(), 1);

        // A second key diverging at bit 2, so bits 0 and 1 are shared. Each shared bit
        // adds a middle node whose other child is empty.
        tree.add(key(0b100), value(0xbb)).unwrap();
        let deepest = Sha256::hash2(
            &leaf_hash(key(0b000), value(0xaa)),
            &leaf_hash(key(0b100), value(0xbb)),
        );
        assert_eq!(
            tree.root(),
            Sha256::hash2(&Sha256::hash2(&deepest, &ZERO_HASH), &ZERO_HASH)
        );
        // Two leaves plus three middle nodes.
        assert_eq!(tree.nodes_count(), 5);

        // Divergence at bit 0 instead, so the two leaves are siblings directly under the
        // root and the argument order of `hash_branch` is what distinguishes them.
        let mut flat = Tree::new(8).unwrap();
        flat.add(key(0), value(0xaa)).unwrap();
        flat.add(key(1), value(0xbb)).unwrap();
        assert_eq!(
            flat.root(),
            Sha256::hash2(
                &leaf_hash(key(0), value(0xaa)),
                &leaf_hash(key(1), value(0xbb))
            )
        );
        assert_eq!(flat.nodes_count(), 3);
    }

    #[test]
    fn rejects_a_duplicate_key() {
        let mut tree = Tree::new(8).unwrap();
        tree.add(key(1), value(0xaa)).unwrap();

        assert_eq!(
            tree.add(key(1), value(0xbb)).unwrap_err(),
            Error::KeyAlreadyExists(key(1))
        );
    }

    #[test]
    fn rejects_keys_sharing_more_bits_than_the_max_depth() {
        let mut tree = Tree::new(4).unwrap();
        // Identical in bits 0..=3, diverging only at bit 4.
        tree.add(key(0b0_0000), value(0xaa)).unwrap();

        assert_eq!(
            tree.add(key(0b1_0000), value(0xbb)).unwrap_err(),
            Error::MaxDepthReached
        );
    }

    /// The root is a function of the live key-value set alone: not of the order the keys
    /// arrived in, and not of anything that was added and later removed.
    #[test]
    fn root_depends_only_on_the_current_key_set() {
        let keys: Vec<Key> = (0..16).map(|bits| key(bits * 7 + 3)).collect();
        let populate = |order: &mut dyn Iterator<Item = usize>| {
            let mut tree = Tree::new(16).unwrap();
            for index in order {
                tree.add(keys[index], value(index as u8)).unwrap();
            }
            tree
        };

        let mut forward = populate(&mut (0..keys.len()));
        let backward = populate(&mut (0..keys.len()).rev());
        assert_ne!(forward.root(), ZERO_HASH);
        assert_eq!(forward.root(), backward.root(), "insertion order");

        // An addition undone by a removal leaves no trace.
        let before = forward.root();
        forward.add(key(0xbeef), value(0xcc)).unwrap();
        assert_ne!(forward.root(), before);
        forward.remove(key(0xbeef)).unwrap();
        assert_eq!(forward.root(), before, "add then remove");

        // So does a removal undone by an addition.
        forward.remove(keys[3]).unwrap();
        assert_ne!(forward.root(), before);
        forward.add(keys[3], value(3)).unwrap();
        assert_eq!(forward.root(), before, "remove then add");

        // Removing everything returns the tree to its initial state.
        for entry in &keys {
            forward.remove(*entry).unwrap();
        }
        assert_eq!(forward.root(), ZERO_HASH);
        assert_eq!(forward.nodes_count(), 0);
    }

    #[test]
    fn proves_every_key_it_holds() {
        let mut tree = Tree::new(32).unwrap();
        for bits in 0..64 {
            tree.add(key(bits * 11 + 1), value(bits as u8)).unwrap();
        }

        for bits in 0..64 {
            let proof = tree.proof(key(bits * 11 + 1));

            assert!(proof.existence, "key {bits} should be present");
            assert_eq!(proof.value, value(bits as u8));
            assert!(Tree::verify_proof(&proof));
        }
    }

    #[test]
    fn proves_absence_with_and_without_an_auxiliary_leaf() {
        let mut tree = Tree::new(32).unwrap();
        tree.add(key(0b0001), value(0xaa)).unwrap();
        tree.add(key(0b1001), value(0xbb)).unwrap();

        // Shares bits 0..=2 with key(0b0001), so the walk lands on that leaf.
        let blocked = tree.proof(key(0b1_0001));
        assert!(!blocked.existence);
        assert!(blocked.aux_existence);
        assert_eq!(blocked.aux_key, key(0b0001));
        assert!(Tree::verify_proof(&blocked));

        // Diverges at bit 1, where the subtree is empty.
        let empty = tree.proof(key(0b0011));
        assert!(!empty.existence);
        assert!(!empty.aux_existence);
        assert!(Tree::verify_proof(&empty));
    }

    #[test]
    fn rejects_a_tampered_proof() {
        let mut tree = Tree::new(32).unwrap();
        for bits in 0..32 {
            tree.add(key(bits * 5 + 1), value(bits as u8)).unwrap();
        }

        let good = tree.proof(key(6));
        assert!(good.existence);
        assert!(Tree::verify_proof(&good));

        let mut wrong_value = good.clone();
        wrong_value.value = value(0xff);
        assert!(!Tree::verify_proof(&wrong_value));

        let mut wrong_sibling = good.clone();
        let level = wrong_sibling
            .siblings
            .iter()
            .position(|sibling| *sibling != ZERO_HASH)
            .expect("the proof has at least one real sibling");
        wrong_sibling.siblings[level][0] ^= 1;
        assert!(!Tree::verify_proof(&wrong_sibling));

        let mut wrong_root = good.clone();
        wrong_root.root[0] ^= 1;
        assert!(!Tree::verify_proof(&wrong_root));

        // Recast as an exclusion proof whose auxiliary leaf is the very key it claims is
        // absent. It hashes identically to the inclusion proof, so only the explicit
        // guard in `verify_proof` rejects it.
        let mut self_contradictory = good;
        self_contradictory.existence = false;
        self_contradictory.aux_existence = true;
        self_contradictory.aux_key = self_contradictory.key;
        self_contradictory.aux_value = self_contradictory.value;
        assert!(!Tree::verify_proof(&self_contradictory));
    }

    #[test]
    fn finds_leaves_by_key() {
        let mut tree = Tree::new(8).unwrap();
        tree.add(key(1), value(0xaa)).unwrap();
        tree.add(key(2), value(0xbb)).unwrap();

        assert_eq!(
            tree.node_by_key(key(2)),
            Node::Leaf {
                key: key(2),
                value: value(0xbb),
                hash: leaf_hash(key(2), value(0xbb)),
            }
        );
        assert_eq!(tree.node_by_key(key(3)), Node::Empty);
    }

    #[test]
    fn updating_a_value_changes_the_root_and_the_proof() {
        let mut tree = Tree::new(16).unwrap();
        for bits in 0..8 {
            tree.add(key(bits * 3 + 1), value(bits as u8)).unwrap();
        }
        let before = tree.root();

        tree.update(key(4), value(0xff)).unwrap();

        assert_ne!(tree.root(), before);
        let proof = tree.proof(key(4));
        assert_eq!(proof.value, value(0xff));
        assert!(Tree::verify_proof(&proof));

        tree.update(key(4), value(1)).unwrap();
        assert_eq!(tree.root(), before, "restoring the value restores the root");
    }

    /// Two keys sharing bits 0 and 1, so the tree has middle nodes with empty children
    /// and both failure modes of a walk are reachable.
    fn forked_tree() -> Tree {
        let mut tree = Tree::new(8).unwrap();
        tree.add(key(0b000), value(0xaa)).unwrap();
        tree.add(key(0b100), value(0xbb)).unwrap();

        tree
    }

    /// Both operations that walk to an existing leaf fail the same two ways: the walk
    /// ends on the wrong key, or it runs into an empty subtree.
    #[test]
    fn rejects_operations_on_absent_keys() {
        let mut tree = forked_tree();

        // Bits 0..=2 all clear, so the walk lands on the leaf holding key(0b000).
        assert!(matches!(
            tree.update(key(0b1000), value(0xcc)),
            Err(Error::LeafDoesNotMatch { .. })
        ));
        assert!(matches!(
            tree.remove(key(0b1000)),
            Err(Error::LeafDoesNotMatch { .. })
        ));

        // Bit 0 set, and the root's right child is empty.
        assert!(matches!(
            tree.update(key(0b001), value(0xcc)),
            Err(Error::NodeDoesNotExist(_))
        ));
        assert!(matches!(
            tree.remove(key(0b001)),
            Err(Error::NodeDoesNotExist(_))
        ));
    }

    #[test]
    fn removal_collapses_middles_so_proofs_still_verify() {
        // Keys chosen to share long prefixes, so removals leave chains of single-child
        // middle nodes behind unless they are collapsed.
        let keys: Vec<Key> = (0..16).map(|bits| key(bits << 4)).collect();

        let mut tree = Tree::new(32).unwrap();
        for (index, entry) in keys.iter().enumerate() {
            tree.add(*entry, value(index as u8)).unwrap();
        }

        for (removed, entry) in keys.iter().enumerate() {
            tree.remove(*entry).unwrap();

            for survivor in &keys[removed + 1..] {
                let proof = tree.proof(*survivor);

                assert!(proof.existence, "survivor {survivor:02x?} should remain");
                assert!(
                    Tree::verify_proof(&proof),
                    "proof for {survivor:02x?} must verify after {} removals",
                    removed + 1
                );
            }
        }
    }
}
