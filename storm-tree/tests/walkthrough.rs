//! A complete, printed walkthrough of a Storm Tree for any node count.
//!
//!     cargo test -p storm-tree --test walkthrough -- --nocapture
//!
//! Or pick a size directly:
//!
//!     STORM_TREE_NODES=6 cargo test -p storm-tree --test walkthrough custom -- --nocapture

use std::collections::BTreeMap;

use itertools::Itertools;
use monotree::{Hash, Hasher, Node, Proof, hasher::Sha2};
use secp256k1::{Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey, musig::KeyAggCache};
use storm_tree::{NodePublicKey, StormTree, StormTreeBranch};

/// Every node in the tree, recovered from the proofs: hash -> serialized bytes.
type NodeMap = BTreeMap<Hash, Vec<u8>>;
/// Leaf value -> the signer combination it stands for, for labelling the printout.
type LeafLabels = BTreeMap<Hash, String>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn short(bytes: &[u8]) -> String {
    hex(&bytes[..4])
}

/// A, B, C, ... for the network's nodes.
fn label(index: usize) -> String {
    if index < 26 {
        char::from(b'A' + index as u8).to_string()
    } else {
        format!("N{index}")
    }
}

/// The first `n` bits of a key, MSB first, because this is the path monotree walks.
fn bits_of(key: &[u8], n: usize) -> String {
    (0..n)
        .map(|i| {
            if key[i / 8] >> (7 - i % 8) & 1 == 1 {
                '1'
            } else {
                '0'
            }
        })
        .collect()
}

fn node_keys(count: usize) -> Vec<NodePublicKey> {
    (1..=count)
        .map(|value| {
            let secret_key = SecretKey::from_secret_bytes([value as u8; 32]).unwrap();
            let keypair = Keypair::from_secret_key(&secret_key);
            XOnlyPublicKey::from_keypair(&keypair).0.serialize()
        })
        .collect()
}

/// The MuSig2 aggregate key for one combination (the same computation `StormTree::new` runs).
fn aggregate(participants: &[NodePublicKey]) -> StormTreeBranch {
    let public_keys: Vec<PublicKey> = participants
        .iter()
        .map(|key| {
            XOnlyPublicKey::from_byte_array(*key)
                .expect("valid node key")
                .public_key(Parity::Even)
        })
        .collect();
    let refs: Vec<&PublicKey> = public_keys.iter().collect();

    KeyAggCache::new(&refs).agg_pk().serialize()
}

fn preview(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        hex(bytes)
    } else {
        format!("{}..{}", hex(&bytes[..4]), hex(&bytes[bytes.len() - 2..]))
    }
}

fn field(bytes: &[u8], start: usize, end: usize, name: &str, spliced_at: usize) {
    let marker = if start == spliced_at {
        "   <-- the running hash goes here"
    } else {
        ""
    };
    println!(
        "        [{start:>3}..{end:>3}) {name:<8} {}{marker}",
        preview(&bytes[start..end])
    );
}

/// Prints a rebuilt node field by field, marking the 32 bytes that came from the fold.
fn print_layout(bytes: &[u8], spliced_at: usize) {
    let len = bytes.len();

    match Node::from_bytes(bytes).expect("node parses") {
        Node::Soft(cell) => {
            let path = cell.as_ref().expect("soft cell").bits.path.len();
            field(bytes, 0, 32, "hash", spliced_at);
            field(bytes, 32, 34, "range.s", spliced_at);
            field(bytes, 34, 36, "range.e", spliced_at);
            field(bytes, 36, 36 + path, "path", spliced_at);
            field(bytes, len - 1, len, "flag 00", spliced_at);
        }
        Node::Hard(left, right) => {
            let path_l = left.as_ref().expect("left cell").bits.path.len();
            let path_r = right.as_ref().expect("right cell").bits.path.len();
            let offset = 36 + path_l;

            field(bytes, 0, 32, "hash_L", spliced_at);
            field(bytes, 32, 34, "rangeL.s", spliced_at);
            field(bytes, 34, 36, "rangeL.e", spliced_at);
            field(bytes, 36, offset, "path_L", spliced_at);
            field(bytes, offset, offset + 2, "rangeR.s", spliced_at);
            field(bytes, offset + 2, offset + 4, "rangeR.e", spliced_at);
            field(bytes, offset + 4, offset + 4 + path_r, "path_R", spliced_at);
            field(bytes, len - 33, len - 1, "hash_R", spliced_at);
            field(bytes, len - 1, len, "flag 01", spliced_at);
        }
    }
}

/// Rebuilds one node of the trie by splicing the running hash back into its cut.
fn splice(hash: &Hash, right: bool, cut: &[u8]) -> Vec<u8> {
    if right {
        let end = cut.len();
        [&cut[..end - 1], &hash[..], &cut[end - 1..]].concat()
    } else {
        [&hash[..], cut].concat()
    }
}

/// Replays a proof, collecting every node it reconstructs on the way up.
fn collect_nodes(branch: &StormTreeBranch, proof: &Proof, nodes: &mut NodeMap) {
    let hasher = Sha2::new();
    let mut hash: Hash = *branch;

    for (right, cut) in proof.iter().rev() {
        let bytes = splice(&hash, *right, cut);
        hash = hasher.digest(&bytes);
        nodes.insert(hash, bytes);
    }
}

/// Prints the trie from `hash` down. A cell is a pointer if its hash names another node,
/// otherwise the hash is a stored leaf value.
fn print_subtree(nodes: &NodeMap, leaves: &LeafLabels, hash: &Hash, indent: &str) {
    let Some(bytes) = nodes.get(hash) else {
        return;
    };
    let node = Node::from_bytes(bytes).expect("node parses");

    let cells = match &node {
        Node::Soft(cell) => vec![(" ", cell)],
        Node::Hard(left, right) => vec![("0", left), ("1", right)],
    };

    for (index, (bit, cell)) in cells.iter().enumerate() {
        let last = index == cells.len() - 1;
        let glyph = if last { "└──" } else { "├──" };
        let child_indent = format!("{indent}{}", if last { "    " } else { "│   " });

        let Some(unit) = cell else { continue };
        let child: Hash = unit.hash.try_into().expect("32-byte hash");
        let range = &unit.bits.range;

        if nodes.contains_key(&child) {
            println!(
                "{indent}{glyph} {bit} node {}   bits {}..{}",
                short(&child),
                range.start,
                range.end
            );
            print_subtree(nodes, leaves, &child, &child_indent);
        } else {
            let who = leaves
                .get(&child)
                .map(String::as_str)
                .unwrap_or("<unknown>");
            println!(
                "{indent}{glyph} {bit} LEAF {}   bits {}..{}   {who}",
                short(&child),
                range.start,
                range.end
            );
        }
    }
}

fn walkthrough(count: usize) {
    let keys = node_keys(count);

    println!("\n=========== STORM TREE, {count} NODES ===========");

    println!("\n1. THE NETWORK — sorted lexicographically by StormTree::new");
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    for (index, key) in sorted.iter().enumerate() {
        println!("   {} = {}", label(index), hex(key));
    }

    let threshold = StormTree::minimum_threshold(count);
    println!(
        "\n2. THRESHOLD — n - n/3 = {count} - {} = {threshold}",
        count / 3
    );

    println!("\n3. BRANCHES — one MuSig2 aggregate key per combination");
    let mut leaves = LeafLabels::new();
    for participants in sorted.iter().copied().combinations(threshold) {
        let branch = aggregate(&participants);
        let who: String = participants
            .iter()
            .map(|key| label(sorted.iter().position(|k| k == key).unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        let who = format!("{{{who}}}");

        println!(
            "   {who:<20} {}   bits {}",
            hex(&branch),
            bits_of(&branch, 8)
        );
        leaves.insert(branch, who);
    }

    let mut tree = StormTree::new(keys).expect("valid node set");
    let branches: Vec<StormTreeBranch> = tree.branches().collect();
    assert_eq!(branches.len(), leaves.len());

    println!("\n4. INSERTION — key == value == the branch itself.");
    println!("   Position comes from the branch's own bits, never from insertion order.");

    let mut node_map = NodeMap::new();
    let mut proofs = Vec::new();
    for branch in &branches {
        let proof = tree.proof(branch).expect("branch is in the tree");
        collect_nodes(branch, &proof, &mut node_map);
        proofs.push((*branch, proof));
    }
    let max_depth = proofs.iter().map(|(_, proof)| proof.len()).max().unwrap();

    println!(
        "\n5. THE TRIE — {} leaves in {} nodes, deepest proof {max_depth} steps",
        branches.len(),
        node_map.len()
    );
    println!("   root {}", short(&tree.root()));
    print_subtree(&node_map, &leaves, &tree.root(), "   ");

    // Show the deepest proof: that is the one that sets the covenant's DEPTH.
    let (branch, proof) = proofs
        .iter()
        .max_by_key(|(_, proof)| proof.len())
        .expect("at least one branch");

    println!("\n6. THE DEEPEST PROOF — this is what fixes DEPTH");
    println!("   combination {}", leaves[branch]);
    println!("   branch      {}", hex(branch));
    println!("   key bits    {}...", bits_of(branch, 16));

    let hasher = Sha2::new();
    let mut hash: Hash = *branch;
    for (level, (right, cut)) in proof.iter().rev().enumerate() {
        let bytes = splice(&hash, *right, cut);
        let kind = match Node::from_bytes(&bytes) {
            Ok(Node::Soft(_)) => "Soft",
            Ok(Node::Hard(_, _)) => "Hard",
            Err(_) => "?",
        };
        let before = hash;
        hash = hasher.digest(&bytes);

        // Two possible insertion points, and the bool picks between them.
        let spliced_at = if *right { cut.len() - 1 } else { 0 };
        println!(
            "\n   level {level}: right={right}, so splice {} at offset {spliced_at} of the {}B cut",
            short(&before),
            cut.len(),
        );
        println!("        {kind} node, {}B:", bytes.len());
        print_layout(&bytes, spliced_at);
        println!("        sha256(node) = {}", short(&hash));
    }

    assert_eq!(hash, tree.root());
    assert!(StormTree::verify_branch(&tree.root(), branch, proof));
    println!(
        "   result      {} == root, verify_branch agrees",
        short(&hash)
    );
}

#[test]
fn walks_through_a_custom_storm_tree() {
    let count: usize = std::env::var("STORM_TREE_NODES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);

    walkthrough(count);
}
