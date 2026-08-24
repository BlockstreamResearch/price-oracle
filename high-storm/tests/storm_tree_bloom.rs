//! Generates real StormTreeBloom witness data from a live Oracle Network.
//!
//!     cargo test -p high-storm --test storm_tree_bloom -- --nocapture --test-threads=1
//!
//! Add `STORM_TREE_VERBOSE=1` for the node-by-node replay of each proof step.

mod common;

use std::time::Duration;

use storm_tree::{NodePublicKey, StormTree, StormTreeBranch, StormTreeProof, StormTreeRoot};
use tokio::time::timeout;

use common::TestNetwork;

/// Stands in for `jet::sig_all_hash()`. The network signs whatever 32 bytes it is handed,
/// so the covenant's sighash drops in here unchanged once the transaction exists.
const MESSAGE_HASH: [u8; 32] = [0x42; 32];

/// Everything `assert_network_authorization(merkle_root, bloom)` consumes.
pub struct BloomWitness {
    /// Storage slot 0 of the Storm Eye covenant.
    pub root: StormTreeRoot,
    /// Bloom field 1: the aggregate signature over `MESSAGE_HASH`.
    pub signature: [u8; 64],
    /// Bloom field 2: the MuSig2 aggregate key of the combination that signed.
    pub branch: StormTreeBranch,
    /// Bloom field 3: the inclusion proof of `branch` under `root`.
    pub proof: StormTreeProof,
    /// Not part of the Bloom (the nodes behind `branch`).
    signers: Vec<NodePublicKey>,
}

/// Starts a network, has node 0 request a signature, and assembles the witness.
///
/// Three steps, only the first of which needs live nodes: the network signs, then the
/// Storm Tree is recomputed locally (it is deterministic), then the proof is packed.
async fn collect_bloom(count: usize) -> (String, BloomWitness) {
    let mut network = TestNetwork::start(count).await;

    let result = timeout(
        Duration::from_secs(10),
        network.nodes[0].sign_test(vec![MESSAGE_HASH]),
    )
    .await
    .expect("signing timed out")
    .expect("signing failed");

    let mut tree = StormTree::new(network.node_keys()).expect("valid node set");
    let branch = result.signing_storm_tree_branch;
    let signers = tree
        .nodes_for_branch(&branch)
        .expect("the signing branch belongs to the tree")
        .to_vec();
    let proof = tree.proof(&branch).expect("branch is in the tree");

    let signed_by = format!(
        "{{{}}}",
        signers
            .iter()
            .map(|signer| network.label(signer))
            .collect::<Vec<_>>()
            .join(",")
    );
    let header = format!(
        "\n=== {count}-node network, threshold {} of {count}, {} branches ===\nsigned by      : {signed_by}",
        tree.threshold(),
        tree.branches().len(),
    );

    network.shutdown().await;
    println!("{header}");

    (
        signed_by,
        BloomWitness {
            root: tree.root(),
            signature: result.signatures[0],
            branch,
            proof,
            signers,
        },
    )
}

/// Prints the Bloom, and checks the proof reaches the stored root.
fn report((_signed_by, bloom): (String, BloomWitness)) {
    if verbose() {
        replay(&bloom);
    }

    println!("\n--- StormTreeBloom ---");
    println!(
        "merkle_root  (storage slot 0) : {}",
        hex::encode(bloom.root)
    );
    println!(
        "signature    (Signature, 64B) : {}",
        hex::encode(bloom.signature)
    );
    println!(
        "branch       (Pubkey,    32B) : {}",
        hex::encode(bloom.branch)
    );
    println!("proof        ({} steps, root-first)", bloom.proof.len());
    for (index, (right, cut)) in bloom.proof.iter().enumerate() {
        println!(
            "  [{index}] right={right:<5} cut={:>3}B  {}",
            cut.len(),
            hex::encode(cut)
        );
    }

    assert!(
        StormTree::verify_branch(&bloom.root, &bloom.branch, &bloom.proof),
        "the proof must reach the stored root"
    );
    println!("  verify_branch agrees");
}

/// Walks the unpacked proof, showing each node monotree reconstructs.
fn replay(bloom: &BloomWitness) {
    use monotree::{Hash, Hasher, Node, hasher::Sha2};

    println!("signers        :");
    for signer in &bloom.signers {
        println!("    {}", hex::encode(signer));
    }
    println!("proof          : {} steps", bloom.proof.len());
    println!(
        "    start           {}  <- the branch itself",
        hex::encode(bloom.branch)
    );

    let hasher = Sha2::new();
    let mut hash: Hash = bloom.branch;
    for (level, (right, cut)) in bloom.proof.iter().rev().enumerate() {
        let node = if *right {
            let end = cut.len();
            [&cut[..end - 1], &hash[..], &cut[end - 1..]].concat()
        } else {
            [&hash[..], &cut[..]].concat()
        };
        let kind = match Node::from_bytes(&node) {
            Ok(Node::Soft(_)) => "Soft",
            Ok(Node::Hard(_, _)) => "Hard",
            Err(_) => "?",
        };
        hash = hasher.digest(&node);
        println!(
            "    level {level}: right={right:<5} cut={:>3}B -> {kind} node {:>3}B -> {}",
            cut.len(),
            node.len(),
            hex::encode(hash),
        );
    }
}

/// Diagnostics are off unless asked for: STORM_TREE_VERBOSE=1.
fn verbose() -> bool {
    std::env::var("STORM_TREE_VERBOSE").is_ok()
}

#[tokio::test]
async fn generates_a_bloom_from_a_three_node_network() {
    report(collect_bloom(3).await);
}

#[tokio::test]
async fn generates_a_bloom_from_a_five_node_network() {
    report(collect_bloom(5).await);
}
