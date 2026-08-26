use simplex::either::Either;

use storm_tree::TREE_DEPTH;
use storm_tree::smt::{Sha256, SparseMerkleTree};

use super::covenant::{PaddedStep, fold, pack_proof};

/// Fold length the covenant is compiled for.
pub const WITNESS_DEPTH: usize = TREE_DEPTH as usize;

/// A MuSig2 aggregate key for one signer combination.
pub type Branch = [u8; 32];

/// One fold step, in the shape `AuthWitness` expects.
pub type WitnessStep = Either<(), (bool, [u8; 32])>;

/// A Storm Tree over arbitrary branch bytes.
///
/// `storm_tree::StormTree` derives its branches from real node keys, which makes it
/// awkward to drive from a covenant test; this builds the same tree over whatever
/// branches the test wants. `mirrors_the_real_storm_tree_construction` keeps the two
/// honest.
pub struct StormTree {
    tree: SparseMerkleTree<Sha256>,
    root: [u8; 32],
}

impl StormTree {
    /// # Panics
    /// Panics if the branches cannot be inserted, which means a duplicate or a pair
    /// sharing more than [`TREE_DEPTH`] leading bits.
    pub fn new(branches: &[Branch]) -> Self {
        let mut tree = SparseMerkleTree::new(TREE_DEPTH).expect("TREE_DEPTH is valid");
        for branch in branches {
            tree.add(*branch, *branch).expect("insertion succeeds");
        }
        let root = tree.root();

        Self { tree, root }
    }

    /// The value that goes into storage slot 0.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The inclusion proof for `branch`, packed and padded to [`WITNESS_DEPTH`].
    ///
    /// # Panics
    /// Panics if the branch is absent or the proof is deeper than the covenant allows.
    pub fn witness_proof(&self, branch: &Branch) -> [WitnessStep; WITNESS_DEPTH] {
        pack_witness(&self.tree.proof(*branch), branch, &self.root)
    }
}

/// Packs a proof into the covenant's witness shape.
///
/// # Panics
/// Panics if the proof does not fit [`WITNESS_DEPTH`], or if the packed steps do not fold
/// back to `expected_root`.
pub fn pack_witness(
    proof: &storm_tree::smt::Proof,
    branch: &Branch,
    expected_root: &[u8; 32],
) -> [WitnessStep; WITNESS_DEPTH] {
    let steps = pack_proof(proof, TREE_DEPTH).expect("proof fits the covenant depth");

    assert_eq!(
        &fold(branch, &steps),
        expected_root,
        "packed witness must fold to the expected root"
    );

    steps
        .iter()
        .map(to_witness_step)
        .collect::<Vec<_>>()
        .try_into()
        .expect("pack_proof returns exactly WITNESS_DEPTH steps")
}

fn to_witness_step(step: &PaddedStep) -> WitnessStep {
    match step {
        None => Either::Left(()),
        Some(step) => Either::Right((step.right, step.sibling)),
    }
}

/// Regression test to check if something went wrong, if the original tree changed.
#[test]
fn mirrors_the_real_storm_tree_construction() {
    use simplex::simplicityhl::elements::secp256k1_zkp::{
        Keypair, Secp256k1, SecretKey, XOnlyPublicKey,
    };
    use storm_tree::StormTree as NetworkStormTree;

    let secp = Secp256k1::new();
    let nodes: Vec<[u8; 32]> = (1u8..=3)
        .map(|seed| {
            let secret = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
            let keypair = Keypair::from_secret_key(&secp, &secret);
            XOnlyPublicKey::from_keypair(&keypair).0.serialize()
        })
        .collect();

    let network_tree = NetworkStormTree::new(nodes).expect("valid node set");
    let branches: Vec<Branch> = network_tree.branches().collect();
    let mirror = StormTree::new(&branches);

    assert_eq!(
        mirror.root(),
        network_tree.root(),
        "the mirror must build the same tree as StormTree::new"
    );

    // And a witness packed from the mirror must fold to the real tree's root.
    for branch in &branches {
        let _ = mirror.witness_proof(branch);
    }
}
