use monotree::database::MemoryDB;
use monotree::hasher::Sha2;
use monotree::{Hash, Monotree};

use simplex::either::Either;

use super::covenant::{PaddedStep, fold, pack_proof};

/// Fold length the covenant is compiled for.
/// Later add something like `[StormTreeProofStep; N]` in auth.simf.
pub const WITNESS_DEPTH: usize = 3;

/// A MuSig2 aggregate key for one signer combination.
pub type Branch = [u8; 32];

/// One packed fold step, in the shape `AuthWitness` expects.
pub type WitnessStep = Either<
    (),
    (
        bool,
        (
            ([u8; 32], [u8; 32], u128, u128, u64, u32, u16, u8),
            (bool, bool, bool, bool, bool, bool, bool, bool),
        ),
    ),
>;

pub struct StormTree {
    tree: Monotree<MemoryDB, Sha2>,
    root: Hash,
}

impl StormTree {
    /// # Panics
    /// Panics if the branches cannot be inserted.
    pub fn new(branches: &[Branch]) -> Self {
        let mut tree = Monotree::<MemoryDB, Sha2>::new("contracts-storm-tree");
        let root = tree
            .inserts(None, branches, branches)
            .expect("insertion succeeds")
            .expect("a tree has at least one branch");

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
    pub fn witness_proof(&mut self, branch: &Branch) -> [WitnessStep; WITNESS_DEPTH] {
        let proof = self
            .tree
            .get_merkle_proof(Some(&self.root), branch)
            .expect("proof generation succeeds")
            .expect("branch is in the tree");

        pack_witness(&proof, branch, &self.root)
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
}

/// Packs a raw monotree proof into the covenant's witness shape.
///
/// Shared by the tree built above and by the captured vectors in `fixtures`, so both go
/// through exactly one packing path.
///
/// # Panics
/// Panics if the proof does not fit [`WITNESS_DEPTH`], or if the packed steps do not fold
/// back to `expected_root` — checked here because a mismatch is far easier to diagnose in
/// the test than as a rejected transaction.
pub fn pack_witness(
    proof: &storm_tree::StormTreeProof,
    branch: &Branch,
    expected_root: &[u8; 32],
) -> [WitnessStep; WITNESS_DEPTH] {
    let steps = pack_proof(proof, WITNESS_DEPTH).expect("proof fits the covenant depth");

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
    let Some(step) = step else {
        return Either::Left(());
    };
    let slots = &step.slots;
    let mask = step.mask;

    Either::Right((
        step.right,
        (
            (
                slots.wide_a,
                slots.wide_b,
                slots.half_a,
                slots.half_b,
                slots.eight,
                slots.four,
                slots.two,
                slots.one,
            ),
            (
                mask[0], mask[1], mask[2], mask[3], mask[4], mask[5], mask[6], mask[7],
            ),
        ),
    ))
}
