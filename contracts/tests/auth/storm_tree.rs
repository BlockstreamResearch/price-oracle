use monotree::database::MemoryDB;
use monotree::hasher::Sha2;
use monotree::{Hash, Monotree};
use simplex::either::Either;
use super::covenant::{PaddedStep, fold, pack_proof};

/// Fold length the covenant is compiled for.
/// Later `[StormTreeProofStep; N]` in auth.simf.
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

        let steps = pack_proof(&proof, WITNESS_DEPTH).expect("proof fits the covenant depth");

        // Checked here rather than on-chain: if this disagrees the covenant will too, and
        // failing in the test is far easier to diagnose than a rejected transaction.
        assert_eq!(
            fold(branch, &steps),
            self.root,
            "packed witness must fold to the stored root"
        );

        steps
            .iter()
            .map(to_witness_step)
            .collect::<Vec<_>>()
            .try_into()
            .expect("pack_proof returns exactly WITNESS_DEPTH steps")
    }
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
