//! What the Storm Eye covenant must decide, written from the spec (§1.4) rather than
//! from `auth.simf`, so the fuzz engine can judge every mutated transaction with it.

use simplex::either::Either;
use simplex::fuzz::{Expect, FuzzCase, FuzzProgram};

use contracts::artifacts::auth::AuthProgram;
use contracts::artifacts::auth::derived_auth::AuthWitness;
use contracts::auth::{Branch, WITNESS_DEPTH, WitnessStep};
use storm_tree::smt::{hash_leaf, hash_node};

pub type Bytes32 = [u8; 32];

/// The two storage slots: the Storm Tree root and the rescue block number.
pub type Storage = (Bytes32, u32);

/// The witness arm of paths 1-5, as `AuthKind` in `auth.simf`.
pub type Kind = Either<u32, Either<Either<(Bytes32, u32), (u32, u32)>, Either<u8, u8>>>;

pub type Bloom = ([u8; 64], Branch, [WitnessStep; WITNESS_DEPTH]);

/// The name the covenant is added to every scenario with.
pub const AUTH: &str = "auth";

/// §1.4.3: a rescue block update moves the rescue height three years of minutes ahead.
pub const RESCUE_EXTENSION: u32 = 1_576_800;

/// Slot 1 holds the height widened to 32 bytes, big-endian.
pub fn rescue_slot(rescue_block_number: u32) -> Bytes32 {
    let mut slot = [0; 32];
    slot[28..].copy_from_slice(&rescue_block_number.to_be_bytes());
    slot
}

pub fn storage_slots((merkle_root, rescue_block_number): Storage) -> Vec<Bytes32> {
    vec![merkle_root, rescue_slot(rescue_block_number)]
}

/// The storage a case's covenant is spent with, read back from its slots.
pub fn program_storage(auth: &FuzzProgram<'_, AuthProgram>) -> Storage {
    let slots = auth.storage();
    let height = u32::from_be_bytes(slots[1][28..].try_into().expect("four bytes"));

    (slots[0], height)
}

/// One spend of the covenant, decoded from its witness.
enum Path {
    Inclusion {
        output_index: u32,
    },
    RootUpdate {
        new_merkle_root: Bytes32,
        output_index: u32,
    },
    RescueBlockUpdate {
        new_rescue_block_number: u32,
        output_index: u32,
    },
    Split {
        count: u8,
    },
    Merge {
        count: u8,
    },
    Rescue {
        output_index: u32,
    },
}

impl Path {
    /// The one output a whole Storm Eye moves to, for the paths that name one.
    fn output_index(&self) -> Option<u32> {
        match *self {
            Self::Inclusion { output_index }
            | Self::RootUpdate { output_index, .. }
            | Self::RescueBlockUpdate { output_index, .. }
            | Self::Rescue { output_index } => Some(output_index),
            Self::Split { .. } | Self::Merge { .. } => None,
        }
    }
}

struct Spend {
    storage: Storage,
    bloom: Option<Bloom>,
    path: Path,
}

impl From<&AuthWitness> for Spend {
    fn from(witness: &AuthWitness) -> Self {
        match witness.path {
            Either::Left((storage, bloom, kind)) => {
                let path = match kind {
                    Either::Left(output_index) => Path::Inclusion { output_index },
                    Either::Right(Either::Left(Either::Left((new_merkle_root, output_index)))) => {
                        Path::RootUpdate {
                            new_merkle_root,
                            output_index,
                        }
                    }
                    Either::Right(Either::Left(Either::Right((
                        new_rescue_block_number,
                        output_index,
                    )))) => Path::RescueBlockUpdate {
                        new_rescue_block_number,
                        output_index,
                    },
                    Either::Right(Either::Right(Either::Left(count))) => Path::Split { count },
                    Either::Right(Either::Right(Either::Right(count))) => Path::Merge { count },
                };

                Self {
                    storage,
                    bloom: Some(bloom),
                    path,
                }
            }
            Either::Right((storage, output_index)) => Self {
                storage,
                bloom: None,
                path: Path::Rescue { output_index },
            },
        }
    }
}

/// The spec of every scenario: the case is accepted iff each covenant input is, and no
/// two of them hand their Storm Eyes to the same output.
pub fn expected(case: &FuzzCase<'_>) -> Expect {
    let auth = case.program::<AuthProgram>(AUTH);
    let spend = Spend::from(auth.witness());
    let model = Model {
        case,
        auth: &auth,
        current: auth.script_hash(),
    };

    let accepted = model.one_storm_eye_per_output(&spend)
        && auth
            .inputs()
            .iter()
            .all(|&input| model.accepts(&spend, input));

    if accepted {
        Expect::Accept
    } else {
        Expect::Reject
    }
}

struct Model<'c, 'a> {
    case: &'c FuzzCase<'a>,
    auth: &'c FuzzProgram<'c, AuthProgram>,
    current: Bytes32,
}

impl Model<'_, '_> {
    /// An output may carry one whole Storm Eye. Every input of a scenario's covenant shares
    /// its witness, so two inputs on a path that names an output name the same one.
    fn one_storm_eye_per_output(&self, spend: &Spend) -> bool {
        spend.path.output_index().is_none() || self.auth.inputs().len() == 1
    }

    fn accepts(&self, spend: &Spend, input: usize) -> bool {
        let (merkle_root, rescue_block_number) = spend.storage;

        // Every path first ties the claimed storage to the script being spent.
        if self.script_for(spend.storage) != self.current {
            return false;
        }

        // Paths 1-5 need the default signer's branch under the claimed root; the engine signs.
        if let Some(bloom) = &spend.bloom
            && !self.authorizes(merkle_root, bloom)
        {
            return false;
        }

        match spend.path {
            Path::Inclusion { output_index } => self.moves_whole(input, output_index, self.current),
            Path::RootUpdate {
                new_merkle_root,
                output_index,
            } => self.moves_whole(
                input,
                output_index,
                self.script_for((new_merkle_root, rescue_block_number)),
            ),
            Path::RescueBlockUpdate {
                new_rescue_block_number,
                output_index,
            } => {
                rescue_block_number.checked_add(RESCUE_EXTENSION) == Some(new_rescue_block_number)
                    && self.moves_whole(
                        input,
                        output_index,
                        self.script_for((merkle_root, new_rescue_block_number)),
                    )
            }
            Path::Split { count } => self.splits(input, count),
            Path::Merge { count } => self.merges(input, count),
            Path::Rescue { output_index } => {
                self.case.lock_height() >= rescue_block_number
                    && self.moves_whole(
                        input,
                        output_index,
                        self.auth.arguments().rescue_output_script_hash,
                    )
            }
        }
    }

    fn authorizes(&self, merkle_root: Bytes32, (_, branch, proof): &Bloom) -> bool {
        let signer = self.case.signer().get_schnorr_public_key().serialize();

        let folded = proof
            .iter()
            .fold(hash_leaf(branch), |hash, step| match step {
                Either::Left(()) => hash,
                Either::Right((true, sibling)) => hash_node(sibling, &hash),
                Either::Right((false, sibling)) => hash_node(&hash, sibling),
            });

        *branch == signer && folded == merkle_root
    }

    /// §1.4.1-§1.4.3 and §1.4.6: the whole input, same asset and amount, at one output.
    fn moves_whole(&self, input: usize, output_index: u32, script_hash: Bytes32) -> bool {
        let output = output_index as usize;

        output < self.case.transaction().n_outputs()
            && self.case.output_script_hash(output) == script_hash
            && self.case.output_asset(output) == self.case.input_asset(input)
            && self.case.output_amount(output) == self.case.input_amount(input)
    }

    /// §1.4.4: input 0 into outputs `0..count`, each under the same storage, in the same
    /// asset, adding up to the input.
    fn splits(&self, input: usize, count: u8) -> bool {
        let max = self.auth.arguments().max_split_utxos_count;
        let outputs = usize::from(count);
        let asset = self.case.input_asset(input);

        let total = (0..outputs).try_fold(0u64, |total, output| {
            let same = output < self.case.transaction().n_outputs()
                && self.case.output_script_hash(output) == self.current
                && self.case.output_asset(output) == asset;

            same.then(|| total.checked_add(self.case.output_amount(output)))
                .flatten()
        });

        input == 0 && count > 1 && count < max && total == Some(self.case.input_amount(input))
    }

    /// §1.4.5: inputs `0..count`, each this covenant in the same asset, into output 0.
    fn merges(&self, input: usize, count: u8) -> bool {
        let max = self.auth.arguments().max_merge_utxos_count;
        let inputs = usize::from(count);
        let asset = self.case.input_asset(input);

        let total = (0..inputs).try_fold(0u64, |total, merged| {
            let same = merged < self.case.transaction().n_inputs()
                && self.case.input_script_hash(merged) == self.current
                && self.case.input_asset(merged) == asset;

            same.then(|| total.checked_add(self.case.input_amount(merged)))
                .flatten()
        });

        count > 1
            && count < max
            && input < inputs
            && self.case.transaction().n_outputs() > 0
            && self.case.output_script_hash(0) == self.current
            && total.is_some_and(|total| {
                self.case.output_asset(0) == asset && self.case.output_amount(0) == total
            })
    }

    /// The covenant's script under `storage`, through the Simplex storage layout.
    fn script_for(&self, storage: Storage) -> Bytes32 {
        let mut program = self.auth.program().clone();
        program.set_storage(storage_slots(storage));

        program.get_script_hash(self.case.network())
    }
}
