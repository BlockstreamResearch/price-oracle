use simplex::{either::Either, transaction::RequiredSignature};

use crate::{
    artifacts::auth::derived_auth::AuthWitness,
    auth::{storage::StormEyeStorage, storm_tree::StormTreeBloom},
};

/// The witness arm selecting a spending path, mirroring `AuthKind` in `auth.simf`.
type AuthKindRaw = Either<u32, Either<Either<([u8; 32], u32), (u32, u32)>, Either<u8, u8>>>;

/// One of the Storm Eye covenant's five network-authorized spending paths (spec
/// §1.4.1-§1.4.5). Every one of them needs the same [`StormTreeBloom`] proof; the §1.4.6
/// rescue path is separate because it needs neither a signature nor a proof.
#[derive(Debug, Clone, Copy)]
pub enum AuthSpendPath {
    /// 1. Spent in full, storage left unchanged.
    Inclusion { output_index: u32 },
    /// 2. Spent in full, rotating the Storm Tree root.
    RootUpdate {
        new_merkle_root: [u8; 32],
        output_index: u32,
    },
    /// 3. Spent in full, rotating the rescue block number.
    RescueBlockUpdate {
        new_rescue_block_number: u32,
        output_index: u32,
    },
    /// 4. Split into `split_utxos_count` UTXOs under the same storage.
    Split { split_utxos_count: u8 },
    /// 5. `utxos_to_merge` Storm Eyes merged into output 0.
    Merge { utxos_to_merge: u8 },
}

impl AuthSpendPath {
    /// The tagged witness path every authorized spend shares.
    #[must_use]
    pub fn required_signature() -> RequiredSignature {
        RequiredSignature::witness_tagged(
            "PATH",
            vec!["Left".to_string(), "1".to_string(), "0".to_string()],
            "OracleNetworkV1/StormEye",
        )
    }

    pub(crate) fn build_witness(
        self,
        storage: StormEyeStorage,
        bloom: StormTreeBloom,
    ) -> AuthWitness {
        let kind: AuthKindRaw = match self {
            Self::Inclusion { output_index } => Either::Left(output_index),
            Self::RootUpdate {
                new_merkle_root,
                output_index,
            } => Either::Right(Either::Left(Either::Left((new_merkle_root, output_index)))),
            Self::RescueBlockUpdate {
                new_rescue_block_number,
                output_index,
            } => Either::Right(Either::Left(Either::Right((
                new_rescue_block_number,
                output_index,
            )))),
            Self::Split { split_utxos_count } => {
                Either::Right(Either::Right(Either::Left(split_utxos_count)))
            }
            Self::Merge { utxos_to_merge } => {
                Either::Right(Either::Right(Either::Right(utxos_to_merge)))
            }
        };

        AuthWitness {
            path: Either::Left((
                (storage.merkle_root, storage.rescue_block_number),
                (bloom.signature, bloom.branch, bloom.proof),
                kind,
            )),
        }
    }
}

pub(crate) fn build_rescue_witness(storage: StormEyeStorage, output_index: u32) -> AuthWitness {
    AuthWitness {
        path: Either::Right((
            (storage.merkle_root, storage.rescue_block_number),
            output_index,
        )),
    }
}
