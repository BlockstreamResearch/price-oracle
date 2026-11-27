use std::collections::BTreeSet;

use simplex::either::Either;
use simplex::fuzz::proptest::collection::vec;
use simplex::fuzz::proptest::prelude::{Just, any};
use simplex::fuzz::proptest::prop_oneof;
use simplex::fuzz::proptest::sample::select;
use simplex::fuzz::proptest::strategy::Strategy;
use simplex::simplicityhl::elements::secp256k1_zkp::{
    Keypair, Secp256k1, SecretKey, XOnlyPublicKey,
};
use simplex::{FuzzMode, TestContext};

use contracts::auth::{Branch, build_tree};
use price_feed::PriceFeedData;
use storm_tree::smt::MerkleTree;

use super::case::{self, Bytes32, Proof};
use super::common::fuzz::{accepts, accepts_signed, rejects, rejects_signed};

fn arb_u32() -> impl Strategy<Value = u32> {
    prop_oneof![select(vec![0, 1, u32::MAX - 1, u32::MAX]), any::<u32>()]
}

fn arb_u64() -> impl Strategy<Value = u64> {
    prop_oneof![select(vec![0, 1, u64::MAX - 1, u64::MAX]), any::<u64>()]
}

fn arb_bytes32() -> impl Strategy<Value = Bytes32> {
    let mut one = [0; 32];
    one[31] = 1;

    prop_oneof![select(vec![[0; 32], one, [u8::MAX; 32]]), any::<Bytes32>()]
}

fn arb_price_feed_data() -> impl Strategy<Value = PriceFeedData> {
    (arb_u32(), arb_u64(), arb_u32(), arb_u64(), arb_u64()).prop_map(
        |(feed_id, price, decimals, received_at, valid_until)| PriceFeedData {
            feed_id,
            price,
            decimals,
            received_at,
            valid_until,
        },
    )
}

/// Adds one to field `field % 5`, wrapping, so each field is shown to reach the hash.
fn bump_field(mut data: PriceFeedData, field: usize) -> PriceFeedData {
    match field % 5 {
        0 => data.feed_id = data.feed_id.wrapping_add(1),
        1 => data.price = data.price.wrapping_add(1),
        2 => data.decimals = data.decimals.wrapping_add(1),
        3 => data.received_at = data.received_at.wrapping_add(1),
        _ => data.valid_until = data.valid_until.wrapping_add(1),
    }
    data
}

fn flip_bit(mut bytes: Bytes32, bit: u8) -> Bytes32 {
    bytes[usize::from(bit / 8)] ^= 1 << (bit % 8);
    bytes
}

fn arb_x_only_key() -> impl Strategy<Value = XOnlyPublicKey> {
    any::<[u8; 32]>()
        .prop_filter_map("valid secret key", |bytes| {
            SecretKey::from_slice(&bytes).ok()
        })
        .prop_map(|secret| {
            Keypair::from_secret_key(&Secp256k1::new(), &secret)
                .x_only_public_key()
                .0
        })
}

/// An x with no curve point, or one at or above the field size.
fn arb_off_curve_x() -> impl Strategy<Value = Bytes32> {
    prop_oneof![Just([0; 32]), Just([u8::MAX; 32]), any::<Bytes32>()]
        .prop_filter("off-curve x", |x| XOnlyPublicKey::from_slice(x).is_err())
}

/// The branches besides the signer's. A tree of 16 leaves is full; 17 adds a level.
fn arb_other_branches() -> impl Strategy<Value = Vec<Branch>> {
    let count = prop_oneof![
        4 => 0usize..=8,
        2 => 9usize..=300,
        1 => select(vec![14usize, 15, 16, 254, 255, 256]),
    ];

    count.prop_flat_map(|count| vec(any::<Branch>(), count))
}

/// The engine signs for the default signer, so that is the branch that must be in the tree.
fn signer_branch(context: &TestContext<FuzzMode>) -> Branch {
    context
        .get_default_signer()
        .get_schnorr_public_key()
        .serialize()
}

fn tree_with(signer: Branch, others: &[Branch]) -> MerkleTree {
    let mut leaves: BTreeSet<Branch> = others.iter().copied().collect();
    leaves.insert(signer);

    build_tree(&leaves.into_iter().collect::<Vec<_>>())
}

/// The levels a proof uses; the rest of the 17 steps are `Left(())` padding.
fn used_steps(proof: &Proof) -> Vec<(bool, Bytes32)> {
    proof
        .iter()
        .filter_map(|step| match step {
            Either::Left(()) => None,
            Either::Right(level) => Some(*level),
        })
        .collect()
}

/// Rewrites the used level `seed % depth` of `branch`'s proof under `tree`.
fn edit_used_level(
    tree: &MerkleTree,
    branch: Branch,
    seed: usize,
    edit: impl FnOnce(&mut Either<(), (bool, Bytes32)>),
) -> case::Case {
    let mut proof = case::proof_in(tree, branch);
    let depth = used_steps(&proof).len();

    edit(&mut proof[seed % depth]);

    case::network_authorization(tree.root(), branch, proof)
}

// 0. storm_eye::storm_tree

#[simplex::fuzz]
fn network_authorization_accepts_a_branch_anywhere_in_the_tree(context: TestContext<FuzzMode>) {
    let signer = signer_branch(&context);

    accepts_signed(
        &context,
        arb_other_branches(),
        move |others| case::network_authorization_in(&tree_with(signer, &others), signer),
        case::storm_eye_signature(),
    );
}

#[simplex::fuzz]
fn network_authorization_rejects_a_flipped_sibling_bit(context: TestContext<FuzzMode>) {
    let signer = signer_branch(&context);

    rejects_signed(
        &context,
        (arb_other_branches(), any::<usize>(), any::<u8>()),
        move |(others, seed, bit)| {
            edit_used_level(&tree_with(signer, &others), signer, seed, |step| {
                if let Either::Right((_, sibling)) = step {
                    *sibling = flip_bit(*sibling, bit);
                }
            })
        },
        case::storm_eye_signature(),
    );
}

#[simplex::fuzz]
fn network_authorization_rejects_a_flipped_direction(context: TestContext<FuzzMode>) {
    let signer = signer_branch(&context);

    rejects_signed(
        &context,
        (arb_other_branches(), any::<usize>()),
        move |(others, seed)| {
            edit_used_level(&tree_with(signer, &others), signer, seed, |step| {
                if let Either::Right((is_right, _)) = step {
                    *is_right = !*is_right;
                }
            })
        },
        case::storm_eye_signature(),
    );
}

#[simplex::fuzz]
fn network_authorization_rejects_a_dropped_level(context: TestContext<FuzzMode>) {
    let signer = signer_branch(&context);

    rejects_signed(
        &context,
        (arb_other_branches(), any::<usize>()),
        move |(others, seed)| {
            edit_used_level(&tree_with(signer, &others), signer, seed, |step| {
                *step = Either::Left(());
            })
        },
        case::storm_eye_signature(),
    );
}

#[simplex::fuzz]
fn network_authorization_rejects_another_root(context: TestContext<FuzzMode>) {
    let signer = signer_branch(&context);

    rejects_signed(
        &context,
        (arb_other_branches(), any::<u8>()),
        move |(others, bit)| {
            let tree = tree_with(signer, &others);

            case::network_authorization(
                flip_bit(tree.root(), bit),
                signer,
                case::proof_in(&tree, signer),
            )
        },
        case::storm_eye_signature(),
    );
}

/// Another branch's proof does not admit the signer, even though both sit in the tree.
#[simplex::fuzz]
fn network_authorization_rejects_another_branchs_proof(context: TestContext<FuzzMode>) {
    let signer = signer_branch(&context);
    let others = arb_other_branches().prop_filter("another branch", move |others| {
        others.iter().any(|other| *other != signer)
    });

    rejects_signed(
        &context,
        others,
        move |others| {
            let tree = tree_with(signer, &others);
            let other = *others
                .iter()
                .find(|other| **other != signer)
                .expect("filtered");

            case::network_authorization(tree.root(), signer, case::proof_in(&tree, other))
        },
        case::storm_eye_signature(),
    );
}

// 1. storm_eye::storage

#[simplex::fuzz]
fn storage_script_hash_matches_the_simplex_storage_layout(context: TestContext<FuzzMode>) {
    accepts(
        &context,
        (arb_bytes32(), arb_u32()),
        |(merkle_root, rescue)| case::storage_script_hash_reference(merkle_root, rescue),
    );
}

#[simplex::fuzz]
fn storage_script_hash_commits_to_both_slots(context: TestContext<FuzzMode>) {
    rejects(
        &context,
        (arb_bytes32(), arb_u32(), any::<bool>(), any::<u8>()),
        |(merkle_root, rescue, change_root, bit)| {
            let expected = case::storage_script_hash_of(merkle_root, rescue);
            let (merkle_root, rescue) = if change_root {
                (flip_bit(merkle_root, bit), rescue)
            } else {
                (merkle_root, rescue ^ (1 << (bit % 32)))
            };

            case::storage_script_hash(merkle_root, rescue, expected)
        },
    );
}

// 2. sdk::voucher_verifier::encode_price_feed_data

#[simplex::fuzz]
fn encode_price_feed_data_matches_the_network_encoding(context: TestContext<FuzzMode>) {
    accepts(
        &context,
        arb_price_feed_data(),
        case::encode_price_feed_data_reference,
    );
}

#[simplex::fuzz]
fn encode_price_feed_data_commits_to_every_field(context: TestContext<FuzzMode>) {
    rejects(
        &context,
        (arb_price_feed_data(), 0usize..5),
        |(data, field)| case::encode_price_feed_data(bump_field(data, field), data.to_bytes()),
    );
}

// 3. sdk::voucher_verifier::get_price_message

#[simplex::fuzz]
fn price_message_matches_what_the_network_signs(context: TestContext<FuzzMode>) {
    accepts(
        &context,
        arb_price_feed_data(),
        case::price_message_reference,
    );
}

#[simplex::fuzz]
fn price_message_commits_to_every_field(context: TestContext<FuzzMode>) {
    rejects(
        &context,
        (arb_price_feed_data(), 0usize..5),
        |(data, field)| {
            case::price_message(
                bump_field(data, field),
                contracts::sdk::SignedPrice::message_for(&data),
            )
        },
    );
}

// 4. lib::taproot

#[simplex::fuzz]
fn p2tr_script_hash_matches_bip341(context: TestContext<FuzzMode>) {
    accepts(
        &context,
        (arb_x_only_key(), arb_bytes32()),
        |(internal_key, tap_node)| case::p2tr_script_hash_reference(internal_key, tap_node),
    );
}

#[simplex::fuzz]
fn p2tr_script_hash_commits_to_the_tap_node(context: TestContext<FuzzMode>) {
    rejects(
        &context,
        (arb_x_only_key(), arb_bytes32(), any::<u8>()),
        |(internal_key, tap_node, bit)| {
            case::p2tr_script_hash(
                internal_key.serialize(),
                flip_bit(tap_node, bit),
                case::p2tr_script_hash_of(internal_key, tap_node),
            )
        },
    );
}

#[simplex::fuzz]
fn p2tr_script_hash_rejects_an_off_curve_key(context: TestContext<FuzzMode>) {
    rejects(
        &context,
        (arb_off_curve_x(), arb_bytes32(), arb_bytes32()),
        |(internal_key, tap_node, expected)| {
            case::p2tr_script_hash(internal_key, tap_node, expected)
        },
    );
}
