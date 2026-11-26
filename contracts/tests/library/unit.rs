use simplex::either::Either;
use simplex::simplicityhl::elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey};
use simplex::utils::tr_unspendable_key;

use contracts::auth::{Branch, WITNESS_DEPTH, build_tree};
use contracts::sdk::SignedPrice;
use price_feed::PriceFeedData;

use super::case::{self, Bytes32};
use super::common::case::DispatchCase;
use super::common::unit::Expect::AssertFailed;

fn branches(count: u32) -> Vec<Branch> {
    (0..count)
        .map(|index| {
            let mut branch = [0x42; 32];
            branch[..4].copy_from_slice(&index.to_be_bytes());
            branch
        })
        .collect()
}

fn price() -> PriceFeedData {
    PriceFeedData {
        feed_id: 7,
        price: 9_876_543_210,
        decimals: 8,
        received_at: 1_700_000_000,
        valid_until: 1_700_000_060,
    }
}

// 0. storm_eye::storm_tree

#[test]
fn network_authorization_folds_both_directions() {
    let leaves = branches(3);
    let tree = build_tree(&leaves);

    // Sorted leaves 0 and 2 sit on opposite sides of their pair, so the first level of
    // their proofs takes `is_right` both ways.
    for leaf in [leaves[0], leaves[2]] {
        case::network_authorization_in(&tree, leaf).accepts_unsigned();
    }
}

#[test]
fn network_authorization_folds_a_single_leaf_tree() {
    let leaf = branches(1)[0];

    case::network_authorization_in(&build_tree(&[leaf]), leaf).accepts_unsigned();
}

/// `TREE_DEPTH` levels: the deepest tree a nodes' proof can need.
#[test]
fn network_authorization_folds_the_full_witness_depth() {
    let leaves = branches((1 << (WITNESS_DEPTH - 1)) + 1);
    let tree = build_tree(&leaves);
    let proof = case::proof_in(&tree, leaves[0]);

    assert!(proof.iter().all(Either::is_right), "every level is used");

    case::network_authorization(tree.root(), leaves[0], proof).accepts_unsigned();
}

#[test]
fn network_authorization_rejects_a_branch_outside_the_tree() {
    let leaves = branches(4);
    let tree = build_tree(&leaves[..3]);

    case::network_authorization(tree.root(), leaves[3], case::proof_in(&tree, leaves[0]))
        .rejects_unsigned(AssertFailed);
}

/// A valid proof is not enough: the placeholder signature fails `bip_0340_verify`.
#[test]
fn network_authorization_checks_the_signature() {
    let leaf = branches(1)[0];

    case::network_authorization_in(&build_tree(&[leaf]), leaf).rejects(AssertFailed);
}

// 1. storm_eye::storage

#[test]
fn storage_script_hash_matches_the_simplex_storage_layout() {
    for (merkle_root, rescue) in [
        ([0; 32], 0),
        ([0x5a; 32], 1_576_800),
        ([u8::MAX; 32], u32::MAX),
    ] {
        case::storage_script_hash_reference(merkle_root, rescue).accepts();
    }
}

/// Slot 1 is the height as 28 zero bytes and 4 big-endian ones; a little-endian
/// encoding would build a different script.
#[test]
fn storage_script_hash_reads_the_height_big_endian() {
    let merkle_root = [0x5a; 32];
    let rescue: u32 = 0x0102_0304;

    case::storage_script_hash(
        merkle_root,
        rescue,
        case::storage_script_hash_of(merkle_root, rescue.swap_bytes()),
    )
    .rejects(AssertFailed);
}

// 2. sdk::voucher_verifier::encode_price_feed_data

#[test]
fn encode_price_feed_data_lays_fields_out_big_endian() {
    let expected: Bytes32 = [
        0, 0, 0, 7, // feed_id
        0, 0, 0, 8, // decimals
        0, 0, 0, 2, 0x4c, 0xb0, 0x16, 0xea, // price
        0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x00, // received_at
        0, 0, 0, 0, 0x65, 0x53, 0xf1, 0x3c, // valid_until
    ];

    case::encode_price_feed_data(price(), expected).accepts();
    case::encode_price_feed_data_reference(price()).accepts();
}

// 3. sdk::voucher_verifier::get_price_message

#[test]
fn price_message_matches_what_the_network_signs() {
    case::price_message_reference(price()).accepts();
}

#[test]
fn price_message_is_not_the_plain_encoding() {
    case::price_message(price(), price().to_bytes()).rejects(AssertFailed);
}

/// A signature over the message verifies, which is what consumers rely on.
#[test]
fn price_message_is_what_bip340_signers_sign() {
    let keypair = Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[0x11; 32]).expect("valid secret"),
    );
    let message = SignedPrice::message_for(&price());
    let signed = SignedPrice::new(
        price(),
        keypair.x_only_public_key().0.serialize(),
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(
                &simplex::simplicityhl::elements::secp256k1_zkp::Message::from_digest(message),
                &keypair,
            )
            .serialize(),
    );

    assert_eq!(signed.verify(), Ok(()));
    case::price_message(price(), message).accepts();
}

// 4. lib::taproot

#[test]
fn p2tr_script_hash_matches_bip341() {
    case::p2tr_script_hash_reference(tr_unspendable_key(), [0x33; 32]).accepts();
}

#[test]
fn p2tr_script_hash_rejects_an_off_curve_key() {
    // x = 0: `0³ + 7` is not a square mod p.
    case::p2tr_script_hash([0; 32], [0x33; 32], [0; 32]).rejects(AssertFailed);
}
