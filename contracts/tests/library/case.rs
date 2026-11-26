use simplex::constants::DUMMY_SIGNATURE;
use simplex::either::Either;
use simplex::provider::SimplicityNetwork;
use simplex::simplicityhl::elements::Script;
use simplex::simplicityhl::elements::secp256k1_zkp::{Secp256k1, XOnlyPublicKey};
use simplex::simplicityhl::elements::taproot::{TapNodeHash, TapTweakHash};
use simplex::transaction::ProgramSignature;
use simplex::utils::hash_script;

use contracts::artifacts::tests::library::LibraryProgram;
use contracts::artifacts::tests::library::derived_library::{LibraryArguments, LibraryWitness};
use contracts::auth::{Branch, WITNESS_DEPTH, WitnessStep, witness_proof};
use contracts::sdk::SignedPrice;
use price_feed::PriceFeedData;
use storm_tree::smt::MerkleTree;

use super::common::case::DispatchCase;

pub(super) type Bytes32 = [u8; 32];
pub(super) type Proof = [WitnessStep; WITNESS_DEPTH];

/// Dispatch arms of the contract. Each index must match `is_selected(index, ..)` in
/// `simf/tests/library.simf`.
#[derive(Clone, Copy)]
enum FunctionToTest {
    NetworkAuthorization = 0,
    StorageScriptHash = 1,
    EncodePriceFeedData = 2,
    PriceMessage = 3,
    P2trScriptHash = 4,
}

/// The tagged signature `assert_network_authorization` verifies, as `Auth` asks for it.
pub(super) fn storm_eye_signature() -> ProgramSignature {
    ProgramSignature::new("STORM_TREE_BLOOM")
        .at_path(["0"])
        .tagged("OracleNetworkV1/StormEye")
}

// 0. storm_eye::storm_tree

/// Accepted iff `branch` folds through `proof` to `merkle_root` and signed the spend.
pub(super) fn network_authorization(merkle_root: Bytes32, branch: Branch, proof: Proof) -> Case {
    Case::new(FunctionToTest::NetworkAuthorization)
        .merkle_root(merkle_root)
        .bloom(branch, proof)
}

/// `branch`'s proof under `tree`, packed by the same code the nodes use.
pub(super) fn network_authorization_in(tree: &MerkleTree, branch: Branch) -> Case {
    network_authorization(tree.root(), branch, proof_in(tree, branch))
}

pub(super) fn proof_in(tree: &MerkleTree, branch: Branch) -> Proof {
    witness_proof(tree, &branch).expect("the proof fits the covenant depth")
}

// 1. storm_eye::storage

pub(super) fn storage_script_hash(
    merkle_root: Bytes32,
    rescue_block_number: u32,
    expected: Bytes32,
) -> Case {
    Case::new(FunctionToTest::StorageScriptHash)
        .merkle_root(merkle_root)
        .rescue_block_number(rescue_block_number)
        .expect(expected)
}

pub(super) fn storage_script_hash_reference(
    merkle_root: Bytes32,
    rescue_block_number: u32,
) -> Case {
    storage_script_hash(
        merkle_root,
        rescue_block_number,
        storage_script_hash_of(merkle_root, rescue_block_number),
    )
}

/// What Simplex puts on chain for this test program with the Storm Eye's two storage
/// slots, which `get_script_hash_for_storage` must rebuild from the current leaf.
pub(super) fn storage_script_hash_of(merkle_root: Bytes32, rescue_block_number: u32) -> Bytes32 {
    let mut rescue_slot = [0u8; 32];
    rescue_slot[28..].copy_from_slice(&rescue_block_number.to_be_bytes());

    let mut program = LibraryProgram::new(LibraryArguments {}).with_storage_capacity(2);
    program.set_storage_at(0, merkle_root);
    program.set_storage_at(1, rescue_slot);

    hash_script(&program.get_script_pubkey(&SimplicityNetwork::default_regtest()))
}

// 2. sdk::voucher_verifier::encode_price_feed_data

pub(super) fn encode_price_feed_data(data: PriceFeedData, expected: Bytes32) -> Case {
    Case::new(FunctionToTest::EncodePriceFeedData)
        .price_feed_data(data)
        .expect(expected)
}

/// The network's encoding, from the `price-feed` crate.
pub(super) fn encode_price_feed_data_reference(data: PriceFeedData) -> Case {
    encode_price_feed_data(data, data.to_bytes())
}

// 3. sdk::voucher_verifier::get_price_message

pub(super) fn price_message(data: PriceFeedData, expected: Bytes32) -> Case {
    Case::new(FunctionToTest::PriceMessage)
        .price_feed_data(data)
        .expect(expected)
}

/// The message the network signs, from `SignedPrice`.
pub(super) fn price_message_reference(data: PriceFeedData) -> Case {
    price_message(data, SignedPrice::message_for(&data))
}

// 4. lib::taproot

pub(super) fn p2tr_script_hash(
    internal_key: Bytes32,
    tap_node: Bytes32,
    expected: Bytes32,
) -> Case {
    Case::new(FunctionToTest::P2trScriptHash)
        .internal_key(internal_key)
        .tap_node(tap_node)
        .expect(expected)
}

pub(super) fn p2tr_script_hash_reference(internal_key: XOnlyPublicKey, tap_node: Bytes32) -> Case {
    p2tr_script_hash(
        internal_key.serialize(),
        tap_node,
        p2tr_script_hash_of(internal_key, tap_node),
    )
}

/// BIP-341: `OP_1 <internal_key + H_TapTweak(internal_key || tap_node)·G>`, hashed.
pub(super) fn p2tr_script_hash_of(internal_key: XOnlyPublicKey, tap_node: Bytes32) -> Bytes32 {
    let tweak = TapTweakHash::from_key_and_tweak(
        internal_key,
        Some(TapNodeHash::from_byte_array(tap_node)),
    );
    let (output_key, _) = internal_key
        .add_tweak(&Secp256k1::verification_only(), &tweak.to_scalar())
        .expect("a hash is a valid tweak");

    let mut script = vec![0x51, 0x20];
    script.extend(output_key.serialize());

    hash_script(&Script::from(script))
}

#[derive(Clone, Debug)]
pub(super) struct Case {
    witness: LibraryWitness,
}

impl Case {
    fn new(function: FunctionToTest) -> Self {
        Self {
            witness: LibraryWitness {
                function_index: function as u8,
                merkle_root: [0; 32],
                storm_tree_bloom: (DUMMY_SIGNATURE, [0; 32], [Either::Left(()); WITNESS_DEPTH]),
                rescue_block_number: 0,
                price_feed_data: (0, 0, 0, 0, 0),
                internal_key: [0; 32],
                tap_node: [0; 32],
                expected: [0; 32],
            },
        }
    }

    fn merkle_root(mut self, merkle_root: Bytes32) -> Self {
        self.witness.merkle_root = merkle_root;
        self
    }

    /// The signature stays a placeholder: the fuzz engine signs, unit cases skip the check.
    fn bloom(mut self, branch: Branch, proof: Proof) -> Self {
        self.witness.storm_tree_bloom = (DUMMY_SIGNATURE, branch, proof);
        self
    }

    fn rescue_block_number(mut self, rescue_block_number: u32) -> Self {
        self.witness.rescue_block_number = rescue_block_number;
        self
    }

    fn price_feed_data(mut self, data: PriceFeedData) -> Self {
        self.witness.price_feed_data = (
            data.feed_id,
            data.price,
            data.decimals,
            data.received_at,
            data.valid_until,
        );
        self
    }

    fn internal_key(mut self, internal_key: Bytes32) -> Self {
        self.witness.internal_key = internal_key;
        self
    }

    fn tap_node(mut self, tap_node: Bytes32) -> Self {
        self.witness.tap_node = tap_node;
        self
    }

    fn expect(mut self, expected: Bytes32) -> Self {
        self.witness.expected = expected;
        self
    }
}

impl DispatchCase for Case {
    type Program = LibraryProgram;

    const PROGRAM_NAME: &'static str = "library";

    fn arguments() -> LibraryArguments {
        LibraryArguments {}
    }

    fn into_witness(self) -> LibraryWitness {
        self.witness
    }
}
