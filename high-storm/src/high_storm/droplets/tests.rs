use crate::NetworkAsset;
use secp256k1_zkp::SecretKey;
use simplex::simplicityhl::elements::{
    AssetId, BlockHash, LockTime, OutPoint, Transaction, TxIn, TxOut, TxOutSecrets, Txid,
    confidential::{self, AssetBlindingFactor, ValueBlindingFactor},
};

use super::*;

#[test]
fn retries_temporary_signer_branch_failures() {
    assert!(DropletsError::Signing(SigningError::NoAvailableBranch).is_retryable());
    assert!(DropletsError::Signing(SigningError::SigningFailed).is_retryable());
}

#[test]
fn does_not_retry_invalid_exchange_requests() {
    assert!(!DropletsError::Invalid("invalid transaction".into()).is_retryable());
}

fn exchange_fixture() -> (
    PartiallySignedTransaction,
    NetworkAsset,
    SimplicityNetwork,
    [u8; 33],
) {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let network = SimplicityNetwork::ElementsCustom {
        policy_asset,
        genesis_hash: BlockHash::from_byte_array([6; 32]),
    };
    let contract_data = StormEyeContractData {
        storm_tree_root: [3; 32],
        rescue_height: 100,
        rescue_output_script_hash: [4; 32],
    };
    let mut storm_eye = NetworkAsset {
        kind: STORM_EYE_KIND.into(),
        name: "Storm Eye".into(),
        asset_id: [7; 32],
        reissuance_token_id: None,
        entropy: Some([1; 32]),
        issuance_txid: [2; 32],
        contract_script: vec![],
        contract_data: Some(postcard::to_stdvec(&contract_data).unwrap()),
        supply: 10_000,
        created_at_block: 1,
    };
    storm_eye.contract_script = storm_eye_program(&storm_eye)
        .unwrap()
        .get_script_pubkey(&network)
        .into_bytes();
    let treasury_script = TreasuryProgram::new(&TreasuryArguments {
        storm_eye_asset_id: storm_eye.asset_id,
    })
    .get_script_pubkey(&network);
    let leader =
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[1; 32]).unwrap());
    let member = leader.x_only_public_key().0.serialize();
    let explicit_output = |asset, value, script_pubkey| TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey,
        witness: Default::default(),
    };
    let storm_eye_utxo = explicit_output(
        AssetId::from_byte_array(storm_eye.asset_id),
        1,
        Script::from(storm_eye.contract_script.clone()),
    );
    let treasury_utxo = explicit_output(policy_asset, 1_000, treasury_script.clone());
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([10; 32]),
                    vout: 0,
                },
                ..Default::default()
            },
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([11; 32]),
                    vout: 1,
                },
                ..Default::default()
            },
        ],
        output: vec![
            storm_eye_utxo.clone(),
            explicit_output(policy_asset, 600, Script::from(vec![0x51])),
            explicit_output(policy_asset, 400, treasury_script),
            explicit_output(policy_asset, 0, member_script(member)),
        ],
    };
    let mut pset = PartiallySignedTransaction::from_tx(transaction);
    pset.inputs_mut()[0].witness_utxo = Some(storm_eye_utxo);
    pset.inputs_mut()[1].witness_utxo = Some(treasury_utxo);

    (pset, storm_eye, network, leader.serialize())
}

#[test]
fn member_marker_round_trips() {
    let member = [7; 32];

    assert_eq!(member_from_script(&member_script(member)), Some(member));
    assert_eq!(member_from_script(&Script::new_op_return(b"other")), None);
}

#[test]
fn rejects_malformed_member_markers() {
    let mut wrong_version = Vec::from(MEMBER_MAGIC);
    wrong_version.push(MEMBER_VERSION + 1);
    wrong_version.extend_from_slice(&[7; 32]);
    let mut trailing_instruction = member_script([7; 32]).into_bytes();
    trailing_instruction.push(0x00);

    assert_eq!(
        member_from_script(&Script::new_op_return(&wrong_version)),
        None
    );
    assert_eq!(
        member_from_script(&Script::new_op_return(&wrong_version[..34])),
        None
    );
    assert_eq!(
        member_from_script(&Script::from(trailing_instruction)),
        None
    );
}

#[test]
fn validates_exchange_with_treasury_change() {
    let (pset, storm_eye, network, leader) = exchange_fixture();
    let request_hash = signing_hash(&pset, &storm_eye, &network).unwrap();

    let exchange = validate_layout(&pset, request_hash, leader, &storm_eye, &network).unwrap();

    assert_eq!(exchange.amount, 600);
    assert_eq!(
        exchange.member,
        PublicKey::from_slice(&leader)
            .unwrap()
            .x_only_public_key()
            .0
            .serialize()
    );
}

#[test]
fn reads_recipient_amount_from_queued_exchange() {
    let (pset, _, _, _) = exchange_fixture();

    assert_eq!(
        exchange_recipient_amount(&encode::serialize(&pset)).unwrap(),
        600
    );
}

#[test]
fn verifies_exchange_amounts_with_zero_value_member_marker() {
    let (pset, _, _, _) = exchange_fixture();
    let spent_utxos = pset
        .inputs()
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();
    let transaction = pset.extract_tx().unwrap();

    verify_exchange_amounts(&transaction, &spent_utxos).unwrap();
}

#[test]
fn rejects_exchange_for_a_different_member() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    pset.outputs_mut()[3].script_pubkey = member_script([9; 32]);

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("member marker is invalid"));
}

#[test]
fn rejects_exchange_without_one_member_marker() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    pset.outputs_mut()[3].script_pubkey = Script::new_op_return(b"unrelated");

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("identify one recipient"));
}

#[test]
fn rejects_non_lbtc_exchange_outputs() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    pset.outputs_mut()[1].asset = Some(AssetId::from_byte_array([9; 32]));

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("output is not LBTC"));
}

#[test]
fn rejects_confidential_exchange_outputs_with_disclosed_metadata() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    let policy_asset = network.policy_asset();
    let secp = Secp256k1::new();
    let blinding_public_key =
        PublicKey::from_secret_key(&secp, &super::super::assets::treasury_blinding_secret());
    let input_secrets = [TxOutSecrets::new(
        policy_asset,
        AssetBlindingFactor::zero(),
        600,
        ValueBlindingFactor::zero(),
    )];
    let (confidential_output, _, _, _) = TxOut::new_last_confidential(
        &mut secp256k1_zkp::rand::thread_rng(),
        &secp,
        600,
        policy_asset,
        Script::from(vec![0x51]),
        blinding_public_key,
        &input_secrets,
        &[],
    )
    .unwrap();
    let mut output = simplex::simplicityhl::elements::pset::Output::from_txout(confidential_output);
    output.asset = Some(policy_asset);
    output.amount = Some(600);
    pset.outputs_mut()[1] = output;

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("LBTC output must be explicit"));
}

#[test]
fn rejects_non_treasury_funding_inputs() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    pset.inputs_mut()[1]
        .witness_utxo
        .as_mut()
        .unwrap()
        .script_pubkey = Script::from(vec![0x51]);

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("non-Treasury funding input"));
}

#[test]
fn rejects_confidential_treasury_funding_inputs() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    let treasury_utxo = pset.inputs()[1].witness_utxo.as_ref().unwrap();
    let policy_asset = treasury_utxo.asset.explicit().unwrap();
    let treasury_script = treasury_utxo.script_pubkey.clone();
    let secp = Secp256k1::new();
    let blinding_public_key =
        PublicKey::from_secret_key(&secp, &super::super::assets::treasury_blinding_secret());
    let input_secrets = [TxOutSecrets::new(
        policy_asset,
        AssetBlindingFactor::zero(),
        1_000,
        ValueBlindingFactor::zero(),
    )];
    let (confidential_utxo, _, _, _) = TxOut::new_last_confidential(
        &mut secp256k1_zkp::rand::thread_rng(),
        &secp,
        1_000,
        policy_asset,
        treasury_script,
        blinding_public_key,
        &input_secrets,
        &[],
    )
    .unwrap();
    pset.inputs_mut()[1].witness_utxo = Some(confidential_utxo);

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("input asset must be explicit"));
}

#[test]
fn rejects_exchange_that_does_not_conserve_value() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    pset.outputs_mut()[1].amount = Some(601);

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("do not conserve Treasury value"));
}

#[test]
fn rejects_exchange_without_a_recipient() {
    let (mut pset, storm_eye, network, leader) = exchange_fixture();
    pset.outputs_mut()[1].script_pubkey = Script::new();

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("identify one recipient"));
}

#[test]
fn rejects_exchange_with_an_invalid_leader_key() {
    let (pset, storm_eye, network, _) = exchange_fixture();

    let error = validate_layout(&pset, [0; 32], [0; 33], &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("invalid leader public key"));
}

#[test]
fn rejects_exchange_with_a_tampered_signing_hash() {
    let (pset, storm_eye, network, leader) = exchange_fixture();

    let error = validate_layout(&pset, [0; 32], leader, &storm_eye, &network).unwrap_err();

    assert!(error.to_string().contains("signing hash mismatch"));
}
