use super::*;
use crate::NodeMessageKind;
use secp256k1::{PublicKey, SecretKey};
use simplex::simplicityhl::elements::{
    BlockHash, LockTime, OutPoint, Transaction, TxIn, confidential,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storm_eye_scan_ignores_foreign_and_confidential_outputs() {
    use serde_json::json;

    let storm_eye_asset = AssetId::from_byte_array([7; 32]);
    let storm_eye = NetworkAsset {
        kind: crate::db::network_asset::STORM_EYE_KIND.into(),
        name: "Storm Eye".into(),
        asset_id: [7; 32],
        reissuance_token_id: None,
        entropy: None,
        issuance_txid: [1; 32],
        contract_script: vec![0x51],
        contract_data: None,
        supply: 10_000,
        created_at_block: 1,
    };
    let genuine = Txid::from_byte_array([2; 32]);
    let dust = Txid::from_byte_array([3; 32]);
    let confidential = Txid::from_byte_array([4; 32]);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
            let result = match request["method"].as_str().unwrap() {
                "scantxoutset" => json!({ "unspents": [
                    { "txid": genuine.to_string(), "vout": 0, "asset": storm_eye_asset.to_string() },
                    { "txid": dust.to_string(), "vout": 0, "asset": AssetId::from_byte_array([8; 32]).to_string() },
                    { "txid": confidential.to_string(), "vout": 0 },
                ] }),
                "gettxout" => {
                    assert_eq!(request["params"][0], json!(genuine.to_string()));
                    json!({
                        "confirmations": 1,
                        "asset": storm_eye_asset.to_string(),
                        "value": 0.00001667,
                        "scriptPubKey": { "hex": "51" },
                    })
                }
                method => panic!("unexpected RPC method: {method}"),
            };
            async move {
                axum::Json(json!({ "id": request["id"], "result": result, "error": null }))
            }
        }),
    );
    let (address, server) = crate::test_support::serve(app).await;
    let result = tokio::task::spawn_blocking(move || {
        let client =
            Client::new(&format!("http://{address}"), bitcoincore_rpc::Auth::None).unwrap();
        for utxos in [
            scan_storm_eye_utxos(&client, &storm_eye),
            scan_storm_eye_utxos_ignoring_mempool(&client, &storm_eye),
        ] {
            let utxos = utxos.unwrap();
            assert_eq!(utxos.len(), 1);
            assert_eq!(utxos[0].outpoint, OutPoint::new(genuine, 0));
        }
    })
    .await;
    server.abort();
    result.unwrap();
}

#[test]
fn confirmation_uses_header_height_only_for_a_canonical_hash() {
    assert_eq!(
        canonical_confirmation(3, 42, [7; 32], [7; 32]),
        Some(TransactionConfirmation {
            confirmations: 3,
            block_height: 42,
            block_hash: [7; 32],
        })
    );
    assert_eq!(canonical_confirmation(3, 42, [7; 32], [8; 32]), None);
}

#[test]
fn executing_votes_override_proposed_reservations() {
    let shared = StormEyeUtxo {
        txid: [1; 32],
        output_index: 2,
    };
    let proposed = stored_reshape([3; 32], shared, false, None);
    let executing = stored_reshape([4; 32], shared, true, None);
    let broadcast = stored_reshape([5; 32], shared, true, Some([6; 32]));
    let executed = stored_reshape([7; 32], shared, false, Some([8; 32]));

    let reservations = storm_eye_reservations(&[proposed, executing, broadcast, executed]).unwrap();
    let reservation = reservations.get(&shared).unwrap();

    assert_eq!(reservation.state, StormEyeState::Executing);
    assert_eq!(
        reservation.voting_request_hashes,
        vec![[3; 32], [4; 32], [5; 32]]
    );
}

#[test]
fn interrupted_execution_remains_retryable() {
    let mut executing = stored_member_update([8; 32], [9; 32]);
    executing.execution_started = true;
    executing.execution_transaction = Some(vec![1, 2, 3]);

    assert!(require_retryable(&executing).is_ok());
    assert!(matches!(
        require_approved_or_executing(&executing, &[4, 5, 6]),
        Err(VotingExecutionError::AlreadyExecuting)
    ));
}

#[test]
fn execution_requires_approval_and_cannot_repeat_after_broadcast_or_finality() {
    let mut vote = stored_member_update([8; 32], [9; 32]);
    vote.approved_at_block_height = None;

    assert!(matches!(
        require_retryable(&vote),
        Err(VotingExecutionError::NotApproved)
    ));
    assert!(matches!(
        require_approved_or_executing(&vote, &[1, 2, 3]),
        Err(VotingExecutionError::NotApproved)
    ));

    vote.approved_at_block_height = Some(2);
    assert!(require_retryable(&vote).is_ok());
    assert!(require_approved_or_executing(&vote, &[1, 2, 3]).is_ok());

    vote.execution_started = true;
    vote.execution_transaction = Some(vec![1, 2, 3]);
    assert!(require_approved_or_executing(&vote, &[1, 2, 3]).is_ok());

    vote.execution_txid = Some([10; 32]);
    assert!(matches!(
        require_retryable(&vote),
        Err(VotingExecutionError::AlreadyExecuting)
    ));
    assert!(matches!(
        require_approved_or_executing(&vote, &[1, 2, 3]),
        Err(VotingExecutionError::AlreadyExecuting)
    ));

    vote.execution_confirmed = true;
    assert!(matches!(
        require_retryable(&vote),
        Err(VotingExecutionError::AlreadyExecuted)
    ));
    assert!(matches!(
        require_approved_or_executing(&vote, &[1, 2, 3]),
        Err(VotingExecutionError::AlreadyExecuted)
    ));
}

#[test]
fn verifies_amounts_with_zero_value_member_marker() {
    let asset = AssetId::from_byte_array([8; 32]);
    let spent_utxo = TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(1_000),
        script_pubkey: Script::from(vec![0x51]),
        ..Default::default()
    };
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![
            TxOut {
                asset: confidential::Asset::Explicit(asset),
                value: confidential::Value::Explicit(1_000),
                script_pubkey: Script::new(),
                ..Default::default()
            },
            TxOut {
                asset: confidential::Asset::Explicit(asset),
                value: confidential::Value::Explicit(0),
                script_pubkey: member_script([7; 32]),
                ..Default::default()
            },
        ],
    };

    verify_voting_amounts(&transaction, &[spent_utxo]).unwrap();
}

#[test]
fn requires_one_signature_and_hash_per_storm_eye_input() {
    assert!(has_signature_per_input(1, 1, 1));
    assert!(has_signature_per_input(2, 2, 2));
    assert!(!has_signature_per_input(1, 1, 2));
    assert!(!has_signature_per_input(2, 1, 2));
}

#[test]
fn member_update_derives_target_root_and_root_update_witness() {
    let member = |byte| {
        PublicKey::from_secret_key(&SecretKey::from_secret_bytes([byte; 32]).unwrap())
            .x_only_public_key()
            .0
            .serialize()
    };
    let current = [member(1), member(2), member(3)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let target = [member(1), member(3), member(4)]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let stored = stored_member_update(member(4), member(2));

    let operation = decode_operation(&stored, &current).unwrap();
    let expected_root = StormTree::new(target.clone()).unwrap().root();
    assert!(matches!(
        &operation,
        ReshapeOperation::UpdateMembers { members, new_root }
            if members == &target && *new_root == expected_root
    ));

    let witness = placeholder_witness(
        &StormEyeContractData {
            storm_tree_root: [8; 32],
            rescue_height: 42,
            rescue_output_script_hash: [9; 32],
        },
        &operation,
        2,
    );
    assert!(matches!(
        witness.path,
        Either::Left((
            (old_root, rescue_height),
            (signature, branch, proof),
            Either::Right(Either::Left(Either::Left((root, 2))))
        )) if old_root == [8; 32]
            && rescue_height == 42
            && root == expected_root
            && signature == [0; 64]
            && branch == [8; 32]
            && proof.iter().all(|step| matches!(step, Either::Left(())))
    ));
}

#[test]
fn member_update_migrates_every_storm_eye_to_the_new_root() {
    let member = |byte| {
        PublicKey::from_secret_key(&SecretKey::from_secret_bytes([byte; 32]).unwrap())
            .x_only_public_key()
            .0
            .serialize()
    };
    let members = [member(1), member(2), member(3)];
    let new_root = StormTree::new(members.to_vec()).unwrap().root();
    let network = SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_byte_array([10; 32]),
        genesis_hash: BlockHash::from_byte_array([11; 32]),
    };
    let mut storm_eye = NetworkAsset {
        kind: STORM_EYE_KIND.to_string(),
        name: "Storm Eye".to_string(),
        asset_id: [12; 32],
        reissuance_token_id: None,
        entropy: None,
        issuance_txid: [13; 32],
        contract_script: Vec::new(),
        contract_data: Some(
            postcard::to_stdvec(&StormEyeContractData {
                storm_tree_root: [14; 32],
                rescue_height: 42,
                rescue_output_script_hash: [15; 32],
            })
            .unwrap(),
        ),
        supply: 10_000,
        created_at_block: 1,
    };
    storm_eye.contract_script = storm_eye_program(&storm_eye)
        .unwrap()
        .get_script_pubkey(&network)
        .into_bytes();
    let storm_asset = AssetId::from_byte_array(storm_eye.asset_id);
    let old_script = Script::from(storm_eye.contract_script.clone());
    let storm_utxo = |byte, output_index, amount| UTXO {
        outpoint: OutPoint::new(Txid::from_byte_array([byte; 32]), output_index),
        txout: TxOut {
            asset: confidential::Asset::Explicit(storm_asset),
            value: confidential::Value::Explicit(amount),
            script_pubkey: old_script.clone(),
            ..Default::default()
        },
        secrets: None,
    };
    let treasury = TreasuryProgram::new(&TreasuryArguments {
        storm_eye_asset_id: storm_eye.asset_id,
    });
    let treasury_utxo = UTXO {
        outpoint: OutPoint::new(Txid::from_byte_array([16; 32]), 0),
        txout: TxOut {
            asset: confidential::Asset::Explicit(network.policy_asset()),
            value: confidential::Value::Explicit(2_000),
            script_pubkey: treasury.get_script_pubkey(&network),
            ..Default::default()
        },
        secrets: None,
    };

    let prepared = build_transaction(
        [17; 32],
        ReshapeOperation::UpdateMembers {
            members: members.to_vec(),
            new_root,
        },
        storm_eye.clone(),
        vec![storm_utxo(18, 0, 4_000), storm_utxo(19, 1, 6_000)],
        vec![treasury_utxo],
        network,
        500,
    )
    .unwrap();
    let destination = migrated_storm_eye_script(&storm_eye, new_root, &network).unwrap();

    assert_eq!(prepared.storm_eye_inputs, 2);
    assert_eq!(prepared.pset.outputs()[0].amount, Some(4_000));
    assert_eq!(prepared.pset.outputs()[1].amount, Some(6_000));
    assert_eq!(prepared.pset.outputs()[0].script_pubkey, destination);
    assert_eq!(prepared.pset.outputs()[1].script_pubkey, destination);
    assert_eq!(
        prepared
            .pset
            .outputs()
            .iter()
            .filter(|output| {
                !output.script_pubkey.is_empty() && output.script_pubkey.is_provably_unspendable()
            })
            .count(),
        1
    );
    assert!(prepared.pset.outputs().iter().any(|output| {
        output.amount == Some(0)
            && output.script_pubkey == migrated_members_script(&members, [17; 32]).unwrap()
    }));
    // The Storm Eyes come first, then the Treasury input deferring to input 0.
    let inputs = prepared.transaction.inputs();
    assert_eq!(inputs.len(), 3);
    assert_eq!(
        inputs[0].partial_input.outpoint.txid,
        Txid::from_byte_array([18; 32])
    );
    assert_eq!(
        inputs[1].partial_input.outpoint.txid,
        Txid::from_byte_array([19; 32])
    );
    assert_eq!(
        inputs[2].partial_input.outpoint.txid,
        Txid::from_byte_array([16; 32])
    );
    assert_eq!(
        inputs[2].partial_input.witness_utxo.script_pubkey,
        treasury.get_script_pubkey(&network)
    );
    assert_eq!(
        inputs[2].program_input.as_ref().unwrap().witness,
        simplex::simplicityhl::WitnessValues::from(
            contracts::artifacts::treasury::derived_treasury::TreasuryWitness {
                storm_eye_input_index: 0,
            }
        )
    );
}

fn stored_reshape(
    message_hash: [u8; 32],
    outpoint: StormEyeUtxo,
    execution_started: bool,
    execution_txid: Option<[u8; 32]>,
) -> StoredVotingRequest {
    let request = crate::NetworkVoteRequest::new(
        NetworkVoteKind::SplitStormEye,
        &SplitStormEye {
            utxo_to_split: outpoint,
            number_of_splits: 2,
        },
    )
    .unwrap();
    let message = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request).unwrap();

    StoredVotingRequest {
        message_hash,
        message: postcard::to_allocvec(&message).unwrap(),
        proposer_public_key: Some([7; 32]),
        block_height: 1,
        approved_at_block_height: None,
        execution_started,
        execution_transaction: execution_started.then(Vec::new),
        execution_request: None,
        execution_txid,
        execution_confirmed: execution_txid.is_some() && !execution_started,
        approvals: Vec::new(),
    }
}

fn stored_member_update(accepted: [u8; 32], removed: [u8; 32]) -> StoredVotingRequest {
    let request = crate::NetworkVoteRequest::new(
        NetworkVoteKind::UpdateNetworkMembers,
        &UpdateNetworkMembers {
            to_accept: vec![accepted],
            to_remove: vec![removed],
        },
    )
    .unwrap();
    let message = NodeMessage::new(NodeMessageKind::NetworkVoteRequest, None, &request).unwrap();

    StoredVotingRequest {
        message_hash: [6; 32],
        message: postcard::to_allocvec(&message).unwrap(),
        proposer_public_key: Some([7; 32]),
        block_height: 1,
        approved_at_block_height: Some(2),
        execution_started: false,
        execution_transaction: None,
        execution_request: None,
        execution_txid: None,
        execution_confirmed: false,
        approvals: Vec::new(),
    }
}
