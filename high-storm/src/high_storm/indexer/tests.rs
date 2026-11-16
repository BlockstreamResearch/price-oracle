use super::*;
use bitcoincore_rpc::Auth;
use secp256k1_zkp::PublicKey;
use simplex::simplicityhl::elements::{
    Script, TxOut, TxOutSecrets, Txid,
    confidential::{self, AssetBlindingFactor, ValueBlindingFactor},
};

#[test]
fn finalized_member_migration_replays_only_for_lagging_active_cursors() {
    let asset = NetworkAsset {
        kind: STORM_EYE_KIND.into(),
        name: "Storm Eye".into(),
        asset_id: [1; 32],
        reissuance_token_id: None,
        entropy: None,
        issuance_txid: [2; 32],
        contract_script: vec![0x52],
        contract_data: Some(vec![4; 32]),
        supply: 10_000,
        created_at_block: 1,
    };
    let migration = FinalizedMemberMigration {
        request_hash: [5; 32],
        block_height: 387,
        block_hash: [6; 32],
        asset_kind: STORM_EYE_KIND.into(),
        previous_script: vec![0x51],
        previous_data: Some(vec![3; 32]),
        next_script: asset.contract_script.clone(),
        next_data: asset.contract_data.clone(),
        previous_members: vec![],
        next_members: vec![],
    };
    for (issued, droplets, halted, expected) in [
        (Some(386), Some(386), false, true),
        (None, Some(387), false, true),
        (Some(387), None, false, true),
        (Some(387), Some(386), false, true),
        (Some(386), Some(387), true, true),
        (Some(387), Some(387), false, false),
        (Some(388), Some(388), false, false),
        (Some(387), Some(386), true, false),
        (Some(387), None, true, false),
    ] {
        assert_eq!(
            member_migration_requires_replay(
                &asset,
                std::slice::from_ref(&migration),
                issued,
                droplets,
                halted,
            ),
            expected,
            "issued={issued:?}, droplets={droplets:?}, halted={halted}",
        );
    }
    for mismatched in [
        NetworkAsset {
            kind: TICK_ASSET_KIND.into(),
            ..asset.clone()
        },
        NetworkAsset {
            contract_script: migration.previous_script.clone(),
            ..asset.clone()
        },
        NetworkAsset {
            contract_data: migration.previous_data.clone(),
            ..asset.clone()
        },
    ] {
        assert!(!member_migration_requires_replay(
            &mismatched,
            std::slice::from_ref(&migration),
            Some(386),
            Some(386),
            false,
        ));
    }
}

#[test]
fn verifies_initial_members_of_the_storm_eye_issuance() {
    use crate::high_storm::assets::{StormEyeContractData, initial_members_script};
    use simplex::simplicityhl::elements::LockTime;

    let members = [1u8, 2, 3]
        .map(|byte| {
            secp256k1_zkp::Keypair::from_seckey_slice(&Secp256k1::new(), &[byte; 32])
                .unwrap()
                .x_only_public_key()
                .0
                .serialize()
        })
        .to_vec();
    let issuance = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            script_pubkey: initial_members_script(&members).unwrap(),
            ..Default::default()
        }],
    };
    let with_root = |root| crate::NetworkAsset {
        kind: STORM_EYE_KIND.into(),
        name: "Storm Eye".into(),
        asset_id: [1; 32],
        reissuance_token_id: None,
        entropy: None,
        issuance_txid: hex::decode(issuance.txid().to_string())
            .unwrap()
            .try_into()
            .unwrap(),
        contract_script: vec![0x51],
        contract_data: Some(
            postcard::to_stdvec(&StormEyeContractData {
                storm_tree_root: root,
                rescue_height: 1,
                rescue_output_script_hash: [0; 32],
            })
            .unwrap(),
        ),
        supply: 10_000,
        created_at_block: 1,
    };
    let genesis = with_root(StormTree::new(members.clone()).unwrap().root());
    let transactions = std::slice::from_ref(&issuance);

    verify_initial_members(transactions, &genesis, &members).unwrap();
    assert!(verify_initial_members(transactions, &genesis, &members[..2]).is_err());
    // A member that joined after a migration it holds no record of.
    verify_initial_members(transactions, &with_root([7; 32]), &members[..2]).unwrap();
}

#[test]
fn public_entropy_matching_does_not_require_a_network_reissuance() {
    use simplex::simplicityhl::elements::{AssetEntropy, AssetIssuance, TxIn};

    let public_entropy = [21; 32];
    let input = TxIn {
        asset_issuance: AssetIssuance {
            asset_entropy: AssetEntropy::from_byte_array(public_entropy),
            amount: confidential::Value::Explicit(1),
            ..Default::default()
        },
        ..Default::default()
    };

    assert_eq!(
        input.asset_issuance.asset_entropy.to_byte_array(),
        public_entropy
    );
    assert_ne!(
        input.issuance_ids().0,
        AssetId::from_entropy(AssetEntropy::from_byte_array(public_entropy))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pegin_and_new_issuance_candidates_are_rejected_without_rpc() {
    use serde_json::json;
    use simplex::simplicityhl::elements::{
        AssetBlindingNonce, AssetEntropy, AssetIssuance, LockTime, TxIn,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let network = SimplicityNetwork::LiquidTestnet;
    let asset = crate::NetworkAsset {
        kind: TICK_ASSET_KIND.into(),
        name: "Tick".into(),
        asset_id: [8; 32],
        reissuance_token_id: Some([9; 32]),
        entropy: Some([21; 32]),
        issuance_txid: [2; 32],
        contract_script: vec![0x51],
        contract_data: None,
        supply: 0,
        created_at_block: 1,
    };
    let storm_eye = crate::NetworkAsset {
        kind: STORM_EYE_KIND.into(),
        asset_id: [7; 32],
        ..asset.clone()
    };
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![explicit_output(
            network.policy_asset(),
            1_000,
            Script::new(),
        )],
    };
    let candidate = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                is_pegin: true,
                ..Default::default()
            },
            TxIn {
                asset_issuance: AssetIssuance {
                    asset_entropy: AssetEntropy::from_byte_array(asset.entropy.unwrap()),
                    amount: confidential::Value::Explicit(1),
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
        output: vec![previous.output[0].clone(), previous.output[0].clone()],
    };
    let previous_hex = hex::encode(encode::serialize(&previous));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
            observed_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request["method"], "getrawtransaction");
            let response = if request["params"][0] == Txid::from_byte_array([0; 32]).to_string() {
                json!({ "result": null, "error": { "code": -5,
                    "message": "No such mempool or blockchain transaction" } })
            } else {
                json!({ "result": previous_hex, "error": null })
            };
            async move {
                axum::Json(json!({ "id": request["id"],
                "result": response["result"], "error": response["error"] }))
            }
        }),
    );
    let (address, server) = crate::high_storm::test_rpc::serve(app).await;
    let result = tokio::task::spawn_blocking(move || {
        let client = Client::new(&format!("http://{address}"), Auth::None).unwrap();
        let mut unrelated = candidate.clone();
        unrelated.input[1].asset_issuance.asset_entropy = AssetEntropy::from_byte_array([22; 32]);
        assert!(
            issuance_tokens(&client, &unrelated, &storm_eye, &[&asset])
                .unwrap()
                .is_none()
        );
        assert!(
            issuance_tokens(&client, &candidate, &storm_eye, &[&asset])
                .unwrap()
                .is_none()
        );

        let mut ordinary = candidate;
        ordinary.input[0].is_pegin = false;
        ordinary.input[0].previous_output.txid = previous.txid();
        ordinary.input[0].previous_output.vout = 0;
        assert!(
            issuance_tokens(&client, &ordinary, &storm_eye, &[&asset])
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let mut reissuance = ordinary.clone();
        reissuance.input[1].asset_issuance.asset_blinding_nonce =
            AssetBlindingNonce::from_byte_array([1; 32]);
        assert!(
            issuance_tokens(&client, &reissuance, &storm_eye, &[&asset])
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let mut pegin_reissuance = reissuance;
        pegin_reissuance.input[0].is_pegin = true;
        assert!(
            issuance_tokens(&client, &pegin_reissuance, &storm_eye, &[&asset])
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    })
    .await;
    server.abort();
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifies_a_locked_exchange_from_its_inputs_and_confirmations() {
    use serde_json::json;
    use simplex::simplicityhl::elements::{LockTime, OutPoint, TxIn};

    let spent_input = Txid::from_byte_array([1; 32]);
    let exchange = |input: Txid, vout: u32| Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: input, vout },
            ..Default::default()
        }],
        output: vec![],
    };
    let confirmed = exchange(spent_input, 1);
    let confirmed_txid = confirmed.txid().to_string();
    let observed_txid = confirmed_txid.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
            let (result, error) = match request["method"].as_str().unwrap() {
                "gettxout" => {
                    assert_eq!(request["params"][2], json!(false));
                    if request["params"][0] == spent_input.to_string() {
                        (json!(null), json!(null))
                    } else {
                        (json!({ "confirmations": 3 }), json!(null))
                    }
                }
                "getrawtransaction" if request["params"][0] == observed_txid => {
                    (json!({ "confirmations": 1 }), json!(null))
                }
                "getrawtransaction" => (
                    json!(null),
                    json!({ "code": -5, "message": "No such mempool or blockchain transaction" }),
                ),
                method => panic!("unexpected RPC method: {method}"),
            };
            async move {
                axum::Json(json!({ "id": request["id"], "result": result, "error": error }))
            }
        }),
    );
    let (address, server) = crate::high_storm::test_rpc::serve(app).await;
    let result = tokio::task::spawn_blocking(move || {
        let client = Client::new(&format!("http://{address}"), Auth::None).unwrap();
        let pending = exchange(Txid::from_byte_array([3; 32]), 0);
        let conflicted = exchange(spent_input, 0);
        let in_mempool = vec![conflicted.txid().to_string()];

        assert_eq!(
            exchange_chain_state(&client, &pending, &[]).unwrap(),
            ExchangeChainState::Pending
        );
        assert_eq!(
            exchange_chain_state(&client, &conflicted, &[]).unwrap(),
            ExchangeChainState::Conflicted
        );
        // Its own confirmation spent the input: settled by indexing, not a conflict.
        assert_eq!(
            exchange_chain_state(&client, &confirmed, &[]).unwrap(),
            ExchangeChainState::Known
        );
        assert_eq!(
            exchange_chain_state(&client, &conflicted, &in_mempool).unwrap(),
            ExchangeChainState::Known
        );
    })
    .await;
    server.abort();
    result.unwrap();
}

#[test]
fn collects_spent_outpoints_from_a_block() {
    let previous = simplex::simplicityhl::elements::OutPoint {
        txid: Txid::from_byte_array([1; 32]),
        vout: 7,
    };
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![simplex::simplicityhl::elements::TxIn {
            previous_output: previous,
            ..Default::default()
        }],
        output: vec![],
    };
    let spending_txid = transaction.txid().to_byte_array();

    assert_eq!(
        spent_monitored_outpoints(&[transaction]),
        vec![([1; 32], 7, spending_txid)]
    );
}

#[test]
fn rejects_a_block_that_does_not_extend_the_indexed_parent() {
    require_parent_hash(Some([3; 32]), [3; 32], 42).unwrap();
    require_parent_hash(None, [4; 32], 42).unwrap();

    assert!(matches!(
        require_parent_hash(Some([3; 32]), [4; 32], 42),
        Err(IndexerError::Reorganization { height: 42 })
    ));
}

#[test]
fn accepts_chain_growth_only_when_the_original_target_remains_canonical() {
    assert!(target_tip_is_canonical(43, 42, [3; 32], [3; 32]));
    assert!(!target_tip_is_canonical(41, 42, [3; 32], [3; 32]));
    assert!(!target_tip_is_canonical(43, 42, [4; 32], [3; 32]));
}

#[test]
fn recognizes_only_the_complete_storm_eye_supply_at_one_script() {
    let asset_bytes = [7; 32];
    let asset = AssetId::from_byte_array(asset_bytes);
    let storm_eye = crate::NetworkAsset {
        kind: STORM_EYE_KIND.into(),
        name: "Storm Eye".into(),
        asset_id: asset_bytes,
        reissuance_token_id: None,
        entropy: None,
        issuance_txid: [2; 32],
        contract_script: vec![0x51],
        contract_data: None,
        supply: 10_000,
        created_at_block: 1,
    };
    let complete = vec![
        explicit_output(asset, 4_000, Script::from(vec![0x51])),
        explicit_output(asset, 6_000, Script::from(vec![0x51])),
    ];

    assert!(matches_storm_eye_supply(&complete, &storm_eye).unwrap());

    let partial = vec![explicit_output(asset, 9_999, Script::from(vec![0x51]))];
    assert!(!matches_storm_eye_supply(&partial, &storm_eye).unwrap());

    let split_scripts = vec![
        explicit_output(asset, 4_000, Script::from(vec![0x51])),
        explicit_output(asset, 6_000, Script::from(vec![0x52])),
    ];
    assert!(!matches_storm_eye_supply(&split_scripts, &storm_eye).unwrap());
}

#[test]
fn recovers_locked_exchanges_according_to_leadership_and_chain_state() {
    use ExchangeChainState::{Conflicted, Known, Pending};

    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let transaction_bytes = encode::serialize(&transaction);
    let pset_bytes = encode::serialize(&PartiallySignedTransaction::from_tx(transaction.clone()));
    let txid = transaction.txid().to_string();
    let balance = |last_tx| DropletBalance {
        xonly_pubkey: [1; 32],
        amount: 100,
        block_height: 10,
        exchange_locked: true,
        last_tx,
    };
    let recover = |last_tx: &Vec<u8>, block_height, is_leader, chain| {
        let exchange = locked_exchange(last_tx);
        exchange_recovery(
            &balance(Some(last_tx.clone())),
            block_height,
            is_leader,
            exchange.as_ref(),
            chain,
        )
    };

    assert_eq!(
        exchange_recovery(&balance(None), 10, true, None, Pending),
        ExchangeRecovery::Unlock
    );
    assert_eq!(
        recover(&vec![1, 2], 10, true, Pending),
        ExchangeRecovery::Keep
    );
    assert_eq!(
        recover(&vec![1, 2], 11, true, Pending),
        ExchangeRecovery::Unlock
    );

    assert_eq!(
        locked_exchange(&pset_bytes),
        Some((transaction.clone(), false))
    );
    assert_eq!(
        locked_exchange(&transaction_bytes),
        Some((transaction, true))
    );
    for is_leader in [false, true] {
        // A signer that never saw the broadcast keeps its lock while the exchange can confirm.
        assert_eq!(
            recover(&pset_bytes, 50, is_leader, Pending),
            ExchangeRecovery::Keep
        );
        for last_tx in [&pset_bytes, &transaction_bytes] {
            assert_eq!(
                recover(last_tx, 50, is_leader, Known),
                ExchangeRecovery::Keep
            );
            assert_eq!(
                recover(last_tx, 50, is_leader, Conflicted),
                ExchangeRecovery::Unlock
            );
        }
    }
    assert_eq!(
        recover(&transaction_bytes, 11, false, Pending),
        ExchangeRecovery::Keep
    );
    assert_eq!(
        recover(&transaction_bytes, 11, true, Pending),
        ExchangeRecovery::Rebroadcast {
            transaction: transaction_bytes.clone(),
            txid,
        }
    );
}

#[test]
fn extracts_tagged_treasury_deposits_and_spends() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let member = [7; 32];
    let deposit = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(policy_asset, 1_000, treasury_script.clone()),
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script(member),
            ),
        ],
    };
    let deposit_txid = deposit.txid().to_byte_array();
    let spend = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![simplex::simplicityhl::elements::TxIn {
            previous_output: simplex::simplicityhl::elements::OutPoint {
                txid: Txid::from_byte_array(deposit_txid),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![explicit_output(
            policy_asset,
            0,
            super::super::droplets::member_script(member),
        )],
    };

    let extracted =
        treasury_transactions(&[deposit, spend], &treasury_script, policy_asset).unwrap();

    assert_eq!(extracted[0].outputs, vec![(0, 1_000)]);
    assert_eq!(extracted[0].deposit_member, Some(member));
    assert_eq!(extracted[1].inputs, vec![(deposit_txid, 0)]);
    assert!(extracted[1].outputs.is_empty());
    assert_eq!(extracted[1].exchange_member, Some(member));
}

#[test]
fn skips_malformed_third_party_member_markers() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let mut poisoned = Vec::from(*b"OM");
    poisoned.push(2);
    poisoned.extend_from_slice(&u16::MAX.to_be_bytes());
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![explicit_output(
            policy_asset,
            0,
            Script::new_op_return(&poisoned),
        )],
    };

    let extracted = treasury_transactions(&[transaction], &treasury_script, policy_asset).unwrap();

    assert!(extracted[0].outputs.is_empty());
    assert_eq!(extracted[0].deposit_member, None);
    assert_eq!(extracted[0].exchange_member, None);
}

#[test]
fn ignores_confidential_lbtc_treasury_deposits() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let member = [7; 32];
    let confidential_output = confidential_output(
        policy_asset,
        1_000,
        treasury_script.clone(),
        treasury_blinding_secret(),
    );
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![
            confidential_output,
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script(member),
            ),
        ],
    };

    let extracted = treasury_transactions(&[transaction], &treasury_script, policy_asset).unwrap();

    assert!(extracted[0].outputs.is_empty());
    assert_eq!(extracted[0].deposit_member, None);
}

#[test]
fn ignores_treasury_outputs_blinded_for_a_foreign_key() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let foreign_secret = secp256k1_zkp::SecretKey::from_slice(&[1; 32]).unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![confidential_output(
            policy_asset,
            1_000,
            treasury_script.clone(),
            foreign_secret,
        )],
    };

    let extracted = treasury_transactions(&[transaction], &treasury_script, policy_asset).unwrap();

    assert!(extracted[0].outputs.is_empty());
}

#[test]
fn ignores_conflicting_member_markers_without_treasury_activity() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script([1; 32]),
            ),
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script([2; 32]),
            ),
        ],
    };

    let extracted = treasury_transactions(&[transaction], &treasury_script, policy_asset).unwrap();

    assert!(extracted[0].inputs.is_empty());
    assert!(extracted[0].outputs.is_empty());
    assert_eq!(extracted[0].deposit_member, None);
    assert_eq!(extracted[0].exchange_member, None);
}

#[test]
fn applies_deposit_tag_only_to_the_immediately_preceding_treasury_output() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let member = [7; 32];
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(policy_asset, 1_000, treasury_script.clone()),
            explicit_output(policy_asset, 1, Script::new()),
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script(member),
            ),
        ],
    };

    let extracted = treasury_transactions(&[transaction], &treasury_script, policy_asset).unwrap();

    assert_eq!(extracted[0].outputs, vec![(0, 1_000)]);
    assert_eq!(extracted[0].deposit_member, None);
    assert_eq!(extracted[0].exchange_member, Some(member));
}

#[test]
fn leaves_conflicting_treasury_markers_unassigned() {
    let policy_asset = AssetId::from_byte_array([8; 32]);
    let treasury_script = Script::from(vec![0x51]);
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(policy_asset, 1_000, treasury_script.clone()),
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script([1; 32]),
            ),
            explicit_output(
                policy_asset,
                0,
                super::super::droplets::member_script([2; 32]),
            ),
        ],
    };

    let extracted = treasury_transactions(&[transaction], &treasury_script, policy_asset).unwrap();

    assert_eq!(extracted[0].deposit_member, Some([1; 32]));
    assert_eq!(extracted[0].exchange_member, None);
}

fn network_asset(kind: &str, asset_id: u8) -> crate::NetworkAsset {
    crate::NetworkAsset {
        kind: kind.into(),
        name: kind.into(),
        asset_id: [asset_id; 32],
        reissuance_token_id: None,
        entropy: Some([asset_id; 32]),
        issuance_txid: [2; 32],
        contract_script: vec![0x51],
        contract_data: None,
        supply: 0,
        created_at_block: 1,
    }
}

#[test]
fn indexes_confirmed_ticks_and_verifiers_with_their_account_reserves() {
    /// x of the secp256k1 generator, a valid signing branch.
    const SIGNER: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];
    let tick = network_asset(TICK_ASSET_KIND, 9);
    let verifier = network_asset(ORACLE_VERIFIER_KIND, 10);
    let tick_asset = AssetId::from_byte_array(tick.asset_id);
    let verifier_asset = AssetId::from_byte_array(verifier.asset_id);
    let network = SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_byte_array([8; 32]),
        genesis_hash: BlockHash::from_byte_array([6; 32]),
    };
    let storm_eye = network_asset(STORM_EYE_KIND, 7);
    let descriptors = [
        IssuedUtxoDescriptor {
            output_index: 3,
            reserve_output_index: 6,
            account_owner_pubkey: [4; 32],
            auth_kind: 2,
            auth_data: [5; 32],
            signer: None,
        },
        IssuedUtxoDescriptor {
            output_index: 4,
            reserve_output_index: 7,
            account_owner_pubkey: [6; 32],
            auth_kind: 2,
            auth_data: [7; 32],
            signer: Some(SIGNER),
        },
        IssuedUtxoDescriptor {
            output_index: 5,
            reserve_output_index: 7,
            account_owner_pubkey: [6; 32],
            auth_kind: 2,
            auth_data: [7; 32],
            signer: None,
        },
    ];
    let scripts = descriptors.each_ref().map(|descriptor| {
        descriptor
            .voucher_program(storm_eye.asset_id)
            .unwrap()
            .get_script_pubkey(&network)
    });
    let account_scripts = [[4; 32], [6; 32]].map(|owner| {
        AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: owner,
        })
        .get_script_pubkey(&network)
    });
    let reissuance = |amount| {
        let mut input = simplex::simplicityhl::elements::TxIn::default();
        input.asset_issuance.amount = confidential::Value::Explicit(amount);
        input
    };
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![
            simplex::simplicityhl::elements::TxIn::default(),
            reissuance(3_400_000_001),
            reissuance(1),
        ],
        output: vec![
            explicit_output(AssetId::from_byte_array([8; 32]), 1, Script::new()),
            explicit_output(AssetId::from_byte_array([8; 32]), 1, Script::new()),
            explicit_output(AssetId::from_byte_array([8; 32]), 1, Script::new()),
            explicit_output(tick_asset, 1_700_000_000, scripts[0].clone()),
            explicit_output(verifier_asset, 1, scripts[1].clone()),
            explicit_output(tick_asset, 1_700_000_001, scripts[2].clone()),
            explicit_output(network.policy_asset(), 1_000, account_scripts[0].clone()),
            explicit_output(network.policy_asset(), 2_000, account_scripts[1].clone()),
            explicit_output(
                network.policy_asset(),
                0,
                IssuedUtxoDescriptor::script_pubkey(&descriptors).unwrap(),
            ),
        ],
    };
    let txid = transaction.txid();
    let tokens = [&tick, &verifier];

    let indexed = indexed_issued_outputs(&transaction, 42, &storm_eye, &tokens, &network).unwrap();

    assert_eq!(indexed.len(), 3);
    assert_eq!(indexed[0].txid, txid.to_byte_array());
    assert_eq!(indexed[0].output_index, 3);
    assert_eq!(indexed[0].asset_kind, TICK_ASSET_KIND);
    assert_eq!(indexed[0].internal_key, None);
    assert_eq!(indexed[0].account_owner_pubkey, [4; 32]);
    assert_eq!(indexed[0].auth_data, vec![5; 32]);
    assert_eq!(indexed[0].burning_fee_txid, txid.to_byte_array());
    assert_eq!(indexed[0].burning_fee_output_index, 6);
    assert_eq!(indexed[1].output_index, 4);
    assert_eq!(indexed[1].asset_kind, ORACLE_VERIFIER_KIND);
    assert_eq!(indexed[1].amount, 1);
    assert_eq!(indexed[1].internal_key, Some(SIGNER));
    assert_eq!(indexed[1].account_owner_pubkey, [6; 32]);
    assert_eq!(indexed[1].burning_fee_output_index, 7);
    assert_eq!(indexed[2].output_index, 5);
    assert_eq!(indexed[2].asset_kind, TICK_ASSET_KIND);

    let mut missing_descriptor = transaction.clone();
    missing_descriptor.output.pop();
    assert!(
        indexed_issued_outputs(&missing_descriptor, 42, &storm_eye, &tokens, &network).is_err()
    );

    let mut valued_descriptor = transaction.clone();
    valued_descriptor.output[8].value = confidential::Value::Explicit(1);
    assert!(indexed_issued_outputs(&valued_descriptor, 42, &storm_eye, &tokens, &network).is_err());

    // A Verifier is always one unit.
    let mut two_unit_verifier = transaction.clone();
    two_unit_verifier.output[4].value = confidential::Value::Explicit(2);
    two_unit_verifier.input[2] = reissuance(2);
    assert!(indexed_issued_outputs(&two_unit_verifier, 42, &storm_eye, &tokens, &network).is_err());

    // Wrong internal key.
    let mut foreign_key = transaction.clone();
    foreign_key.output[4].script_pubkey = scripts[0].clone();
    assert!(indexed_issued_outputs(&foreign_key, 42, &storm_eye, &tokens, &network).is_err());

    // No Verifier token reissued.
    assert!(indexed_issued_outputs(&transaction, 42, &storm_eye, &[&tick], &network).is_err());
}

fn explicit_output(asset: AssetId, amount: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(amount),
        script_pubkey,
        ..Default::default()
    }
}

fn confidential_output(
    asset: AssetId,
    amount: u64,
    script_pubkey: Script,
    blinding_secret: secp256k1_zkp::SecretKey,
) -> TxOut {
    let secp = Secp256k1::new();
    let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
    let input_secrets = [TxOutSecrets::new(
        asset,
        AssetBlindingFactor::zero(),
        amount,
        ValueBlindingFactor::zero(),
    )];
    TxOut::new_last_confidential(
        &mut secp256k1_zkp::rand::thread_rng(),
        &secp,
        amount,
        asset,
        script_pubkey,
        blinding_public_key,
        &input_secrets,
        &[],
    )
    .unwrap()
    .0
}
