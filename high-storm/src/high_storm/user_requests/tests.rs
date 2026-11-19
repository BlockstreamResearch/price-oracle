use super::*;
use crate::high_storm::utxo::{
    matches_expected_asset, matches_scanned_asset, storm_eye_pool_index,
};
use bitcoincore_rpc::Auth;
use secp256k1::{Keypair, SecretKey, schnorr};

const NOW: u64 = 1_700_000_000;
const LBTC_USDT: FeedId = 4;
const SIBLING: [u8; 32] = [3; 32];

#[tokio::test]
async fn mempool_spender_supports_missing_rpc_without_hiding_other_errors() {
    use simplex::simplicityhl::elements::{LockTime, Transaction, TxIn};
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    let outpoint = OutPoint::new(Txid::from_byte_array([1; 32]), 2);
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            ..Default::default()
        }],
        output: vec![],
    };
    let txid = transaction.txid();
    let missing = serde_json::json!({"code": -32601, "message": "Method not found"});
    let unavailable = serde_json::json!({"code": -5, "message": "No such mempool transaction"});
    let failure = serde_json::json!({"code": -1, "message": "RPC failure"});
    let cases = vec![
        (
            vec![
                (
                    "gettxspendingprevout",
                    serde_json::Value::Null,
                    missing.clone(),
                ),
                (
                    "getrawmempool",
                    serde_json::json!([txid]),
                    serde_json::Value::Null,
                ),
                (
                    "getrawtransaction",
                    serde_json::json!(hex::encode(encode::serialize(&transaction))),
                    serde_json::Value::Null,
                ),
            ],
            Ok(Some(txid)),
        ),
        (
            vec![
                (
                    "gettxspendingprevout",
                    serde_json::Value::Null,
                    missing.clone(),
                ),
                (
                    "getrawmempool",
                    serde_json::json!([]),
                    serde_json::Value::Null,
                ),
            ],
            Ok(None),
        ),
        (
            vec![
                ("gettxspendingprevout", serde_json::Value::Null, missing),
                (
                    "getrawmempool",
                    serde_json::json!([txid]),
                    serde_json::Value::Null,
                ),
                ("getrawtransaction", serde_json::Value::Null, unavailable),
            ],
            Ok(None),
        ),
        (
            vec![(
                "gettxspendingprevout",
                serde_json::json!([{"spendingtxid": txid}]),
                serde_json::Value::Null,
            )],
            Ok(Some(txid)),
        ),
        (
            vec![(
                "gettxspendingprevout",
                serde_json::json!([{}]),
                serde_json::Value::Null,
            )],
            Ok(None),
        ),
        (
            vec![("gettxspendingprevout", serde_json::Value::Null, failure)],
            Err(()),
        ),
    ];

    for (responses, expected) in cases {
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let pending = responses.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                let (method, result, error) = responses.lock().unwrap().pop_front().unwrap();
                assert_eq!(request["method"], method);
                async move {
                    axum::Json(serde_json::json!({
                        "id": request["id"], "result": result, "error": error,
                    }))
                }
            }),
        );
        let (address, server) = crate::test_support::serve(app).await;
        let result = tokio::task::spawn_blocking(move || {
            let client = Client::new(&format!("http://{address}"), Auth::None).unwrap();
            find_mempool_spender(&client, outpoint).map_err(|_| ())
        })
        .await
        .unwrap();
        server.abort();

        assert_eq!(result, expected);
        assert!(pending.lock().unwrap().is_empty());
    }
}

/// A round whose second signature covers `price`, as the signers produce it.
fn round_signed_over(price: &PriceFeedData) -> SigningResult {
    let keypair = Keypair::from_secret_key(&SecretKey::from_secret_bytes([9; 32]).unwrap());

    SigningResult {
        request_hash: [0; 32],
        signing_storm_tree_branch: keypair.x_only_public_key().0.serialize(),
        signatures: vec![
            [0; 64],
            schnorr::sign(&price_hash(price), &keypair).to_byte_array(),
        ],
    }
}

fn proof() -> storm_tree::StormTreeProof {
    storm_tree::StormTreeProof {
        leaf: [1; 32],
        root: [2; 32],
        siblings: vec![(true, SIBLING)],
    }
}

fn rate(feed: FeedId, price: u64) -> PriceFeedData {
    PriceFeedData {
        feed_id: feed,
        price,
        decimals: 8,
        received_at: NOW,
        valid_until: NOW + 300,
    }
}

#[test]
fn issues_a_round_at_the_feed_its_first_priced_batch_names() {
    let own = rate(LBTC_USDT, 10_000_000_000);
    let other = rate(0, 500_000_000);

    // A plain Tick batch rides along with any round.
    assert_eq!(round_rate(None, None, None), RoundRate::Carries(None));
    assert_eq!(
        round_rate(Some(own), None, None),
        RoundRate::Carries(Some(own))
    );
    // The first batch naming a feed sets the rate from this node's value.
    assert_eq!(
        round_rate(None, Some(LBTC_USDT), Some(own)),
        RoundRate::Carries(Some(own))
    );
    assert_eq!(
        round_rate(Some(own), Some(LBTC_USDT), None),
        RoundRate::Carries(Some(own))
    );
    // A batch of another feed waits for a round of its own, while one this
    // node cannot price waits only until it has waited too long.
    assert_eq!(
        round_rate(Some(other), Some(LBTC_USDT), None),
        RoundRate::AnotherFeed
    );
    assert_eq!(
        round_rate(None, Some(LBTC_USDT), None),
        RoundRate::NoLocalPrice
    );
}

#[test]
fn fails_an_unpriced_request_only_once_it_has_waited_its_blocks() {
    assert!(!waited_too_long(MAX_UNPRICED_REQUEST_BLOCKS, 0));
    assert!(waited_too_long(MAX_UNPRICED_REQUEST_BLOCKS + 1, 0));
    assert!(!waited_too_long(5, 9));
}

#[test]
fn issues_only_at_a_rate_that_outlasts_the_session_signing_it() {
    let expiring = rate(LBTC_USDT, 10_000_000_000);
    let margin = SIGNING_SESSION_TIMEOUT.as_secs();

    // The second it expires in is too late, and so is the whole session
    // before it: a signer reaching the message at the end of one would
    // read the rate as stale and fail the round for everyone in it.
    assert!(!usable_for_round(&expiring, expiring.valid_until));
    assert!(!usable_for_round(&expiring, expiring.valid_until - margin));
    assert!(usable_for_round(
        &expiring,
        expiring.valid_until - margin - 1
    ));
}

#[test]
fn carries_the_rate_only_beside_the_batches_issued_at_it() {
    let instructed = rate(LBTC_USDT, 10_000_000_000);

    assert_eq!(
        batch_payload(Some(LBTC_USDT), Some(&instructed)),
        Some(instructed.to_bytes().to_vec())
    );
    assert_eq!(batch_payload(None, Some(&instructed)), None);
    assert_eq!(batch_payload(Some(LBTC_USDT), None), None);
}

#[test]
fn reads_the_rate_a_batch_is_issued_at() {
    let instructed = rate(LBTC_USDT, 10_000_000_000);
    let payload = instructed.to_bytes();

    assert_eq!(
        instructed_price(Some(LBTC_USDT), Some(&payload), None).unwrap(),
        Some(instructed)
    );
    assert_eq!(instructed_price(None, None, None).unwrap(), None);
    // A later batch of the same round repeats the rate.
    assert_eq!(
        instructed_price(None, None, Some(instructed)).unwrap(),
        Some(instructed)
    );
}

#[test]
fn rejects_a_batch_whose_instructed_rate_does_not_match_it() {
    let instructed = rate(LBTC_USDT, 10_000_000_000);
    let payload = instructed.to_bytes();
    let other_feed = rate(0, 10_000_000_000).to_bytes();

    assert!(instructed_price(Some(LBTC_USDT), None, None).is_err());
    assert!(instructed_price(None, Some(&payload), None).is_err());
    assert!(instructed_price(Some(LBTC_USDT), Some(&other_feed), None).is_err());
    assert!(
        instructed_price(
            Some(LBTC_USDT),
            Some(&payload),
            Some(rate(LBTC_USDT, 10_000_000_001))
        )
        .is_err()
    );
    assert!(instructed_price(Some(LBTC_USDT), Some(&[7; 8]), None).is_err());
}

#[test]
fn excludes_foreign_assets_from_contract_lanes() {
    let expected = [1; 32];
    let expected_asset = AssetId::from_byte_array(expected);

    assert!(matches_expected_asset(expected_asset, Some(expected)));
    assert!(!matches_expected_asset(
        AssetId::from_byte_array([2; 32]),
        Some(expected)
    ));
    assert!(matches_scanned_asset(
        Some(&expected_asset.to_string()),
        Some(expected)
    ));
    assert!(!matches_scanned_asset(None, Some(expected)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lanes_keep_their_storm_eye_after_earlier_lanes_broadcast() {
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    let asset = AssetId::from_byte_array([7; 32]);
    let txids = (1..=6)
        .map(|byte| Txid::from_byte_array([byte; 32]))
        .collect::<Vec<_>>();
    let spent = Arc::new(Mutex::new(vec![txids[3], txids[4]]));
    let mempool = spent.clone();
    let scanned = txids.clone();
    let app =
        axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                let result = match request["method"].as_str().unwrap() {
                    "scantxoutset" => json!({ "unspents": scanned.iter().map(|txid| json!({
                    "txid": txid.to_string(), "vout": 0, "asset": asset.to_string(),
                })).collect::<Vec<_>>() }),
                    "gettxout" => {
                        let txid = Txid::from_str(request["params"][0].as_str().unwrap()).unwrap();
                        let include_mempool = request["params"][2] == json!(true);
                        if include_mempool && mempool.lock().unwrap().contains(&txid) {
                            json!(null)
                        } else {
                            json!({
                                "confirmations": 1,
                                "asset": asset.to_string(),
                                "value": 0.00000001,
                                "scriptPubKey": { "hex": "51" },
                            })
                        }
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
        let client = Client::new(&format!("http://{address}"), Auth::None).unwrap();
        let find = |pool| {
            find_contract_utxo(&client, &[0x51], Some([7; 32]), pool)
                .map(|utxo| utxo.outpoint.txid)
                .map_err(|error| error.to_string())
        };

        // Burn lanes 0 and 1 already broadcast; lane 2 still owns its Storm Eye.
        assert_eq!(find(StormEyePool::NetworkLeader(2)), Ok(txids[5]));
        assert!(
            find(StormEyePool::NetworkLeader(0))
                .unwrap_err()
                .contains("already used")
        );
        assert_eq!(find(StormEyePool::UserRequests(0)), Ok(txids[0]));
        assert_eq!(find(StormEyePool::AnyNetworkLeader), Ok(txids[5]));

        spent.lock().unwrap().push(txids[5]);
        assert!(find(StormEyePool::NetworkLeader(2)).is_err());
        assert!(find(StormEyePool::AnyNetworkLeader).is_err());
    })
    .await;
    server.abort();
    result.unwrap();
}

#[test]
fn maps_every_storm_eye_lane_into_its_pool() {
    assert_eq!(
        storm_eye_pool_index(6, StormEyePool::UserRequests(0)),
        Some(0)
    );
    assert_eq!(
        storm_eye_pool_index(6, StormEyePool::UserRequests(2)),
        Some(2)
    );
    assert_eq!(storm_eye_pool_index(6, StormEyePool::UserRequests(3)), None);
    assert_eq!(
        storm_eye_pool_index(6, StormEyePool::NetworkLeader(0)),
        Some(3)
    );
    assert_eq!(
        storm_eye_pool_index(6, StormEyePool::NetworkLeader(2)),
        Some(5)
    );
    assert_eq!(
        storm_eye_pool_index(6, StormEyePool::NetworkLeader(3)),
        None
    );

    assert_eq!(
        storm_eye_pool_index(5, StormEyePool::UserRequests(1)),
        Some(1)
    );
    assert_eq!(
        storm_eye_pool_index(5, StormEyePool::NetworkLeader(0)),
        Some(2)
    );
    assert_eq!(
        storm_eye_pool_index(5, StormEyePool::NetworkLeader(2)),
        Some(4)
    );
}

fn config() -> ProtocolConfig {
    ProtocolConfig {
        operational_fee_sats: 100,
        tick_burn_reserve_sats: 200,
        issuance_transaction_fee_sats: 150,
        burn_transaction_fee_sats: 50,
        exchange_transaction_fee_sats: 50,
        tick_lifetime_blocks: 60,
        finality_confirmations: 2,
    }
}

#[test]
fn allocates_transaction_fee_across_account_surplus() {
    let reserves = allocate_account_reserves(&[(1, 400), (1, 500)], &config()).unwrap();

    assert_eq!(reserves, vec![200, 350]);
}

#[test]
fn rejects_insufficient_aggregate_transaction_fee() {
    let error = allocate_account_reserves(&[(1, 349), (1, 400)], &config()).unwrap_err();

    assert!(matches!(error, UserRequestError::Invalid(message)
        if message == "insufficient funds for the issuance transaction fee"));
}

#[test]
fn hands_a_user_the_signature_over_the_rate_it_was_issued_at() {
    let price = rate(LBTC_USDT, 10_000_000_000);
    let signing = round_signed_over(&price);

    let (price_data, bloom) = signed_price_bloom(&price, &signing, &proof()).unwrap();

    assert_eq!(price_data, hex::encode(price.to_bytes()));
    assert_eq!(bloom.branch, hex::encode(signing.signing_storm_tree_branch));
    assert_eq!(bloom.signature, hex::encode(signing.signatures[1]));
    assert_eq!(bloom.proof.len(), 1);
    assert!(bloom.proof[0].right);
    assert_eq!(bloom.proof[0].hash, hex::encode(SIBLING));
}

#[test]
fn refuses_a_signature_taken_over_another_rate() {
    let signing = round_signed_over(&rate(LBTC_USDT, 10_000_000_001));

    let error = signed_price_bloom(&rate(LBTC_USDT, 10_000_000_000), &signing, &proof());

    assert!(error.is_err());
}

#[test]
fn refuses_a_round_that_signed_only_its_transaction() {
    let price = rate(LBTC_USDT, 10_000_000_000);
    let mut signing = round_signed_over(&price);
    signing.signatures.truncate(1);

    assert!(signed_price_bloom(&price, &signing, &proof()).is_err());
}

use simplex::simplicityhl::elements::{
    AssetBlindingNonce, AssetEntropy, AssetIssuance, LockTime, Transaction, TxIn,
};

fn network() -> SimplicityNetwork {
    SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_byte_array([8; 32]),
        genesis_hash: BlockHash::from_byte_array([6; 32]),
    }
}

fn explicit(asset: AssetId, value: u64, script: Script) -> TxOut {
    TxOut {
        asset: confidential::Asset::Explicit(asset),
        value: confidential::Value::Explicit(value),
        nonce: confidential::Nonce::Null,
        script_pubkey: script,
        witness: Default::default(),
    }
}

fn input(vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint::new(Txid::from_byte_array([10; 32]), vout),
        ..Default::default()
    }
}

fn storm_eye() -> NetworkAsset {
    let mut storm_eye = NetworkAsset {
        kind: STORM_EYE_KIND.into(),
        name: "Storm Eye".into(),
        asset_id: [7; 32],
        reissuance_token_id: None,
        entropy: None,
        issuance_txid: [2; 32],
        contract_script: vec![],
        contract_data: Some(
            postcard::to_stdvec(&StormEyeContractData {
                storm_tree_root: [3; 32],
                rescue_height: 100,
                rescue_output_script_hash: [4; 32],
            })
            .unwrap(),
        ),
        supply: 10_000,
        created_at_block: 1,
    };
    storm_eye.contract_script = storm_eye_program(&storm_eye)
        .unwrap()
        .get_script_pubkey(&network())
        .into_bytes();
    storm_eye
}

fn signature_auth() -> UtxoAuthMethod {
    UtxoAuthMethod {
        kind: "signature-auth".into(),
        auth_data: hex::encode([5; 32]),
    }
}

/// A Verifier at output 1 and a Tick at output 2, before any branch signs.
fn round_transaction() -> RoundTransaction {
    let network = network();
    let storm_eye = storm_eye();
    let descriptors = vec![
        IssuedUtxoDescriptor::from_request(
            1,
            4,
            [4; 32],
            &signature_auth(),
            Some(PLACEHOLDER_SIGNER),
        )
        .unwrap(),
        IssuedUtxoDescriptor::from_request(2, 4, [4; 32], &signature_auth(), None).unwrap(),
    ];
    let script = |descriptor: &IssuedUtxoDescriptor| {
        descriptor
            .voucher_program(storm_eye.asset_id)
            .unwrap()
            .get_script_pubkey(&network)
    };
    let storm_eye_utxo = explicit(
        AssetId::from_byte_array(storm_eye.asset_id),
        1,
        Script::from(storm_eye.contract_script.clone()),
    );
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(0)],
        output: vec![
            storm_eye_utxo.clone(),
            explicit(
                AssetId::from_byte_array([12; 32]),
                1,
                script(&descriptors[0]),
            ),
            explicit(
                AssetId::from_byte_array([13; 32]),
                NOW,
                script(&descriptors[1]),
            ),
            explicit(
                network.policy_asset(),
                0,
                IssuedUtxoDescriptor::script_pubkey(&descriptors).unwrap(),
            ),
        ],
    };
    let mut pset = PartiallySignedTransaction::from_tx(transaction);
    pset.inputs_mut()[0].witness_utxo = Some(storm_eye_utxo);

    RoundTransaction {
        pset,
        descriptors,
        descriptor_output: 3,
        storm_eye,
        network,
    }
}

#[test]
fn commits_every_verifier_to_the_branch_an_attempt_signs_under() {
    let round = round_transaction();
    let branch = Keypair::from_secret_key(&SecretKey::from_secret_bytes([9; 32]).unwrap())
        .x_only_public_key()
        .0
        .serialize();

    let (pset, signing_hash) = round.for_branch(branch).unwrap();

    let committed = committed_to(&round.descriptors, branch);
    assert_eq!(committed[0].signer, Some(branch));
    assert_eq!(
        pset.outputs()[1].script_pubkey,
        committed[0]
            .voucher_program(round.storm_eye.asset_id)
            .unwrap()
            .get_script_pubkey(&round.network)
    );
    // The Tick keeps its script, and the descriptor names the new signer.
    assert_eq!(
        pset.outputs()[2].script_pubkey,
        round.pset.outputs()[2].script_pubkey
    );
    assert_eq!(
        IssuedUtxoDescriptor::from_script(&pset.outputs()[3].script_pubkey).unwrap(),
        Some(committed)
    );
    // Another branch is another transaction, so another signing hash.
    let (_, placeholder_hash) = round.for_branch(PLACEHOLDER_SIGNER).unwrap();
    assert_ne!(signing_hash, placeholder_hash);
    assert_eq!(round.for_branch(branch).unwrap().1, signing_hash);
}

#[test]
fn signs_a_round_without_verifiers_the_same_under_every_branch() {
    let mut round = round_transaction();
    round.descriptors.remove(0);
    let branch = Keypair::from_secret_key(&SecretKey::from_secret_bytes([9; 32]).unwrap())
        .x_only_public_key()
        .0
        .serialize();

    assert_eq!(
        round.for_branch(branch).unwrap().1,
        round.for_branch(PLACEHOLDER_SIGNER).unwrap().1
    );
}

/// A reissuance token blinded to the Treasury, as a round finds it.
fn round_token(entropy: [u8; 32], vout: u32, issuance_amount: u64) -> RoundToken {
    round_token_with_script(entropy, vout, issuance_amount, Script::from(vec![0x51]))
}

fn round_token_with_script(
    entropy: [u8; 32],
    vout: u32,
    issuance_amount: u64,
    script: Script,
) -> RoundToken {
    let secp = Secp256k1::new();
    let asset_entropy = AssetEntropy::from_byte_array(entropy);
    let token_id = AssetId::reissuance_token_from_entropy(asset_entropy, false);
    let (txout, _, _, _) = TxOut::new_last_confidential(
        &mut secp256k1_zkp::rand::thread_rng(),
        &secp,
        1,
        token_id,
        script.clone(),
        PublicKey::from_secret_key(&secp, &treasury_blinding_secret()),
        &[explicit_txout_secrets(&explicit(token_id, 1, Script::new())).unwrap()],
        &[],
    )
    .unwrap();
    let secrets = txout.unblind(&secp, treasury_blinding_secret()).unwrap();

    RoundToken {
        asset: NetworkAsset {
            kind: "token".into(),
            name: "token".into(),
            asset_id: AssetId::from_entropy(asset_entropy).to_byte_array(),
            reissuance_token_id: Some(token_id.to_byte_array()),
            entropy: Some(entropy),
            issuance_txid: [2; 32],
            contract_script: script.into_bytes(),
            contract_data: None,
            supply: 0,
            created_at_block: 1,
        },
        utxo: UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([10; 32]), vout),
            txout,
            secrets: Some(secrets),
        },
        secrets,
        issuance_amount,
    }
}

/// Reissues a Tick and a Verifier with `secrets` as the surjection inputs.
fn reissue_both(
    spent_secrets: impl Fn(&[RoundToken], TxOutSecrets) -> Vec<TxOutSecrets>,
) -> Result<(), String> {
    let policy_asset = network().policy_asset();
    let tokens = [round_token([21; 32], 1, NOW), round_token([22; 32], 2, 1)];
    let fee_input = explicit(policy_asset, 10_000, Script::from(vec![0x52]));
    let mut transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![input(0), input(1), input(2)],
        output: vec![explicit(policy_asset, 9_000, Script::from(vec![0x52]))],
    };
    for (offset, token) in tokens.iter().enumerate() {
        transaction.input[1 + offset].asset_issuance = AssetIssuance {
            asset_blinding_nonce: AssetBlindingNonce::from_blinding_factor(token.secrets.asset_bf),
            asset_entropy: AssetEntropy::from_byte_array(token.asset.entropy.unwrap()),
            amount: confidential::Value::Explicit(token.issuance_amount),
            inflation_keys: confidential::Value::Null,
        };
        transaction.output.push(token.utxo.txout.clone());
    }
    for token in &tokens {
        transaction.output.push(explicit(
            AssetId::from_byte_array(token.asset.asset_id),
            token.issuance_amount,
            Script::from(vec![0x53]),
        ));
    }
    transaction
        .output
        .push(explicit(policy_asset, 1_000, Script::new()));
    let mut pset = PartiallySignedTransaction::from_tx(transaction);
    pset.inputs_mut()[0].witness_utxo = Some(fee_input.clone());
    for (offset, token) in tokens.iter().enumerate() {
        pset.inputs_mut()[1 + offset].witness_utxo = Some(token.utxo.txout.clone());
    }

    let fee_secrets = explicit_txout_secrets(&fee_input).unwrap();
    reblind_tokens(&mut pset, &tokens, &spent_secrets(&tokens, fee_secrets))
        .map_err(|error| error.to_string())?;
    let transaction = pset.extract_tx().map_err(|error| error.to_string())?;
    for (offset, token) in tokens.iter().enumerate() {
        let returned = transaction.output[1 + offset]
            .unblind(&Secp256k1::new(), treasury_blinding_secret())
            .map_err(|error| error.to_string())?;
        assert_eq!((returned.asset, returned.value), (token.secrets.asset, 1));
    }
    transaction
        .verify_tx_amt_proofs(
            &Secp256k1::new(),
            &[
                fee_input,
                tokens[0].utxo.txout.clone(),
                tokens[1].utxo.txout.clone(),
            ],
        )
        .map_err(|error| error.to_string())
}

#[test]
fn shrinking_the_confirmed_pool_exhausts_the_third_six_eye_burn_lane() {
    let mut remaining = 6;
    let mut selected = Vec::new();
    for lane in 0..3 {
        let index = storm_eye_pool_index(remaining, StormEyePool::NetworkLeader(lane));
        selected.push(index);
        if index.is_some() {
            remaining -= 1;
        }
    }

    assert_eq!(selected, vec![Some(3), Some(3), None]);
    assert_eq!(remaining, 4);
    assert_eq!(
        storm_eye_pool_index(4, StormEyePool::NetworkLeader(0)),
        Some(2)
    );
}

#[tokio::test]
async fn signer_layout_accepts_a_fee_input_that_is_already_a_burn_reserve() {
    use crate::db::{
        Database,
        monitored_utxo::{IndexedBlock, MonitoredUtxo},
    };
    use crate::high_storm::message::ExternalRequests;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    for count in [1usize, 99] {
        let network = network();
        let storm_eye = storm_eye();
        let config = config();
        let keypair = Keypair::from_secret_key(&SecretKey::from_secret_bytes([9; 32]).unwrap());
        let owner = keypair.x_only_public_key().0.serialize();
        let account_script = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: storm_eye.asset_id,
            account_owner_pubkey: owner,
        })
        .get_script_pubkey(&network);
        let treasury_script = TreasuryProgram::new(&TreasuryArguments {
            storm_eye_asset_id: storm_eye.asset_id,
        })
        .get_script_pubkey(&network);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut token =
            round_token_with_script([21; 32], 1, now * count as u64, treasury_script.clone());
        token.asset.kind = TICK_ASSET_KIND.into();
        token.asset.contract_data = Some(
            postcard::to_stdvec(&TickAssetContractData {
                issuance_tx: encode::serialize(&Transaction {
                    version: 2,
                    lock_time: LockTime::ZERO,
                    input: vec![],
                    output: vec![token.utxo.txout.clone()],
                }),
                token_output_index: 0,
            })
            .unwrap(),
        );
        let fee_amount = count as u64
            * (config.operational_fee_sats + config.tick_burn_reserve_sats)
            + config.issuance_transaction_fee_sats;
        let fee_input = explicit(network.policy_asset(), fee_amount, account_script.clone());
        let storm_eye_input = explicit(
            AssetId::from_byte_array(storm_eye.asset_id),
            1,
            Script::from(storm_eye.contract_script.clone()),
        );
        let auth = UtxoAuthMethod {
            kind: "signature-auth".into(),
            auth_data: hex::encode(owner),
        };
        let descriptors = (0..count)
            .map(|offset| {
                IssuedUtxoDescriptor::from_request(
                    2 + offset as u32,
                    2 + count as u32,
                    owner,
                    &auth,
                    None,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![input(0), input(1), input(3)],
            output: vec![storm_eye_input.clone(), token.utxo.txout.clone()],
        };
        transaction.input[1].asset_issuance = AssetIssuance {
            asset_blinding_nonce: AssetBlindingNonce::from_blinding_factor(token.secrets.asset_bf),
            asset_entropy: AssetEntropy::from_byte_array(token.asset.entropy.unwrap()),
            amount: confidential::Value::Explicit(token.issuance_amount),
            inflation_keys: confidential::Value::Null,
        };
        for descriptor in &descriptors {
            transaction.output.push(explicit(
                AssetId::from_byte_array(token.asset.asset_id),
                now,
                descriptor
                    .voucher_program(storm_eye.asset_id)
                    .unwrap()
                    .get_script_pubkey(&network),
            ));
        }
        transaction.output.extend([
            explicit(
                network.policy_asset(),
                count as u64 * config.tick_burn_reserve_sats,
                account_script,
            ),
            explicit(
                network.policy_asset(),
                0,
                IssuedUtxoDescriptor::script_pubkey(&descriptors).unwrap(),
            ),
            explicit(
                network.policy_asset(),
                count as u64 * config.operational_fee_sats,
                treasury_script,
            ),
            explicit(
                network.policy_asset(),
                config.issuance_transaction_fee_sats,
                Script::new(),
            ),
        ]);
        let mut pset = PartiallySignedTransaction::from_tx(transaction);
        pset.inputs_mut()[0].witness_utxo = Some(storm_eye_input.clone());
        pset.inputs_mut()[1].witness_utxo = Some(token.utxo.txout.clone());
        pset.inputs_mut()[2].witness_utxo = Some(fee_input.clone());
        let mut spent_secrets = vec![explicit_txout_secrets(&storm_eye_input).unwrap()];
        spent_secrets.extend(token_input_secrets(std::slice::from_ref(&token)).unwrap());
        spent_secrets.push(explicit_txout_secrets(&fee_input).unwrap());
        reblind_tokens(&mut pset, std::slice::from_ref(&token), &spent_secrets).unwrap();
        let mut verifiable = pset.extract_tx().unwrap();
        verifiable.output.retain(|output| {
            output.value.explicit() != Some(0) || !output.script_pubkey.is_provably_unspendable()
        });
        verifiable
            .verify_tx_amt_proofs(
                &Secp256k1::new(),
                &[storm_eye_input, token.utxo.txout.clone(), fee_input],
            )
            .unwrap();

        let payload = json!({ "utxo_auth_method": {
            "kind": "signature-auth", "auth_data": hex::encode(owner),
        }})
        .to_string();
        let fee_outpoint = format!("{}:3", hex::encode([10; 32]));
        let mut signed_message = payload.repeat(count).into_bytes();
        signed_message.extend_from_slice(fee_outpoint.as_bytes());
        let signature = schnorr::sign(
            &crate::crypto::tagged_hash("OracleNetworkV1/NetworkUserRequests", &signed_message),
            &keypair,
        );
        let encoded = serde_json::to_vec(&json!({
            "header": { "public_key": hex::encode(owner),
                "signature": hex::encode(signature.to_byte_array()),
                "fee_utxos": [fee_outpoint] },
            "requests": (0..count).map(|_| json!({
                "kind": "tick-utxo", "payload": payload,
            })).collect::<Vec<_>>(),
        }))
        .unwrap();
        let request = ExecuteUserRequests {
            signing_hash: issuance_signing_hash(&pset, &storm_eye, &network).unwrap(),
            tx: encode::serialize(&pset),
            signing_storm_tree_branch: PLACEHOLDER_SIGNER,
            external_requests: vec![ExternalRequests {
                request_hash: Sha256::digest(&encoded).into(),
                network_user_requests: encoded,
                additional_payload: None,
            }],
            chain_tip: None,
        };
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock::at(1),
                &[MonitoredUtxo {
                    txid: [10; 32],
                    output_index: 0,
                    asset_kind: TICK_ASSET_KIND.into(),
                    amount: now,
                    script_pubkey: descriptors[0]
                        .voucher_program(storm_eye.asset_id)
                        .unwrap()
                        .get_script_pubkey(&network)
                        .into_bytes(),
                    auth_method: auth.kind.clone(),
                    auth_data: owner.to_vec(),
                    account_owner_pubkey: owner,
                    internal_key: None,
                    burning_fee_txid: [10; 32],
                    burning_fee_output_index: 3,
                    block_height: 1,
                    status: "active".into(),
                    status_block_height: 1,
                    burn_txid: None,
                }],
                &[],
                60,
            )
            .await
            .unwrap();

        assert!(store.is_reserved_for_burning([10; 32], 3).await.unwrap());
        assert_eq!(
            validate_execute_request(
                &request,
                &storm_eye,
                Some(&token.asset),
                None,
                &config,
                &network
            )
            .unwrap(),
            None
        );

        let mut tampered = request;
        tampered.signing_hash = [0; 32];
        assert!(
            validate_execute_request(
                &tampered,
                &storm_eye,
                Some(&token.asset),
                None,
                &config,
                &network
            )
            .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rounds_reject_reserved_or_unanchored_fee_utxos() {
    use crate::db::{
        Database,
        monitored_utxo::{IndexedBlock, MonitoredUtxo},
    };

    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(10),
            &[MonitoredUtxo {
                txid: [1; 32],
                output_index: 2,
                asset_kind: TICK_ASSET_KIND.into(),
                amount: 1,
                script_pubkey: vec![0x51],
                auth_method: "signature-auth".into(),
                auth_data: vec![2; 32],
                account_owner_pubkey: [3; 32],
                internal_key: None,
                burning_fee_txid: [4; 32],
                burning_fee_output_index: 5,
                block_height: 10,
                status: "active".into(),
                status_block_height: 10,
                burn_txid: None,
            }],
            &[],
            60,
        )
        .await
        .unwrap();

    // Output [6;32]:0 confirmed at 10, [7;32]:0 at 11; the node's tip is 11.
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(
            |axum::Json(request): axum::Json<serde_json::Value>| async move {
                let result = match request["method"].as_str().unwrap() {
                    "getblockcount" => serde_json::json!(11),
                    "gettxout" => {
                        assert_eq!(request["params"][2], serde_json::json!(false));
                        let confirmations = match request["params"][0].as_str().unwrap() {
                            txid if txid == Txid::from_byte_array([6; 32]).to_string() => 2,
                            txid if txid == Txid::from_byte_array([7; 32]).to_string() => 1,
                            _ => 0,
                        };
                        if confirmations == 0 {
                            serde_json::Value::Null
                        } else {
                            serde_json::json!({
                                "confirmations": confirmations,
                                "scriptPubKey": { "hex": "51" },
                            })
                        }
                    }
                    method => panic!("unexpected RPC method: {method}"),
                };
                axum::Json(serde_json::json!({
                    "id": request["id"], "result": result, "error": null,
                }))
            },
        ),
    );
    let (address, server) = crate::test_support::serve(app).await;
    let client = Client::new(&format!("http://{address}"), Auth::None).unwrap();
    let fee = |txid: u8, output_index: u32| FeeUtxo {
        txid: [txid; 32],
        output_index,
    };
    let anchor = |height: u64| {
        Some(ChainTip {
            height,
            hash: [height as u8; 32],
        })
    };

    let check = async |chain_tip: Option<ChainTip>, fee_utxos: &[FeeUtxo]| {
        require_unreserved_anchored_fee_utxos(&store, &client, chain_tip, fee_utxos)
            .await
            .map_err(|error| error.to_string())
    };
    assert_eq!(check(anchor(10), &[fee(6, 0)]).await, Ok(()));
    assert_eq!(check(anchor(11), &[fee(6, 0), fee(7, 0)]).await, Ok(()));
    for (chain_tip, fee_utxos, reason) in [
        (
            anchor(11),
            vec![fee(6, 0), fee(4, 5)],
            "reserved for burning",
        ),
        (
            anchor(10),
            vec![fee(7, 0)],
            "not confirmed at the round's anchored block",
        ),
        (
            anchor(11),
            vec![fee(8, 0)],
            "not confirmed at the round's anchored block",
        ),
        (None, vec![fee(6, 0)], "no chain anchor"),
    ] {
        let error = check(chain_tip, &fee_utxos).await.unwrap_err();
        assert!(error.contains(reason), "{error}");
    }
    server.abort();
}

#[test]
fn reblinds_both_tokens_of_a_round_into_a_balanced_transaction() {
    reissue_both(|tokens, fee| {
        let mut secrets = vec![fee];
        secrets.extend(token_input_secrets(tokens).unwrap());
        secrets
    })
    .unwrap();
}

#[test]
fn surjects_over_each_token_beside_what_it_reissues() {
    // Both tokens first, then both reissued assets: not the domain order
    // consensus checks the token surjection proofs against.
    let grouped = reissue_both(|tokens, fee| {
        let interleaved = token_input_secrets(tokens).unwrap();
        let mut secrets = vec![fee];
        secrets.extend(interleaved.iter().step_by(2));
        secrets.extend(interleaved.iter().skip(1).step_by(2));
        secrets
    });

    assert!(grouped.is_err());
}
