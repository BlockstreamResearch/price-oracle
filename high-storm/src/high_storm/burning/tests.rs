use super::*;
use crate::{external_api::users::UtxoAuthMethod, high_storm::issuance::IssuedUtxoDescriptor};
use simplex::simplicityhl::elements::BlockHash;

/// x of the secp256k1 generator, a valid signing branch.
const SIGNER: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// A Burning over `store` whose Elements RPC wallet is `test` at `url`.
fn test_burning(
    store: &MonitoredUtxoStore,
    database: &crate::db::Database,
    url: String,
) -> Burning {
    Burning::new(
        store.clone(),
        database.network_assets(),
        ElementsRpcConfig {
            url,
            username: String::new(),
            password: String::new(),
            wallet: "test".into(),
        },
        ProtocolConfig {
            operational_fee_sats: 1_000,
            tick_burn_reserve_sats: 1_000,
            issuance_transaction_fee_sats: 500,
            burn_transaction_fee_sats: 500,
            exchange_transaction_fee_sats: 500,
            tick_lifetime_blocks: 60,
            finality_confirmations: 2,
        },
    )
}

fn verifier(txid: u8, output_index: u32, reserve: u8, owner: u8) -> MonitoredUtxo {
    MonitoredUtxo {
        asset_kind: ORACLE_VERIFIER_KIND.into(),
        amount: 1,
        internal_key: Some(SIGNER),
        ..tick(txid, output_index, reserve, owner)
    }
}

fn tick(txid: u8, output_index: u32, reserve: u8, owner: u8) -> MonitoredUtxo {
    MonitoredUtxo {
        txid: [txid; 32],
        output_index,
        asset_kind: TICK_ASSET_KIND.into(),
        amount: 1_700_000_000,
        script_pubkey: vec![0x51],
        auth_method: "signature-auth".into(),
        auth_data: vec![2; 32],
        account_owner_pubkey: [owner; 32],
        internal_key: None,
        burning_fee_txid: [reserve; 32],
        burning_fee_output_index: 7,
        block_height: 1,
        status: "expired".into(),
        status_block_height: 61,
        burn_txid: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn burn_broadcast_uses_elements_23_3_4_rpc_without_retries() {
    use std::sync::{Arc, Mutex};

    for error in [
        None,
        Some(serde_json::json!({
            "code": -1, "message": "sendrawtransaction \"hexstring\" ( maxfeerate )",
        })),
        Some(serde_json::json!({"code": -26, "message": "min relay fee not met"})),
        Some(serde_json::json!({"code": -1, "message": "unrelated failure"})),
    ] {
        let accepted = error.is_none();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                assert_eq!(request["method"], "sendrawtransaction");
                let mut calls = observed.lock().unwrap();
                calls.push(request["params"].clone());
                let response = if calls.len() == 1 && error.is_some() {
                    serde_json::json!({"id": request["id"], "result": null, "error": error})
                } else {
                    serde_json::json!({"id": request["id"], "result": "txid", "error": null})
                };
                async move { axum::Json(response) }
            }),
        );
        let (address, server) = crate::test_support::serve(app).await;
        let result = tokio::task::spawn_blocking(move || {
            let client =
                Client::new(&format!("http://{address}"), bitcoincore_rpc::Auth::None).unwrap();
            send_burn_transaction(&client, "raw".into())
        })
        .await
        .unwrap();

        assert_eq!(result.is_ok(), accepted);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], serde_json::json!(["raw", "0.10"]));
        server.abort();
    }
}

#[test]
fn selects_ticks_from_different_users_in_deterministic_order() {
    let groups = select_groups(
        vec![tick(3, 1, 2, 4), tick(1, 1, 1, 3), tick(2, 1, 2, 4)],
        MAX_TICKS_PER_BURN,
    )
    .unwrap();

    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].reserve, ([1; 32], 7));
    assert_eq!(groups[0].ticks.len(), 1);
    assert_eq!(groups[1].reserve, ([2; 32], 7));
    assert_eq!(groups[1].ticks.len(), 2);
}

#[test]
fn burns_the_oldest_group_first_whatever_its_reserve_txid() {
    let aged = |txid: u8, reserve: u8, block_height: u64| MonitoredUtxo {
        block_height,
        ..tick(txid, 1, reserve, reserve)
    };
    // A full round of newer groups whose reserves sort before the old one.
    let mut expired = (1..=100)
        .map(|reserve| aged(reserve, reserve, 50))
        .collect::<Vec<_>>();
    expired.push(aged(200, 255, 10));

    let groups = select_groups(expired, MAX_TICKS_PER_BURN).unwrap();

    assert_eq!(groups.len(), 100);
    assert_eq!(groups[0].reserve, ([255; 32], 7));
    assert!(!groups.iter().any(|group| group.reserve == ([100; 32], 7)));
}

#[test]
fn fills_a_round_past_a_group_that_does_not_fit() {
    let group = |reserve: u8, count: u8, block_height: u64| {
        (0..count).map(move |index| MonitoredUtxo {
            block_height,
            ..tick(reserve, u32::from(index), reserve, reserve)
        })
    };
    let expired = group(1, 60, 1)
        .chain(group(2, 50, 2))
        .chain(group(3, 40, 3))
        .collect();

    let groups = select_groups(expired, MAX_TICKS_PER_BURN).unwrap();

    assert_eq!(
        groups
            .iter()
            .map(|group| group.reserve.0[0])
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    assert_eq!(
        groups.iter().map(|group| group.ticks.len()).sum::<usize>(),
        100
    );
}

#[tokio::test]
async fn reconciliation_excludes_observed_spends_and_keeps_other_expired_items() {
    use crate::db::{Database, monitored_utxo::IndexedBlock};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let spent = tick(1, 2, 3, 4);
    let available = tick(2, 2, 5, 6);
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(61),
            &[spent.clone(), available.clone()],
            &[],
            60,
        )
        .await
        .unwrap();

    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![simplex::simplicityhl::elements::TxIn {
            previous_output: simplex::simplicityhl::elements::OutPoint {
                txid: Txid::from_byte_array(spent.txid),
                vout: spent.output_index,
            },
            ..Default::default()
        }],
        output: vec![],
    };
    let txid = transaction.txid();
    let encoded = hex::encode(encode::serialize(&transaction));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    let app = axum::Router::new().route(
        "/wallet/test",
        axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
            observed_calls.fetch_add(1, Ordering::SeqCst);
            let result = match request["method"].as_str().unwrap() {
                "getrawmempool" => serde_json::json!([txid]),
                "getrawtransaction" => {
                    assert_eq!(request["params"], serde_json::json!([txid, false]));
                    serde_json::json!(encoded)
                }
                method => panic!("unexpected RPC method: {method}"),
            };
            async move {
                axum::Json(serde_json::json!({
                    "id": request["id"], "result": result, "error": null,
                }))
            }
        }),
    );
    let (address, server) = crate::test_support::serve(app).await;
    let burning = test_burning(&store, &database, format!("http://{address}"));

    let result = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async {
            let first = burning.reconcile_mempool(61).await?;
            let second = burning.reconcile_mempool(61).await?;
            Ok::<_, BurningError>((first, second))
        })
    })
    .await;
    server.abort();

    assert_eq!(result.unwrap().unwrap(), (1, 0));
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let expired = store.list_expired(10).await.unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].txid, available.txid);
    assert!(
        store
            .is_reserved_for_burning(spent.burning_fee_txid, spent.burning_fee_output_index)
            .await
            .unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn releases_only_items_whose_burning_transaction_vanished() {
    use crate::db::{Database, monitored_utxo::IndexedBlock};
    use serde_json::json;

    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let items = (1..=4).map(|txid| tick(txid, 0, 9, 4)).collect::<Vec<_>>();
    store
        .apply_block("burning-v1", &IndexedBlock::at(61), &items, &[], 60)
        .await
        .unwrap();
    let pending = [10; 32];
    let confirmed = [11; 32];
    let vanished = [12; 32];
    for (burn_txid, batch) in [
        (pending, &items[..1]),
        (confirmed, &items[1..2]),
        (vanished, &items[2..]),
    ] {
        let outpoints = batch
            .iter()
            .map(|item| (item.txid, item.output_index))
            .collect::<Vec<_>>();
        store.mark_burning(&outpoints, burn_txid, 61).await.unwrap();
    }

    let pending_txid = Txid::from_byte_array(pending).to_string();
    let confirmed_txid = Txid::from_byte_array(confirmed).to_string();
    let app = axum::Router::new().route(
        "/wallet/test",
        axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
            let (result, error) = match request["method"].as_str().unwrap() {
                "getrawmempool" => (json!([pending_txid]), json!(null)),
                "getrawtransaction" if request["params"][0] == confirmed_txid => {
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
    let (address, server) = crate::test_support::serve(app).await;
    let burning = test_burning(&store, &database, format!("http://{address}"));

    assert_eq!(burning.release_vanished_burns(62).await.unwrap(), 2);
    assert_eq!(burning.release_vanished_burns(62).await.unwrap(), 0);
    server.abort();

    let expired = store.list_expired(10).await.unwrap();
    assert_eq!(
        expired.iter().map(|item| item.txid).collect::<Vec<_>>(),
        vec![items[2].txid, items[3].txid]
    );
    assert!(
        expired
            .iter()
            .all(|item| item.burn_txid.is_none() && item.status_block_height == 62)
    );
    assert_eq!(
        store.burning_txids().await.unwrap(),
        vec![pending, confirmed]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_round_leaves_out_items_spent_after_reconciliation() {
    use crate::db::{Database, monitored_utxo::IndexedBlock};
    use serde_json::json;

    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let unspent = tick(1, 0, 9, 4);
    let spent_in_mempool = tick(2, 0, 9, 4);
    let spent_in_block = tick(3, 0, 9, 4);
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(61),
            &[
                unspent.clone(),
                spent_in_mempool.clone(),
                spent_in_block.clone(),
            ],
            &[],
            60,
        )
        .await
        .unwrap();

    let spender = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![simplex::simplicityhl::elements::TxIn {
            previous_output: simplex::simplicityhl::elements::OutPoint {
                txid: Txid::from_byte_array(spent_in_mempool.txid),
                vout: 0,
            },
            ..Default::default()
        }],
        output: vec![],
    };
    let spender_txid = spender.txid();
    let spender_hex = hex::encode(encode::serialize(&spender));
    let unspent_txid = Txid::from_byte_array(unspent.txid).to_string();
    let tick_asset = AssetId::from_byte_array([5; 32]);
    let app =
        axum::Router::new().route(
            "/wallet/test",
            axum::routing::post(move |axum::Json(request): axum::Json<serde_json::Value>| {
                let result = match request["method"].as_str().unwrap() {
                    "gettxout" if request["params"][0] == unspent_txid => json!({
                        "confirmations": 2,
                        "asset": tick_asset.to_string(),
                        "value": 17,
                        "scriptPubKey": { "hex": "51" },
                    }),
                    "gettxout" => json!(null),
                    "getrawmempool" => json!([spender_txid]),
                    "getrawtransaction" => json!(spender_hex),
                    method => panic!("unexpected RPC method: {method}"),
                };
                async move {
                    axum::Json(json!({ "id": request["id"], "result": result, "error": null }))
                }
            }),
        );
    let (address, server) = crate::test_support::serve(app).await;
    let burning = test_burning(&store, &database, format!("http://{address}"));
    let group = select_groups(store.list_expired(10).await.unwrap(), MAX_TICKS_PER_BURN)
        .unwrap()
        .remove(0);

    let client = burning.client().unwrap();
    let (group, utxos) = burning
        .available_ticks(&client, group, 61)
        .await
        .unwrap()
        .unwrap();
    server.abort();

    assert_eq!(
        group.ticks.iter().map(|tick| tick.txid).collect::<Vec<_>>(),
        vec![unspent.txid]
    );
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].amount(), 1_700_000_000);
    // The mempool spend is tracked; the block spend waits for indexing to delete it.
    let expired = store.list_expired(10).await.unwrap();
    assert_eq!(
        expired.iter().map(|tick| tick.txid).collect::<Vec<_>>(),
        vec![unspent.txid, spent_in_block.txid]
    );
}

#[test]
fn collects_transaction_inputs_for_burn_observation() {
    let transaction = Transaction {
        version: 2,
        lock_time: simplex::simplicityhl::elements::LockTime::ZERO,
        input: vec![simplex::simplicityhl::elements::TxIn {
            previous_output: simplex::simplicityhl::elements::OutPoint {
                txid: Txid::from_byte_array([3; 32]),
                vout: 7,
            },
            ..Default::default()
        }],
        output: vec![],
    };

    assert_eq!(
        spent_outpoints(&transaction),
        BTreeSet::from([([3; 32], 7)])
    );
}

#[test]
fn splits_the_configured_fee_exactly_across_reserves() {
    let shares = (0..3)
        .map(|index| fee_share(500, 3, index).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(shares, vec![167, 167, 166]);
    assert_eq!(shares.into_iter().sum::<u64>(), 500);
}

#[test]
fn rejects_conflicting_owners_for_one_reserve() {
    let error =
        select_groups(vec![tick(1, 1, 3, 4), tick(2, 1, 3, 5)], MAX_TICKS_PER_BURN).unwrap_err();

    assert!(matches!(error, BurningError::Invalid(_)));
}

#[test]
fn reconstructs_descriptor_covenant_for_every_authentication_mode() {
    let authentication = [
        ("asset-id-auth", hex::encode([1; 32])),
        ("scriptPubKey-auth", hex::encode([0x51])),
        ("signature-auth", hex::encode([2; 32])),
    ];
    let network = SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_byte_array([8; 32]),
        genesis_hash: BlockHash::from_byte_array([9; 32]),
    };

    for (kind, auth_data) in authentication {
        for signer in [None, Some(SIGNER)] {
            let descriptor = IssuedUtxoDescriptor::from_request(
                2,
                3,
                [4; 32],
                &UtxoAuthMethod {
                    kind: kind.into(),
                    auth_data: auth_data.clone(),
                },
                signer,
            )
            .unwrap();
            let mut monitored = if signer.is_some() {
                verifier(1, 2, 3, 4)
            } else {
                tick(1, 2, 3, 4)
            };
            monitored.auth_method = descriptor.auth_method_name().into();
            monitored.auth_data = descriptor.auth_data.to_vec();

            assert_eq!(
                issued_program([7; 32], &monitored, voucher_program)
                    .unwrap()
                    .get_script_pubkey(&network),
                descriptor
                    .voucher_program([7; 32])
                    .unwrap()
                    .get_script_pubkey(&network)
            );
        }
    }
}
/// Production-shaped burn inputs on Liquid, without a node.
struct BurnFixture {
    network: SimplicityNetwork,
    assets: BurnAssets,
    storm_eye: NetworkAsset,
    storm_eye_utxo: UTXO,
}

impl BurnFixture {
    const STORM_EYE_ID: [u8; 32] = [7; 32];

    fn new() -> Self {
        let network = SimplicityNetwork::Liquid;
        let mut storm_eye = NetworkAsset {
            kind: STORM_EYE_KIND.into(),
            name: "Storm Eye".into(),
            asset_id: Self::STORM_EYE_ID,
            reissuance_token_id: None,
            entropy: None,
            issuance_txid: [0; 32],
            contract_script: Vec::new(),
            contract_data: Some(
                postcard::to_stdvec(&StormEyeContractData {
                    storm_tree_root: SIGNER,
                    rescue_height: 1_000_000,
                    rescue_output_script_hash: [3; 32],
                })
                .unwrap(),
            ),
            supply: 1,
            created_at_block: 1,
        };
        let script = storm_eye_program(&storm_eye)
            .unwrap()
            .get_script_pubkey(&network);
        storm_eye.contract_script = script.as_bytes().to_vec();
        let storm_eye_utxo = Self::utxo(
            200,
            0,
            AssetId::from_byte_array(Self::STORM_EYE_ID),
            1,
            script,
        );
        Self {
            network,
            assets: BurnAssets {
                tick: Some(AssetId::from_byte_array([1; 32])),
                verifier: Some(AssetId::from_byte_array([2; 32])),
            },
            storm_eye,
            storm_eye_utxo,
        }
    }

    fn utxo(txid: u8, vout: u32, asset: AssetId, amount: u64, script: Script) -> UTXO {
        use simplex::simplicityhl::elements::{OutPoint, confidential};

        UTXO {
            outpoint: OutPoint::new(Txid::from_byte_array([txid; 32]), vout),
            txout: TxOut {
                asset: confidential::Asset::Explicit(asset),
                value: confidential::Value::Explicit(amount),
                script_pubkey: script,
                ..Default::default()
            },
            secrets: None,
        }
    }

    fn group(
        &self,
        reserve: u8,
        items: usize,
        verifiers: bool,
        reserve_sats: u64,
    ) -> BurnableGroup {
        let owner = [reserve; 32];
        let account = AccountProgram::new(&AccountArguments {
            storm_eye_asset_id: Self::STORM_EYE_ID,
            account_owner_pubkey: owner,
        });
        let mut ticks = Vec::with_capacity(items);
        let mut tick_utxos = Vec::with_capacity(items);
        for index in 0..items as u32 {
            let mut item = if verifiers {
                verifier(reserve, index, reserve, reserve)
            } else {
                tick(reserve, index, reserve, reserve)
            };
            let script = issued_program(Self::STORM_EYE_ID, &item, voucher_program)
                .unwrap()
                .get_script_pubkey(&self.network);
            item.script_pubkey = script.as_bytes().to_vec();
            item.burning_fee_txid = [reserve; 32];
            item.burning_fee_output_index = 1_000;
            tick_utxos.push(Self::utxo(
                reserve,
                index,
                self.assets.of(&item).unwrap(),
                item.amount,
                script,
            ));
            ticks.push(item);
        }
        let reserve_utxo = Self::utxo(
            reserve,
            1_000,
            self.network.policy_asset(),
            reserve_sats,
            account.get_script_pubkey(&self.network),
        );
        (
            BurnGroup {
                reserve: ([reserve; 32], 1_000),
                owner,
                ticks,
            },
            reserve_utxo,
            account,
            tick_utxos,
        )
    }

    fn build(&self, groups: &[BurnableGroup], minimum_fee: u64) -> Result<BuiltBurn, BurningError> {
        build_burn_transaction(
            &self.storm_eye,
            &self.storm_eye_utxo,
            groups,
            &self.assets,
            &self.network,
            minimum_fee,
        )
    }
}

#[test]
fn sizes_the_burn_fee_to_the_relay_floor_above_the_minimum() {
    assert_eq!(burn_fee(500, 1, 1).unwrap(), 500);
    assert_eq!(burn_fee(500, 30, 1).unwrap(), 500);
    assert_eq!(burn_fee(500, 31, 1).unwrap(), 504);
    // 3,900 + 500 * 50 + 750 = 29,650 WU -> 7,413 vB -> 742 sats at 0.1 sat/vB.
    assert_eq!(burn_fee(500, 50, 1).unwrap(), 742);
    assert_eq!(burn_fee(500, 100, 100).unwrap(), 3_223);
    assert_eq!(burn_fee(5_000, 100, 100).unwrap(), 5_000);
}

#[test]
fn signers_recompute_the_sized_fee_of_a_large_burn() {
    let fixture = BurnFixture::new();
    let groups = [fixture.group(1, 50, false, 100_000)];
    let built = fixture.build(&groups, 500).unwrap();
    let (pset, _) = built.final_transaction.extract_pst();
    let fee_output = pset.outputs().last().unwrap();
    assert_eq!(fee_output.amount, Some(742));
    assert_eq!(
        pset.outputs()[pset.outputs().len() - 2].amount,
        Some(100_000 - 742)
    );

    let request = BurnExpiredUtxos {
        tx: encode::serialize(&pset),
        signing_hash: signing_hash(&pset, &fixture.storm_eye, &fixture.network).unwrap(),
        signing_storm_tree_branch: built.signing_branch,
        block_height: 61,
        chain_tip: None,
    };
    let validate = |minimum_fee| {
        validate_layout(
            &pset,
            &request,
            &groups[0].0.ticks,
            &fixture.storm_eye,
            &fixture.assets,
            &fixture.network,
            minimum_fee,
        )
    };
    validate(500).unwrap();
    validate(742).unwrap();
    assert!(validate(743).is_err());
}

#[test]
fn reports_a_reserve_shortfall_so_the_round_can_shrink() {
    let fixture = BurnFixture::new();
    let groups = [
        fixture.group(1, 1, false, 200),
        fixture.group(2, 1, false, 200),
    ];

    assert!(matches!(
        fixture.build(&groups, 500),
        Err(BurningError::ReserveShortfall)
    ));
    fixture.build(&groups, 300).unwrap();
}

#[test]
fn separates_reserves_claimed_by_conflicting_owners() {
    let (consistent, conflicting) = split_conflicting_reserves(vec![
        tick(1, 0, 5, 1),
        tick(2, 0, 5, 2),
        tick(3, 0, 6, 3),
        tick(4, 0, 6, 3),
    ]);

    assert_eq!(
        consistent
            .iter()
            .map(|item| item.txid[0])
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    assert_eq!(conflicting.len(), 1);
    assert_eq!(conflicting[&([5; 32], 7)].len(), 2);
    select_groups(consistent, MAX_TICKS_PER_BURN).unwrap();
}

#[test]
fn finds_persistent_faults_in_a_groups_items() {
    let fixture = BurnFixture::new();
    let validate = |(group, _, _, utxos): &BurnableGroup| {
        validate_group_items(BurnFixture::STORM_EYE_ID, &fixture.assets, group, utxos)
    };
    validate(&fixture.group(1, 3, false, 1_000)).unwrap();
    validate(&fixture.group(1, 3, true, 1_000)).unwrap();

    let mut changed = fixture.group(1, 3, false, 1_000);
    changed.3[1].txout.value = simplex::simplicityhl::elements::confidential::Value::Explicit(1);
    assert!(matches!(validate(&changed), Err(BurningError::Invalid(_))));

    let mut keyless = fixture.group(1, 3, true, 1_000);
    keyless.0.ticks[2].internal_key = None;
    assert!(matches!(validate(&keyless), Err(BurningError::Invalid(_))));
}

#[tokio::test]
async fn quarantining_a_group_leaves_the_rest_of_the_queue() {
    use crate::db::{Database, monitored_utxo::IndexedBlock};

    let database = Database::connect("sqlite::memory:", 1).await.unwrap();
    let store = database.monitored_utxos();
    let faulty = [tick(1, 0, 5, 1), tick(2, 0, 5, 1)];
    let healthy = tick(3, 0, 6, 3);
    store
        .apply_block(
            "burning-v1",
            &IndexedBlock::at(61),
            &[faulty[0].clone(), faulty[1].clone(), healthy.clone()],
            &[],
            60,
        )
        .await
        .unwrap();
    let burning = test_burning(&store, &database, "http://127.0.0.1:9".into());

    burning
        .quarantine_group(([5; 32], 7), &faulty, 61, "indexed issued UTXO changed")
        .await
        .unwrap();

    let expired = store.list_expired(10).await.unwrap();
    assert_eq!(
        expired.iter().map(|item| item.txid).collect::<Vec<_>>(),
        vec![healthy.txid]
    );
    assert!(
        burning
            .quarantine_group(([5; 32], 7), &faulty, 62, "again")
            .await
            .is_err()
    );
}

/// Finalized weight of production burn transactions; the Storm Eye witness is the
/// fixed template the round limit already uses.
#[test]
#[ignore = "measurement taking about a minute; run with --ignored --nocapture"]
fn measures_burn_transaction_weight() {
    let fixture = BurnFixture::new();
    let weight = |groups: &[BurnableGroup]| {
        let built = fixture.build(groups, 500).unwrap();
        let (pset, _) = built.final_transaction.extract_pst();
        let weight =
            finalized_dummy_weight(&built.final_transaction, &pset, &fixture.network).unwrap();
        let items = groups.iter().map(|(group, _, _, _)| group.ticks.len());
        let bound = BURN_BASE_WEIGHT
            + BURN_ITEM_WEIGHT * items.sum::<usize>() as u64
            + BURN_RESERVE_WEIGHT * groups.len() as u64;
        assert!(
            weight as u64 <= bound,
            "{weight} WU exceeds the fee bound {bound}"
        );
        weight
    };

    let mut previous = 0;
    for items in [1, 2, 10, 20, 50, 100] {
        let tick_weight = weight(&[fixture.group(1, items, false, 100_000)]);
        let verifier_weight = weight(&[fixture.group(1, items, true, 100_000)]);
        let spread = (1..=items as u8)
            .map(|reserve| fixture.group(reserve, 1, false, 100_000))
            .collect::<Vec<_>>();
        let spread_weight = weight(&spread);
        println!(
            "items={items} one_reserve_ticks_wu={tick_weight} \
                 one_reserve_verifiers_wu={verifier_weight} one_reserve_each_wu={spread_weight}"
        );
        assert!(tick_weight > previous);
        assert!(spread_weight >= tick_weight);
        previous = tick_weight;
    }
}

#[test]
fn refuses_to_burn_a_verifier_without_its_internal_key() {
    let mut monitored = verifier(1, 2, 3, 4);
    monitored.internal_key = None;

    assert!(issued_program([7; 32], &monitored, voucher_program).is_err());
}

#[test]
fn burns_each_asset_into_an_op_return_of_its_own() {
    let assets = BurnAssets {
        tick: Some(AssetId::from_byte_array([1; 32])),
        verifier: Some(AssetId::from_byte_array([2; 32])),
    };
    let utxos = [
        verifier(1, 1, 1, 1),
        tick(2, 1, 1, 1),
        verifier(3, 1, 1, 1),
        tick(4, 1, 1, 1),
    ];

    assert_eq!(
        burn_outputs(&utxos, &assets).unwrap(),
        vec![
            (AssetId::from_byte_array([1; 32]), 3_400_000_000),
            (AssetId::from_byte_array([2; 32]), 2),
        ]
    );
    assert_eq!(
        burn_outputs(&utxos[..1], &assets).unwrap(),
        vec![(AssetId::from_byte_array([2; 32]), 1)]
    );
    assert!(
        burn_outputs(
            &utxos,
            &BurnAssets {
                verifier: None,
                ..assets
            }
        )
        .is_err()
    );
}
