use std::str::FromStr;

use bitcoincore_rpc::Auth;

use super::*;

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
