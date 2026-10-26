use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bitcoincore_rpc::{Auth, Client, RpcApi};
use metrics::gauge;
use serde::Deserialize;
use tokio::time::MissedTickBehavior;

use super::{flag, names};
use crate::config::ElementsRpcConfig;

/// Calls run on a blocking thread one probe at a time, each bounded by the
/// RPC transport's own timeout.
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
struct BlockchainInfo {
    blocks: u64,
    time: u64,
    initialblockdownload: bool,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ElementsStatus {
    tip_height: u64,
    tip_time: u64,
    peers: u64,
    initial_block_download: bool,
}

/// The last tip height Elements reported; 0 until it first answers.
static TIP_HEIGHT: AtomicU64 = AtomicU64::new(0);

/// Elements' tip as last seen, which does not wait for this node to index it.
pub(super) fn tip_height() -> Option<u64> {
    Some(TIP_HEIGHT.load(Ordering::Relaxed)).filter(|height| *height > 0)
}

/// Probes the node's Elements daemon until the process exits.
pub fn spawn_elements_probe(config: &ElementsRpcConfig) -> Result<(), bitcoincore_rpc::Error> {
    let client = Arc::new(Client::new(
        &config.url,
        Auth::UserPass(config.username.clone(), config.password.clone()),
    )?);
    tokio::spawn(async move {
        let mut probe = tokio::time::interval(PROBE_INTERVAL);
        probe.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_known = None;
        loop {
            probe.tick().await;
            let client = client.clone();
            let status = tokio::task::spawn_blocking(move || read_status(&client))
                .await
                .ok()
                .and_then(Result::ok);
            last_known = status.or(last_known);
            if let Some(status) = status {
                TIP_HEIGHT.store(status.tip_height, Ordering::Relaxed);
            }
            record_status(status.is_some(), last_known.as_ref());
        }
    });
    Ok(())
}

fn read_status(client: &Client) -> Result<ElementsStatus, bitcoincore_rpc::Error> {
    let info: BlockchainInfo = client.call("getblockchaininfo", &[])?;
    let peers: u64 = client.call("getconnectioncount", &[])?;
    Ok(ElementsStatus {
        tip_height: info.blocks,
        tip_time: info.time,
        peers,
        initial_block_download: info.initialblockdownload,
    })
}

/// While Elements is unreachable the last known tip is republished, so its
/// age keeps growing instead of the gauges going idle.
fn record_status(up: bool, last_known: Option<&ElementsStatus>) {
    gauge!(names::ELEMENTS_RPC_UP).set(flag(up));
    let Some(status) = last_known else {
        return;
    };
    gauge!(names::ELEMENTS_TIP_HEIGHT).set(status.tip_height as f64);
    gauge!(names::ELEMENTS_TIP_TIMESTAMP).set(status.tip_time as f64);
    gauge!(names::ELEMENTS_PEERS).set(status.peers as f64);
    gauge!(names::ELEMENTS_INITIAL_BLOCK_DOWNLOAD).set(flag(status.initial_block_download));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::builder;

    #[test]
    fn reads_the_fields_elements_returns() {
        let info: BlockchainInfo = serde_json::from_str(
            r#"{
                "chain": "elementsregtest",
                "blocks": 113,
                "headers": 113,
                "time": 1792596164,
                "mediantime": 1792595864,
                "initialblockdownload": false
            }"#,
        )
        .unwrap();

        assert_eq!(info.blocks, 113);
        assert_eq!(info.time, 1_792_596_164);
        assert!(!info.initialblockdownload);
    }

    #[test]
    fn keeps_the_last_known_tip_while_elements_is_down() {
        let status = ElementsStatus {
            tip_height: 113,
            tip_time: 1_792_596_164,
            peers: 4,
            initial_block_download: false,
        };
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || record_status(false, Some(&status)));

        let rendered = recorder.handle().render();
        for line in [
            "high_storm_elements_rpc_up 0",
            "high_storm_elements_tip_height 113",
            "high_storm_elements_tip_timestamp_seconds 1792596164",
            "high_storm_elements_peers 4",
            "high_storm_elements_initial_block_download 0",
        ] {
            assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
        }
    }

    #[test]
    fn shares_the_tip_only_once_elements_has_answered() {
        TIP_HEIGHT.store(0, Ordering::Relaxed);
        assert_eq!(tip_height(), None);

        TIP_HEIGHT.store(140, Ordering::Relaxed);
        assert_eq!(tip_height(), Some(140));
    }

    #[test]
    fn reports_down_before_any_tip_is_known() {
        let recorder = builder().unwrap().build_recorder();

        metrics::with_local_recorder(&recorder, || record_status(false, None));

        let rendered = recorder.handle().render();
        assert!(rendered.contains("high_storm_elements_rpc_up 0"));
        assert!(!rendered.contains("high_storm_elements_tip_height"));
    }
}
