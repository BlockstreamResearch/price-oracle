use price_feed::PriceFeedData;

use super::*;
use crate::monitoring::builder;

const LBTC_USD: FeedId = 0;
const USDT_USD: FeedId = 1;
const LBTC_USDT: FeedId = 4;
const USDC_USD: FeedId = 7;

fn coingecko(feed: FeedId) -> PolledSource {
    PolledSource {
        feed,
        source: 0,
        name: "coingecko",
    }
}

#[test]
fn measures_a_change_only_between_comparable_prices() {
    let at = |price, decimals| SourceObservation::new(price, decimals, 0, 0);

    assert_eq!(change_bps(&at(10_000, 8), &at(8_900, 8)), Some(1_100));
    assert_eq!(change_bps(&at(10_000, 8), &at(10_000, 8)), Some(0));
    assert_eq!(change_bps(&at(10_000, 8), &at(9_000, 6)), None);
    assert_eq!(change_bps(&at(0, 8), &at(9_000, 8)), None);
}

#[test]
fn reports_each_members_latest_attestation() {
    let attestation = |key: u8, price, valid_until| PriceAttestation {
        feed: PriceFeedData {
            feed_id: LBTC_USD,
            price,
            decimals: 8,
            received_at: 1_700_000_000,
            valid_until,
        },
        signature: Vec::new(),
        public_key: [key; 32],
    };
    let members = BTreeMap::from([([2; 32], [2; 33]), ([3; 32], [3; 33])]);
    let own = PriceFeedData {
        feed_id: LBTC_USD,
        price: 10_000,
        decimals: 8,
        received_at: 1_700_000_000,
        valid_until: 1_700_000_100,
    };
    let recorder = builder().unwrap().build_recorder();

    metrics::with_local_recorder(&recorder, || {
        record_feed_attestations(
            "LBTC/USD",
            &members,
            &[
                attestation(2, 10_250, 1_700_000_100),
                // Expired, so only its timestamp is reported.
                attestation(3, 20_000, 1_700_000_010),
                // Its own, or a node that is no longer a member.
                attestation(1, 10_000, 1_700_000_100),
            ],
            Some(own),
            1_700_000_050,
        );
    });

    let rendered = recorder.handle().render();
    let (second, third) = (hex::encode([2; 33]), hex::encode([3; 33]));
    for line in [
        format!(
            "high_storm_price_peer_attestation_timestamp_seconds{{feed=\"LBTC/USD\",peer=\"{second}\"}} 1700000000"
        ),
        format!(
            "high_storm_price_peer_attestation_timestamp_seconds{{feed=\"LBTC/USD\",peer=\"{third}\"}} 1700000000"
        ),
        format!("high_storm_price_peer_deviation_bps{{feed=\"LBTC/USD\",peer=\"{second}\"}} 250"),
    ] {
        assert!(rendered.contains(&line), "missing {line:?} in:\n{rendered}");
    }
    assert!(rendered.contains(&format!(
        "high_storm_price_peer_deviation_bps{{feed=\"LBTC/USD\",peer=\"{third}\"}} NaN"
    )));
    assert!(!rendered.contains(&hex::encode([1; 33])));
}

#[test]
fn tells_a_refused_api_key_from_an_unreachable_source() {
    let recorder = builder().unwrap().build_recorder();

    metrics::with_local_recorder(&recorder, || {
        record_price_poll_error("keyed", ConnectionError::Unauthorized);
        record_price_poll_error("keyed", ConnectionError::RequestFailure);
    });

    let rendered = recorder.handle().render();
    for reason in ["unauthorized", "request_failure"] {
        assert!(rendered.contains(&format!(
            "high_storm_price_poll_failures_total{{source=\"keyed\",reason=\"{reason}\"}} 1"
        )));
    }
}

#[test]
fn republishes_the_last_change() {
    let at = |price| SourceObservation::new(price, 8, 0, 0);
    let first = builder().unwrap().build_recorder();
    metrics::with_local_recorder(&first, || {
        record_price_change(USDC_USD, "republished", &at(10_000), &at(10_050));
    });
    let second = builder().unwrap().build_recorder();

    metrics::with_local_recorder(&second, record_price_changes);

    assert!(
        second
            .handle()
            .render()
            .contains(r#"high_storm_price_change_bps{feed="USDC/USD",source="republished"} 50"#)
    );
}

#[test]
fn covers_only_the_feeds_a_source_can_price() {
    let polled = [
        coingecko(LBTC_USD),
        coingecko(USDT_USD),
        coingecko(USDC_USD),
    ];

    let feeds = priced_feeds(&FeedRegistry::default(), &polled);

    // No source quotes EURX or DePix, so neither they nor their Cross pairs count.
    assert_eq!(
        feeds
            .iter()
            .map(|definition| definition.id)
            .collect::<Vec<_>>(),
        vec![LBTC_USD, USDT_USD, LBTC_USDT, USDC_USD]
    );
}

#[test]
fn records_feed_and_source_health() {
    let polled = [coingecko(LBTC_USD), coingecko(USDT_USD)];
    let feeds = priced_feeds(&FeedRegistry::default(), &polled);
    let health = PriceHealth {
        sources: vec![
            SourceHealth {
                feed: LBTC_USD,
                source: 0,
                state: SourceState::Active,
                observed_at: Some(1_700_000_000),
            },
            SourceHealth {
                feed: USDT_USD,
                source: 0,
                state: SourceState::Dropped,
                observed_at: None,
            },
        ],
        values: vec![
            (
                LBTC_USD,
                Some(PriceFeedData {
                    feed_id: LBTC_USD,
                    price: 100,
                    decimals: 8,
                    received_at: 1_700_000_001,
                    valid_until: 1_700_000_301,
                }),
            ),
            (USDT_USD, None),
            (LBTC_USDT, None),
        ],
    };
    let recorder = builder().unwrap().build_recorder();

    metrics::with_local_recorder(&recorder, || {
        record_price_health(&feeds, &polled, &health);
    });

    let rendered = recorder.handle().render();
    for line in [
        r#"high_storm_price_feed_available{feed="LBTC/USD"} 1"#,
        r#"high_storm_price_feed_available{feed="USDT/USD"} 0"#,
        r#"high_storm_price_feed_available{feed="LBTC/USDT"} 0"#,
        r#"high_storm_price_feed_received_timestamp_seconds{feed="LBTC/USD"} 1700000001"#,
        r#"high_storm_price_feed_valid_until_timestamp_seconds{feed="LBTC/USD"} 1700000301"#,
        r#"high_storm_price_feed_active_sources{feed="LBTC/USD"} 1"#,
        r#"high_storm_price_feed_active_sources{feed="USDT/USD"} 0"#,
        r#"high_storm_price_source_state{feed="LBTC/USD",source="coingecko",state="active"} 1"#,
        r#"high_storm_price_source_state{feed="USDT/USD",source="coingecko",state="dropped"} 1"#,
        r#"high_storm_price_source_state{feed="USDT/USD",source="coingecko",state="active"} 0"#,
        r#"high_storm_price_source_last_observed_timestamp_seconds{feed="LBTC/USD",source="coingecko"} 1700000000"#,
    ] {
        assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
    }
    assert!(!rendered.contains(r#"active_sources{feed="LBTC/USDT"}"#));
}
