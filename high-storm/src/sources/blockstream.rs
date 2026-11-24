use std::collections::BTreeMap;

use price_feed::{
    Asset, Clock, ConnectionError, FeedId, FeedKind, FeedRegistry, PriceSource, SourceObservation,
};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{base_units, http_client, liquid_asset_id};
use crate::config::BlockstreamConfig;

/// Answers `{"data": {"asset_id": "<hex>", "currency": "usd", "price": <price>,
/// "is_stale": <bool>, "is_fallback": <bool>, "updated_at": "<RFC 3339>"}}`.
const BASE_URL: &str = "https://enterprise.blockstream.info/price/api/v1/assets";

pub struct Blockstream {
    client: reqwest::Client,
    /// Every feed this source prices, all quoted in USD.
    assets: BTreeMap<FeedId, LiquidAsset>,
}

#[derive(Clone, Copy)]
struct LiquidAsset {
    id: &'static str,
    decimals: u32,
}

impl Blockstream {
    /// What an operator, and a persisted freeze, name this source by. It must
    /// never change, or a frozen source comes back unfrozen.
    pub const NAME: &'static str = "blockstream";

    pub fn new(_config: &BlockstreamConfig) -> Result<Self, reqwest::Error> {
        let assets = FeedRegistry::default()
            .feeds()
            .filter(|definition| {
                definition.kind == FeedKind::Direct && definition.quote == Asset::Usd
            })
            .filter_map(|definition| {
                let asset = LiquidAsset {
                    id: liquid_asset_id(definition.base)?,
                    decimals: definition.decimals,
                };
                Some((definition.id, asset))
            })
            .collect();

        Ok(Self {
            client: http_client()?,
            assets,
        })
    }

    pub fn feeds(&self) -> impl Iterator<Item = FeedId> + '_ {
        self.assets.keys().copied()
    }

    async fn fetch(&self, asset: LiquidAsset) -> Result<Value, ConnectionError> {
        let url = format!("{BASE_URL}/{}/price?currency=usd", asset.id);
        let response = self
            .client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| ConnectionError::RequestFailure)?;
        response
            .json()
            .await
            .map_err(|_| ConnectionError::MalformedResponse)
    }
}

impl PriceSource for Blockstream {
    async fn poll(&self, feed: FeedId) -> Result<SourceObservation, ConnectionError> {
        let asset = *self
            .assets
            .get(&feed)
            .ok_or(ConnectionError::RequestFailure)?;
        let body = self.fetch(asset).await?;
        observation(&body, asset, Clock::System.now())
    }
}

/// A quote the API flags stale, or replaces with its last known good price, is
/// not current whatever its `updated_at` says, so it is stamped at the epoch,
/// which `validate` rejects as `Expired`.
fn observation(
    body: &Value,
    asset: LiquidAsset,
    received_at: u64,
) -> Result<SourceObservation, ConnectionError> {
    let quote = body.get("data").ok_or(ConnectionError::MalformedResponse)?;
    let answers_for =
        |field: &str, expected: &str| quote.get(field).and_then(Value::as_str) == Some(expected);
    if !answers_for("asset_id", asset.id) || !answers_for("currency", "usd") {
        return Err(ConnectionError::MalformedResponse);
    }
    let price = quote
        .get("price")
        .ok_or(ConnectionError::MalformedResponse)?;
    let flag = |field: &str| quote.get(field).and_then(Value::as_bool);
    let (Some(stale), Some(fallback)) = (flag("is_stale"), flag("is_fallback")) else {
        return Err(ConnectionError::MalformedResponse);
    };
    let updated_at = quote
        .get("updated_at")
        .and_then(Value::as_str)
        .and_then(|stamp| OffsetDateTime::parse(stamp, &Rfc3339).ok())
        .and_then(|stamp| u64::try_from(stamp.unix_timestamp()).ok())
        .ok_or(ConnectionError::MalformedResponse)?;
    let observed_at = if stale || fallback { 0 } else { updated_at };

    Ok(SourceObservation::new(
        base_units(price.as_f64(), asset.decimals),
        asset.decimals,
        observed_at,
        received_at,
    ))
}

#[cfg(test)]
mod tests {
    use price_feed::{RejectionReason, registry::FEED_DECIMALS};
    use serde_json::json;

    use super::*;

    /// 2023-11-14T22:13:20Z.
    const NOW: u64 = 1_700_000_000;
    const LBTC_USD: FeedId = 0;
    const USDT_USD: FeedId = 1;
    const EURX_USD: FeedId = 2;
    const DEPIX_USD: FeedId = 3;
    const LBTC: LiquidAsset = LiquidAsset {
        id: "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        decimals: FEED_DECIMALS,
    };

    fn body(price: Value, stale: bool, fallback: bool) -> Value {
        json!({
            "data": {
                "asset_id": LBTC.id,
                "ticker": "LBTC",
                "name": "Liquid Bitcoin",
                "currency": "usd",
                "price": price,
                "price_usd": price,
                "is_stale": stale,
                "is_fallback": fallback,
                "updated_at": "2023-11-14T22:13:15.452990+00:00",
            },
            "meta": { "timestamp": "2023-11-14T22:13:20.000000+00:00", "currency": "usd" },
        })
    }

    #[test]
    fn reads_a_quote_into_base_units() {
        let observation =
            observation(&body(json!(95_123.456_789_01), false, false), LBTC, NOW).unwrap();

        assert_eq!(observation.price, 9_512_345_678_901);
        assert_eq!(observation.observed_at, NOW - 5);
    }

    #[test]
    fn rejects_a_quote_the_api_flags_stale_or_fallback_as_expired() {
        for (stale, fallback) in [(true, false), (false, true)] {
            let observation =
                observation(&body(json!(95_123.45), stale, fallback), LBTC, NOW).unwrap();

            assert_eq!(
                Blockstream::validate(&observation, None),
                Err(RejectionReason::Expired)
            );
        }
    }

    #[test]
    fn maps_an_unusable_answer_to_the_specified_errors() {
        let quote = body(json!(95_123.45), false, false);
        let without = |field: &str| {
            let mut body = quote.clone();
            body["data"].as_object_mut().unwrap().remove(field);
            body
        };
        let with = |field: &str, value: Value| {
            let mut body = quote.clone();
            body["data"][field] = value;
            body
        };
        // No quote, a missing field, another asset or currency, and an
        // unreadable timestamp.
        for body in [
            json!({}),
            without("price"),
            without("is_stale"),
            without("is_fallback"),
            without("updated_at"),
            with("asset_id", json!("ce09")),
            with("currency", json!("eur")),
            with("updated_at", json!("yesterday")),
        ] {
            assert_eq!(
                observation(&body, LBTC, NOW),
                Err(ConnectionError::MalformedResponse)
            );
        }

        // Unpriced, non-numeric, negative, and past u64 in base units.
        for price in [Value::Null, json!("95123.45"), json!(-1.0), json!(1e30)] {
            let observation = observation(&body(price, false, false), LBTC, NOW).unwrap();

            assert_eq!(
                Blockstream::validate(&observation, None),
                Err(RejectionReason::InvalidPrice)
            );
        }
    }

    #[tokio::test]
    #[ignore = "reaches the live Blockstream price API"]
    async fn polls_live_quotes() {
        let source = Blockstream::new(&BlockstreamConfig {}).unwrap();
        let feeds: Vec<_> = source.feeds().collect();
        assert_eq!(feeds, [LBTC_USD, USDT_USD, EURX_USD, DEPIX_USD]);

        // Freshness is left out: the API refreshes its quotes less often than
        // the source data validity duration.
        let mut prices = BTreeMap::new();
        for feed in feeds {
            let observation = source.poll(feed).await.unwrap();
            prices.insert(feed, observation.price);
        }

        // In base units: Bitcoin above $1,000, USDt within 10% of $1, EURx
        // between $0.50 and $2, DePix between $0.05 and $1.
        let dollar = 10u64.pow(FEED_DECIMALS);
        assert!(prices[&LBTC_USD] > 1_000 * dollar);
        assert!((dollar * 9 / 10..=dollar * 11 / 10).contains(&prices[&USDT_USD]));
        assert!((dollar / 2..=dollar * 2).contains(&prices[&EURX_USD]));
        assert!((dollar / 20..=dollar).contains(&prices[&DEPIX_USD]));
    }
}
