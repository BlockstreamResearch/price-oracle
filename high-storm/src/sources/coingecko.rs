use std::{collections::BTreeMap, sync::Arc, time::Duration};

use price_feed::{
    Asset, Clock, ConnectionError, FeedId, FeedKind, FeedRegistry, PriceSource, SourceObservation,
};
use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs};
use serde_json::Value;

use crate::config::CoinGeckoConfig;

/// Answers `{"<coin id>": {"usd": <price>, "last_updated_at": <unix>}}`.
const SIMPLE_PRICE_URL: &str = "https://api.coingecko.com/api/v3/simple/price";

/// CoinGecko's edge refuses a request that names no client.
const USER_AGENT: &str = concat!("high-storm/", env!("CARGO_PKG_VERSION"));

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct CoinGecko {
    client: reqwest::Client,
    api_key: Option<String>,
    /// Every feed this source prices, all quoted in USD.
    coins: BTreeMap<FeedId, Coin>,
}

#[derive(Clone, Copy)]
struct Coin {
    id: &'static str,
    decimals: u32,
}

impl CoinGecko {
    pub fn new(config: &CoinGeckoConfig) -> Result<Self, reqwest::Error> {
        let coins = FeedRegistry::default()
            .feeds()
            .filter(|definition| {
                definition.kind == FeedKind::Direct && definition.quote == Asset::Usd
            })
            .filter_map(|definition| {
                let coin = Coin {
                    id: coin_id(definition.base)?,
                    decimals: definition.decimals,
                };
                Some((definition.id, coin))
            })
            .collect();

        Ok(Self {
            client: reqwest::Client::builder()
                .use_preconfigured_tls(tls())
                .user_agent(USER_AGENT)
                .timeout(REQUEST_TIMEOUT)
                .build()?,
            api_key: config.api_key.clone(),
            coins,
        })
    }

    pub fn feeds(&self) -> impl Iterator<Item = FeedId> + '_ {
        self.coins.keys().copied()
    }

    async fn fetch(&self, coin: Coin) -> Result<Value, ConnectionError> {
        let url = format!(
            "{SIMPLE_PRICE_URL}?ids={}&vs_currencies=usd&include_last_updated_at=true",
            coin.id
        );
        let mut request = self.client.get(url);
        if let Some(key) = &self.api_key {
            request = request.header("x-cg-demo-api-key", key);
        }
        let response = request
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

/// reqwest's rustls backend brings no crypto of its own, so the client carries
/// its TLS configuration instead of relying on a process-wide default.
fn tls() -> ClientConfig {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// CoinGecko prices LBTC as Bitcoin, which LBTC is pegged to one-to-one. It
/// lists neither EURx nor DePix.
fn coin_id(asset: Asset) -> Option<&'static str> {
    match asset {
        Asset::Lbtc => Some("bitcoin"),
        Asset::Usdt => Some("tether"),
        Asset::Usdc => Some("usd-coin"),
        Asset::Usd | Asset::Eurx | Asset::DePix => None,
    }
}

impl PriceSource for CoinGecko {
    async fn poll(&self, feed: FeedId) -> Result<SourceObservation, ConnectionError> {
        let coin = *self
            .coins
            .get(&feed)
            .ok_or(ConnectionError::RequestFailure)?;
        let body = self.fetch(coin).await?;
        observation(&body, coin, Clock::System.now())
    }
}

fn observation(
    body: &Value,
    coin: Coin,
    received_at: u64,
) -> Result<SourceObservation, ConnectionError> {
    let quote = body
        .get(coin.id)
        .ok_or(ConnectionError::MalformedResponse)?;
    let price = quote.get("usd").ok_or(ConnectionError::MalformedResponse)?;
    let observed_at = quote
        .get("last_updated_at")
        .and_then(Value::as_u64)
        .ok_or(ConnectionError::MalformedResponse)?;

    Ok(SourceObservation::new(
        base_units(price, coin.decimals),
        coin.decimals,
        observed_at,
        received_at,
    ))
}

/// A price that is not a usable number becomes zero, which `validate` rejects
/// as `InvalidPrice`.
fn base_units(price: &Value, decimals: u32) -> u64 {
    let scaled = price.as_f64().unwrap_or_default() * 10f64.powi(decimals as i32);
    if (0.0..u64::MAX as f64).contains(&scaled) {
        scaled.round() as u64
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use price_feed::{RejectionReason, constants::VALIDITY_WINDOW, registry::FEED_DECIMALS};
    use serde_json::json;

    use super::*;

    const NOW: u64 = 1_700_000_000;
    const LBTC_USD: FeedId = 0;
    const USDT_USD: FeedId = 1;
    const USDC_USD: FeedId = 7;
    const BITCOIN: Coin = Coin {
        id: "bitcoin",
        decimals: FEED_DECIMALS,
    };

    #[test]
    fn reads_a_quote_into_base_units() {
        let body = json!({ "bitcoin": { "usd": 95_123.456_789_01, "last_updated_at": NOW - 5 } });

        let observation = observation(&body, BITCOIN, NOW).unwrap();

        assert_eq!(observation.price, 9_512_345_678_901);
        assert_eq!(observation.observed_at, NOW - 5);
    }

    #[test]
    fn maps_an_unusable_answer_to_the_specified_errors() {
        // No quote, no USD price, and no timestamp.
        for body in [
            json!({}),
            json!({ "bitcoin": { "last_updated_at": NOW } }),
            json!({ "bitcoin": { "usd": 95_123.45 } }),
        ] {
            assert_eq!(
                observation(&body, BITCOIN, NOW),
                Err(ConnectionError::MalformedResponse)
            );
        }

        // Non-numeric, negative, and past u64 in base units.
        for price in [json!("95123.45"), json!(-1.0), json!(1e30)] {
            let body = json!({ "bitcoin": { "usd": price, "last_updated_at": NOW } });
            let observation = observation(&body, BITCOIN, NOW).unwrap();

            assert_eq!(
                CoinGecko::validate(&observation, None),
                Err(RejectionReason::InvalidPrice)
            );
        }
    }

    #[tokio::test]
    #[ignore = "reaches the live CoinGecko API"]
    async fn polls_live_quotes_as_the_specification_requires() {
        let source = CoinGecko::new(&CoinGeckoConfig { api_key: None }).unwrap();
        let feeds: Vec<_> = source.feeds().collect();
        assert_eq!(feeds, [LBTC_USD, USDT_USD, USDC_USD]);

        let mut prices = BTreeMap::new();
        for feed in feeds {
            let polled_at = Clock::System.now();
            let observation = source.poll(feed).await.unwrap();

            assert_eq!(CoinGecko::validate(&observation, None), Ok(()));
            assert!((polled_at..=Clock::System.now()).contains(&observation.received_at));
            assert_eq!(
                observation.valid_until,
                observation.received_at + VALIDITY_WINDOW
            );
            prices.insert(feed, observation.price);
        }

        // In base units: Bitcoin above $1,000, the stablecoins within 10% of $1.
        let dollar = 10u64.pow(FEED_DECIMALS);
        assert!(prices[&LBTC_USD] > 1_000 * dollar);
        for feed in [USDT_USD, USDC_USD] {
            assert!((dollar * 9 / 10..=dollar * 11 / 10).contains(&prices[&feed]));
        }
    }
}
