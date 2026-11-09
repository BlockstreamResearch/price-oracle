use std::{collections::BTreeMap, sync::Arc};

use futures_util::{SinkExt, StreamExt};
use price_feed::{
    Asset, Clock, ConnectionError, FeedId, FeedKind, FeedRegistry, PriceFeedData, PriceSource,
    SourceObservation,
};
use rustls::ClientConfig;
use serde_json::{Value, json};
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::Message};

use super::{REQUEST_TIMEOUT, base_units, liquid_asset_id, tls};
use crate::{HighStormHandle, config::SideSwapConfig};

/// JSON-RPC over WebSocket. A `market` `subscribe` answers with the pair's
/// order book: `{"orders": [{"price": <quote per base>, "trade_dir": "Buy" |
/// "Sell", "online": <bool>, ...}], "timestamp": <unix millis>}`.
const API_URL: &str = "wss://api.sideswap.io/json-rpc-ws";

const REQUEST_ID: u64 = 1;

/// Prices assets from SideSwap's Liquid order books, where they trade against
/// USDt, and converts them to USD with the node's own USDT/USD value.
pub struct SideSwap {
    api_url: String,
    node: HighStormHandle,
    tls: Arc<ClientConfig>,
    usdt_usd: FeedId,
    /// Every feed this source prices, all quoted in USD.
    markets: BTreeMap<FeedId, Market>,
}

#[derive(Clone, Copy)]
struct Market {
    base: &'static str,
    quote: &'static str,
    /// The book prices USDt in the asset rather than the asset in USDt.
    inverted: bool,
    decimals: u32,
}

impl SideSwap {
    /// What an operator, and a persisted freeze, name this source by. It must
    /// never change, or a frozen source comes back unfrozen.
    pub const NAME: &'static str = "sideswap";

    pub fn new(_config: &SideSwapConfig, node: HighStormHandle) -> Self {
        Self::at(API_URL, node)
    }

    /// Reads the books from another deployment of the API, such as SideSwap's
    /// testnet or a stand-in a test serves.
    pub fn at(api_url: impl Into<String>, node: HighStormHandle) -> Self {
        let registry = FeedRegistry::default();
        let usdt_usd = registry
            .feeds()
            .find(|definition| {
                definition.kind == FeedKind::Direct
                    && definition.base == Asset::Usdt
                    && definition.quote == Asset::Usd
            })
            .expect("the built-in registry prices USDT/USD")
            .id;
        let markets = registry
            .feeds()
            .filter(|definition| {
                definition.kind == FeedKind::Direct && definition.quote == Asset::Usd
            })
            .filter_map(|definition| {
                let (base, quote) = pair(definition.base)?;
                let market = Market {
                    base: liquid_asset_id(base)?,
                    quote: liquid_asset_id(quote)?,
                    inverted: base == Asset::Usdt,
                    decimals: definition.decimals,
                };
                Some((definition.id, market))
            })
            .collect();

        Self {
            api_url: api_url.into(),
            node,
            tls: Arc::new(tls()),
            usdt_usd,
            markets,
        }
    }

    pub fn feeds(&self) -> impl Iterator<Item = FeedId> + '_ {
        self.markets.keys().copied()
    }
}

/// The pair SideSwap lists the asset in against USDt, base first. USDt itself
/// has no USD market there, and USDC is not on Liquid.
fn pair(asset: Asset) -> Option<(Asset, Asset)> {
    match asset {
        Asset::Lbtc => Some((Asset::Lbtc, Asset::Usdt)),
        Asset::Eurx => Some((Asset::Eurx, Asset::Usdt)),
        Asset::DePix => Some((Asset::Usdt, Asset::DePix)),
        Asset::Usd | Asset::Usdt | Asset::Usdc => None,
    }
}

impl PriceSource for SideSwap {
    async fn poll(&self, feed: FeedId) -> Result<SourceObservation, ConnectionError> {
        let market = *self
            .markets
            .get(&feed)
            .ok_or(ConnectionError::RequestFailure)?;
        let book = fetch(&self.api_url, &self.tls, market).await?;
        // Without a current USDT/USD value there is no USD price to give, so
        // the poll fails as an unreachable source's would.
        let usdt_usd = self
            .node
            .price_feed_value(self.usdt_usd)
            .await
            .ok_or(ConnectionError::RequestFailure)?;
        observation(&book, market, usdt_usd, Clock::System.now())
    }
}

/// One connection per poll: subscribing answers with the whole book, after
/// which the connection is of no further use.
async fn fetch(
    api_url: &str,
    tls: &Arc<ClientConfig>,
    market: Market,
) -> Result<Value, ConnectionError> {
    let exchange = async {
        let connector = Connector::Rustls(tls.clone());
        let (mut socket, _) = connect_async_tls_with_config(api_url, None, false, Some(connector))
            .await
            .map_err(|_| ConnectionError::RequestFailure)?;
        let request = json!({
            "id": REQUEST_ID,
            "method": "market",
            "params": {
                "subscribe": { "asset_pair": { "base": market.base, "quote": market.quote } },
            },
        });
        socket
            .send(Message::text(request.to_string()))
            .await
            .map_err(|_| ConnectionError::RequestFailure)?;
        // Notifications may arrive ahead of the answer.
        let answer = loop {
            let message = socket
                .next()
                .await
                .ok_or(ConnectionError::RequestFailure)?
                .map_err(|_| ConnectionError::RequestFailure)?;
            let Message::Text(text) = message else {
                continue;
            };
            let body: Value = serde_json::from_str(text.as_str())
                .map_err(|_| ConnectionError::MalformedResponse)?;
            if body.get("id").and_then(Value::as_u64) == Some(REQUEST_ID) {
                break body;
            }
        };
        // The book is read, so how the close goes changes nothing.
        let _ = socket.close(None).await;
        Ok(answer)
    };
    tokio::time::timeout(REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| ConnectionError::RequestFailure)?
}

/// Priced at the midpoint of the best bid and ask among the orders whose
/// makers are online; an offline order is not a live quote. A book without a
/// live quote on either side has no midpoint, which leaves the price at zero
/// and `validate` rejects it as `InvalidPrice`.
fn observation(
    body: &Value,
    market: Market,
    usdt_usd: PriceFeedData,
    received_at: u64,
) -> Result<SourceObservation, ConnectionError> {
    let book = body
        .pointer("/result/subscribe")
        .ok_or(ConnectionError::MalformedResponse)?;
    let observed_at = book
        .get("timestamp")
        .and_then(Value::as_u64)
        .ok_or(ConnectionError::MalformedResponse)?
        / 1_000;
    let orders = book
        .get("orders")
        .and_then(Value::as_array)
        .ok_or(ConnectionError::MalformedResponse)?;

    let (mut bid, mut ask) = (None::<f64>, None::<f64>);
    for order in orders {
        let online = order.get("online").and_then(Value::as_bool);
        let price = order.get("price").and_then(Value::as_f64);
        let side = order.get("trade_dir").and_then(Value::as_str);
        let (Some(online), Some(price), Some(side)) = (online, price, side) else {
            return Err(ConnectionError::MalformedResponse);
        };
        match side {
            // An offline order is not a live quote, but it is still read, so an
            // unknown side is malformed whether or not its maker is online.
            "Buy" if online => bid = Some(bid.map_or(price, |best| best.max(price))),
            "Sell" if online => ask = Some(ask.map_or(price, |best| best.min(price))),
            "Buy" | "Sell" => {}
            _ => return Err(ConnectionError::MalformedResponse),
        }
    }

    let in_usd = bid.zip(ask).map(|(bid, ask)| {
        let mid = (bid + ask) / 2.0;
        let in_usdt = if market.inverted { 1.0 / mid } else { mid };
        in_usdt * usdt_usd.price as f64 / 10f64.powi(usdt_usd.decimals as i32)
    });

    // The USD price is only as good as the USDT/USD value it was converted
    // with, so it expires no later than that value does.
    Ok(SourceObservation::new(
        base_units(in_usd, market.decimals),
        market.decimals,
        observed_at,
        received_at,
    )
    .valid_no_later_than(usdt_usd.valid_until))
}

#[cfg(test)]
mod tests {
    use price_feed::{RejectionReason, constants::VALIDITY_WINDOW, registry::FEED_DECIMALS};

    use super::*;

    const NOW: u64 = 1_700_000_000;
    const USDT_USD: FeedId = 1;
    const LBTC_USDT: Market = Market {
        base: "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        quote: "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2",
        inverted: false,
        decimals: FEED_DECIMALS,
    };
    const USDT_DEPIX: Market = Market {
        base: "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2",
        quote: "02f22f8d9c76ab41661a2729e4752e2c5d1a263012141b86ea98af5472df5189",
        inverted: true,
        decimals: FEED_DECIMALS,
    };

    fn usdt_usd(price: u64) -> PriceFeedData {
        PriceFeedData {
            feed_id: USDT_USD,
            price,
            decimals: FEED_DECIMALS,
            received_at: NOW,
            valid_until: NOW + VALIDITY_WINDOW,
        }
    }

    fn order(price: f64, side: &str, online: bool) -> Value {
        json!({ "amount": 100_000, "order_id": 1, "price": price, "trade_dir": side, "online": online })
    }

    fn book(orders: Vec<Value>) -> Value {
        json!({
            "id": REQUEST_ID,
            "method": "market",
            "result": { "subscribe": { "orders": orders, "timestamp": (NOW - 2) * 1_000 + 345 } },
        })
    }

    #[test]
    fn prices_the_midpoint_of_the_live_quotes_in_usd() {
        // The offline orders would otherwise be the best on each side.
        let body = book(vec![
            order(83_000.0, "Buy", true),
            order(82_000.0, "Buy", true),
            order(83_400.0, "Sell", true),
            order(83_300.0, "Buy", false),
            order(83_100.0, "Sell", false),
        ]);

        let observation = observation(&body, LBTC_USDT, usdt_usd(99_900_000), NOW).unwrap();

        // 83,200 USDt at 0.999 USD each.
        assert_eq!(observation.price, 8_311_680_000_000);
        assert_eq!(observation.observed_at, NOW - 2);
        assert_eq!(observation.received_at, NOW);
    }

    #[test]
    fn inverts_a_book_that_prices_usdt_in_the_asset() {
        let body = book(vec![order(5.0, "Buy", true), order(5.2, "Sell", true)]);

        let observation = observation(&body, USDT_DEPIX, usdt_usd(100_000_000), NOW).unwrap();

        // 5.1 DePix per USDt is 1 / 5.1 USD per DePix.
        assert_eq!(observation.price, 19_607_843);
    }

    #[test]
    fn expires_with_the_usdt_usd_value_it_was_converted_with() {
        let body = book(vec![
            order(83_000.0, "Buy", true),
            order(83_400.0, "Sell", true),
        ]);
        let nearly_expired = PriceFeedData {
            valid_until: NOW + 10,
            ..usdt_usd(100_000_000)
        };

        let observation = observation(&body, LBTC_USDT, nearly_expired, NOW).unwrap();

        assert_eq!(observation.valid_until, NOW + 10);
        // The book still dates the observation, so a price that moved is not
        // taken for one that stood still.
        assert_eq!(observation.observed_at, NOW - 2);
        assert_eq!(SideSwap::validate(&observation, Some(NOW - 3)), Ok(()));
    }

    #[test]
    fn rejects_a_book_without_live_quotes_on_both_sides() {
        for orders in [
            vec![],
            vec![order(83_000.0, "Buy", true)],
            vec![order(83_400.0, "Sell", true)],
            vec![
                order(83_000.0, "Buy", false),
                order(83_400.0, "Sell", false),
            ],
        ] {
            let observation =
                observation(&book(orders), LBTC_USDT, usdt_usd(100_000_000), NOW).unwrap();

            assert_eq!(
                SideSwap::validate(&observation, None),
                Err(RejectionReason::InvalidPrice)
            );
        }
    }

    #[test]
    fn maps_an_unreadable_book_to_malformed_response() {
        let without = |field: &str| {
            let mut order = order(83_000.0, "Buy", true);
            order.as_object_mut().unwrap().remove(field);
            book(vec![order])
        };
        let mut untimed = book(vec![]);
        untimed["result"]["subscribe"]
            .as_object_mut()
            .unwrap()
            .remove("timestamp");

        for body in [
            json!({ "id": REQUEST_ID, "error": { "code": -32600, "message": "invalid" } }),
            untimed,
            without("price"),
            without("trade_dir"),
            without("online"),
            book(vec![order(83_000.0, "Hold", true)]),
            book(vec![order(83_000.0, "Hold", false)]),
        ] {
            assert_eq!(
                observation(&body, LBTC_USDT, usdt_usd(100_000_000), NOW),
                Err(ConnectionError::MalformedResponse)
            );
        }
    }

    #[tokio::test]
    #[ignore = "reaches the live SideSwap API"]
    async fn reads_live_books() {
        let tls = Arc::new(tls());
        let at = |asset| liquid_asset_id(asset).unwrap();
        let market = |base, quote, inverted| Market {
            base: at(base),
            quote: at(quote),
            inverted,
            decimals: FEED_DECIMALS,
        };

        let mut prices = Vec::new();
        for market in [
            market(Asset::Lbtc, Asset::Usdt, false),
            market(Asset::Eurx, Asset::Usdt, false),
            market(Asset::Usdt, Asset::DePix, true),
        ] {
            let polled_at = Clock::System.now();
            let book = fetch(API_URL, &tls, market).await.unwrap();
            let observation = observation(&book, market, usdt_usd(100_000_000), polled_at).unwrap();

            assert_eq!(SideSwap::validate(&observation, None), Ok(()));
            prices.push(observation.price);
        }

        // In base units, taking USDt at $1: Bitcoin above $1,000, EURx between
        // $0.50 and $2, DePix between $0.05 and $1.
        let dollar = 10u64.pow(FEED_DECIMALS);
        assert!(prices[0] > 1_000 * dollar);
        assert!((dollar / 2..=dollar * 2).contains(&prices[1]));
        assert!((dollar / 20..=dollar).contains(&prices[2]));
    }
}
