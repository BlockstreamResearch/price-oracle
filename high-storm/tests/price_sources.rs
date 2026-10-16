mod common;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_util::{SinkExt, StreamExt};
use high_storm::{
    HighStorm, HighStormHandle,
    high_storm::PollOutcome,
    initialize_host,
    sources::{coingecko::CoinGecko, sideswap::SideSwap},
};
use price_feed::{FeedId, SourceObservation, constants::MAX_POLLING_ERROR_NUM};
use serde_json::{Value, json};
use tokio::{net::TcpListener, time::timeout};
use tokio_tungstenite::{accept_async, tungstenite::Message};

use common::TestNode;

const LBTC_USD: FeedId = 0;
const USDT_USD: FeedId = 1;
const EURX_USD: FeedId = 2;
const DEPIX_USD: FeedId = 3;
const LBTC_USDT: FeedId = 4;

/// Where each source sits in a feed's state, as `sources::spawn` places them.
const COINGECKO: usize = 0;
const SIDESWAP: usize = 2;

const LBTC: &str = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
const USDT: &str = "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2";
const EURX: &str = "18729918ab4bca843656f08d4dd877bed6641fbd596a0a963abbf199cfeb3cec";
const DEPIX: &str = "02f22f8d9c76ab41661a2729e4752e2c5d1a263012141b86ea98af5472df5189";

/// One US dollar, or one USDt, at the feeds' 8 decimals.
const DOLLAR: u64 = 100_000_000;

#[tokio::test]
async fn sideswap_prices_nothing_until_another_source_prices_usdt() {
    let network = Network::start().await;
    let node = network.node.handle();
    network.sideswap.quote(LBTC, USDT, 83_000.0, 83_400.0);
    let sideswap = SideSwap::at(&network.sideswap.url, node.clone());
    register(&node, LBTC_USD, SIDESWAP, SideSwap::NAME).await;

    // Nothing to convert its USDt price with yet.
    assert_eq!(
        node.poll_price_source(LBTC_USD, SIDESWAP, &sideswap).await,
        PollOutcome::Failed
    );
    assert_eq!(node.price_feed_value(LBTC_USD).await, None);

    node.record_price_observation(USDT_USD, COINGECKO, observation(99_900_000))
        .await;
    assert_eq!(
        node.poll_price_source(LBTC_USD, SIDESWAP, &sideswap).await,
        PollOutcome::Observed
    );

    // 83,200 USDt at 0.999 USD each.
    let lbtc = node.price_feed_value(LBTC_USD).await.unwrap();
    assert_eq!(lbtc.price, 8_311_680_000_000);

    network.shutdown().await;
}

#[tokio::test]
async fn combines_coingecko_and_sideswap_into_every_feed() {
    let network = Network::start().await;
    let node = network.node.handle();
    network.sideswap.quote(LBTC, USDT, 83_000.0, 83_400.0);
    network.sideswap.quote(EURX, USDT, 1.1, 1.14);
    network.sideswap.quote(USDT, DEPIX, 5.0, 5.2);
    let sideswap = SideSwap::at(&network.sideswap.url, node.clone());

    // CoinGecko prices LBTC at $84,000 and USDt at $1.
    for (feed, price) in [(LBTC_USD, 84_000 * DOLLAR), (USDT_USD, DOLLAR)] {
        register(&node, feed, COINGECKO, CoinGecko::NAME).await;
        node.record_price_observation(feed, COINGECKO, observation(price))
            .await;
    }
    for feed in [LBTC_USD, EURX_USD, DEPIX_USD] {
        register(&node, feed, SIDESWAP, SideSwap::NAME).await;
        assert_eq!(
            node.poll_price_source(feed, SIDESWAP, &sideswap).await,
            PollOutcome::Observed
        );
    }

    // LBTC is the median of CoinGecko's $84,000 and SideSwap's $83,200.
    let price = |feed| {
        let node = node.clone();
        async move { node.price_feed_value(feed).await.unwrap().price }
    };
    assert_eq!(price(LBTC_USD).await, 83_600 * DOLLAR);
    // SideSwap alone prices EURx and DePix: 1.12 USDt, and 1 / 5.1 USDt.
    assert_eq!(price(EURX_USD).await, 112_000_000);
    assert_eq!(price(DEPIX_USD).await, 19_607_843);
    // A Cross pair is priced from the combined Direct feeds.
    assert_eq!(price(LBTC_USDT).await, 83_600 * DOLLAR);
    // USDt is CoinGecko's alone, SideSwap offering no price for it.
    assert_eq!(price(USDT_USD).await, DOLLAR);

    network.shutdown().await;
}

#[tokio::test]
async fn a_sideswap_price_expires_with_the_usdt_usd_value_it_was_converted_with() {
    let network = Network::start().await;
    let node = network.node.handle();
    network.sideswap.quote(LBTC, USDT, 83_000.0, 83_400.0);
    let sideswap = SideSwap::at(&network.sideswap.url, node.clone());

    // USDt was last observed long enough ago that it expires in 10 seconds.
    let observed = now() - 290;
    let usdt = SourceObservation::new(DOLLAR, 8, observed, observed);
    node.record_price_observation(USDT_USD, COINGECKO, usdt)
        .await;
    assert_eq!(
        node.poll_price_source(LBTC_USD, SIDESWAP, &sideswap).await,
        PollOutcome::Observed
    );

    let lbtc = node.price_feed_value(LBTC_USD).await.unwrap();
    assert_eq!(lbtc.valid_until, usdt.valid_until);

    network.shutdown().await;
}

#[tokio::test]
async fn sideswap_drops_out_once_its_usdt_usd_source_is_frozen() {
    let network = Network::start().await;
    let node = network.node.handle();
    network.sideswap.quote(LBTC, USDT, 83_000.0, 83_400.0);
    let sideswap = SideSwap::at(&network.sideswap.url, node.clone());
    for (feed, price) in [(LBTC_USD, 84_000 * DOLLAR), (USDT_USD, DOLLAR)] {
        register(&node, feed, COINGECKO, CoinGecko::NAME).await;
        node.record_price_observation(feed, COINGECKO, observation(price))
            .await;
    }
    register(&node, LBTC_USD, SIDESWAP, SideSwap::NAME).await;
    node.poll_price_source(LBTC_USD, SIDESWAP, &sideswap).await;
    assert_eq!(
        node.price_feed_value(LBTC_USD).await.unwrap().price,
        83_600 * DOLLAR
    );

    node.set_price_source_frozen(USDT_USD, CoinGecko::NAME, true)
        .await
        .unwrap();
    assert_eq!(node.price_feed_value(USDT_USD).await, None);

    // Freezing CoinGecko on USDT/USD leaves SideSwap itself active, so the
    // price it already gave for LBTC stays in the median until it is dropped
    // for failing to convert. Only the frozen source's own price goes at once.
    assert_eq!(
        node.price_feed_value(LBTC_USD).await.unwrap().price,
        83_600 * DOLLAR
    );
    for _ in 0..MAX_POLLING_ERROR_NUM {
        assert_eq!(
            node.poll_price_source(LBTC_USD, SIDESWAP, &sideswap).await,
            PollOutcome::Failed
        );
    }
    assert_eq!(
        node.poll_price_source(LBTC_USD, SIDESWAP, &sideswap).await,
        PollOutcome::Skipped
    );
    assert_eq!(
        node.price_feed_value(LBTC_USD).await.unwrap().price,
        84_000 * DOLLAR
    );

    network.shutdown().await;
}

/// A single node, which prices feeds without needing any peer, and a stand-in
/// for SideSwap's API.
struct Network {
    _definition: TestNode,
    node: HighStorm,
    sideswap: FakeSideSwap,
}

impl Network {
    async fn start() -> Self {
        let definition = TestNode::new(41).await;
        let node = timeout(
            Duration::from_secs(5),
            initialize_host(&definition.config, &definition.store, &[]),
        )
        .await
        .expect("node initialization timed out")
        .expect("node initialization failed");

        Self {
            _definition: definition,
            node,
            sideswap: FakeSideSwap::start().await,
        }
    }

    async fn shutdown(mut self) {
        self.node.shutdown().await;
    }
}

/// The best online bid and ask of each pair, by base and quote asset id.
type Books = Arc<Mutex<HashMap<(String, String), (f64, f64)>>>;

/// Answers a `market` `subscribe` as SideSwap's API does, with a notification
/// ahead of the answer that the source must pass over.
struct FakeSideSwap {
    url: String,
    books: Books,
}

impl FakeSideSwap {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let books = Arc::new(Mutex::new(HashMap::new()));
        let served = books.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(stream, served.clone()));
            }
        });
        Self { url, books }
    }

    fn quote(&self, base: &str, quote: &str, bid: f64, ask: f64) {
        self.books
            .lock()
            .unwrap()
            .insert((base.to_string(), quote.to_string()), (bid, ask));
    }
}

async fn answer(stream: tokio::net::TcpStream, books: Books) {
    let Ok(mut socket) = accept_async(stream).await else {
        return;
    };
    let Some(Ok(Message::Text(request))) = socket.next().await else {
        return;
    };
    let request: Value = serde_json::from_str(request.as_str()).unwrap();
    let pair = &request["params"]["subscribe"]["asset_pair"];
    let pair = (
        pair["base"].as_str().unwrap().to_string(),
        pair["quote"].as_str().unwrap().to_string(),
    );
    let quote = books.lock().unwrap().get(&pair).copied();
    // An offline order better than either live quote, which must not count.
    let orders = quote.map_or(json!([]), |(bid, ask)| {
        json!([
            { "price": bid, "trade_dir": "Buy", "online": true },
            { "price": ask, "trade_dir": "Sell", "online": true },
            { "price": ask * 2.0, "trade_dir": "Buy", "online": false },
        ])
    });

    let notification = json!({ "method": "market", "params": { "order_removed": {} } });
    let book = json!({
        "id": request["id"],
        "method": "market",
        "result": { "subscribe": { "orders": orders, "timestamp": now() * 1_000 } },
    });
    for message in [notification, book] {
        if socket
            .send(Message::text(message.to_string()))
            .await
            .is_err()
        {
            return;
        }
    }
    // Held open until the source closes it.
    while let Some(Ok(_)) = socket.next().await {}
}

async fn register(node: &HighStormHandle, feed: FeedId, index: usize, name: &'static str) {
    node.register_price_source(feed, index, name).await.unwrap();
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn observation(price: u64) -> SourceObservation {
    let now = now();
    SourceObservation::new(price, 8, now, now)
}
