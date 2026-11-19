use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use price_feed::{
    ConnectionError, SourceState,
    constants::{MAX_CLOCK_SKEW, MAX_POLLING_ERROR_NUM, VALIDITY_WINDOW},
};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_700_000_000;

fn keypair(byte: u8) -> Keypair {
    Keypair::from_secret_key(&SecretKey::from_secret_bytes([byte; 32]).unwrap())
}

/// The same vector the SDK checks itself against, so the two
/// implementations of the message cannot drift apart unnoticed.
#[test]
fn signs_a_price_under_the_message_a_client_recomputes() {
    let price = PriceFeedData {
        feed_id: 4,
        decimals: 8,
        price: 10_000_000_000,
        received_at: 1_700_000_000,
        valid_until: 1_700_000_300,
    };

    assert_eq!(
        hex::encode(price.to_bytes()),
        "000000040000000800000002540be400000000006553f100000000006553f22c"
    );
    assert_eq!(
        hex::encode(price_hash(&price)),
        "dd5c6a22d1a989ec39cfcd82b64d8e1f43bcca770dc3d2949022a9808b3d6340"
    );
}

fn feed() -> PriceFeedData {
    PriceFeedData {
        feed_id: 0,
        price: 9_876_543_210,
        decimals: 8,
        received_at: NOW,
        valid_until: NOW + 60,
    }
}

fn attest(keypair: &Keypair, feed: PriceFeedData) -> PriceAttestation {
    PriceAttestation {
        signature: schnorr::sign(&price_hash(&feed), keypair)
            .to_byte_array()
            .to_vec(),
        public_key: keypair.x_only_public_key().0.serialize(),
        feed,
    }
}

#[test]
fn accepts_an_attestation_from_the_key_that_signed_it() {
    assert!(verify(&attest(&keypair(1), feed())).is_ok());
}

#[test]
fn rejects_an_attestation_whose_price_data_was_altered() {
    let mut attestation = attest(&keypair(1), feed());
    attestation.feed.price += 1;

    assert!(matches!(
        verify(&attestation),
        Err(PriceError::InvalidSignature(0))
    ));
}

#[test]
fn rejects_an_attestation_credited_to_another_node() {
    let mut attestation = attest(&keypair(1), feed());
    attestation.public_key = keypair(2).x_only_public_key().0.serialize();

    assert!(matches!(
        verify(&attestation),
        Err(PriceError::InvalidSignature(0))
    ));
}

#[test]
fn rejects_a_signature_of_the_wrong_length() {
    let mut attestation = attest(&keypair(1), feed());
    attestation.signature.pop();

    assert!(matches!(
        verify(&attestation),
        Err(PriceError::InvalidSignature(0))
    ));
}

fn members(keys: [u8; 2]) -> BTreeSet<[u8; 32]> {
    keys.iter()
        .map(|byte| keypair(*byte).x_only_public_key().0.serialize())
        .collect()
}

#[test]
fn accepts_attestations_from_network_members() {
    let attestations = [attest(&keypair(1), feed())];

    assert!(
        check(
            &attestations,
            &members([1, 2]),
            &FeedRegistry::default(),
            NOW
        )
        .is_ok()
    );
}

#[test]
fn rejects_an_attestation_from_a_node_outside_the_network() {
    let attestations = [attest(&keypair(9), feed())];

    assert!(matches!(
        check(
            &attestations,
            &members([1, 2]),
            &FeedRegistry::default(),
            NOW
        ),
        Err(PriceError::NotAMember(_))
    ));
}

#[test]
fn rejects_more_than_one_attestation_for_a_feed() {
    let attestations = [attest(&keypair(1), feed()), attest(&keypair(1), feed())];

    assert!(matches!(
        check(
            &attestations,
            &members([1, 2]),
            &FeedRegistry::default(),
            NOW
        ),
        Err(PriceError::RepeatedFeed(0))
    ));
}

fn checked(feed: PriceFeedData) -> Result<(), PriceError> {
    check(
        &[attest(&keypair(1), feed)],
        &members([1, 2]),
        &FeedRegistry::default(),
        NOW,
    )
}

#[test]
fn accepts_the_stamps_a_feed_carries() {
    // A Direct feed of one source is valid for exactly the window.
    let whole_window = PriceFeedData {
        received_at: NOW - 10,
        valid_until: NOW - 10 + VALIDITY_WINDOW,
        ..feed()
    };
    // A Cross pair expires with its stalest leg, before its own window.
    let part_of_one = PriceFeedData {
        received_at: NOW,
        valid_until: NOW + 5,
        ..feed()
    };

    assert!(checked(whole_window).is_ok());
    assert!(checked(part_of_one).is_ok());
}

#[tokio::test]
async fn counts_refused_attestations_against_the_peer_that_sent_them() {
    let prices = prices().await;
    let sender = keypair(2).public_key().serialize();
    let storm = storm::Storm::from_peers(
        secp256k1_zkp::SecretKey::from_slice(&[OWN_KEY; 32]).unwrap(),
        vec![storm::Peer::new(sender)],
    );
    // Signed by a key that is not a member.
    let message = NodeMessage::new(
        NodeMessageKind::AttestPrice,
        None,
        &AttestPriceMsg {
            attestations: vec![attest(&keypair(9), feed())],
        },
    )
    .unwrap();
    let context = StormContext {
        storm_handle: storm.handle(),
        storm_message: message.clone().into_storm_message().unwrap(),
        message_context: storm::MessageContext {
            peer_public_key: sender,
        },
    };
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();

    {
        let _local = metrics::set_default_local_recorder(&recorder);
        assert!(matches!(
            prices.handle_attestation(message, &context).await,
            Err(PriceError::NotAMember(_))
        ));
    }

    assert!(recorder.handle().render().contains(&format!(
        "high_storm_price_attestations_rejected_total{{peer=\"{}\",reason=\"not_a_member\"}} 1",
        hex::encode(sender)
    )));
}

#[test]
fn blames_a_peer_only_for_what_it_sent() {
    let ahead = PriceFeedData {
        received_at: NOW + MAX_CLOCK_SKEW + 1,
        ..feed()
    };
    let outsider = check(
        &[attest(&keypair(9), feed())],
        &members([1, 2]),
        &FeedRegistry::default(),
        NOW,
    )
    .unwrap_err();

    assert_eq!(outsider.rejection_reason(), Some("not_a_member"));
    assert_eq!(
        checked(ahead).unwrap_err().rejection_reason(),
        Some("implausible_timestamp")
    );
    assert_eq!(
        PriceError::InvalidPeerKey("local peer table".into()).rejection_reason(),
        None
    );
}

#[test]
fn rejects_an_attestation_stamped_further_ahead_than_a_clock_explains() {
    let ahead = PriceFeedData {
        received_at: NOW + MAX_CLOCK_SKEW + 1,
        ..feed()
    };

    assert!(matches!(
        checked(ahead),
        Err(PriceError::ImplausibleTimestamp(0))
    ));
}

#[test]
fn rejects_an_attestation_valid_for_longer_than_the_window() {
    let forever = PriceFeedData {
        valid_until: u64::MAX,
        ..feed()
    };
    // An old price cannot be given a fresh validity.
    let stretched = PriceFeedData {
        received_at: NOW - VALIDITY_WINDOW - 1,
        valid_until: NOW + VALIDITY_WINDOW,
        ..feed()
    };

    assert!(matches!(
        checked(forever),
        Err(PriceError::StretchedValidity(0))
    ));
    assert!(matches!(
        checked(stretched),
        Err(PriceError::StretchedValidity(0))
    ));
}

#[tokio::test]
async fn reads_no_rate_from_a_price_stretched_beyond_its_validity() {
    let prices = prices().await;
    let stretched = PriceFeedData {
        received_at: NOW - VALIDITY_WINDOW - 1,
        valid_until: NOW + VALIDITY_WINDOW,
        ..feed()
    };
    let own = attest(&keypair(OWN_KEY), stretched);
    prices.store.store_latest(&own).await.unwrap();

    assert_eq!(
        prices
            .rate_for(LBTC_USD, &members([OWN_KEY, 9]))
            .await
            .unwrap(),
        FeedRate::Expired
    );
}

#[test]
fn rejects_an_attestation_quoted_at_other_decimals_than_its_feed() {
    let rescaled = PriceFeedData {
        decimals: 0,
        ..feed()
    };
    let attestations = [attest(&keypair(1), rescaled)];

    assert!(matches!(
        check(
            &attestations,
            &members([1, 2]),
            &FeedRegistry::default(),
            NOW
        ),
        Err(PriceError::WrongDecimals(0))
    ));
}

#[test]
fn rejects_an_attestation_for_an_unregistered_feed() {
    let mut unknown = feed();
    unknown.feed_id = 99;
    let attestations = [attest(&keypair(1), unknown)];

    assert!(matches!(
        check(
            &attestations,
            &members([1, 2]),
            &FeedRegistry::default(),
            NOW
        ),
        Err(PriceError::UnregisteredFeed(99))
    ));
}

#[test]
fn rejects_the_whole_message_when_one_attestation_is_bad() {
    let mut tampered = attest(&keypair(2), feed());
    tampered.feed.price += 1;
    tampered.feed.feed_id = 1;
    let attestations = [attest(&keypair(1), feed()), tampered];

    assert!(
        check(
            &attestations,
            &members([1, 2]),
            &FeedRegistry::default(),
            NOW
        )
        .is_err()
    );
}

#[test]
fn rejects_a_signature_made_without_the_price_tag() {
    let keypair = keypair(1);
    let feed = feed();
    let untagged: [u8; 32] = Sha256::digest(feed.to_bytes()).into();
    let attestation = PriceAttestation {
        signature: schnorr::sign(&untagged, &keypair).to_byte_array().to_vec(),
        public_key: keypair.x_only_public_key().0.serialize(),
        feed,
    };

    assert!(matches!(
        verify(&attestation),
        Err(PriceError::InvalidSignature(0))
    ));
}

const LBTC_USD: FeedId = 0;

/// Answers every poll alike, and counts them.
struct Fake {
    answer: Result<SourceObservation, ConnectionError>,
    polls: AtomicUsize,
}

impl Fake {
    fn answering(answer: Result<SourceObservation, ConnectionError>) -> Self {
        Self {
            answer,
            polls: AtomicUsize::new(0),
        }
    }

    fn polls(&self) -> usize {
        self.polls.load(Ordering::Relaxed)
    }
}

impl PriceSource for Fake {
    async fn poll(&self, _feed: FeedId) -> Result<SourceObservation, ConnectionError> {
        self.polls.fetch_add(1, Ordering::Relaxed);
        self.answer
    }
}

async fn prices() -> Prices {
    let database = crate::db::Database::connect("sqlite::memory:", 1)
        .await
        .unwrap();
    Prices::new(
        [7; 32],
        database.price_attestations(),
        database.frozen_price_sources(),
        Clock::Fixed(NOW),
    )
}

/// `prices()` signs with this key, so this is its own attestation.
const OWN_KEY: u8 = 7;

/// Expired against the `Clock::Fixed(NOW)` the test node reads: the second
/// a price is valid until is still its own.
fn expired(feed: PriceFeedData) -> PriceFeedData {
    PriceFeedData {
        valid_until: NOW - 1,
        ..feed
    }
}

#[tokio::test]
async fn reports_the_health_of_polled_sources_and_feeds() {
    const USDT_USD: FeedId = 1;
    const LBTC_USDT: FeedId = 4;
    let prices = prices().await;
    let source = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));
    assert_eq!(
        prices.poll(LBTC_USD, 0, "test", &source).await,
        PollOutcome::Observed
    );

    let health = prices
        .health(
            &[(LBTC_USD, 0), (USDT_USD, 0), (LBTC_USDT, 0)],
            &[LBTC_USD, LBTC_USDT],
        )
        .await;

    assert_eq!(
        health.sources,
        vec![
            SourceHealth {
                feed: LBTC_USD,
                source: 0,
                state: SourceState::Active,
                observed_at: Some(NOW),
            },
            // Not polled yet, so active with nothing observed.
            SourceHealth {
                feed: USDT_USD,
                source: 0,
                state: SourceState::Active,
                observed_at: None,
            },
        ]
    );
    assert!(health.values[0].1.is_some());
    // The Cross pair also needs USDT/USD, which has no price yet.
    assert_eq!(health.values[1], (LBTC_USDT, None));
}

#[tokio::test]
async fn reads_a_feed_as_its_own_attestation_beside_the_ones_it_holds() {
    let prices = prices().await;
    let own = attest(&keypair(OWN_KEY), feed());
    let peer = attest(&keypair(9), feed());
    prices.store.store_latest(&peer).await.unwrap();
    prices.store.store_latest(&own).await.unwrap();

    let rate = prices
        .rate_for(LBTC_USD, &members([OWN_KEY, 9]))
        .await
        .unwrap();

    assert_eq!(
        rate,
        FeedRate::Current(ExchangeRateInfo {
            main: own,
            auxiliary: vec![peer],
        })
    );
}

#[tokio::test]
async fn reads_no_rate_for_a_feed_it_has_not_attested_itself() {
    let prices = prices().await;
    let peer = attest(&keypair(9), feed());
    prices.store.store_latest(&peer).await.unwrap();

    assert_eq!(
        prices
            .rate_for(LBTC_USD, &members([OWN_KEY, 9]))
            .await
            .unwrap(),
        FeedRate::Unattested
    );
}

#[tokio::test]
async fn reads_no_rate_once_its_own_price_is_past_its_validity() {
    let prices = prices().await;
    let own = attest(&keypair(OWN_KEY), expired(feed()));
    prices.store.store_latest(&own).await.unwrap();

    // A feed it priced before reads apart from one it never priced.
    assert_eq!(
        prices
            .rate_for(LBTC_USD, &members([OWN_KEY, 9]))
            .await
            .unwrap(),
        FeedRate::Expired
    );
    // Expired or not, a restart still reads it back.
    assert_eq!(
        prices
            .store
            .last_attested(own.public_key, LBTC_USD)
            .await
            .unwrap(),
        Some(own.feed)
    );
}

#[tokio::test]
async fn leaves_an_expired_or_removed_member_out_of_a_feed_it_reads() {
    let prices = prices().await;
    let own = attest(&keypair(OWN_KEY), feed());
    let stale_member = attest(&keypair(9), expired(feed()));
    let removed = attest(&keypair(5), feed());
    for attestation in [&own, &stale_member, &removed] {
        prices.store.store_latest(attestation).await.unwrap();
    }

    let rate = prices
        .rate_for(LBTC_USD, &members([OWN_KEY, 9]))
        .await
        .unwrap();

    assert_eq!(
        rate,
        FeedRate::Current(ExchangeRateInfo {
            main: own,
            auxiliary: Vec::new(),
        })
    );
}

#[tokio::test]
async fn drops_a_source_whose_polls_keep_failing_and_stops_polling_it() {
    let prices = prices().await;
    let unreachable = Fake::answering(Err(ConnectionError::RequestFailure));
    let rejected = Fake::answering(Ok(SourceObservation::new(0, 8, NOW, NOW)));

    for _ in 0..MAX_POLLING_ERROR_NUM {
        assert_eq!(
            prices.poll(LBTC_USD, 0, "test", &unreachable).await,
            PollOutcome::Failed
        );
        assert_eq!(
            prices.poll(LBTC_USD, 1, "test", &rejected).await,
            PollOutcome::Failed
        );
    }

    // Both are dropped, so neither is polled until `POLLING_RETRY_TIME`.
    assert_eq!(
        prices.poll(LBTC_USD, 0, "test", &unreachable).await,
        PollOutcome::Skipped
    );
    assert_eq!(
        prices.poll(LBTC_USD, 1, "test", &rejected).await,
        PollOutcome::Skipped
    );
    assert_eq!(unreachable.polls(), MAX_POLLING_ERROR_NUM as usize);
}

const USDT_USD: FeedId = 1;
const LBTC_USDT: FeedId = 4;

async fn database() -> crate::db::Database {
    crate::db::Database::connect("sqlite::memory:", 1)
        .await
        .unwrap()
}

fn prices_on(database: &crate::db::Database) -> Prices {
    Prices::new(
        [7; 32],
        database.price_attestations(),
        database.frozen_price_sources(),
        Clock::Fixed(NOW),
    )
}

const COINGECKO: &str = "coingecko";
const KRAKEN: &str = "kraken";

fn source_state(listed: &[FeedSources], feed: FeedId, name: &str) -> SourceState {
    listed
        .iter()
        .find(|listed| listed.feed.id == feed)
        .and_then(|listed| listed.sources.iter().find(|source| source.name == name))
        .unwrap()
        .status
        .state
}

#[tokio::test]
async fn lists_every_direct_feed_with_its_registered_sources() {
    let prices = prices().await;
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();

    let listed = prices.sources().await.unwrap();

    let ids: Vec<_> = listed.iter().map(|feed| feed.feed.id).collect();
    assert_eq!(ids, [0, 1, 2, 3, 7]);
    assert_eq!(listed[0].sources.len(), 1);
    assert_eq!(
        source_state(&listed, LBTC_USD, COINGECKO),
        SourceState::Active
    );
    assert!(listed[1].sources.is_empty());
    assert!(!listed[0].available);
}

#[tokio::test]
async fn stops_polling_a_frozen_source_and_its_feed_goes_unavailable() {
    let prices = prices().await;
    let source = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();
    prices.poll(LBTC_USD, 0, COINGECKO, &source).await;
    assert!(prices.value(LBTC_USD).await.is_some());

    prices
        .set_source_frozen(LBTC_USD, COINGECKO, true)
        .await
        .unwrap();

    assert_eq!(
        prices.poll(LBTC_USD, 0, COINGECKO, &source).await,
        PollOutcome::Skipped
    );
    assert_eq!(source.polls(), 1);
    assert_eq!(prices.value(LBTC_USD).await, None);
    // A Cross pair with the frozen leg goes with it.
    assert_eq!(prices.value(LBTC_USDT).await, None);
    let listed = prices.sources().await.unwrap();
    assert_eq!(listed[0].sources[0].frozen_at, Some(NOW));
}

#[tokio::test]
async fn freezing_one_of_two_sources_takes_it_out_of_the_price() {
    let prices = prices().await;
    let good = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));
    let wrong = Fake::answering(Ok(SourceObservation::new(1_000_000, 8, NOW, NOW)));
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();
    prices.register_source(LBTC_USD, 1, "kraken").await.unwrap();
    prices.poll(LBTC_USD, 0, COINGECKO, &good).await;
    prices.poll(LBTC_USD, 1, KRAKEN, &wrong).await;
    assert_eq!(prices.value(LBTC_USD).await.unwrap().price, 500_050);

    prices
        .set_source_frozen(LBTC_USD, "kraken", true)
        .await
        .unwrap();

    // The wrong price is gone from the median straight away, which is what
    // an operator freezes a source to do.
    assert_eq!(prices.value(LBTC_USD).await.unwrap().price, 100);

    // Unfreezing brings the observation it kept back.
    prices
        .set_source_frozen(LBTC_USD, "kraken", false)
        .await
        .unwrap();
    assert_eq!(prices.value(LBTC_USD).await.unwrap().price, 500_050);
}

#[tokio::test]
async fn freezing_a_source_registered_at_another_index_for_its_feed() {
    let prices = prices().await;
    // One source, polled at index 0 for one feed and index 1 for another,
    // which registering allows: an index may not be renamed, but a name is
    // not tied to one index.
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();
    prices
        .register_source(USDT_USD, 1, COINGECKO)
        .await
        .unwrap();

    prices
        .set_source_frozen(USDT_USD, COINGECKO, true)
        .await
        .unwrap();

    let listed = prices.sources().await.unwrap();
    assert_eq!(
        source_state(&listed, USDT_USD, COINGECKO),
        SourceState::Frozen
    );
    // Freezing it for one feed leaves it alone in the other.
    assert_eq!(
        source_state(&listed, LBTC_USD, COINGECKO),
        SourceState::Active
    );
}

#[tokio::test]
async fn unfreezing_resumes_polling_the_source() {
    let prices = prices().await;
    let source = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();
    prices
        .set_source_frozen(LBTC_USD, COINGECKO, true)
        .await
        .unwrap();

    prices
        .set_source_frozen(LBTC_USD, COINGECKO, false)
        .await
        .unwrap();

    assert_eq!(
        prices.poll(LBTC_USD, 0, COINGECKO, &source).await,
        PollOutcome::Observed
    );
    let listed = prices.sources().await.unwrap();
    assert_eq!(
        source_state(&listed, LBTC_USD, COINGECKO),
        SourceState::Active
    );
    assert_eq!(listed[0].sources[0].frozen_at, None);
}

#[tokio::test]
async fn freezes_a_source_again_when_it_registers_after_a_restart() {
    let database = database().await;
    let before = prices_on(&database);
    before
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();
    before
        .register_source(USDT_USD, 0, COINGECKO)
        .await
        .unwrap();
    before
        .set_source_frozen(LBTC_USD, COINGECKO, true)
        .await
        .unwrap();

    let after = prices_on(&database);
    after.register_source(LBTC_USD, 0, COINGECKO).await.unwrap();
    after.register_source(USDT_USD, 0, COINGECKO).await.unwrap();

    let listed = after.sources().await.unwrap();
    assert_eq!(
        source_state(&listed, LBTC_USD, COINGECKO),
        SourceState::Frozen
    );
    assert_eq!(
        source_state(&listed, USDT_USD, COINGECKO),
        SourceState::Active
    );
}

#[tokio::test]
async fn keeps_a_source_frozen_when_a_restart_polls_it_at_another_index() {
    let database = database().await;
    let before = prices_on(&database);
    before
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();
    before
        .set_source_frozen(LBTC_USD, COINGECKO, true)
        .await
        .unwrap();

    // A new version polls another source first, so CoinGecko moves to 1.
    let after = prices_on(&database);
    after.register_source(LBTC_USD, 0, KRAKEN).await.unwrap();
    after.register_source(LBTC_USD, 1, COINGECKO).await.unwrap();

    let listed = after.sources().await.unwrap();
    assert_eq!(
        source_state(&listed, LBTC_USD, COINGECKO),
        SourceState::Frozen
    );
    assert_eq!(source_state(&listed, LBTC_USD, KRAKEN), SourceState::Active);
    let skipped = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));
    assert_eq!(
        after.poll(LBTC_USD, 1, COINGECKO, &skipped).await,
        PollOutcome::Skipped
    );
}

#[tokio::test]
async fn refuses_one_index_registered_under_two_names() {
    let prices = prices().await;
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();

    assert!(matches!(
        prices.register_source(USDT_USD, 0, KRAKEN).await,
        Err(PriceSourceError::RenamedSource { index: 0, .. })
    ));
}

#[tokio::test]
async fn refuses_to_freeze_what_has_no_source() {
    let prices = prices().await;
    prices
        .register_source(LBTC_USD, 0, COINGECKO)
        .await
        .unwrap();

    assert!(matches!(
        prices.set_source_frozen(99, COINGECKO, true).await,
        Err(PriceSourceError::UnknownFeed(99))
    ));
    assert!(matches!(
        prices.set_source_frozen(LBTC_USDT, COINGECKO, true).await,
        Err(PriceSourceError::CrossPair(LBTC_USDT))
    ));
    assert!(matches!(
        prices.set_source_frozen(LBTC_USD, KRAKEN, true).await,
        Err(PriceSourceError::UnknownSource { feed: LBTC_USD, .. })
    ));
    // A source registered for one feed is not one of another's.
    assert!(matches!(
        prices.set_source_frozen(USDT_USD, COINGECKO, true).await,
        Err(PriceSourceError::UnknownSource { feed: USDT_USD, .. })
    ));
    // Nothing was persisted for any of them.
    for (feed, source) in [
        (99, COINGECKO),
        (LBTC_USDT, COINGECKO),
        (LBTC_USD, KRAKEN),
        (USDT_USD, COINGECKO),
    ] {
        assert_eq!(prices.frozen.frozen_at(feed, source).await.unwrap(), None);
    }
}

#[tokio::test]
async fn counts_each_poll_and_the_change_between_observations() {
    let prices = prices().await;
    let first = Fake::answering(Ok(SourceObservation::new(100_000, 8, NOW - 10, NOW)));
    let moved = Fake::answering(Ok(SourceObservation::new(112_000, 8, NOW - 5, NOW)));
    let limited = Fake::answering(Err(ConnectionError::RateLimited));
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();

    {
        let _local = metrics::set_default_local_recorder(&recorder);
        for (index, source, outcome) in [
            (0, &first, PollOutcome::Observed),
            (0, &moved, PollOutcome::Observed),
            (0, &moved, PollOutcome::Unchanged),
            (1, &limited, PollOutcome::Failed),
        ] {
            assert_eq!(prices.poll(LBTC_USD, index, "test", source).await, outcome);
        }
    }

    let rendered = recorder.handle().render();
    for line in [
        r#"high_storm_price_polls_total{feed="LBTC/USD",source="test",outcome="observed"} 2"#,
        r#"high_storm_price_polls_total{feed="LBTC/USD",source="test",outcome="unchanged"} 1"#,
        r#"high_storm_price_polls_total{feed="LBTC/USD",source="test",outcome="failed"} 1"#,
        r#"high_storm_price_poll_failures_total{source="test",reason="rate_limited"} 1"#,
        r#"high_storm_price_poll_duration_seconds_count{source="test"} 4"#,
        r#"high_storm_price_change_bps{feed="LBTC/USD",source="test"} 1200"#,
    ] {
        assert!(rendered.contains(line), "missing {line:?} in:\n{rendered}");
    }
}

#[tokio::test]
async fn never_drops_a_source_that_keeps_republishing() {
    let prices = prices().await;
    let stuck = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));

    assert_eq!(
        prices.poll(LBTC_USD, 0, "test", &stuck).await,
        PollOutcome::Observed
    );
    for _ in 0..=MAX_POLLING_ERROR_NUM {
        assert_eq!(
            prices.poll(LBTC_USD, 0, "test", &stuck).await,
            PollOutcome::Unchanged
        );
    }

    let feeds = prices.feeds.lock().await;
    assert_eq!(feeds.get(LBTC_USD).unwrap().state(0), SourceState::Active);
}
