use std::{collections::BTreeSet, sync::Arc};

use price_feed::{
    Clock, FeedAvailability, FeedId, FeedRegistry, FeedStates, PriceFeedData, PriceSource,
    RejectionReason, SourceObservation, ValidationError,
    constants::{MAX_CLOCK_SKEW, VALIDITY_WINDOW},
    instruction,
};
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, schnorr};
use secp256k1_zkp::PublicKey as TransportPublicKey;
use storm::{StormContext, StormHandle};
use tokio::sync::Mutex;

use crate::crypto::tagged_hash;
use crate::db::price_attestation::PriceAttestationStore;

use super::{
    AttestPriceMsg, NodeMessage, NodeMessageKind, PriceAttestation,
    voting::{active_remote_peers, member_keys},
};

const PRICE_TAG: &str = "OracleNetworkV1/Price";

#[derive(Debug, thiserror::Error)]
pub enum PriceError {
    #[error("price attestation database operation failed: {0}")]
    Database(#[from] crate::db::price_attestation::Error),
    #[error("failed to encode price attestations: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("failed to frame price attestations: {0}")]
    Message(#[from] storm::MessageError),
    #[error("failed to broadcast price attestations: {0}")]
    Transport(#[from] storm::Error),
    #[error("attestation for feed {0} carries a signature that does not verify")]
    InvalidSignature(FeedId),
    #[error("attestation public key is not a valid identity key")]
    InvalidPublicKey,
    #[error("attestation claims feed {0}, which is not registered")]
    UnregisteredFeed(FeedId),
    #[error("a peer sent more than one attestation for feed {0}")]
    RepeatedFeed(FeedId),
    #[error("attestation for feed {0} is stamped further ahead than a clock explains")]
    ImplausibleTimestamp(FeedId),
    #[error("attestation for feed {0} is valid for longer than the validity window")]
    StretchedValidity(FeedId),
    #[error("attestation for feed {0} is not quoted at the decimals of that feed")]
    WrongDecimals(FeedId),
    #[error("invalid peer public key: {0}")]
    InvalidPeerKey(String),
    #[error("{0} is not a network member")]
    NotAMember(String),
}

/// What a client reads for one feed: this node's own attestation, and the
/// ones it holds from the other members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeRateInfo {
    pub main: PriceAttestation,
    pub auxiliary: Vec<PriceAttestation>,
}

/// What this node has for a feed a client asks about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeedRate {
    Current(ExchangeRateInfo),
    /// Attested before, but not again since that price expired.
    Expired,
    /// Never attested by this node.
    Unattested,
}

/// What one poll of a source did to its feed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollOutcome {
    /// Dropped and not yet due its retry, or frozen, so not polled.
    Skipped,
    Observed,
    /// The source published nothing new, which is not a failed poll.
    Unchanged,
    /// Unreachable, unreadable or rejected, counting towards a drop.
    Failed,
}

#[derive(Clone)]
pub(crate) struct Prices {
    store: PriceAttestationStore,
    registry: FeedRegistry,
    keypair: Keypair,
    clock: Clock,
    feeds: Arc<Mutex<FeedStates>>,
}

impl Prices {
    pub(crate) fn new(secret_key: [u8; 32], store: PriceAttestationStore, clock: Clock) -> Self {
        let secret_key = SecretKey::from_secret_bytes(secret_key)
            .expect("the transport signer key was already validated");
        let registry = FeedRegistry::default();
        Self {
            feeds: Arc::new(Mutex::new(
                FeedStates::new(&registry, clock)
                    .expect("the built-in registry routes every Cross pair"),
            )),
            store,
            registry,
            clock,
            keypair: Keypair::from_secret_key(&secret_key),
        }
    }

    pub(crate) async fn record_observation(
        &self,
        feed: FeedId,
        source: usize,
        observation: SourceObservation,
    ) {
        let mut feeds = self.feeds.lock().await;
        if let Some(state) = feeds.get_mut(feed) {
            state.record_poll_success(source, observation);
        }
    }

    pub(crate) async fn record_failure(&self, feed: FeedId, source: usize) {
        let mut feeds = self.feeds.lock().await;
        if let Some(state) = feeds.get_mut(feed) {
            state.record_poll_failure(source);
        }
    }

    /// Polls `source`, the one at `index` in the feed's state, if that state
    /// allows it, and records what it answered.
    pub(crate) async fn poll<S: PriceSource>(
        &self,
        feed: FeedId,
        index: usize,
        source: &S,
    ) -> PollOutcome {
        let pollable = self
            .feeds
            .lock()
            .await
            .get(feed)
            .is_some_and(|state| state.is_pollable(index));
        if !pollable {
            return PollOutcome::Skipped;
        }
        // Not locked while the source answers, so a slow one never holds the feeds.
        let answer = source.poll(feed).await;

        let mut feeds = self.feeds.lock().await;
        let Some(state) = feeds.get_mut(feed) else {
            return PollOutcome::Skipped;
        };
        match answer {
            Ok(observation) => match S::validate(&observation, state.last_observed_at(index)) {
                Ok(()) => {
                    state.record_poll_success(index, observation);
                    PollOutcome::Observed
                }
                Err(RejectionReason::StaleObservation) => PollOutcome::Unchanged,
                Err(reason) => {
                    tracing::debug!(feed, source = index, %reason, "rejected a price observation");
                    state.record_poll_failure(index);
                    PollOutcome::Failed
                }
            },
            Err(error) => {
                tracing::debug!(feed, source = index, %error, "failed to poll a price source");
                state.record_poll_failure(index);
                PollOutcome::Failed
            }
        }
    }

    /// Only the feeds that produced a new observation, so an unchanged price is
    /// not rebroadcast and a restarted node stays quiet until its data moves.
    /// A Cross pair is as new as its freshest leg. A value that changed within
    /// the second it was last attested in is stamped a second later, since a
    /// peer keeps only a strictly newer one.
    pub(crate) async fn attest(&self, storm: &StormHandle) -> Result<usize, PriceError> {
        let values: Vec<PriceFeedData> = {
            let feeds = self.feeds.lock().await;
            self.registry
                .feeds()
                .filter_map(|definition| feeds.value(definition.id))
                .collect()
        };

        let attester = self.keypair.x_only_public_key().0.serialize();
        let mut attestations = Vec::new();
        for mut feed in values {
            if let Some(last) = self.store.last_attested(attester, feed.feed_id).await?
                && feed.received_at <= last.received_at
            {
                let unchanged = PriceFeedData {
                    received_at: last.received_at,
                    ..feed
                } == last;
                if unchanged {
                    continue;
                }
                feed.received_at = last.received_at + 1;
            }
            attestations.push(self.sign(feed));
        }
        if attestations.is_empty() {
            return Ok(0);
        }

        let attested = attestations.len();
        let message = NodeMessage::new(
            NodeMessageKind::AttestPrice,
            None,
            &AttestPriceMsg {
                attestations: attestations.clone(),
            },
        )?;
        let peers = storm.peers().await;
        send(storm, message, &active_remote_peers(&peers)).await?;

        // Its own attestation is held like any other, and is what a restart
        // reads back to decide whether an observation is new.
        for attestation in &attestations {
            self.store.store_latest(attestation).await?;
        }
        Ok(attested)
    }

    /// Keeps the latest attestation per (node, feed).
    pub(crate) async fn handle_attestation(
        &self,
        message: NodeMessage,
        context: &StormContext,
    ) -> Result<(), PriceError> {
        let announcement: AttestPriceMsg = message.decode_payload()?;
        let peers = context.storm_handle.peers().await;
        let members =
            member_keys(&peers).map_err(|error| PriceError::InvalidPeerKey(error.to_string()))?;
        check(
            &announcement.attestations,
            &members,
            &self.registry,
            self.clock.now(),
        )?;

        for attestation in &announcement.attestations {
            self.store.store_latest(attestation).await?;
        }
        tracing::debug!(
            peer = hex::encode(context.message_context.peer_public_key),
            attestations = announcement.attestations.len(),
            "recorded price attestations"
        );
        Ok(())
    }

    // This node's own attestation is among them.
    pub(crate) async fn attestations_for(
        &self,
        feed: FeedId,
    ) -> Result<Vec<PriceAttestation>, PriceError> {
        Ok(self.store.attestations_for(feed).await?)
    }

    pub(crate) fn registry(&self) -> &FeedRegistry {
        &self.registry
    }

    /// The value it would attest next, `None` while the feed is unavailable.
    pub(crate) async fn value(&self, feed: FeedId) -> Option<PriceFeedData> {
        self.feeds.lock().await.value(feed)
    }

    /// An instructed rate is judged by what its sources say now, not by what
    /// it last attested.
    pub(crate) async fn validate_instruction(
        &self,
        instructed: &PriceFeedData,
    ) -> Result<(), ValidationError> {
        let own = self.value(instructed.feed_id).await;

        instruction::validate(instructed, &self.registry, own, self.clock.now())
    }

    /// Only a current member's attestation is read, this node's own included,
    /// and none of them past its `valid_until`. A feed reads as `Current` only
    /// while the node holds a price of its own for it, since that is the one
    /// it stands behind.
    pub(crate) async fn rate_for(
        &self,
        feed: FeedId,
        members: &BTreeSet<[u8; 32]>,
    ) -> Result<FeedRate, PriceError> {
        let attester = self.keypair.x_only_public_key().0.serialize();
        let now = self.clock.now();

        let (mut main, mut auxiliary) = (None, Vec::new());
        let mut attested_before = false;
        for attestation in self.attestations_for(feed).await? {
            let own = attestation.public_key == attester;
            // Its own attestations never pass through `check`.
            if now > attestation.feed.valid_until
                || stamped_ahead(&attestation.feed, now)
                || validity_stretched(&attestation.feed)
            {
                attested_before |= own;
                continue;
            }
            if !members.contains(&attestation.public_key) {
                continue;
            }
            if own {
                main = Some(attestation);
            } else {
                auxiliary.push(attestation);
            }
        }

        Ok(match (main, attested_before) {
            (Some(main), _) => FeedRate::Current(ExchangeRateInfo { main, auxiliary }),
            (None, true) => FeedRate::Expired,
            (None, false) => FeedRate::Unattested,
        })
    }

    fn sign(&self, feed: PriceFeedData) -> PriceAttestation {
        PriceAttestation {
            signature: schnorr::sign(&price_hash(&feed), &self.keypair)
                .to_byte_array()
                .to_vec(),
            public_key: self.keypair.x_only_public_key().0.serialize(),
            feed,
        }
    }
}

async fn send(
    storm: &StormHandle,
    message: NodeMessage,
    recipients: &[[u8; 33]],
) -> Result<(), PriceError> {
    let recipients: Vec<TransportPublicKey> = recipients
        .iter()
        .map(|key| {
            TransportPublicKey::from_slice(key)
                .map_err(|error| PriceError::InvalidPeerKey(error.to_string()))
        })
        .collect::<Result<_, _>>()?;
    if recipients.is_empty() {
        return Ok(());
    }
    storm
        .send_message(message.into_storm_message()?, &recipients)
        .await?;
    Ok(())
}

/// Every attestation in the message must pass, so a member cannot slip a bad
/// entry in beside good ones.
fn check(
    attestations: &[PriceAttestation],
    members: &BTreeSet<[u8; 32]>,
    registry: &FeedRegistry,
    now: u64,
) -> Result<(), PriceError> {
    let mut seen: BTreeSet<FeedId> = BTreeSet::new();
    for attestation in attestations {
        if !members.contains(&attestation.public_key) {
            return Err(PriceError::NotAMember(hex::encode(attestation.public_key)));
        }
        let Some(definition) = registry.get(attestation.feed.feed_id) else {
            return Err(PriceError::UnregisteredFeed(attestation.feed.feed_id));
        };
        if stamped_ahead(&attestation.feed, now) {
            return Err(PriceError::ImplausibleTimestamp(attestation.feed.feed_id));
        }
        if validity_stretched(&attestation.feed) {
            return Err(PriceError::StretchedValidity(attestation.feed.feed_id));
        }
        // Other decimals put a client reading the price off by that power.
        if attestation.feed.decimals != definition.decimals {
            return Err(PriceError::WrongDecimals(attestation.feed.feed_id));
        }
        // At most one attestation per feed per cycle.
        if !seen.insert(attestation.feed.feed_id) {
            return Err(PriceError::RepeatedFeed(attestation.feed.feed_id));
        }
        verify(attestation)?;
    }
    Ok(())
}

/// No member's clock runs more than `MAX_CLOCK_SKEW` ahead of this one.
fn stamped_ahead(feed: &PriceFeedData, now: u64) -> bool {
    feed.received_at > now.saturating_add(MAX_CLOCK_SKEW)
}

/// A price is valid for `VALIDITY_WINDOW` from when it was received, or an old
/// one beside a fresh `valid_until` reads as current.
fn validity_stretched(feed: &PriceFeedData) -> bool {
    feed.valid_until > feed.received_at.saturating_add(VALIDITY_WINDOW)
}

fn verify(attestation: &PriceAttestation) -> Result<(), PriceError> {
    let public_key = XOnlyPublicKey::from_byte_array(attestation.public_key)
        .map_err(|_| PriceError::InvalidPublicKey)?;
    let signature: [u8; 64] = attestation
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| PriceError::InvalidSignature(attestation.feed.feed_id))?;

    schnorr::verify(
        &schnorr::Signature::from_byte_array(signature),
        &price_hash(&attestation.feed),
        &public_key,
    )
    .map_err(|_| PriceError::InvalidSignature(attestation.feed.feed_id))
}

fn price_hash(feed: &PriceFeedData) -> [u8; 32] {
    tagged_hash(PRICE_TAG, &feed.to_bytes())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use price_feed::{ConnectionError, SourceState, constants::MAX_POLLING_ERROR_NUM};
    use sha2::{Digest, Sha256};

    const NOW: u64 = 1_700_000_000;

    fn keypair(byte: u8) -> Keypair {
        Keypair::from_secret_key(&SecretKey::from_secret_bytes([byte; 32]).unwrap())
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
        let store = crate::db::Database::connect("sqlite::memory:", 1)
            .await
            .unwrap()
            .price_attestations();
        Prices::new([7; 32], store, Clock::Fixed(NOW))
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
                prices.poll(LBTC_USD, 0, &unreachable).await,
                PollOutcome::Failed
            );
            assert_eq!(
                prices.poll(LBTC_USD, 1, &rejected).await,
                PollOutcome::Failed
            );
        }

        // Both are dropped, so neither is polled until `POLLING_RETRY_TIME`.
        assert_eq!(
            prices.poll(LBTC_USD, 0, &unreachable).await,
            PollOutcome::Skipped
        );
        assert_eq!(
            prices.poll(LBTC_USD, 1, &rejected).await,
            PollOutcome::Skipped
        );
        assert_eq!(unreachable.polls(), MAX_POLLING_ERROR_NUM as usize);
    }

    #[tokio::test]
    async fn never_drops_a_source_that_keeps_republishing() {
        let prices = prices().await;
        let stuck = Fake::answering(Ok(SourceObservation::new(100, 8, NOW, NOW)));

        assert_eq!(
            prices.poll(LBTC_USD, 0, &stuck).await,
            PollOutcome::Observed
        );
        for _ in 0..=MAX_POLLING_ERROR_NUM {
            assert_eq!(
                prices.poll(LBTC_USD, 0, &stuck).await,
                PollOutcome::Unchanged
            );
        }

        let feeds = prices.feeds.lock().await;
        assert_eq!(feeds.get(LBTC_USD).unwrap().state(0), SourceState::Active);
    }
}
