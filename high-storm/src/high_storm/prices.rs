use std::{collections::BTreeSet, sync::Arc};

use price_feed::{
    Clock, FeedAvailability, FeedId, FeedRegistry, FeedStates, PriceFeedData, PriceSource,
    RejectionReason, SourceObservation,
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
    #[error("invalid peer public key: {0}")]
    InvalidPeerKey(String),
    #[error("{0} is not a network member")]
    NotAMember(String),
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
    /// A Cross pair's is new when a leg's change recomputed it.
    pub(crate) async fn attest(&self, storm: &StormHandle) -> Result<usize, PriceError> {
        let values: Vec<PriceFeedData> = {
            let mut feeds = self.feeds.lock().await;
            self.registry
                .feeds()
                .filter_map(|definition| feeds.value(definition.id))
                .collect()
        };

        let attester = self.keypair.x_only_public_key().0.serialize();
        let mut attestations = Vec::new();
        for feed in values {
            let last = self.store.last_attested(attester, feed.feed_id).await?;
            if last.is_some_and(|last| feed.received_at <= last) {
                continue;
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
        check(&announcement.attestations, &members, &self.registry)?;

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
) -> Result<(), PriceError> {
    let mut seen: BTreeSet<FeedId> = BTreeSet::new();
    for attestation in attestations {
        if !members.contains(&attestation.public_key) {
            return Err(PriceError::NotAMember(hex::encode(attestation.public_key)));
        }
        if registry.get(attestation.feed.feed_id).is_none() {
            return Err(PriceError::UnregisteredFeed(attestation.feed.feed_id));
        }
        // At most one attestation per feed per cycle.
        if !seen.insert(attestation.feed.feed_id) {
            return Err(PriceError::RepeatedFeed(attestation.feed.feed_id));
        }
        verify(attestation)?;
    }
    Ok(())
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

        assert!(check(&attestations, &members([1, 2]), &FeedRegistry::default()).is_ok());
    }

    #[test]
    fn rejects_an_attestation_from_a_node_outside_the_network() {
        let attestations = [attest(&keypair(9), feed())];

        assert!(matches!(
            check(&attestations, &members([1, 2]), &FeedRegistry::default()),
            Err(PriceError::NotAMember(_))
        ));
    }

    #[test]
    fn rejects_more_than_one_attestation_for_a_feed() {
        let attestations = [attest(&keypair(1), feed()), attest(&keypair(1), feed())];

        assert!(matches!(
            check(&attestations, &members([1, 2]), &FeedRegistry::default()),
            Err(PriceError::RepeatedFeed(0))
        ));
    }

    #[test]
    fn rejects_an_attestation_for_an_unregistered_feed() {
        let mut unknown = feed();
        unknown.feed_id = 99;
        let attestations = [attest(&keypair(1), unknown)];

        assert!(matches!(
            check(&attestations, &members([1, 2]), &FeedRegistry::default()),
            Err(PriceError::UnregisteredFeed(99))
        ));
    }

    #[test]
    fn rejects_the_whole_message_when_one_attestation_is_bad() {
        let mut tampered = attest(&keypair(2), feed());
        tampered.feed.price += 1;
        tampered.feed.feed_id = 1;
        let attestations = [attest(&keypair(1), feed()), tampered];

        assert!(check(&attestations, &members([1, 2]), &FeedRegistry::default()).is_err());
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
