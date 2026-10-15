use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use price_feed::{
    Clock, FeedAvailability, FeedDefinition, FeedId, FeedRegistry, FeedStates, PriceFeedData,
    PriceSource, RejectionReason, SourceObservation, SourceState, SourceStatus, ValidationError,
    instruction,
};
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, schnorr};
use secp256k1_zkp::PublicKey as TransportPublicKey;
use storm::{StormContext, StormHandle};
use tokio::sync::Mutex;

use crate::crypto::tagged_hash;
use crate::db::{price_attestation::PriceAttestationStore, price_source::FrozenPriceSourceStore};

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

#[derive(Debug, thiserror::Error)]
pub enum PriceSourceError {
    #[error("frozen price source database operation failed: {0}")]
    Database(#[from] crate::db::price_source::Error),
    #[error("feed {0} is not in the registry")]
    UnknownFeed(FeedId),
    #[error("feed {0} is a cross pair, which is priced from other feeds and has no sources")]
    CrossPair(FeedId),
    #[error("feed {feed} has no source '{name}'")]
    UnknownSource { feed: FeedId, name: String },
    #[error("price source {index} is already registered as '{registered}', not '{name}'")]
    RenamedSource {
        index: usize,
        registered: &'static str,
        name: &'static str,
    },
}

/// One source of a Direct feed, as this node's operator sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceSourceInfo {
    /// What a freeze is persisted by, and the operator names it by.
    pub name: &'static str,
    pub status: SourceStatus,
    /// When the operator froze it, `None` while it is not frozen.
    pub frozen_at: Option<u64>,
}

/// A Direct feed and the sources this node prices it from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedSources {
    pub feed: FeedDefinition,
    /// Whether this node holds a price of its own for the feed.
    pub available: bool,
    pub sources: Vec<PriceSourceInfo>,
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
    frozen: FrozenPriceSourceStore,
    registry: FeedRegistry,
    keypair: Keypair,
    clock: Clock,
    feeds: Arc<Mutex<FeedStates>>,
    /// The name of the source at each index of a feed's state. An index is
    /// where this run polls a source; only a name outlives a restart.
    source_names: Arc<Mutex<BTreeMap<usize, &'static str>>>,
}

impl Prices {
    pub(crate) fn new(
        secret_key: [u8; 32],
        store: PriceAttestationStore,
        frozen: FrozenPriceSourceStore,
        clock: Clock,
    ) -> Self {
        let secret_key = SecretKey::from_secret_bytes(secret_key)
            .expect("the transport signer key was already validated");
        let registry = FeedRegistry::default();
        Self {
            feeds: Arc::new(Mutex::new(
                FeedStates::new(&registry, clock)
                    .expect("the built-in registry routes every Cross pair"),
            )),
            source_names: Arc::default(),
            store,
            frozen,
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

    /// Lists the source at `index` under `feed` before it first reports,
    /// frozen again if this node's operator froze it, by `name`, before a
    /// restart.
    pub(crate) async fn register_source(
        &self,
        feed: FeedId,
        index: usize,
        name: &'static str,
    ) -> Result<(), PriceSourceError> {
        let mut feeds = self.feeds.lock().await;
        let state = direct_feed(&self.registry, &mut feeds, feed)?;
        {
            let mut names = self.source_names.lock().await;
            match names.get(&index) {
                Some(registered) if *registered != name => {
                    return Err(PriceSourceError::RenamedSource {
                        index,
                        registered,
                        name,
                    });
                }
                Some(_) => {}
                None => {
                    names.insert(index, name);
                }
            }
        }
        state.register(index);
        if self.frozen.frozen_at(feed, name).await?.is_some() {
            state.freeze(index);
        }
        Ok(())
    }

    /// Freezing is this node's own decision and is not broadcast: it changes
    /// only the price this node attests and signs. The freeze is persisted
    /// first, and under the lock, so a restart freezes exactly what is frozen.
    pub(crate) async fn set_source_frozen(
        &self,
        feed: FeedId,
        name: &str,
        frozen: bool,
    ) -> Result<(), PriceSourceError> {
        let mut feeds = self.feeds.lock().await;
        let state = direct_feed(&self.registry, &mut feeds, feed)?;
        let index = self
            .source_names
            .lock()
            .await
            .iter()
            .find_map(|(index, registered)| (*registered == name).then_some(*index))
            .filter(|index| state.is_registered(*index))
            .ok_or_else(|| PriceSourceError::UnknownSource {
                feed,
                name: name.to_string(),
            })?;
        if frozen {
            self.frozen.freeze(feed, name, self.clock.now()).await?;
            state.freeze(index);
        } else {
            self.frozen.unfreeze(feed, name).await?;
            state.unfreeze(index);
        }
        Ok(())
    }

    /// Every Direct feed in id order, with the sources registered for it.
    pub(crate) async fn sources(&self) -> Result<Vec<FeedSources>, PriceSourceError> {
        let mut listed: Vec<FeedSources> = {
            let feeds = self.feeds.lock().await;
            let names = self.source_names.lock().await;
            self.registry
                .feeds()
                .filter_map(|definition| {
                    let state = feeds.get(definition.id)?;
                    Some(FeedSources {
                        feed: *definition,
                        available: state.is_available(),
                        // A source is listed once it is registered, which
                        // is what names it.
                        sources: state
                            .sources()
                            .filter_map(|(index, status)| {
                                Some(PriceSourceInfo {
                                    name: names.get(&index)?,
                                    status,
                                    frozen_at: None,
                                })
                            })
                            .collect(),
                    })
                })
                .collect()
        };
        // The freeze times are read from the database once the lock is
        // released, so listing never holds up polling.
        for feed in &mut listed {
            for source in &mut feed.sources {
                if source.status.state == SourceState::Frozen {
                    source.frozen_at = self.frozen.frozen_at(feed.feed.id, source.name).await?;
                }
            }
        }
        Ok(listed)
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
                || attestation.feed.stamped_ahead(now)
                || attestation.feed.validity_stretched()
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

/// Only a Direct feed has sources of its own.
fn direct_feed<'a>(
    registry: &FeedRegistry,
    feeds: &'a mut FeedStates,
    feed: FeedId,
) -> Result<&'a mut price_feed::FeedState, PriceSourceError> {
    if registry.get(feed).is_none() {
        return Err(PriceSourceError::UnknownFeed(feed));
    }
    feeds.get_mut(feed).ok_or(PriceSourceError::CrossPair(feed))
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
        if attestation.feed.stamped_ahead(now) {
            return Err(PriceError::ImplausibleTimestamp(attestation.feed.feed_id));
        }
        if attestation.feed.validity_stretched() {
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

/// The message an attestation signs, and the one a round signs beside its
/// issuance transaction so a user can verify the rate it was issued at.
pub(crate) fn price_hash(feed: &PriceFeedData) -> [u8; 32] {
    tagged_hash(PRICE_TAG, &feed.to_bytes())
}

#[cfg(test)]
mod tests {
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
        prices.poll(LBTC_USD, 0, &source).await;
        assert!(prices.value(LBTC_USD).await.is_some());

        prices
            .set_source_frozen(LBTC_USD, COINGECKO, true)
            .await
            .unwrap();

        assert_eq!(
            prices.poll(LBTC_USD, 0, &source).await,
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
            prices.poll(LBTC_USD, 0, &source).await,
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
            after.poll(LBTC_USD, 1, &skipped).await,
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
