use std::{collections::BTreeSet, sync::Arc};

use price_feed::{
    Clock, FeedAvailability, FeedId, FeedRegistry, FeedStates, PriceFeedData, SourceObservation,
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
            feeds: Arc::new(Mutex::new(FeedStates::new(&registry, clock))),
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

    /// Only the feeds that produced a new observation, so an unchanged price is
    /// not rebroadcast and a restarted node stays quiet until its data moves.
    pub(crate) async fn attest(&self, storm: &StormHandle) -> Result<usize, PriceError> {
        let values: Vec<PriceFeedData> = {
            let feeds = self.feeds.lock().await;
            self.registry
                .feeds()
                .filter_map(|definition| feeds.get(definition.id)?.value())
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
    use super::*;
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
}
