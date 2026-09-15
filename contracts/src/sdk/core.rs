use price_feed::PriceFeedData;
use simplex::simplicityhl::elements::hashes::{Hash, HashEngine, sha256};
use simplex::simplicityhl::elements::secp256k1_zkp::{
    Message, Secp256k1, XOnlyPublicKey, schnorr::Signature,
};
use thiserror::Error;

use crate::auth::StormTreeBloom;

/// BIP-340 tag the network signs prices under.
pub const PRICE_TAG: &[u8] = b"OracleNetworkV1/Price";

/// `sdk::voucher::PriceFeedData` in witness form:
/// `feed_id`, `price`, `decimals`, `received_at`, `valid_until`.
pub type PriceFeedDataWitness = (u32, u64, u32, u64, u64);

/// Errors checking a [`SignedPrice`] off-chain.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignedPriceError {
    #[error("signer is not a valid x-only public key")]
    InvalidSigner,
    #[error("signature is malformed")]
    InvalidSignature,
    #[error("signature does not verify for this price under the signer")]
    SignatureMismatch,
}

/// A price the network signed under a Storm Tree Branch, as a consumer receives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedPrice {
    price: PriceFeedData,
    signer: [u8; 32],
    signature: [u8; 64],
}

impl SignedPrice {
    #[must_use]
    pub fn new(price: PriceFeedData, signer: [u8; 32], signature: [u8; 64]) -> Self {
        Self {
            price,
            signer,
            signature,
        }
    }

    /// From the network's response to a `signed-price-data` request: the signed price and the
    /// Bloom carrying the signature and the signing branch.
    #[must_use]
    pub fn from_bloom(price: PriceFeedData, bloom: &StormTreeBloom) -> Self {
        Self::new(price, bloom.branch, bloom.signature)
    }

    /// The message the network signs for `price`, and `sdk::voucher::get_price_message`
    /// recomputes with the [`PRICE_TAG`] tagged hash.
    #[must_use]
    pub fn message_for(price: &PriceFeedData) -> [u8; 32] {
        let tag = sha256::Hash::hash(PRICE_TAG);

        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_ref());
        engine.input(tag.as_ref());
        engine.input(&price.to_bytes());

        sha256::Hash::from_engine(engine).to_byte_array()
    }

    #[must_use]
    pub fn get_price(&self) -> &PriceFeedData {
        &self.price
    }

    #[must_use]
    pub fn get_signer(&self) -> [u8; 32] {
        self.signer
    }

    #[must_use]
    pub fn get_signature(&self) -> [u8; 64] {
        self.signature
    }

    #[must_use]
    pub fn get_message(&self) -> [u8; 32] {
        Self::message_for(&self.price)
    }

    /// The price in the shape the consumer's witness takes.
    #[must_use]
    pub fn get_price_witness(&self) -> PriceFeedDataWitness {
        (
            self.price.feed_id,
            self.price.price,
            self.price.decimals,
            self.price.received_at,
            self.price.valid_until,
        )
    }

    /// Checks the signature as `verify_price` will.
    ///
    /// # Errors
    /// Returns [`SignedPriceError`] if the signer or signature is malformed, or the signature
    /// is not the signer's over this price.
    pub fn verify(&self) -> Result<(), SignedPriceError> {
        let signer = XOnlyPublicKey::from_slice(&self.signer)
            .map_err(|_| SignedPriceError::InvalidSigner)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| SignedPriceError::InvalidSignature)?;

        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(self.get_message()),
                &signer,
            )
            .map_err(|_| SignedPriceError::SignatureMismatch)
    }
}
