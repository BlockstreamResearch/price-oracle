//! Rust side of `simf/sdk/`: what a consumer contract passes to the voucher checks.

mod core;

pub use core::{PRICE_TAG, PriceFeedDataWitness, SignedPrice, SignedPriceError};
