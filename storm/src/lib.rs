//! Peer-to-peer messaging over authenticated, encrypted TCP connections.
//!
//! Storm manages a known set of secp256k1 peers, establishes Noise-encrypted
//! connections, and routes application-defined [`CustomMsg`] values. Nodes can
//! coordinate initial peer discovery, join through a discovery peer, or restart
//! from a previously saved peer table.
//!
//! # Example
//!
//! ```no_run
//! use secp256k1_zkp::SecretKey;
//! use storm::Storm;
//!
//! # async fn run() -> Result<(), storm::Error> {
//! let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
//! let mut storm = Storm::from_peers(secret_key, Vec::new());
//! storm.start(Some("127.0.0.1:9000".into())).await?;
//! storm.shutdown().await;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod constants;
mod crypto;
mod error;
mod handle;
mod message;
mod message_handlers;
mod network;
mod peer;
mod state;
mod storm;

pub use error::Error;
pub use message::{MAX_MESSAGE_SIZE, MessageError, StormMessage, StormMessageHeader};
pub use message_handlers::custom::CustomMsg;
pub use peer::{Peer, PeerStatus};
pub(crate) use state::StormState;
pub(crate) use storm::CustomHandler;
pub use storm::{MessageContext, Storm, StormContext, StormHandle};

#[cfg(test)]
mod tests;
