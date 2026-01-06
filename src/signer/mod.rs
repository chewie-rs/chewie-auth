//! Cryptographic signing traits.

mod error;
#[cfg(feature = "crypto-native")]
pub mod native;
mod r#trait;

pub use error::JwsSignerError;
pub use r#trait::{BoxedJwsSigner, HasPublicKey, JwsSigner, KeyMetadata};
