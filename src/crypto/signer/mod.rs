//! Cryptographic signing key traits.

mod error;
#[cfg(feature = "crypto-native")]
pub mod native;
pub mod resolver;
mod r#trait;
#[cfg(all(target_arch = "wasm32", feature = "crypto-webcrypto"))]
pub mod webcrypto;

pub use error::JwsSignerError;
pub use r#trait::{BoxedJwsSigningKey, HasPublicKey, JwsSigningKey, SigningKeyMetadata};
