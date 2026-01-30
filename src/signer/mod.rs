//! Cryptographic signing traits.

mod error;
#[cfg(feature = "crypto-native")]
pub mod native;
mod r#trait;
#[cfg(all(target_arch = "wasm32", feature = "crypto-webcrypto"))]
pub mod webcrypto;

pub use error::JwsSignerError;
pub use r#trait::{BoxedJwsSigner, HasPublicKey, JwsSigner, KeyMetadata};
