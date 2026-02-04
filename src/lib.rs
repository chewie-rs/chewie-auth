/*!
chewie-auth is a typesafe `OAuth2` and OIDC library for rust. Its main goal is to provide a
solution for modern authentication needs. Cloud services, secret handling, token binding,
and WASM environments are not esoteric features, but essential pieces of how authentication
should be implemented.

For example, you should be able to load a set of private keys from a secret manager
implementation, supporting rotation simply by adding a new value to the secret manager.
Operations requiring high security and auditing should be able to use a cloud KMS without
much more effort than instantiating the KMS library and passing it to chewie-auth. Or a
WASM implementation should use fetch for HTTP requests, store tokens in `LocalStorage`, and
use `WebCrypto` for cryptography operations.

The design stands on a few central ideas:

 - Support for both Send and non-Send environments
 - Support swappable implementations through traits
 - Trait-based cryptography, including async calls
 - Grant traits implement the action of getting a token from the token endpoint
 - Flows implement a durable workflow - the _process_ by which you get a token
*/
#![forbid(unsafe_code)]
//#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]

pub mod authorizer;
pub mod cache;
pub mod client_auth;
pub mod crypto;
pub mod dpop;
mod error;
pub mod grant;
pub mod http;
pub mod jwk;
pub mod jwt;
pub mod platform;
pub mod prelude;
pub mod secrets;
pub mod server_metadata;
mod token;

pub use error::{BoxedError, Error};
pub use token::{AccessToken, IdToken, RefreshToken};

/// Documentation
pub mod _documentation {
    #[doc = include_str!("../README.md")]
    mod readme {}
    #[doc = include_str!("../CHANGELOG.md")]
    pub mod changelog {}
}

/// Re-export of parts of the `secrecy` crate.
pub mod secrecy {
    pub use ::secrecy::{ExposeSecret, SecretBox, SecretString};
}

pub use bytes::Bytes;
