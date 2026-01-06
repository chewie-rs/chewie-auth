#![forbid(unsafe_code)]
//#![deny(missing_docs)]
//#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(clippy::pedantic)]

//! Crypto integrations for rustcrypto.
//!
//! Implements `chewie-crypto` traits for rustcrypto.

pub mod asymmetric;
