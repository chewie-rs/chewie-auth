//! Implements the OAuth 2.0 Device Authorization Grant (RFC 8628 §4.1).

mod flow;
mod grant;

pub use flow::Flow;
pub use grant::{Grant, GrantConfig, GrantConfigBuilder};
