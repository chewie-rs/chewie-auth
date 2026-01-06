//! Built-in secret source providers.

use std::ffi::OsString;

use snafu::prelude::*;

use crate::secrets::{
    DecodingError, Secret,
    encodings::{SecretDecoder, StringEncoding},
};

/// Errors that can occur when using built-in secret implementations.
#[derive(Debug, Snafu)]
pub enum SecretAccessError {
    /// The environment variable was not found or was not valid unicode.
    #[snafu(display("Failed to read env variable '{}'", var_name.to_string_lossy()))]
    EnvAccess {
        /// The name of the environment variable that could not be accessed.
        var_name: OsString,
        /// The underlying error from the environment variable lookup.
        source: std::env::VarError,
    },
    /// Failed to decode the secret.
    #[snafu(display("Failed to decode secret"))]
    Decode {
        /// The encoding error.
        source: DecodingError,
    },
}

impl crate::Error for SecretAccessError {
    fn is_retryable(&self) -> bool {
        false
    }
}

/// Retrieves secrets from environment variables with configurable encoding.
#[derive(Debug, Clone)]
pub struct EnvVarSecret<E: SecretDecoder = StringEncoding> {
    /// The name of the environment variable containing the secret.
    var_name: OsString,
    /// The encoding of the secret.
    encoding: E,
}

impl<E: SecretDecoder> EnvVarSecret<E> {
    /// Creates a new environment variable secret provider with the specified encoding.
    pub fn new(var_name: impl Into<OsString>, encoding: E) -> Self {
        Self {
            var_name: var_name.into(),
            encoding,
        }
    }
}

impl EnvVarSecret<StringEncoding> {
    /// Creates a new environment variable secret provider returning a `SecretString`.
    pub fn string(var_name: impl Into<OsString>) -> Self {
        Self::new(var_name, StringEncoding)
    }
}

impl<E: SecretDecoder> Secret for EnvVarSecret<E> {
    type Output = E::Output;
    type Error = SecretAccessError;

    async fn get_secret_value(&self) -> Result<E::Output, Self::Error> {
        let var_name = self.var_name.clone();
        let value = std::env::var(&self.var_name).context(EnvAccessSnafu { var_name })?;
        self.encoding.decode(value.as_bytes()).context(DecodeSnafu)
    }
}
