//! `OAuth2` client authentication support.
//!
//! This module includes base types and implementations for different ways
//! clients can authenticate to an authorization server inside the request.
//!
//! Note: mTLS authentication is a transport-level concern, and should be
//! implemented at the HTTP client level. In such cases, the server may not
//! need any credentials inside the request, and [`ClientIdOnly`] authentication
//! may suffice here.

mod client_id_only;
mod client_secret;
mod jwt_bearer;

use std::borrow::Cow;

use bon::Builder;
pub use client_id_only::ClientIdOnly;
pub use client_secret::{ClientSecret, ClientSecretBuilder};
pub use jwt_bearer::{JwtBearer, JwtBearerBuilder};

use http::HeaderMap;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use url::Url;

use crate::platform::{MaybeSend, MaybeSendSync};

#[derive(Debug, Clone)]
pub enum FormValue {
    NonSensitive(Cow<'static, str>),
    Sensitive(SecretString),
}

impl From<&'static str> for FormValue {
    fn from(value: &'static str) -> Self {
        Self::NonSensitive(Cow::Borrowed(value))
    }
}

impl From<Cow<'static, str>> for FormValue {
    fn from(value: Cow<'static, str>) -> Self {
        Self::NonSensitive(value)
    }
}

impl From<SecretString> for FormValue {
    fn from(value: SecretString) -> Self {
        Self::Sensitive(value)
    }
}

impl Serialize for FormValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FormValue::NonSensitive(cow) => cow.serialize(serializer),
            FormValue::Sensitive(secret_box) => secret_box.expose_secret().serialize(serializer),
        }
    }
}

/// The authentication credentials that need to be added to the request.
#[derive(Debug, Clone, Builder)]
pub struct AuthenticationParams {
    /// Additional headers to include in the request.
    pub headers: Option<HeaderMap>,
    /// Additional form parameters to include in the request body.
    pub form_params: Option<Vec<(&'static str, FormValue)>>,
}

/// Trait for `OAuth2` client authentication.
///
/// Any implementation of client authentication must implement this trait,
/// which describes how the token endpoint request can be modified to add
/// the client authentication details.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `chewie_auth::client_auth::ClientAuthentication`",
    label = "This type cannot authenticate OAuth2 clients",
    note = "Requires Clone and, in threaded contexts, Send + Sync (see `MaybeSendSync`)",
    note = "Use an implementation from `chewie_auth::client_auth`, or implement ClientAuthentication"
)]
pub trait ClientAuthentication: MaybeSendSync + Clone {
    /// The error type that may be returned during authentication.
    type Error: crate::Error + 'static;

    /// Returns the `OAuth2` client ID.
    fn client_id(&self) -> &str;

    /// Returns the authentication parameters for the token request.
    fn authentication_params(
        &self,
        token_endpoint: &Url,
        allowed_methods: Option<&[String]>,
    ) -> impl Future<Output = Result<AuthenticationParams, Self::Error>> + MaybeSend;
}
