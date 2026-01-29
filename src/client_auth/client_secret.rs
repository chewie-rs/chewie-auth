use std::borrow::Cow;

use base64::Engine as _;
use bon::Builder;
use http::{HeaderMap, header::InvalidHeaderValue};
use secrecy::{ExposeSecret as _, SecretString};
use snafu::prelude::*;
use url::Url;

use crate::{
    client_auth::{AuthenticationParams, ClientAuthentication},
    secrets::Secret,
};

#[derive(Debug, Snafu)]
pub enum ClientSecretError<SecErr: crate::Error> {
    FetchSecret { source: SecErr },
    InvalidHeader { source: InvalidHeaderValue },
}

impl<SecErr: crate::Error + 'static> crate::Error for ClientSecretError<SecErr> {
    fn is_retryable(&self) -> bool {
        match self {
            ClientSecretError::FetchSecret { source } => source.is_retryable(),
            ClientSecretError::InvalidHeader { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ClientSecretMethod {
    Basic,
    Post,
}

impl ClientSecretMethod {
    /// The OIDC discovery value for this method.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            ClientSecretMethod::Basic => "client_secret_basic",
            ClientSecretMethod::Post => "client_secret_post",
        }
    }

    /// Default priority order for method selection.
    ///
    /// Basic is preferred (see RFC 6749 section 2.3.1).
    pub const PRIORITY: &'static [Self] = &[Self::Basic, Self::Post];
}

/// Authentication using a shared secret.
///
/// This is an authentication implementation where a client secret
/// is passed to the server, either in the request headers, or in
/// the request body.
#[derive(Debug, Clone, Builder)]
pub struct ClientSecret<Sec: Secret<Output = SecretString>> {
    client_secret: Sec,
    #[builder(into)]
    client_id: Cow<'static, str>,
}

impl<Sec: Secret<Output = SecretString>> ClientSecret<Sec> {
    /// Selects the authentication method to use from a set of allowed methods.
    fn basic_authentication_params(
        &self,
        client_secret: &SecretString,
    ) -> Result<AuthenticationParams, ClientSecretError<Sec::Error>> {
        use url::form_urlencoded::byte_serialize;
        let client_id: String = byte_serialize(self.client_id.as_bytes()).collect();
        let client_secret: String =
            byte_serialize(client_secret.expose_secret().as_bytes()).collect();

        let credentials = format!("{client_id}:{client_secret}");
        let auth_header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            auth_header.parse().context(InvalidHeaderSnafu)?,
        );

        Ok(AuthenticationParams::builder().headers(headers).build())
    }

    fn post_authentication_params(&self, client_secret: &SecretString) -> AuthenticationParams {
        AuthenticationParams::builder()
            .form_params(bon::map! {
                "client_id": self.client_id.clone(),
                "client_secret": client_secret.clone()
            })
            .build()
    }
}

impl<Sec: Secret<Output = SecretString>> ClientAuthentication for ClientSecret<Sec> {
    type Error = ClientSecretError<Sec::Error>;

    fn client_id(&self) -> &str {
        &self.client_id
    }

    async fn authentication_params(
        &self,
        _token_endpoint: &Url,
        allowed_methods: Option<&[String]>,
    ) -> Result<super::AuthenticationParams, Self::Error> {
        let client_secret = self
            .client_secret
            .get_secret_value()
            .await
            .context(FetchSecretSnafu)?;

        match select_method(allowed_methods) {
            ClientSecretMethod::Basic => self.basic_authentication_params(&client_secret),
            ClientSecretMethod::Post => Ok(self.post_authentication_params(&client_secret)),
        }
    }
}

fn select_method(allowed_methods: Option<&[String]>) -> ClientSecretMethod {
    match allowed_methods {
        None => ClientSecretMethod::Basic,
        Some(allowed) => ClientSecretMethod::PRIORITY
            .iter()
            .find(|m| allowed.iter().any(|a| a == m.as_str()))
            .copied()
            .unwrap_or(ClientSecretMethod::Basic),
    }
}
