pub mod form;

use std::{collections::HashMap, sync::Arc, time::Duration};

use bon::Builder;
use http::{Uri, uri::InvalidUri};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::prelude::*;
use url::Url;

use crate::{
    AccessToken,
    client_auth::ClientAuthentication,
    dpop::AuthorizationServerDPoP,
    grant::{
        core::form::{OAuth2FormError, OAuth2FormRequest},
        refresh,
    },
    http::{HttpClient, HttpResponse},
    platform::{MaybeSend, MaybeSendSync},
    token::{IdToken, RefreshToken},
};

/// Exchange grant.
pub trait ExchangeGrant: MaybeSendSync {
    /// The error that can occur when getting a token.
    type Error<C: HttpClient>: crate::Error + 'static;

    /// Parameters exchanged when making token request.
    type Parameters: MaybeSendSync;
    /// Exchange the parameters for an access token.
    fn exchange<C: HttpClient>(
        &self,
        http_client: &C,
        params: Self::Parameters,
    ) -> impl Future<Output = Result<TokenResponse, Self::Error<C>>> + MaybeSend;
}

impl<T: ExchangeGrant + ?Sized> ExchangeGrant for Arc<T> {
    type Error<C: HttpClient> = T::Error<C>;
    type Parameters = T::Parameters;

    async fn exchange<C: HttpClient>(
        &self,
        http_client: &C,
        params: Self::Parameters,
    ) -> Result<TokenResponse, Self::Error<C>> {
        (**self).exchange(http_client, params).await
    }
}

/// OAuth2-specialized exchange grant.
pub trait OAuth2ExchangeGrant: Clone + MaybeSendSync {
    /// Parameters exchanged when making token request.
    type Parameters: Clone + MaybeSendSync;
    /// `OAuth2` client credentials used when making token request.
    type ClientAuth: ClientAuthentication + 'static;
    /// `DPoPProof` used when adding `DPoP` token binding.
    type DPoP: AuthorizationServerDPoP + 'static;
    /// The request body.
    type Form<'a>: MaybeSendSync + Serialize
    where
        Self: 'a;

    /// The `OAuth2` token endpoint URL.
    fn token_endpoint(&self) -> &Url;
    /// Returns the configured client auth.
    fn client_auth(&self) -> &Self::ClientAuth;
    /// Returns the configured `DPoP` implementation.
    fn dpop(&self) -> &Self::DPoP;
    /// Builds the body for the request.
    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_>;
    /// Returns the refresh grant corresponding to this grant.
    fn refresh_grant(&self) -> refresh::Grant<Self::ClientAuth, Self::DPoP>;

    /// Returns allowed authentication methods (formatted as in OIDC discovery).
    fn allowed_auth_methods(&self) -> Option<&[String]>;
}

/// The token response from the `OAuth2` endpoint.
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct TokenResponse {
    #[builder(into)]
    pub access_token: AccessToken,
    #[builder(into)]
    pub token_type: String,
    pub expires_in: Option<u64>,
    #[builder(into)]
    pub refresh_token: Option<RefreshToken>,
    #[builder(into)]
    pub scope: Option<String>,
    #[builder(into)]
    pub id_token: Option<IdToken>,
    #[builder(into)]
    pub issued_token_type: Option<String>,
    #[builder(skip = crate::platform::SystemTime::now())]
    #[serde(skip, default = "crate::platform::SystemTime::now")]
    pub received_at: crate::platform::SystemTime,
    #[serde(flatten)]
    extra: Option<HashMap<String, Value>>,
}

impl TokenResponse {
    /// Gets a value from the "extra" token claims.
    #[must_use]
    pub fn get_extra(&self, key: &str) -> Option<&Value> {
        self.extra.as_ref().and_then(|extra| extra.get(key))
    }

    pub fn is_expired(&self, unspecified_duration: Option<Duration>) -> bool {
        let expires_in = self.expires_in.map_or(
            unspecified_duration.unwrap_or_else(|| Duration::from_secs(3600)),
            Duration::from_secs,
        );

        crate::platform::SystemTime::now() >= self.received_at + expires_in
    }
}

#[derive(Debug, Snafu)]
pub enum OAuth2ExchangeGrantError<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    AuthErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> {
    Auth {
        source: AuthErr,
    },
    InvalidUri {
        source: InvalidUri,
    },
    OAuth2Form {
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
}

impl<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    AuthErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> crate::Error for OAuth2ExchangeGrantError<HttpErr, HttpRespErr, AuthErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::Auth { source } => source.is_retryable(),
            Self::InvalidUri { .. } => false,
            Self::OAuth2Form { source } => source.is_retryable(),
        }
    }
}

impl<A: OAuth2ExchangeGrant> ExchangeGrant for A {
    type Error<C: HttpClient> = OAuth2ExchangeGrantError<
        C::Error,
        <C::Response as HttpResponse>::Error,
        <A::ClientAuth as ClientAuthentication>::Error,
        <A::DPoP as AuthorizationServerDPoP>::Error,
    >;
    type Parameters = A::Parameters;

    async fn exchange<C: HttpClient>(
        &self,
        http_client: &C,
        params: Self::Parameters,
    ) -> Result<TokenResponse, Self::Error<C>> {
        let auth_params = self
            .client_auth()
            .authentication_params(self.token_endpoint(), self.allowed_auth_methods())
            .await
            .context(AuthSnafu)?;

        let form = self.build_form(params);

        let token_response = OAuth2FormRequest::builder()
            .auth_params(auth_params)
            .dpop(self.dpop())
            .form(&form)
            .uri(
                self.token_endpoint()
                    .to_string()
                    .parse::<Uri>()
                    .context(InvalidUriSnafu)?,
            )
            .build()
            .execute(http_client)
            .await
            .context(OAuth2FormSnafu)?;

        Ok(token_response)
    }
}
