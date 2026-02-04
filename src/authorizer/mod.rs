use bon::Builder;
use http::{
    HeaderMap, HeaderName, Method, Uri,
    header::{AUTHORIZATION, InvalidHeaderValue},
};
use secrecy::ExposeSecret;
use snafu::prelude::*;

use crate::{
    cache::{GetTokenError, OAuthTokenCache, RefreshTokenStore, TokenCache},
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    grant::{ExchangeGrant, OAuth2ExchangeGrant},
    http::HttpClient,
};

/// An authorizer for OAuth2 grants.
///
/// This can provide appropriate headers for a request, including any
/// required DPoP headers, refreshing tokens as necessary using the
/// underlying OAuth2 grant.
#[derive(Builder)]
pub struct OAuthAuthorizer<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    cache: OAuthTokenCache<G, S>,
    #[builder(skip = cache.grant.dpop().to_resource_server_dpop())]
    dpop: <G::DPoP as AuthorizationServerDPoP>::ResourceServerDPoP,
    #[builder(default = AUTHORIZATION)]
    authorization_header: HeaderName,
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> std::fmt::Debug for OAuthAuthorizer<G, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthAuthorizer")
            .field("authorization_header", &self.authorization_header)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur when getting headers for a request.
#[derive(Debug, Snafu)]
pub enum AuthorizerError<TcErr: crate::Error + 'static, DPoPErr: crate::Error + 'static> {
    /// The token cache returned an error when attempting to return a token.
    TokenCache {
        /// The underlying token cache error.
        source: TcErr,
    },
    /// An error occurred when creating the DPoP proof.
    DPoP {
        /// The underlying DPoP error.
        source: DPoPErr,
    },
    /// The token could not be used as it was not a valid token value.
    InvalidTokenValue,
    /// A DPoP token was received, but no DPoP configuration for the proof was present.
    #[snafu(display("Received DPoP token but no DPoP configuration present"))]
    UnexpectedDPoPToken,
    /// The token could not be used as it was not a valid header value.
    InvalidHeader {
        /// The underlying error.
        source: InvalidHeaderValue,
    },
}

impl<TcErr: crate::Error + 'static, DPoPErr: crate::Error + 'static> crate::Error
    for AuthorizerError<TcErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            Self::TokenCache { source } => source.is_retryable(),
            Self::DPoP { source } => source.is_retryable(),
            Self::InvalidTokenValue | Self::UnexpectedDPoPToken | Self::InvalidHeader { .. } => {
                false
            }
        }
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> OAuthAuthorizer<G, S> {
    /// Get the authorization headers for this request, including any necessary DPoP headers.
    ///
    /// The call uses the provided HTTP client for any calls that are necessary to get the
    /// headers. The method and URI are passed to the DPoP proof when used.
    pub async fn get_headers<C: HttpClient>(
        &self,
        http_client: &C,
        method: &Method,
        uri: &Uri,
    ) -> Result<
        HeaderMap,
        AuthorizerError<
            GetTokenError<<G as ExchangeGrant>::Error<C>>,
            <<G::DPoP as AuthorizationServerDPoP>::ResourceServerDPoP as ResourceServerDPoP>::Error,
        >,
    > {
        let token = self
            .cache
            .get_token(http_client)
            .await
            .context(TokenCacheSnafu)?;

        ensure!(
            is_header_safe(token.access_token.expose_secret()),
            InvalidTokenValueSnafu
        );

        let mut headers = HeaderMap::new();

        if token.token_type.eq_ignore_ascii_case("dpop") {
            if let Some(proof) = self
                .dpop
                .proof(method, uri, &token.access_token)
                .await
                .context(DPoPSnafu)?
            {
                headers.insert(
                    "DPoP",
                    proof.expose_secret().parse().context(InvalidHeaderSnafu)?,
                );
                headers.insert(
                    &self.authorization_header,
                    format!("DPoP {}", token.access_token.expose_secret())
                        .parse()
                        .context(InvalidHeaderSnafu)?,
                );
            } else {
                return UnexpectedDPoPTokenSnafu.fail();
            }
        } else {
            headers.insert(
                &self.authorization_header,
                format!("Bearer {}", token.access_token.expose_secret())
                    .parse()
                    .context(InvalidHeaderSnafu)?,
            );
        }

        Ok(headers)
    }
}

fn is_header_safe(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|b| (0x20..0x7F).contains(&b))
}

/// Allows users to extract the DPoP nonce from a set of headers.
///
/// This is meant for use by users who are interacting with resource servers,
/// who can then call `dpop.update_nonce(uri, nonce)` to update the
/// bookkeeping for sending DPoP nonces.
#[must_use]
pub fn extract_dpop_nonce(headers: &HeaderMap) -> Option<String> {
    headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}
