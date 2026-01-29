use bon::Builder;
use http::{
    HeaderMap, Method, Uri,
    header::{AUTHORIZATION, InvalidHeaderValue},
};
use secrecy::ExposeSecret;
use snafu::{ResultExt as _, Snafu, ensure};

use crate::{
    cache::{GetTokenError, OAuthTokenCache, RefreshTokenStore, TokenCache},
    dpop::{AuthorizationServerDPoP, ResourceServerDPoP},
    grant::{ExchangeGrant, OAuth2ExchangeGrant},
    http::HttpClient,
};

#[derive(Builder)]
pub struct OAuthAuthorizer<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    cache: OAuthTokenCache<G, S>,
    dpop: <G::DPoP as AuthorizationServerDPoP>::ResourceServerDPoP,
}

#[derive(Debug, Snafu)]
pub enum AuthorizerError<TcErr: crate::Error + 'static, DPoPErr: crate::Error + 'static> {
    TokenCache {
        source: TcErr,
    },
    DPoP {
        source: DPoPErr,
    },
    InvalidHeaderValue,
    #[snafu(display("Received DPoP token but no DPoP configuration present"))]
    UnexpectedDPoPToken,
    InvalidHeader {
        source: InvalidHeaderValue,
    },
}

impl<TcErr: crate::Error + 'static, DPoPErr: crate::Error + 'static> crate::Error
    for AuthorizerError<TcErr, DPoPErr>
{
    fn is_retryable(&self) -> bool {
        match self {
            AuthorizerError::TokenCache { source } => source.is_retryable(),
            AuthorizerError::DPoP { source } => source.is_retryable(),
            AuthorizerError::InvalidHeaderValue => false,
            AuthorizerError::UnexpectedDPoPToken => false,
            AuthorizerError::InvalidHeader { .. } => false,
        }
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> OAuthAuthorizer<G, S> {
    pub fn new(cache: OAuthTokenCache<G, S>) -> Self {
        let dpop = cache.grant.dpop().to_resource_server_dpop();
        Self { cache, dpop }
    }

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
            InvalidHeaderValueSnafu
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
                    AUTHORIZATION,
                    format!("DPoP {}", token.access_token.expose_secret())
                        .parse()
                        .context(InvalidHeaderSnafu)?,
                );
            } else {
                return UnexpectedDPoPTokenSnafu.fail();
            }
        } else {
            headers.insert(
                AUTHORIZATION,
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

#[must_use]
pub fn extract_dpop_nonce(headers: &HeaderMap) -> Option<String> {
    headers
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}
