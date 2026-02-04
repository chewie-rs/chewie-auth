use std::sync::Arc;
use std::time::Duration;

use bon::Builder;
use parking_lot::RwLock;
use snafu::{ResultExt as _, Snafu};

use crate::RefreshToken;
use crate::authorizer::OAuthAuthorizer;
use crate::grant::{ExchangeGrant, OAuth2ExchangeGrant, TokenResponse, refresh};
use crate::http::HttpClient;
use crate::platform::{MaybeSend, MaybeSendSync};

pub trait TokenCache {
    type Error<C: HttpClient>: crate::Error + 'static;

    fn get_token<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> impl Future<Output = Result<Arc<TokenResponse>, Self::Error<C>>> + MaybeSend;

    fn prime(&self, response: TokenResponse) -> impl Future<Output = ()> + MaybeSend;

    fn invalidate(&self);
}

#[derive(Debug, Builder)]
#[builder(state_mod(name = "oauth_token_cache_builder"))]
pub struct OAuthTokenCache<G: OAuth2ExchangeGrant, S: RefreshTokenStore> {
    pub(crate) grant: G,
    grant_parameters: Option<G::Parameters>,
    refresh_store: S,
    // Cache state (initialized automatically)
    #[builder(skip = Default::default())]
    cached: RwLock<Option<Arc<TokenResponse>>>,
    #[builder(skip = Default::default())]
    refresh_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug, Snafu)]
pub enum GetTokenError<E: crate::Error + 'static> {
    Exchange { source: E },
    NoRefreshToken,
}

impl<E: crate::Error + 'static> crate::Error for GetTokenError<E> {
    fn is_retryable(&self) -> bool {
        match self {
            GetTokenError::Exchange { source } => source.is_retryable(),
            GetTokenError::NoRefreshToken => false,
        }
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> TokenCache for OAuthTokenCache<G, S> {
    type Error<C: HttpClient> = GetTokenError<<G as ExchangeGrant>::Error<C>>;

    async fn get_token<C: HttpClient>(
        &self,
        http_client: &C,
    ) -> Result<Arc<TokenResponse>, Self::Error<C>> {
        let maybe_cached_token = self.cached.read().clone();
        let mut best_error: Option<<G as ExchangeGrant>::Error<C>> = None;

        if let Some(cached_token) = maybe_cached_token.clone()
            && !cached_token.is_expired(Some(Duration::from_secs(3600)))
        {
            return Ok(cached_token);
        }

        let _refresh_lock = self.refresh_lock.lock().await;

        let maybe_cached_token = self.cached.read().clone();

        if let Some(cached_token) = maybe_cached_token
            && !cached_token.is_expired(Some(Duration::from_secs(3600)))
        {
            return Ok(cached_token);
        }

        if let Some(refresh_token) = self.refresh_store.get().await {
            let token_response = self
                .grant
                .refresh_grant()
                .exchange(
                    http_client,
                    refresh::Parameters::builder()
                        .refresh_token(refresh_token)
                        .build(),
                )
                .await;

            match token_response {
                Ok(token_response) => {
                    let token_response = Arc::new(token_response);

                    self.store_token_response(token_response.clone()).await;

                    return Ok(token_response);
                }
                Err(err) => {
                    self.refresh_store.clear().await;
                    best_error = Some(err);
                }
            }
        }

        if let Some(params) = self.grant_parameters.clone() {
            let token_response = Arc::new(
                self.grant
                    .exchange(http_client, params)
                    .await
                    .context(ExchangeSnafu)?,
            );

            self.store_token_response(token_response.clone()).await;

            Ok(token_response)
        } else {
            match best_error {
                Some(err) => Err(err).context(ExchangeSnafu),
                None => NoRefreshTokenSnafu.fail(),
            }
        }
    }

    async fn prime(&self, response: TokenResponse) {
        if let Some(refresh_token) = &response.refresh_token {
            self.refresh_store.set(refresh_token).await;
        }

        *self.cached.write() = Some(Arc::new(response));
    }

    fn invalidate(&self) {
        *self.cached.write() = None;
    }
}

impl<G: OAuth2ExchangeGrant, S: RefreshTokenStore> OAuthTokenCache<G, S> {
    async fn store_token_response(&self, token: Arc<TokenResponse>) {
        *self.cached.write() = Some(token.clone());

        if let Some(refresh_token) = token.refresh_token.as_ref() {
            self.refresh_store.set(refresh_token).await;
        } else {
            self.refresh_store.clear().await;
        }
    }

    /// Convert the cache into an authorizer with the default configuration.
    pub fn into_authorizer(self) -> OAuthAuthorizer<G, S> {
        OAuthAuthorizer::builder().cache(self).build()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cache::{InMemoryStore, OAuthTokenCache},
        client_auth::ClientIdOnly,
        grant::client_credentials,
    };

    #[test]
    fn test_setup() {
        let _cache = OAuthTokenCache::builder()
            .grant(
                client_credentials::Grant::builder()
                    .client_auth(ClientIdOnly::new("client_id"))
                    .no_dpop()
                    .token_endpoint("https://blah".parse().unwrap())
                    .build(),
            )
            .grant_parameters(
                client_credentials::Parameters::builder()
                    .scopes(bon::vec!["read", "write"])
                    .build(),
            )
            .refresh_store(InMemoryStore::default())
            .build();
    }
}

pub trait RefreshTokenStore: MaybeSendSync {
    fn get(&self) -> impl Future<Output = Option<RefreshToken>> + MaybeSend;
    fn set(&self, token: &RefreshToken) -> impl Future<Output = ()> + MaybeSend;
    fn clear(&self) -> impl Future<Output = ()> + MaybeSend;
}

#[derive(Debug, Default)]
pub struct InMemoryStore {
    refresh_token: RwLock<Option<RefreshToken>>,
}

impl RefreshTokenStore for InMemoryStore {
    async fn get(&self) -> Option<RefreshToken> {
        self.refresh_token.read().clone()
    }

    async fn set(&self, token: &RefreshToken) {
        *self.refresh_token.write() = Some(token.clone());
    }
    async fn clear(&self) {
        *self.refresh_token.write() = None;
    }
}
