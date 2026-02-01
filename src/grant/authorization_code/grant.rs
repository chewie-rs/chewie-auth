use bon::Builder;
use serde::Serialize;
use url::Url;

use crate::{
    AuthorizationServerMetadata,
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{
        OAuth2ExchangeGrant,
        authorization_code::{
            RedirectUrl,
            grant::grant_config_builder::{
                SetDpop, SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported,
            },
        },
        refresh,
    },
};

/// The authorization code grant.
///
/// # Examples
///
/// ## Simple flow example (public `OAuth2` client, no `DPoP`).
///
/// ```rust
/// # async fn test(client: reqwest::Client, authorization_server_metadata: &chewie_auth::AuthorizationServerMetadata) {
/// use chewie_auth::prelude::*;
/// use chewie_auth::grant::TokenResponse;
/// use chewie_auth::grant::authorization_code;
/// use chewie_auth::client_auth::ClientIdOnly;
/// use chewie_auth::dpop::NoDPoP;
///
/// let grant: authorization_code::Grant<ClientIdOnly> =
///     authorization_code::Grant::from_authorization_server_metadata(authorization_server_metadata)
///         .redirect_url("https://redirect_url".parse().unwrap())
///         .client_auth(ClientIdOnly::new("client_id"))
///         .dpop(NoDPoP)
///         .build();
///
/// let token: TokenResponse = grant.exchange(&client, authorization_code::Parameters::builder().code("code").build()).await.unwrap();
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Grant<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP = NoDPoP> {
    pub(super) config: GrantConfig<Auth, DPoP>,
}

impl<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP> Grant<Auth, DPoP> {
    /// The builder for the authorization code grant.
    pub fn builder() -> GrantConfigBuilder<Auth, DPoP> {
        GrantConfig::builder()
    }

    /// Configure the grant from authorization server metadata.
    pub fn from_authorization_server_metadata(
        oidc_metadata: &AuthorizationServerMetadata,
    ) -> GrantConfigBuilder<Auth, DPoP, SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint>>
    {
        Self::builder()
            .token_endpoint(oidc_metadata.token_endpoint.clone())
            .token_endpoint_auth_methods_supported(
                oidc_metadata.token_endpoint_auth_methods_supported.clone(),
            )
    }
}

/// The authorization code grant config.
#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct GrantConfig<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP> {
    /// The client authentication method.
    pub(super) client_auth: Auth,

    /// The `DPoP` configuration.
    pub(super) dpop: DPoP,

    /// The URL of the token endpoint.
    pub(super) token_endpoint: Url,

    /// The redirect URL registered with the authorization server.
    pub(super) redirect_url: RedirectUrl,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    pub(super) token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP, S: grant_config_builder::State>
    GrantConfigBuilder<Auth, DPoP, S>
where
    S: grant_config_builder::IsComplete,
{
    /// Build
    pub fn build(self) -> Grant<Auth, DPoP> {
        Grant {
            config: self.build_internal(),
        }
    }
}

impl<Auth: ClientAuthentication, S: grant_config_builder::State>
    GrantConfigBuilder<Auth, NoDPoP, S>
{
    pub fn no_dpop(self) -> GrantConfigBuilder<Auth, NoDPoP, SetDpop<S>>
    where
        S::Dpop: grant_config_builder::IsUnset,
    {
        self.dpop(NoDPoP)
    }
}

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
pub struct Parameters {
    /// The temporary authorization code received from the redirect callback.
    #[builder(into)]
    pub code: String,
    /// The PKCE verifier.
    #[builder(into)]
    pub pkce_verifier: Option<String>,
}

/// Authorization code grant body.
#[derive(Debug, Serialize)]
pub struct AuthorizationCodeForm<'a> {
    grant_type: &'static str,
    code: String,
    redirect_uri: &'a RedirectUrl,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<String>,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for Grant<Auth, DPoP>
{
    type Parameters = Parameters;
    type ClientAuth = Auth;
    type DPoP = DPoP;
    type Form<'a> = AuthorizationCodeForm<'a>;

    fn token_endpoint(&self) -> &Url {
        &self.config.token_endpoint
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.config.client_auth
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.config.dpop
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        Self::Form {
            grant_type: "authorization_code",
            code: params.code,
            redirect_uri: &self.config.redirect_url,
            code_verifier: params.pkce_verifier,
        }
    }

    fn refresh_grant(&self) -> refresh::Grant<Self::ClientAuth, Self::DPoP> {
        refresh::Grant::builder()
            .client_auth(self.config.client_auth.clone())
            .dpop(self.config.dpop.clone())
            .token_url(self.config.token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.config.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.config.token_endpoint_auth_methods_supported.as_deref()
    }
}
