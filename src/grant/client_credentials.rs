//! Client credentials grant.

use bon::Builder;
use serde::Serialize;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{
        client_credentials::grant_builder::{
            SetDpop, SetTokenEndpoint, SetTokenEndpointAuthMethodsSupported,
        },
        core::OAuth2ExchangeGrant,
        refresh,
    },
    oidc::discovery::OidcProviderMetadata,
};

/// Client credentials grant.
#[derive(Debug, Clone, Builder)]
pub struct Grant<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP = NoDPoP> {
    /// The client authentication method.
    client_auth: Auth,

    /// The `DPoP` signer.
    dpop: DPoP,

    /// The URL of the token endpoint.
    token_endpoint: Url,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

impl<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP> Grant<Auth, DPoP> {
    /// Configure the grant from OIDC provider metadata.
    pub fn from_oidc_provider_metadata(
        oidc_metadata: &OidcProviderMetadata,
    ) -> GrantBuilder<Auth, DPoP, SetTokenEndpointAuthMethodsSupported<SetTokenEndpoint>> {
        Self::builder()
            .token_endpoint(oidc_metadata.token_endpoint.clone())
            .token_endpoint_auth_methods_supported(
                oidc_metadata.token_endpoint_auth_methods_supported.clone(),
            )
    }
}

impl<Auth: ClientAuthentication, S: grant_builder::State> GrantBuilder<Auth, NoDPoP, S> {
    pub fn no_dpop(self) -> GrantBuilder<Auth, NoDPoP, SetDpop<S>>
    where
        S::Dpop: grant_builder::IsUnset,
    {
        self.dpop(NoDPoP)
    }
}

fn mk_scopes(scopes: impl IntoIterator<Item = String>, separator: &str) -> Option<String> {
    let maybe_scopes = scopes
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect::<Vec<_>>();

    if maybe_scopes.is_empty() {
        None
    } else {
        Some(maybe_scopes.join(separator))
    }
}

/// Client credentials grant body.
#[derive(Debug, Serialize)]
pub struct Form {
    grant_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Parameters when requesting a token.
#[derive(Debug, Clone, Builder)]
pub struct Parameters {
    #[builder(required, name = "scopes", with = |scopes: impl IntoIterator<Item = String>| mk_scopes(scopes, " "))]
    scope: Option<String>,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for Grant<Auth, DPoP>
{
    type Parameters = Parameters;
    type ClientAuth = Auth;
    type DPoP = DPoP;
    type Form<'a> = Form;

    fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.dpop
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        Form {
            grant_type: "client_credentials",
            scope: params.scope,
        }
    }

    fn refresh_grant(&self) -> refresh::Grant<Self::ClientAuth, Self::DPoP> {
        refresh::Grant::builder()
            .client_auth(self.client_auth.clone())
            .dpop(self.dpop.clone())
            .token_url(self.token_endpoint.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }
}
