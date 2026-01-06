//! Refresh grant.

use bon::Builder;
use serde::Serialize;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::core::OAuth2ExchangeGrant,
    token::RefreshToken,
};

/// Refresh grant.
#[derive(Debug, Clone, Builder)]
pub struct Grant<
    Auth: ClientAuthentication + 'static,
    DPoP: AuthorizationServerDPoP + 'static = NoDPoP,
> {
    /// The client authentication method.
    client_auth: Auth,

    /// The `DPoP` signer.
    dpop: DPoP,

    /// The URL of the token endpoint.
    token_url: Url,

    /// Supported endpoint auth methods; used to auto-select basic or form auth for client secrets.
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// Parameters passed to each token request.
#[derive(Debug, Clone, Builder)]
pub struct Parameters {
    /// The refresh token to use in the refresh token request.
    refresh_token: RefreshToken,
    /// Scopes for downscoping (must be previously granted scopes).
    #[builder(into)]
    scopes: Option<Vec<String>>,
}

/// Refresh grant body.
#[derive(Debug, Serialize)]
pub struct Form {
    grant_type: &'static str,
    refresh_token: RefreshToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for Grant<Auth, DPoP>
{
    type Parameters = Parameters;
    type ClientAuth = Auth;
    type DPoP = DPoP;

    type Form<'a> = Form;

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.token_endpoint_auth_methods_supported.as_deref()
    }

    fn token_endpoint(&self) -> &Url {
        &self.token_url
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.client_auth
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.dpop
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        Form {
            grant_type: "refresh_token",
            refresh_token: params.refresh_token,
            scope: params.scopes.and_then(|scopes| mk_scopes(scopes, " ")),
        }
    }

    fn refresh_grant(&self) -> Self {
        self.clone()
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
