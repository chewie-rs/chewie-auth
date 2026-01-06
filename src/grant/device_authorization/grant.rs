use bon::Builder;
use serde::Serialize;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{OAuth2ExchangeGrant, refresh},
};

/// The device authorization grant.
#[derive(Debug, Clone)]
pub struct Grant<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP = NoDPoP> {
    pub(super) config: GrantConfig<Auth, DPoP>,
}

impl<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP> Grant<Auth, DPoP> {
    /// The builder for the device authorization grant.
    pub fn builder() -> GrantConfigBuilder<Auth, DPoP> {
        GrantConfig::builder()
    }
}

/// The config for the device authorization grant.
#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct GrantConfig<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP> {
    /// The client authentication method.
    pub(super) client_auth: Auth,

    /// The `DPoP` configuration.
    pub(super) dpop: DPoP,

    /// The URL of the token endpoint.
    pub(super) token_url: Url,

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

/// Parameters passed to each token request.
#[derive(Debug, Clone)]
pub struct Parameters {
    /// The device verification code, `device_code`, from the device authorization response.
    pub device_code: String,
}

/// Authorization code grant body.
#[derive(Debug, Serialize)]
pub struct Form {
    /// Must be set to `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4).
    grant_type: &'static str,
    /// The device verification code, `device_code`, from the authorization response (RFC 8628 §3.4).
    device_code: String,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    OAuth2ExchangeGrant for Grant<Auth, DPoP>
{
    type Parameters = Parameters;
    type ClientAuth = Auth;
    type DPoP = DPoP;
    type Form<'a> = Form;

    fn token_endpoint(&self) -> &Url {
        &self.config.token_url
    }

    fn client_auth(&self) -> &Self::ClientAuth {
        &self.config.client_auth
    }

    fn dpop(&self) -> &Self::DPoP {
        &self.config.dpop
    }

    fn build_form(&self, params: Self::Parameters) -> Self::Form<'_> {
        Self::Form {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: params.device_code,
        }
    }

    fn refresh_grant(&self) -> refresh::Grant<Self::ClientAuth, Self::DPoP> {
        refresh::Grant::builder()
            .client_auth(self.config.client_auth.clone())
            .dpop(self.config.dpop.clone())
            .token_url(self.config.token_url.clone())
            .maybe_token_endpoint_auth_methods_supported(
                self.config.token_endpoint_auth_methods_supported.clone(),
            )
            .build()
    }

    fn allowed_auth_methods(&self) -> Option<&[String]> {
        self.config.token_endpoint_auth_methods_supported.as_deref()
    }
}
