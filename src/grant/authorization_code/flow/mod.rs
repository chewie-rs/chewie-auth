#[cfg(feature = "authorization-flow-loopback")]
mod loopback;
mod par;

#[cfg(feature = "authorization-flow-loopback")]
pub use loopback::{LoopbackError, bind_loopback};

use bon::Builder;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use subtle::ConstantTimeEq;
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::{AuthorizationServerDPoP, NoDPoP},
    grant::{
        ExchangeGrant, OAuth2ExchangeGrant, TokenResponse,
        authorization_code::{
            Parameters,
            flow::{
                flow_builder::{
                    SetAuthorizationEndpoint, SetAuthorizationResponseIssParameterSupported,
                    SetIssuer, SetPushedAuthorizationRequestEndpoint,
                    SetRequirePushedAuthorizationRequests,
                },
                par::ParError,
            },
            grant::Grant,
            pkce::Pkce,
        },
    },
    http::{HttpClient, HttpResponse},
    server_metadata::AuthorizationServerMetadata,
};

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

/// The authorization code flow.
///
/// # Examples
///
/// ## Simple flow example (public `OAuth2` client, no `DPoP`).
///
/// ```rust, no_run
/// use chewie_auth::server_metadata::AuthorizationServerMetadata;
/// use chewie_auth::grant::authorization_code;
/// use chewie_auth::client_auth::ClientIdOnly;
/// use chewie_auth::dpop::NoDPoP;
///
/// let authorization_server_metadata: AuthorizationServerMetadata = todo!();
///
/// let grant: authorization_code::Grant<ClientIdOnly> =
///     authorization_code::Grant::from_authorization_server_metadata(&authorization_server_metadata)
///         .redirect_uri("https://redirect_url")
///         .client_auth(ClientIdOnly::new("client_id"))
///         .dpop(NoDPoP)
///         .build();
///
/// let flow: authorization_code::Flow<ClientIdOnly> =
///     authorization_code::Flow::from_authorization_server_metadata(&authorization_server_metadata)
///         .unwrap()
///         .grant(grant)
///         .build();
/// ```
#[derive(Debug, Clone, Builder)]
pub struct Flow<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP = NoDPoP> {
    /// The grant used when requesting a token from the token endpoint.
    grant: Grant<Auth, DPoP>,
    /// The authorization endpoint (RFC 6749 §3.1).
    authorization_endpoint: Url,
    /// The expected issuer.
    #[builder(into)]
    issuer: Option<String>,
    /// The pushed authorization request endpoint (RFC 9126 §5).
    pushed_authorization_request_endpoint: Option<Url>,
    /// Set to true if the provider requires PAR requests only (RFC 9126 §5).
    ///
    /// The value is usually set using authorization server metadata (RFC 8414).
    #[builder(default = false)]
    require_pushed_authorization_requests: bool,
    /// Set to true
    #[builder(default = true)]
    prefer_pushed_authorization_requests: bool,
    /// Set to true if the provider supports the `iss` parameter in the authorization code callback (RFC 9207).
    #[builder(default = false)]
    authorization_response_iss_parameter_supported: bool,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    Flow<Auth, DPoP>
{
    /// Configure the flow from authorization server metadata.
    #[must_use]
    pub fn from_authorization_server_metadata(
        oidc_metadata: &AuthorizationServerMetadata,
    ) -> Option<
        FlowBuilder<
            Auth,
            DPoP,
            SetAuthorizationResponseIssParameterSupported<
                SetRequirePushedAuthorizationRequests<
                    SetPushedAuthorizationRequestEndpoint<SetIssuer<SetAuthorizationEndpoint>>,
                >,
            >,
        >,
    > {
        Some(
            Self::builder()
                .authorization_endpoint(oidc_metadata.authorization_endpoint.clone()?)
                .issuer(oidc_metadata.issuer.clone())
                .maybe_pushed_authorization_request_endpoint(
                    oidc_metadata.pushed_authorization_request_endpoint.clone(),
                )
                .require_pushed_authorization_requests(
                    oidc_metadata.require_pushed_authorization_requests,
                )
                .authorization_response_iss_parameter_supported(
                    oidc_metadata.authorization_response_iss_parameter_supported,
                ),
        )
    }

    #[cfg(feature = "authorization-flow-loopback")]
    pub async fn complete_on_loopback<C: HttpClient>(
        &self,
        http_client: &C,
        listener: &tokio::net::TcpListener,
        callback_state: &CallbackState,
    ) -> Result<
        TokenResponse,
        LoopbackError<CompleteError<<Grant<Auth, DPoP> as ExchangeGrant>::Error<C>>>,
    > {
        loopback::complete_on_loopback(listener, callback_state, async |complete_input| {
            self.complete(http_client, callback_state, complete_input)
                .await
        })
        .await
    }

    pub async fn start<C: HttpClient>(
        &self,
        http_client: &C,
        start_input: StartInput,
    ) -> Result<
        StartResult,
        StartError<Auth::Error, C::Error, <C::Response as HttpResponse>::Error, DPoP::Error>,
    > {
        let pkce = Pkce::generate_s256_pair().context(RandSnafu)?;
        let payload = build_authorization_payload(self, &start_input, &pkce);

        let (authorization_url, expires_in) = if let Some(par_url) =
            &self.pushed_authorization_request_endpoint
            && (self.prefer_pushed_authorization_requests
                || self.require_pushed_authorization_requests)
        {
            let par_response = par::make_par_call(
                http_client,
                par_url.clone(),
                self.grant
                    .config
                    .client_auth
                    .authentication_params(
                        &self.grant.config.token_endpoint,
                        self.grant.allowed_auth_methods(),
                    )
                    .await
                    .context(ClientAuthSnafu)?,
                payload,
                self.grant.dpop().clone(),
            )
            .await
            .context(ParSnafu)?;

            let push_payload = par::AuthorizationPushPayload {
                client_id: self.grant.config.client_auth.client_id(),
                request_uri: &par_response.request_uri,
            };

            (
                add_payload_to_url(self.authorization_endpoint.clone(), push_payload)
                    .context(UrlSnafu)?,
                Some(par_response.expires_in),
            )
        } else {
            (
                add_payload_to_url(self.authorization_endpoint.clone(), payload)
                    .context(UrlSnafu)?,
                None,
            )
        };

        Ok(StartResult {
            authorization_url,
            expires_in,
            callback_state: CallbackState {
                redirect_uri: self.grant.config.redirect_uri.clone(),
                pkce_verifier: Some(pkce.verifier),
                state: start_input.state,
            },
        })
    }

    pub async fn complete<C: HttpClient>(
        &self,
        http_client: &C,
        callback_state: &CallbackState,
        complete_input: CompleteInput,
    ) -> Result<TokenResponse, CompleteError<<Grant<Auth, DPoP> as ExchangeGrant>::Error<C>>> {
        // CSRF protection.
        if callback_state
            .state
            .as_bytes()
            .ct_ne(complete_input.state.as_bytes())
            .into()
        {
            return StateMismatchSnafu {
                original: callback_state.state.clone(),
                callback: complete_input.state,
            }
            .fail();
        }

        // RFC 9207 - check issuer match.
        if self.authorization_response_iss_parameter_supported
            && let Some(config_issuer) = &self.issuer
        {
            if let Some(issuer) = complete_input.iss {
                if issuer.as_bytes().ct_ne(config_issuer.as_bytes()).into() {
                    return IssuerMismatchSnafu {
                        original: config_issuer,
                        callback: issuer,
                    }
                    .fail();
                }
            } else {
                // Server claimed to support RFC 9207 but no issuer received.
                return MissingIssuerSnafu.fail();
            }
        }

        let token = self
            .grant
            .exchange(
                http_client,
                Parameters {
                    code: complete_input.code.to_string(),
                    pkce_verifier: callback_state.pkce_verifier.clone(),
                },
            )
            .await
            .context(GrantSnafu)?;

        Ok(token)
    }
}

#[derive(Debug, Clone, Snafu)]
pub enum CompleteError<GrantErr: crate::Error + 'static> {
    Grant { source: GrantErr },
    IssuerMismatch { original: String, callback: String },
    StateMismatch { original: String, callback: String },
    MissingIssuer,
}

impl<GrantErr: crate::Error + 'static> crate::Error for CompleteError<GrantErr> {
    fn is_retryable(&self) -> bool {
        match self {
            CompleteError::Grant { source } => source.is_retryable(),
            CompleteError::IssuerMismatch { .. } => false,
            CompleteError::StateMismatch { .. } => false,
            CompleteError::MissingIssuer => false,
        }
    }
}

#[derive(Debug, Clone, Builder)]
#[builder(finish_fn(vis = "", name = build_internal))]
pub struct StartInput {
    #[builder(finish_fn)]
    pub state: String,
    #[builder(required, with = |scopes: impl IntoIterator<Item = String>| mk_scopes(scopes, " "))]
    scopes: Option<String>,
}

impl<S: start_input_builder::IsComplete> StartInputBuilder<S> {
    pub fn build(self) -> Result<StartInput, rand::rand_core::OsError> {
        Ok(self.build_internal(generate_random_value()?))
    }
}

#[derive(Debug, Clone)]
pub struct StartResult {
    pub authorization_url: Url,
    pub expires_in: Option<u64>,
    pub callback_state: CallbackState,
}

#[derive(Debug, Snafu)]
pub enum StartError<
    AuthErr: crate::Error + 'static,
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> {
    Url {
        source: serde_qs::Error,
    },
    Par {
        source: ParError<HttpErr, HttpRespErr, DPoPErr>,
    },
    Rand {
        source: rand::rand_core::OsError,
    },
    ClientAuth {
        source: AuthErr,
    },
}

#[derive(Debug, Clone, Builder)]
pub struct CompleteInput {
    #[builder(into)]
    code: String,
    #[builder(into)]
    state: String,
    #[builder(into)]
    iss: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackState {
    pub redirect_uri: String,
    pub pkce_verifier: Option<String>,
    pub state: String,
}

#[derive(Debug, Serialize)]
struct AuthorizationPayload<'a> {
    client_id: &'a str,
    response_type: &'static str,
    redirect_uri: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    state: &'a str,
    code_challenge: &'a str,
    code_challenge_method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_jkt: Option<&'a str>,
}

fn build_authorization_payload<
    'a,
    Auth: ClientAuthentication + 'static,
    DPoP: AuthorizationServerDPoP + 'static,
>(
    flow: &'a Flow<Auth, DPoP>,
    start_input: &'a StartInput,
    pkce: &'a Pkce,
) -> AuthorizationPayload<'a> {
    AuthorizationPayload {
        client_id: flow.grant.config.client_auth.client_id(),
        response_type: "code",
        redirect_uri: &flow.grant.config.redirect_uri,
        scope: start_input.scopes.as_deref(),
        state: &start_input.state,
        code_challenge: &pkce.challenge,
        code_challenge_method: "S256",
        dpop_jkt: flow.grant.dpop().jwk_thumbprint(),
    }
}

fn add_payload_to_url<T: Serialize>(mut endpoint: Url, payload: T) -> Result<Url, serde_qs::Error> {
    endpoint.set_query(Some(&serde_qs::to_string(&payload)?));
    Ok(endpoint)
}

const RANDOM_VALUE_BYTES: usize = 32;

fn generate_random_value() -> Result<String, rand::rand_core::OsError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let mut random_bytes = [0u8; RANDOM_VALUE_BYTES];
    rand::rngs::OsRng.try_fill_bytes(&mut random_bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(random_bytes))
}
