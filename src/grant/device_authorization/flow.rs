use std::time::Duration;

use bon::Builder;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};
use url::Url;

use crate::{
    client_auth::ClientAuthentication,
    dpop::AuthorizationServerDPoP,
    grant::{
        ExchangeGrant, OAuth2ExchangeGrant, OAuth2ExchangeGrantError, TokenResponse,
        core::form::{HandleResponseError, OAuth2ErrorBody, OAuth2FormError, OAuth2FormRequest},
        device_authorization::Grant,
    },
    http::{HttpClient, HttpResponse},
    platform::sleep,
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

#[derive(Debug, Clone, Builder)]
pub struct Flow<Auth: ClientAuthentication, DPoP: AuthorizationServerDPoP> {
    grant: Grant<Auth, DPoP>,
    #[builder(getter)]
    device_authorization_endpoint: Url,
}

/// Response from the device authorization endpoint.
#[derive(Debug, Clone, Deserialize)]
struct DeviceAuthorizationResponse {
    /// The device verification code.
    device_code: String,

    /// The end-user verification code.
    user_code: String,

    /// The end-user verification URI on the authorization server.
    verification_uri: String,

    /// Optional: A verification URI that includes the user code.
    verification_uri_complete: Option<String>,

    /// The lifetime in seconds of the `device_code` and `user_code`.
    expires_in: u32,

    /// The minimum amount of time in seconds the client should wait between polling requests.
    /// Defaults to 5 seconds if not provided by the server.
    #[serde(default = "default_interval")]
    interval: u32,
}

/// Default polling interval in seconds.
#[inline]
const fn default_interval() -> u32 {
    5
}

#[derive(Debug, Serialize)]
struct DeviceAuthorizationRequest<'a> {
    scope: Option<&'a str>,
}

#[derive(Debug, Builder, Serialize, Deserialize)]
#[builder(on(String, into))]
pub struct PendingState {
    device_code: String,
    expires_at: crate::platform::SystemTime,
    interval_secs: u32,
}

#[derive(Debug)]
pub struct StartResult {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub pending_state: PendingState,
}

impl<Auth: ClientAuthentication + 'static, DPoP: AuthorizationServerDPoP + 'static>
    Flow<Auth, DPoP>
{
    pub async fn start<C: HttpClient>(
        &self,
        http_client: &C,
        start_input: StartInput,
    ) -> Result<
        StartResult,
        StartError<Auth::Error, C::Error, <C::Response as HttpResponse>::Error, DPoP::Error>,
    > {
        let auth_params = self
            .grant
            .config
            .client_auth
            .authentication_params(
                self.grant.token_endpoint(),
                self.grant.allowed_auth_methods(),
            )
            .await
            .context(ClientAuthSnafu)?;

        let payload = DeviceAuthorizationRequest {
            scope: start_input.scopes.as_deref(),
        };

        let response: DeviceAuthorizationResponse = OAuth2FormRequest::builder()
            .form(&payload)
            .auth_params(auth_params)
            .uri(self.device_authorization_endpoint.as_str().parse().unwrap())
            .dpop(self.grant.dpop())
            .build()
            .execute(http_client)
            .await
            .context(FormSnafu)?;

        Ok(StartResult {
            user_code: response.user_code,
            verification_uri: response.verification_uri,
            verification_uri_complete: response.verification_uri_complete,
            pending_state: PendingState {
                device_code: response.device_code,
                expires_at: crate::platform::SystemTime::now()
                    .checked_add(Duration::from_secs(response.expires_in.into()))
                    .unwrap_or_else(crate::platform::SystemTime::now),
                interval_secs: response.interval,
            },
        })
    }

    pub async fn poll_to_completion<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: PendingState,
        event: impl AsyncFn(u32),
    ) -> Result<TokenResponse, PollError<<Grant<Auth, DPoP> as ExchangeGrant>::Error<C>>> {
        let mut pending_state = pending_state;

        loop {
            sleep(Duration::from_secs(pending_state.interval_secs.into())).await;

            match self.poll(http_client, pending_state).await? {
                PollResult::Pending(pending) => {
                    pending_state = pending;
                    event(pending_state.interval_secs).await;
                }
                PollResult::Complete(token_response) => return Ok(token_response),
            }
        }
    }

    pub async fn poll<C: HttpClient>(
        &self,
        http_client: &C,
        pending_state: PendingState,
    ) -> Result<PollResult, PollError<<Grant<Auth, DPoP> as ExchangeGrant>::Error<C>>> {
        let token_or_err = self
            .grant
            .exchange(
                http_client,
                super::grant::Parameters {
                    device_code: pending_state.device_code.clone(),
                },
            )
            .await;

        match token_or_err {
            Ok(token) => Ok(PollResult::Complete(token)),
            Err(err) => match &err {
                OAuth2ExchangeGrantError::OAuth2Form {
                    source:
                        OAuth2FormError::Response {
                            source:
                                HandleResponseError::OAuth2 {
                                    body: OAuth2ErrorBody { error, .. },
                                    ..
                                },
                        },
                } => match error.as_ref() {
                    "slow_down" => Ok(PollResult::Pending(PendingState {
                        interval_secs: pending_state.interval_secs.saturating_add(5),
                        ..pending_state
                    })),
                    "authorization_pending" => Ok(PollResult::Pending(pending_state)),
                    "access_denied" => AccessDeniedSnafu.fail(),
                    "expired_token" => TokenExpiredSnafu.fail(),
                    _ => Err(err).context(ExchangeSnafu),
                },
                _ => Err(err).context(ExchangeSnafu),
            },
        }
    }
}

#[derive(Debug, Snafu)]
pub enum PollError<ExchangeErr: crate::Error + 'static> {
    AccessDenied,
    TokenExpired,
    Exchange { source: ExchangeErr },
}

pub enum PollResult {
    Pending(PendingState),
    Complete(TokenResponse),
}

#[derive(Debug, Clone, Builder)]
pub struct StartInput {
    #[builder(required, with = |scopes: impl IntoIterator<Item = String>| mk_scopes(scopes, " "))]
    scopes: Option<String>,
}

#[derive(Debug, Snafu)]
pub enum StartError<
    AuthErr: crate::Error + 'static,
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> {
    Form {
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
    ClientAuth {
        source: AuthErr,
    },
}
