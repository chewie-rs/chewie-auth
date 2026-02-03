use http::uri::InvalidUri;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt as _, Snafu};
use url::Url;

use crate::{
    client_auth::AuthenticationParams,
    dpop::AuthorizationServerDPoP,
    grant::{
        authorization_code::flow::AuthorizationPayload,
        core::form::{OAuth2FormError, OAuth2FormRequest},
    },
    http::{HttpClient, HttpResponse},
};

#[derive(Debug, Serialize)]
pub(super) struct AuthorizationPushPayload<'a> {
    pub client_id: &'a str,
    pub request_uri: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct AuthorizationPushResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

pub(super) async fn make_par_call<C: HttpClient, D: AuthorizationServerDPoP>(
    http_client: &C,
    par_url: Url,
    auth_params: AuthenticationParams,
    payload: AuthorizationPayload<'_>,
    dpop: D,
) -> Result<
    AuthorizationPushResponse,
    ParError<C::Error, <C::Response as HttpResponse>::Error, D::Error>,
> {
    OAuth2FormRequest::builder()
        .form(&payload)
        .auth_params(auth_params)
        .uri(par_url.as_str().parse().context(UrlSnafu)?)
        .dpop(&dpop)
        .build()
        .execute(http_client)
        .await
        .context(FormSnafu)
}

#[derive(Debug, Snafu)]
pub enum ParError<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
    DPoPErr: crate::Error + 'static,
> {
    Form {
        source: OAuth2FormError<HttpErr, HttpRespErr, DPoPErr>,
    },
    Url {
        source: InvalidUri,
    },
    DPoP {
        source: DPoPErr,
    },
}
