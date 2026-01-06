use bon::bon;
use bytes::Bytes;
use http::{Method, Uri};
use serde::Deserialize;
use url::Url;

use crate::http::HttpClient;

fn default_response_modes_supported() -> Vec<String> {
    bon::vec!["query", "fragment"]
}

fn default_grant_types_supported() -> Vec<String> {
    bon::vec!["authorization_code", "implicit"]
}

fn default_auth_methods_supported() -> Vec<String> {
    bon::vec!["client_secret_basic"]
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: Option<Url>,
    token_endpoint: Option<Url>,
    jwks_uri: Option<Url>,
    registration_endpoint: Option<Url>,
    scopes_supported: Option<Vec<String>>,
    response_types_supported: Vec<String>,
    #[serde(default = "default_response_modes_supported")]
    response_modes_supported: Vec<String>,
    #[serde(default = "default_grant_types_supported")]
    grant_types_supported: Vec<String>,
    #[serde(default = "default_auth_methods_supported")]
    token_endpoint_auth_methods_supported: Vec<String>,
    token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    service_documentation: Option<String>,
    ui_locales_supported: Option<Vec<String>>,
    op_policy_uri: Option<Url>,
    op_tos_uri: Option<Url>,
    revocation_endpoint: Option<Url>,
    #[serde(default = "default_auth_methods_supported")]
    revocation_endpoint_auth_methods_supported: Vec<String>,
    revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    introspection_endpoint: Option<Url>,
    introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default = "Vec::new")]
    code_challenge_methods_supported: Vec<String>,
    /**
     * RFC 8628 - OAuth 2.0 Device Authorization Grant
     */
    pub device_authorization_endpoint: Option<Url>,
    /**
     * RFC 9126 - OAuth 2.0 Pushed Authorization Requests
     */
    // Specifies the URL of the pushed authorization request endpoint (RFC 9126 §5).
    pushed_authorization_request_endpoint: Option<Url>,
    // If true, indicates that pushed authorization requests are required (RFC 9126 §5).
    #[serde(default)]
    require_pushed_authorization_requests: bool,
    /**
     * RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
     */
    // Indicates support for an `iss` identifier in the authorization endpoint response (RFC 9207 §3).
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

#[bon]
impl AuthorizationServerMetadata {
    #[builder]
    pub async fn from_issuer<C: HttpClient>(
        #[builder(start_fn, into)] issuer: &str,
        http_client: &C,
        #[builder(into)] _well_known_path: &str,
    ) -> Self {
        let issuer_as_uri = issuer.parse::<Uri>().unwrap();
        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = Method::GET;

        let _path = issuer_as_uri.path();

        let request = http::Request::from_parts(parts, Bytes::new());

        http_client.execute(request).await.unwrap();

        todo!()
    }
}
