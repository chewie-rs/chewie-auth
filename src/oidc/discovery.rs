//! `OpenID` Connect Discovery.

use bon::bon;
use bytes::Bytes;
use http::Uri;
use serde::Deserialize;
use snafu::prelude::*;
use url::Url;

use crate::http::{HttpClient, HttpResponse};

fn default_response_modes_supported() -> Vec<String> {
    bon::vec!["query", "fragment"]
}

fn default_grant_types_supported() -> Vec<String> {
    bon::vec!["authorization_code", "implicit"]
}

fn default_auth_methods_supported() -> Vec<String> {
    bon::vec!["client_secret_basic"]
}

fn default_claim_types_supported() -> Vec<String> {
    bon::vec!["normal"]
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub userinfo_endpoint: Option<Url>,
    pub jwks_uri: Url,
    pub registration_endpoint: Option<Url>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    #[serde(default = "default_response_modes_supported")]
    pub response_modes_supported: Vec<String>,
    #[serde(default = "default_grant_types_supported")]
    pub grant_types_supported: Vec<String>,
    pub acr_values_supported: Option<Vec<String>>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    #[serde(default = "default_auth_methods_supported")]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub display_values_supported: Option<Vec<String>>,
    #[serde(default = "default_claim_types_supported")]
    pub claim_types_supported: Vec<String>,
    pub claims_supported: Option<Vec<String>>,
    pub service_documentation: Option<String>,
    pub claims_locales_supported: Option<Vec<String>>,
    pub ui_locales_supported: Option<Vec<String>>,
    #[serde(default)]
    pub claims_parameter_supported: bool,
    #[serde(default)]
    pub request_parameter_supported: bool,
    #[serde(default)]
    pub request_uri_parameter_supported: bool,
    #[serde(default)]
    pub require_request_uri_registration: bool,
    pub op_policy_uri: Option<Url>,
    pub op_tos_uri: Option<Url>,
    /**
     * `OpenID` Connect Session Management 1.0
     */
    pub check_session_iframe: Option<Url>,
    /**
     * RFC 8414 - OAuth 2.0 Authorization Server Metadata
     */
    pub revocation_endpoint: Option<Url>,
    #[serde(default = "default_auth_methods_supported")]
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub introspection_endpoint: Option<Url>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default = "Vec::new")]
    pub code_challenge_methods_supported: Vec<String>,
    /**
     * RFC 8628 - OAuth 2.0 Device Authorization Grant
     */
    pub device_authorization_endpoint: Option<Url>,
    /**
     * RFC 9126 - OAuth 2.0 Pushed Authorization Requests
     */
    // Specifies the URL of the pushed authorization request endpoint (RFC 9126 §5).
    pub pushed_authorization_request_endpoint: Option<Url>,
    // If true, indicates that pushed authorization requests are required (RFC 9126 §5).
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /**
     * RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification
     */
    // Indicates support for an `iss` identifier in the authorization endpoint response (RFC 9207 §3).
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

#[bon]
impl OidcProviderMetadata {
    #[builder]
    pub async fn from_issuer<C: HttpClient>(
        #[builder(start_fn, into)] issuer: &str,
        http_client: &C,
    ) -> Result<Self, OidcProviderFetchError<C::Error, <C::Response as HttpResponse>::Error>> {
        let configuration_endpoint = append_openid_config(issuer).context(BadIssuerSnafu)?;
        let request = http::Request::get(configuration_endpoint)
            .body(Bytes::new())
            .context(InvalidBodySnafu)?;
        let response = http_client
            .execute(request)
            .await
            .context(BadRequestSnafu)?;

        if response.status().is_success() {
            let body = response.body().await.context(BadResponseSnafu)?;
            let v = serde_json::from_slice::<Self>(&body).context(ParseJsonSnafu)?;
            Ok(v)
        } else {
            Err(todo!())
        }
    }
}

#[derive(Debug, Snafu)]
pub enum OidcProviderFetchError<
    HttpErr: crate::Error + 'static,
    HttpRespErr: crate::Error + 'static,
> {
    InvalidBody {
        source: http::Error,
    },
    BadRequest {
        /// The underlying error when making the HTTP request.
        source: HttpErr,
    },
    BadResponse {
        source: HttpRespErr,
    },
    ParseJson {
        source: serde_json::Error,
    },
    BadIssuer {
        /// The underlying error when parsing the issuer as a URL.
        source: http::Error,
    },
}

fn append_openid_config(issuer: &str) -> Result<Uri, http::Error> {
    let issuer_as_uri = issuer.parse::<Uri>()?;
    let path = issuer_as_uri.path();
    let cleaned_path = path.strip_suffix('/').unwrap_or(path);
    let new_path = format!("{cleaned_path}/.well-known/openid-configuration");
    let mut parts = issuer_as_uri.into_parts();
    parts.path_and_query = Some(new_path.try_into()?);
    Ok(Uri::from_parts(parts)?)
}

#[cfg(test)]
mod tests {
    use crate::oidc::discovery::OidcProviderMetadata;

    /// Test the document from OIDC Discovery §4.2.
    #[test]
    fn test_oidc_spec() {
        let source = r#"
            {
             "issuer":
               "https://server.example.com",
             "authorization_endpoint":
               "https://server.example.com/connect/authorize",
             "token_endpoint":
               "https://server.example.com/connect/token",
             "token_endpoint_auth_methods_supported":
               ["client_secret_basic", "private_key_jwt"],
             "token_endpoint_auth_signing_alg_values_supported":
               ["RS256", "ES256"],
             "userinfo_endpoint":
               "https://server.example.com/connect/userinfo",
             "check_session_iframe":
               "https://server.example.com/connect/check_session",
             "end_session_endpoint":
               "https://server.example.com/connect/end_session",
             "jwks_uri":
               "https://server.example.com/jwks.json",
             "registration_endpoint":
               "https://server.example.com/connect/register",
             "scopes_supported":
               ["openid", "profile", "email", "address",
                "phone", "offline_access"],
             "response_types_supported":
               ["code", "code id_token", "id_token", "id_token token"],
             "acr_values_supported":
               ["urn:mace:incommon:iap:silver",
                "urn:mace:incommon:iap:bronze"],
             "subject_types_supported":
               ["public", "pairwise"],
             "userinfo_signing_alg_values_supported":
               ["RS256", "ES256", "HS256"],
             "userinfo_encryption_alg_values_supported":
               ["RSA-OAEP-256", "A128KW"],
             "userinfo_encryption_enc_values_supported":
               ["A128CBC-HS256", "A128GCM"],
             "id_token_signing_alg_values_supported":
               ["RS256", "ES256", "HS256"],
             "id_token_encryption_alg_values_supported":
               ["RSA-OAEP-256", "A128KW"],
             "id_token_encryption_enc_values_supported":
               ["A128CBC-HS256", "A128GCM"],
             "request_object_signing_alg_values_supported":
               ["none", "RS256", "ES256"],
             "display_values_supported":
               ["page", "popup"],
             "claim_types_supported":
               ["normal", "distributed"],
             "claims_supported":
               ["sub", "iss", "auth_time", "acr",
                "name", "given_name", "family_name", "nickname",
                "profile", "picture", "website",
                "email", "email_verified", "locale", "zoneinfo",
                "http://example.info/claims/groups"],
             "claims_parameter_supported":
               true,
             "service_documentation":
               "http://server.example.com/connect/service_documentation.html",
             "ui_locales_supported":
               ["en-US", "en-GB", "en-CA", "fr-FR", "fr-CA"]
            }
"#;
        let parsed = serde_json::from_str::<OidcProviderMetadata>(source).unwrap();
        assert_eq!(parsed.issuer, "https://server.example.com");
        assert_eq!(
            parsed.authorization_endpoint,
            "https://server.example.com/connect/authorize"
                .parse()
                .unwrap()
        );
    }
}
