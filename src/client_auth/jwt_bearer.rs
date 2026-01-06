use std::{borrow::Cow, time::Duration};

use bon::Builder;

use crate::{
    client_auth::{AuthenticationParams, ClientAuthentication},
    jwt::{JwsSerializationError, SimpleJwt},
    signer::JwsSigner,
};

/// JWT Authentication (RFC 7521 / 7523 / `OpenID` Connect Core 1.0 §9)
///
/// With this method, the client authenticates using a JWT which has been
/// cryptographically signed.
///
/// The caller provides the client ID and signing implementation.
///
/// The implementation creates a JWT with these claims:
///  - iss (client ID)
///  - sub (client ID)
///  - aud (defaults to the token endpoint)
///  - exp (expiry time)
///  - iat (current time)
///  - jti (unique ID for replay protection)
///
/// Note: FAPI 2.0 requires that the audience value is the authorization
/// server's issuer identifier, so setting a custom audience is necessary
/// in this case.
///
/// ## Asymmetric private key
///
/// When the underlying key is an asymmetric private key, the code implements
/// RFC 7523 (private key JWT).
///
/// Benefits:
///  - no shared secrets
///  - stateless verification
///  - non-repudiation (proof that the client sent it)
///
/// ## HMAC shared key
///
/// When the underlying key is a symmetric HMAC key, the code implements
/// `OpenID` Connect Core 1.0 §9 (`client_secret_jwt`).
///
/// Benefits:
///  - simpler setup when a shared secret is acceptable
#[derive(Debug, Clone, Builder)]
pub struct JwtBearer<Sgn: JwsSigner> {
    /// The signer of the JWT.
    signer: Sgn,
    /// The `OAuth2` client ID.
    #[builder(into)]
    client_id: Cow<'static, str>,
    /// If set, the aud claim is set to this value.
    #[builder(into)]
    audience: Option<Cow<'static, str>>,
    /// The lifetime of the JWT (as set in the `exp` claim).
    #[builder(default = Duration::from_secs(300))]
    expires_after: Duration,
}

impl<Sgn: JwsSigner> ClientAuthentication for JwtBearer<Sgn> {
    type Error = JwsSerializationError<Sgn::Error>;

    fn client_id(&self) -> &str {
        &self.client_id
    }

    async fn authentication_params(
        &self,
        token_endpoint: &url::Url,
        _allowed_methods: Option<&[String]>,
    ) -> Result<super::AuthenticationParams, Self::Error> {
        let jwt = SimpleJwt::builder()
            .audience(self.audience.as_deref().unwrap_or(token_endpoint.as_str()))
            .issuer(self.client_id())
            .subject(self.client_id())
            .issued_now_expires_after(self.expires_after)
            .build();

        Ok(AuthenticationParams::builder()
            .form_params(bon::map! {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": jwt.to_jws_compact(&self.signer).await?
            })
            .build())
    }
}
