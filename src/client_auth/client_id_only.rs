use std::{borrow::Cow, convert::Infallible};

use crate::client_auth::{AuthenticationParams, ClientAuthentication};

/// Authentication that only provides the client ID.
///
/// The client may be public, or provide authentication through another mechanism.
#[derive(Debug, Clone)]
pub struct ClientIdOnly {
    /// The OAuth client identifier.
    client_id: Cow<'static, str>,
}

impl ClientIdOnly {
    /// Creates a new `ClientIdOnly` value.
    pub fn new(client_id: impl Into<Cow<'static, str>>) -> Self {
        Self {
            client_id: client_id.into(),
        }
    }
}

impl ClientAuthentication for ClientIdOnly {
    type Error = Infallible;

    fn client_id(&self) -> &str {
        &self.client_id
    }

    async fn authentication_params(
        &self,
        _token_endpoint: &url::Url,
        _allowed_methods: Option<&[String]>,
    ) -> Result<super::AuthenticationParams, Self::Error> {
        Ok(AuthenticationParams::builder()
            .form_params(bon::map! {
                "client_id": self.client_id.clone()
            })
            .build())
    }
}
