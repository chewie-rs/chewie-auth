use chewie_auth::{
    client_auth::ClientSecret,
    crypto::signer::native::Es256PrivateKey,
    dpop::DPoP,
    grant::authorization_code,
    secrets::{EnvVarSecret, StringEncoding},
    server_metadata::AuthorizationServerMetadata,
};
use secrecy::ExposeSecret;
use snafu::prelude::*;

#[snafu::report]
#[tokio::main]
pub async fn main() -> Result<(), snafu::Whatever> {
    let http_client = reqwest::Client::new();
    let authorization_server_metadata = AuthorizationServerMetadata::from_issuer(
        std::env::var("ISSUER")
            .whatever_context("Failed to get ISSUER")?
            .as_str(),
    )
    .call(&http_client)
    .await
    .whatever_context("Failed to get authorization server metadata")?;

    let (listener, redirect_uri) = authorization_code::bind_loopback("/callback", 3000)
        .await
        .whatever_context("Failed to bind port for callback")?;

    let grant = authorization_code::Grant::from_authorization_server_metadata(
        &authorization_server_metadata,
    )
    .client_auth(
        ClientSecret::builder()
            .client_id(std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?)
            .client_secret(EnvVarSecret::new("CLIENT_SECRET", StringEncoding))
            .build(),
    )
    .dpop(DPoP::builder().signer(Es256PrivateKey::generate()).build())
    .redirect_uri(redirect_uri)
    .build();

    let flow = authorization_code::Flow::from_authorization_server_metadata(
        &authorization_server_metadata,
    )
    .whatever_context("Authorization server metadata did not include authorization endpoint")?
    .grant(grant)
    .prefer_pushed_authorization_requests(true)
    .build();

    let result = flow
        .start(
            &http_client,
            authorization_code::StartInput::builder()
                .scopes(bon::vec!["test"])
                .build()
                .whatever_context("Failed to build input for flow")?,
        )
        .await
        .whatever_context("Failed to start flow")?;

    println!("Auth URL: {}", result.authorization_url);

    let token_response = flow
        .complete_on_loopback(&http_client, &listener, &result.callback_state)
        .await
        .whatever_context("Failed to complete flow")?;

    println!(
        "Access Token: {:?}",
        token_response.access_token.expose_secret()
    );

    Ok(())
}
