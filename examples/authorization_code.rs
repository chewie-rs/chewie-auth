use chewie_auth::{
    AuthorizationServerMetadata,
    client_auth::ClientSecret,
    grant::authorization_code::{self, CompleteInput, RedirectUrl, StartInput},
    secrets::{EnvVarSecret, StringEncoding},
};
use snafu::prelude::*;

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
    .unwrap();

    let grant = authorization_code::Grant::from_authorization_server_metadata(
        &authorization_server_metadata,
    )
    .client_auth(
        ClientSecret::builder()
            .client_id(std::env::var("CLIENT_ID").unwrap())
            .client_secret(EnvVarSecret::new("CLIENT_SECRET", StringEncoding))
            .build(),
    )
    .no_dpop()
    .redirect_url(RedirectUrl::new("http://localhost:3000/callback").unwrap())
    .build();

    let flow = authorization_code::Flow::from_authorization_server_metadata(
        &authorization_server_metadata,
    )
    .unwrap()
    .grant(grant)
    .build();

    let start_input = StartInput::builder()
        .scopes(bon::vec!["test"])
        .build()
        .whatever_context("Failed to generate random ID")?;

    // Note: this is incorrect, just want to see the full flow. State should be read from the callback.
    let state_for_later = start_input.state.clone();

    let start_result = flow
        .start(&http_client, start_input)
        .await
        .whatever_context("Failed to start flow")?;

    println!("Callback URL: {}", start_result.authorization_url);

    let token_response = flow
        .complete(
            &http_client,
            &start_result.callback_state,
            CompleteInput::builder()
                .code("1234")
                .state(state_for_later)
                .build(),
        )
        .await
        .whatever_context("Failed to complete flow")?;

    println!("Access Token: {:?}", token_response);

    Ok(())
}
