use chewie_auth::{
    client_auth::ClientSecret,
    grant::authorization_code::{self, CompleteInput, RedirectUrl, StartInput},
    oidc::discovery::OidcProviderMetadata,
    secrets::{EnvVarSecret, StringEncoding},
};

#[tokio::main]
pub async fn main() {
    let http_client = reqwest::Client::new();
    let oidc_provider_metadata =
        OidcProviderMetadata::from_issuer(std::env::var("ISSUER").unwrap().as_str())
            .http_client(&http_client)
            .call()
            .await
            .unwrap();

    let grant = authorization_code::Grant::from_oidc_provider_metadata(&oidc_provider_metadata)
        .client_auth(
            ClientSecret::builder()
                .client_id(std::env::var("CLIENT_ID").unwrap())
                .client_secret(EnvVarSecret::new("CLIENT_SECRET", StringEncoding))
                .build(),
        )
        .no_dpop()
        .redirect_url(RedirectUrl::new("http://localhost:3000/callback").unwrap())
        .build();

    let flow = authorization_code::Flow::from_oidc_provider_metadata(&oidc_provider_metadata)
        .grant(grant)
        .build();

    let start_input = StartInput::builder()
        .scopes(bon::vec!["test"])
        .build()
        .unwrap();

    // Note: this is incorrect, just want to see the full flow. State should be read from the callback.
    let state_for_later = start_input.state.clone();

    let callback_state = flow.start(&http_client, start_input).await.unwrap();

    println!("Callback URL: {}", callback_state.authorization_url);

    let token_response = flow
        .complete(
            &http_client,
            &callback_state,
            CompleteInput::builder()
                .code("1234")
                .state(state_for_later)
                .build(),
        )
        .await
        .unwrap();

    println!("Access Token: {:?}", token_response);
}
