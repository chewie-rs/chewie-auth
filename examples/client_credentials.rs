use chewie_auth::{
    client_auth::ClientSecret,
    grant::{ExchangeGrant, client_credentials},
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

    let grant = client_credentials::Grant::from_oidc_provider_metadata(&oidc_provider_metadata)
        .client_auth(
            ClientSecret::builder()
                .client_id(std::env::var("CLIENT_ID").unwrap())
                .client_secret(EnvVarSecret::new("CLIENT_SECRET", StringEncoding))
                .build(),
        )
        .no_dpop()
        .build();

    let token_response = grant
        .exchange(
            &http_client,
            client_credentials::Parameters::builder()
                .scopes(bon::vec!["test"])
                .build(),
        )
        .await
        .unwrap();

    println!("Access Token: {:?}", token_response);
}
