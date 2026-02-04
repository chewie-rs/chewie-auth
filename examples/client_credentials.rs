use chewie_auth::{
    authorizer::OAuthAuthorizer,
    cache::{InMemoryStore, OAuthTokenCache},
    client_auth::ClientSecret,
    crypto::signer::native::Es256PrivateKey,
    dpop::DPoP,
    grant::client_credentials,
    secrets::{EnvVarSecret, StringEncoding},
    server_metadata::AuthorizationServerMetadata,
};
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
    .whatever_context("Failed to get metadata")?;

    let grant = client_credentials::Grant::from_authorization_server_metadata(
        &authorization_server_metadata,
    )
    .client_auth(
        ClientSecret::builder()
            .client_id(std::env::var("CLIENT_ID").whatever_context("Failed to get CLIENT_ID")?)
            .client_secret(EnvVarSecret::new("CLIENT_SECRET", StringEncoding))
            .build(),
    )
    .dpop(DPoP::builder().signer(Es256PrivateKey::generate()).build())
    .build();

    let authorizer = OAuthTokenCache::builder()
        .grant(grant)
        .grant_parameters(
            client_credentials::Parameters::builder()
                .scopes(bon::vec!["test"])
                .build(),
        )
        .refresh_store(InMemoryStore::default())
        .build()
        .into_authorizer();

    let uri = "https://blah/".parse().unwrap();
    let headers = authorizer
        .get_headers(&http_client, &http::Method::GET, &uri)
        .await
        .whatever_context("Failed to get headers")?;

    println!("Headers: {:?}", headers);

    Ok(())
}
