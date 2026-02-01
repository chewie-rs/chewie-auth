# chewie-auth

This crate implements authentication functionality using `OAuth2` specifications,
adhering to modern security practices (e.g. requirements for FAPI 2.0 support).

## Why use this?

This crate fills in the rest of the owl that many authentication implementations don't
implement. For example, it provides secure approaches to getting secret data (e.g.
keys) into your configuration. It recognises that in many cases, authentication is
a process, and encodes the process in a secure way. A good example of this is the
authorization code grant, which can require calls to the pushed authorization
request endpoint, then authorization endpoint, followed by the token endpoint;
while maintaining various security requirements, and acting in line with server
metadata discovery.

The crate is also based on the idea that modern security (e.g. FAPI 2.0) is not
"just for banking organizations"; these are actually good modern practices for a
secure system, and the features deserve to be available to anybody writing code
in rust. Systems should be secure by default, and flexible by design.

## Example

```rust
use chewie_auth::prelude::*;
use chewie_auth::authorizer::OAuthAuthorizer;
use chewie_auth::grant::client_credentials;
use chewie_auth::cache::{InMemoryStore, OAuthTokenCache};
use chewie_auth::client_auth::ClientSecret;
use chewie_auth::dpop::NoDPoP;
use chewie_auth::AuthorizationServerMetadata;
use chewie_auth::secrets::{EnvVarSecret, StringEncoding};

async fn example(http_client: &reqwest::Client, authorization_server_metadata: &AuthorizationServerMetadata) {
    let client_auth = ClientSecret::builder()
        .client_id("client_id")
        .client_secret(EnvVarSecret::new("CLIENT_SECRET", StringEncoding))
        .build();

    let grant = client_credentials::Grant::from_authorization_server_metadata(authorization_server_metadata)
        .client_auth(client_auth)
        .no_dpop()
        .build();

    let cache = OAuthTokenCache::builder()
        .grant(grant)
        .grant_parameters(client_credentials::Parameters::builder()
            .scopes(bon::vec!["test"])
            .build())
        .refresh_store(InMemoryStore::default())
        .build();

    let authorizer = OAuthAuthorizer::new(cache);

    let uri = "https://blah/".parse().unwrap();
    let headers: http::HeaderMap = authorizer.get_headers(http_client, &http::Method::GET, &uri).await.unwrap();
}
```

## Feature Set

- Request an access token using most common `OAuth2` grants.
- Workflows for multi-step token acquisition. Workflows encode many required steps for secure implementations that can be missed when manually implementing, e.g. issuer/state/nonce checks for authorization code grant.
- Client authentication supports public clients, client credentials, and signed JWTs (`private_key_jwt`/`client_secret_jwt` from RFC 7523).
- Secret abstraction allows secret data to come from secret managers, etc. without exposing them in the API.
- Supports proof of possession using `DPoP`.
- Token cache with automatic refresh.
- JWK/JWKS parsing.
- Serverless friendly (code is designed around the expectation that the process may be suspended arbitrarily.)
- Pluggable HTTP client.
- Authorizer layer ("give me the authorization headers") supports `DPoP`-bound tokens.
- Authorization server metadata can influence configuration (e.g. whether to use PAR).
- Signing is an async operation, can be implemented using a network call. This allows it to support cloud KMS (e.g. in GCP/AWS) for signing.
- Usable on WASM platforms (e.g. browser, edge computing).
- Grants are traits, so can be implemented by third parties.
- Similarly, crypto operations can be implemented by third parties.

## RFCs

### OAuth 2.0 Core

- RFC 6749 - OAuth 2.0 Authorization Framework
- RFC 6750 - Bearer Token Usage
- RFC 8414 - Authorization Server Metadata

### Grant Types

- RFC 6749 §4.1 - Authorization Code Grant
- RFC 6749 §4.4 - Client Credentials Grant
- RFC 6749 §6 - Refresh Token Grant
- RFC 8628 - Device Authorization Grant

### Security Extensions

- RFC 7636 - PKCE (Proof Key for Code Exchange)
- RFC 9126 - Pushed Authorization Requests (PAR)
- RFC 9207 - Authorization Server Issuer Identification
- RFC 9449 - `DPoP` (Demonstrating Proof of Possession)
- RFC 9700 - Best Current Practice for OAuth 2.0 Security

### Client Authentication

- RFC 6749 §2.3 - Client Password (Basic + POST)
- RFC 7521 - Assertion Framework for OAuth 2.0
- RFC 7523 - JWT Bearer Client Authentication

### JWT/JWK/JWS

- RFC 7515 - JSON Web Signature (JWS)
- RFC 7517 - JSON Web Key (JWK)
- RFC 7518 - JSON Web Algorithms (JWA)
- RFC 7519 - JSON Web Token (JWT)
- RFC 7638 - JSON Web Key (JWK) Thumbprint
- RFC 8037 - CFRG Elliptic Curve Signatures in JOSE (OKP/Ed25519)

### `OpenID` Connect

- `OpenID` Connect Discovery 1.0
- `OpenID` Connect Core §9 (Client Authentication)
