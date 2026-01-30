//! HTTP client abstraction.

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};

use crate::platform::{MaybeSend, MaybeSendSync};

/// HTTP client trait.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not implement `HttpClient`",
    label = "This type cannot execute HTTP requests for OAuth2",
    note = "HttpClient requires: Clone + MaybeSendSync",
    note = "Enable the 'http-client-reqwest-0_13' feature to use reqwest::Client, or implement HttpClient"
)]
pub trait HttpClient: MaybeSendSync + Clone {
    /// The error type returned by the client for a failed request.
    type Error: crate::Error + 'static;

    /// The associated response type returned by this HTTP client.
    type Response: HttpResponse + MaybeSend;

    /// Executes an HTTP request and returns an owned response.
    ///
    /// # Arguments
    ///
    /// * `request`: The `http::Request` to be executed. The body is provided as `bytes::Bytes`.
    ///
    /// # Returns
    ///
    /// A `Future` that resolves to a `Result` containing the `Self::Response` on success,
    /// or `Self::Error` on failure.
    fn execute(
        &self,
        request: Request<Bytes>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + MaybeSend;
}

/// A trait defining the common interface for HTTP responses.
///
/// This trait allows `chewie-auth` to work with responses from different
/// `HttpClient` implementations.
pub trait HttpResponse {
    /// The error type when getting the response body.
    type Error: crate::Error + 'static;

    /// Returns the HTTP status code of the response.
    fn status(&self) -> StatusCode;

    /// Returns an immutable reference to the response's HTTP headers.
    fn headers(&self) -> &HeaderMap;

    /// Consumes the response and asynchronously returns its body as `bytes::Bytes`.
    ///
    /// # Returns
    ///
    /// A `Future` that resolves to a `Result` containing the response body on success,
    /// or an error if reading the body fails.
    fn body(self) -> impl Future<Output = Result<Bytes, Self::Error>> + MaybeSend;
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http-client-reqwest-0_13"))]
impl HttpResponse for reqwest::Response {
    type Error = reqwest_0_13::Error;

    /// Returns the HTTP status code of the `reqwest::Response`.
    fn status(&self) -> StatusCode {
        self.status()
    }

    /// Returns an immutable reference to the `reqwest::Response`'s headers.
    fn headers(&self) -> &HeaderMap {
        self.headers()
    }

    /// Consumes the `reqwest::Response` and asynchronously returns its body as `bytes::Bytes`.
    ///
    /// This method leverages `reqwest::Response::bytes()` to read the full body.
    async fn body(self) -> Result<Bytes, Self::Error> {
        self.bytes().await
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http-client-reqwest-0_13"))]
impl crate::Error for reqwest_0_13::Error {
    fn is_retryable(&self) -> bool {
        self.is_connect()
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http-client-reqwest-0_13"))]
impl HttpClient for reqwest::Client {
    /// The response type is `reqwest::Response`.
    type Response = reqwest::Response;
    /// The error type is `reqwest::Error`.
    type Error = reqwest::Error;

    /// Executes an `http::Request` using the `reqwest::Client`.
    ///
    /// This method converts the generic `http::Request<Bytes>` into a `reqwest::Request`
    /// and then sends it.
    ///
    /// # Arguments
    ///
    /// * `request`: The `http::Request` to be executed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `reqwest::Response` on success, or a `reqwest::Error` on failure.
    async fn execute(&self, request: Request<Bytes>) -> Result<Self::Response, Self::Error> {
        let (parts, body) = request.into_parts();
        let reqwest_request = self
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .build()?;

        let response = self.execute(reqwest_request).await?;

        Ok(response)
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "http-client-reqwest-0_13"))]
pub use reqwest as reqwest_0_13;
