//! HTTP client abstraction.

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};

use crate::platform::{MaybeSend, MaybeSendSync};

#[cfg(all(not(target_arch = "wasm32"), feature = "http-client-reqwest-0_13"))]
mod reqwest_0_13;

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
