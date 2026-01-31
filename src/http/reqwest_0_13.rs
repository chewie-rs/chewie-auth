use super::{HttpClient, HttpResponse};

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};

impl HttpResponse for reqwest_0_13::Response {
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

impl crate::Error for reqwest_0_13::Error {
    fn is_retryable(&self) -> bool {
        self.is_connect()
    }
}

impl HttpClient for reqwest_0_13::Client {
    /// The response type is `reqwest::Response`.
    type Response = reqwest_0_13::Response;
    /// The error type is `reqwest::Error`.
    type Error = reqwest_0_13::Error;

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
