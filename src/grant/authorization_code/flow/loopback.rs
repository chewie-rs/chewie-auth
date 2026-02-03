use snafu::{ResultExt as _, Snafu};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
};
use url::Url;

use crate::grant::{
    TokenResponse,
    authorization_code::{CallbackState, CompleteInput},
};

#[derive(Debug, Snafu)]
pub enum LoopbackError<CompleteErr: crate::Error + 'static> {
    #[snafu(display("Invalid redirect URI in callback state: {source}"))]
    InvalidRedirectUri { source: url::ParseError },
    #[snafu(display("Failed to accept connection: {source}"))]
    Accept { source: std::io::Error },
    #[snafu(display("Failed to read request: {source}"))]
    ReadRequest { source: std::io::Error },
    #[snafu(display("Authorization server returned error: {error}"))]
    OAuthError {
        error: String,
        error_description: Option<String>,
    },
    #[snafu(display("Missing required parameter: {param}"))]
    MissingParameter { param: &'static str },
    #[snafu(display("Failed to complete authorization: {source}"))]
    Complete { source: CompleteErr },
}

impl<CompleteErr: crate::Error + 'static> crate::Error for LoopbackError<CompleteErr> {
    fn is_retryable(&self) -> bool {
        match self {
            LoopbackError::InvalidRedirectUri { .. } => false,
            LoopbackError::Accept { .. } => true,
            LoopbackError::ReadRequest { .. } => true,
            LoopbackError::OAuthError { .. } => false,
            LoopbackError::MissingParameter { .. } => false,
            LoopbackError::Complete { source } => source.is_retryable(),
        }
    }
}

pub async fn complete_on_loopback<E: crate::Error + 'static>(
    listener: &TcpListener,
    callback_state: &CallbackState,
    complete: impl AsyncFnOnce(CompleteInput) -> Result<TokenResponse, E>,
) -> Result<TokenResponse, LoopbackError<E>> {
    let redirect_uri: Url = callback_state
        .redirect_uri
        .parse()
        .context(InvalidRedirectUriSnafu)?;

    loop {
        let (mut stream, _) = listener.accept().await.context(AcceptSnafu)?;
        // Parse the HTTP request
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .await
            .context(ReadRequestSnafu)?;

        // Drain remaining headers until empty line
        let mut header_line = String::new();
        loop {
            header_line.clear();
            reader
                .read_line(&mut header_line)
                .await
                .context(ReadRequestSnafu)?;
            // Empty line (just \r\n or \n) marks end of headers
            if header_line.trim().is_empty() {
                break;
            }
        }

        // Extract the path and query parameters
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            let _ = send_error_response(&mut stream, 400, "Bad Request").await;
            continue;
        }

        let path_and_query = parts[1];

        // Check if this is our callback path
        if !path_and_query.starts_with(redirect_uri.path()) {
            let _ = send_error_response(&mut stream, 404, "Not Found").await;
            continue;
        }

        // Parse query parameters
        let complete_input = parse_callback_params::<E>(path_and_query)?;

        let result = complete(complete_input).await.context(CompleteSnafu);

        // Send response to browser based on result
        match &result {
            Ok(_) => {
                let _ = send_success_response(&mut stream).await;
            }
            Err(_) => {
                let _ = send_error_response(&mut stream, 500, "Token exchange failed").await;
            }
        }

        return result;
    }
}

fn parse_callback_params<E: crate::Error + 'static>(
    path_and_query: &str,
) -> Result<CompleteInput, LoopbackError<E>> {
    // Parse the URL to extract query parameters
    // This parse shouldn't fail since we control the format, but we handle it gracefully
    let url = Url::parse(&format!("http://localhost{}", path_and_query))
        .expect("localhost URL with path should always parse");

    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut error: Option<String> = None;
    let mut error_description: Option<String> = None;
    let mut iss: Option<String> = None;

    // Extract query parameters using the url crate
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            "error" => error = Some(value.to_string()),
            "iss" => iss = Some(value.to_string()),
            "error_description" => error_description = Some(value.to_string()),
            _ => {} // Ignore other parameters
        }
    }

    // Check for OAuth error response first
    if let Some(error) = error {
        return Err(LoopbackError::OAuthError {
            error,
            error_description,
        });
    }

    let code = code.ok_or(LoopbackError::MissingParameter { param: "code" })?;
    let state = state.ok_or(LoopbackError::MissingParameter { param: "state" })?;

    Ok(CompleteInput { code, state, iss })
}

async fn send_success_response(stream: &mut TcpStream) -> Result<(), std::io::Error> {
    let body = "<html><body><h1>Authorization Successful!</h1><p>You can close this window and return to the application.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn send_error_response(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), std::io::Error> {
    let body = format!(
        "<html><body><h1>Error {}</h1><p>{}</p></body></html>",
        status, message
    );
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        status,
        get_status_text(status),
        body.len(),
        body
    );

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn get_status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

pub async fn bind_loopback(path: &str, port: u16) -> std::io::Result<(TcpListener, String)> {
    // Try IPv4 first (more commonly supported), fall back to IPv6
    let listener = match TcpListener::bind(format!("127.0.0.1:{port}")).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind(format!("[::1]:{port}")).await?,
    };

    let addr = listener.local_addr()?;
    let redirect_uri = match addr {
        std::net::SocketAddr::V4(a) => format!("http://{}:{}{}", a.ip(), a.port(), path),
        std::net::SocketAddr::V6(a) => format!("http://[{}]:{}{}", a.ip(), a.port(), path),
    };

    Ok((listener, redirect_uri))
}
