use std::{error::Error as StdError, fmt};

use serde::Deserialize;
use serde_json::{Map, Value};

/// Errors returned by [`OAuth2Client`](crate::OAuth2Client) calls.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The call needs an endpoint URL that was never configured on the
    /// builder.
    MissingEndpoint(Endpoint),
    /// The call needs to perform I/O but no HTTP client is configured
    /// (enable a backend feature such as `reqwest`, or set one with
    /// [`http_client`](crate::OAuth2ClientBuilder::http_client)).
    NoHttpClient,
    /// PKCE is enabled on the client but no verifier was passed to
    /// [`finish_login`](crate::OAuth2Client::finish_login).
    MissingPkceVerifier,
    /// The HTTP request itself failed (connect, TLS, timeout, ...).
    Http(HttpError),
    /// The server answered with a well-formed OAuth2 error body
    /// (RFC 6749 §5.2).
    Server(ServerError),
    /// The server response could not be parsed.
    Parse(ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingEndpoint(endpoint) => {
                write!(f, "no {endpoint} endpoint configured")
            }
            Error::NoHttpClient => f.write_str(
                "no HTTP client configured (enable a backend feature such as `reqwest`, or set one on the builder)",
            ),
            Error::MissingPkceVerifier => {
                f.write_str("PKCE is enabled but no verifier was passed to finish_login")
            }
            Error::Http(error) => error.fmt(f),
            Error::Server(error) => error.fmt(f),
            Error::Parse(error) => error.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Http(error) => Some(error),
            Error::Server(error) => Some(error),
            Error::Parse(error) => Some(error),
            _ => None,
        }
    }
}

/// The endpoint a call was missing, see [`Error::MissingEndpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Endpoint {
    Auth,
    Token,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Auth => f.write_str("authorization"),
            Endpoint::Token => f.write_str("token"),
        }
    }
}

/// A transport-level failure; [`source`](StdError::source) returns the
/// backend's error.
#[derive(Debug)]
pub struct HttpError(pub(crate) HttpErrorKind);

#[derive(Debug)]
pub(crate) enum HttpErrorKind {
    #[cfg(feature = "reqwest")]
    Reqwest(reqwest::Error),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        match self.0 {
            #[cfg(feature = "reqwest")]
            HttpErrorKind::Reqwest(ref error) => write!(f, "http request failed: {error}"),
        }
    }
}

impl StdError for HttpError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.0 {
            #[cfg(feature = "reqwest")]
            HttpErrorKind::Reqwest(ref error) => Some(error),
        }
    }
}

/// A well-formed OAuth2 error body from the server (RFC 6749 §5.2), plus
/// the HTTP status it arrived with.
#[derive(Debug)]
pub struct ServerError {
    code: ErrorCode,
    description: Option<String>,
    uri: Option<String>,
    status: u16,
    extra: Map<String, Value>,
}

impl ServerError {
    /// The `error` code from the response body.
    pub fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The optional human-readable `error_description`.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The optional `error_uri` pointing at documentation.
    pub fn uri(&self) -> Option<&str> {
        self.uri.as_deref()
    }

    /// The HTTP status code of the response.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Deserializes a single unrecognized field of the error body.
    pub fn extra_field<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        let value = self.extra.get(key)?;
        serde_json::from_value(value.clone()).ok()
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "server returned error \"{}\" (status {})",
            self.code, self.status
        )?;
        if let Some(description) = &self.description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}

impl StdError for ServerError {}

/// The `error` code of an RFC 6749 §5.2 error body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    /// An extension / nonstandard error code.
    Other(String),
}

impl ErrorCode {
    /// The error code as it appeared on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InvalidClient => "invalid_client",
            ErrorCode::InvalidGrant => "invalid_grant",
            ErrorCode::UnauthorizedClient => "unauthorized_client",
            ErrorCode::UnsupportedGrantType => "unsupported_grant_type",
            ErrorCode::InvalidScope => "invalid_scope",
            ErrorCode::Other(code) => code,
        }
    }

    fn from_wire(code: String) -> Self {
        match code.as_str() {
            "invalid_request" => ErrorCode::InvalidRequest,
            "invalid_client" => ErrorCode::InvalidClient,
            "invalid_grant" => ErrorCode::InvalidGrant,
            "unauthorized_client" => ErrorCode::UnauthorizedClient,
            "unsupported_grant_type" => ErrorCode::UnsupportedGrantType,
            "invalid_scope" => ErrorCode::InvalidScope,
            _ => ErrorCode::Other(code),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The wire shape of an RFC 6749 §5.2 error body.
#[derive(Deserialize)]
pub(crate) struct ServerErrorWire {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    error_uri: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl ServerErrorWire {
    pub(crate) fn into_server_error(self, status: u16) -> ServerError {
        ServerError {
            code: ErrorCode::from_wire(self.error),
            description: self.error_description,
            uri: self.error_uri,
            status,
            extra: self.extra,
        }
    }
}

/// A response body that could not be parsed.
///
/// The raw body is retained for diagnostics but deliberately kept out of
/// `Debug` and `Display` — a failed *success* parse can contain live
/// tokens. Reading it requires the explicit [`body`](ParseError::body)
/// accessor.
pub struct ParseError {
    pub(crate) url: String,
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) body: Vec<u8>,
    pub(crate) source: serde_json::Error,
}

impl ParseError {
    /// The endpoint URL the response came from.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The HTTP status code of the response.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The `Content-Type` of the response, if any.
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// The raw response body. May contain secrets — handle with care.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParseError")
            .field("url", &self.url)
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field(
                "body",
                &format_args!("[redacted, {} bytes]", self.body.len()),
            )
            .field("source", &self.source)
            .finish()
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "could not parse response from \"{}\" (status {}, content-type {}, {} bytes): {}",
            self.url,
            self.status,
            self.content_type.as_deref().unwrap_or("unknown"),
            self.body.len(),
            self.source
        )
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}
