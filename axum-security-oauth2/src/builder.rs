use std::{error::Error as StdError, fmt};

use url::Url;

use crate::{client::OAuth2Client, http::HttpClient, secret::ClientSecret};

/// Builds an [`OAuth2Client`]. Created with
/// [`OAuth2Client::builder()`](OAuth2Client::builder).
///
/// Only `client_id` is required; endpoints stay optional and calls that
/// need a missing one fail with
/// [`Error::MissingEndpoint`](crate::Error::MissingEndpoint).
pub struct OAuth2ClientBuilder {
    client_id: Option<String>,
    client_secret: Option<ClientSecret>,
    auth_url: Option<String>,
    token_url: Option<String>,
    redirect_url: Option<String>,
    scopes: Vec<String>,
    pkce: bool,
    http: Option<HttpClient>,
}

impl OAuth2ClientBuilder {
    pub(crate) fn new() -> Self {
        Self {
            client_id: None,
            client_secret: None,
            auth_url: None,
            token_url: None,
            redirect_url: None,
            scopes: Vec::new(),
            pkce: true,
            http: None,
        }
    }

    /// The OAuth2 client id. Required.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// The OAuth2 client secret. When set, token requests authenticate via
    /// HTTP Basic (RFC 6749 §2.3.1); without it the `client_id` is sent in
    /// the request body.
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(ClientSecret::new(client_secret));
        self
    }

    /// The authorization endpoint, parsed in [`build`](Self::build).
    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    /// The token endpoint, parsed in [`build`](Self::build).
    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(token_url.into());
        self
    }

    /// The redirect URL sent on both legs of the flow, parsed in
    /// [`build`](Self::build).
    pub fn redirect_url(mut self, redirect_url: impl Into<String>) -> Self {
        self.redirect_url = Some(redirect_url.into());
        self
    }

    /// The scopes requested on every login. Replaces any previously set
    /// scopes; the default is none.
    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|scope| scope.to_string()).collect();
        self
    }

    /// Enables PKCE (the default).
    pub fn pkce(self) -> Self {
        self.set_pkce(true)
    }

    /// Enables or disables PKCE.
    pub fn set_pkce(mut self, pkce: bool) -> Self {
        self.pkce = pkce;
        self
    }

    /// The HTTP backend for token requests. Defaults to a reqwest client
    /// that never follows redirects and times out after 10 seconds (when
    /// the `reqwest` feature is enabled).
    // Without a backend feature `HttpClient` is uninhabited and this
    // method cannot be reached.
    #[cfg_attr(not(feature = "reqwest"), allow(unreachable_code, unused_mut))]
    pub fn http_client(mut self, http_client: impl Into<HttpClient>) -> Self {
        self.http = Some(http_client.into());
        self
    }

    /// Validates the configuration and builds the client.
    ///
    /// Panics on invalid configuration; use [`try_build`](Self::try_build)
    /// to handle the error instead.
    pub fn build(self) -> OAuth2Client {
        self.try_build().unwrap()
    }

    /// Validates the configuration and builds the client.
    pub fn try_build(self) -> Result<OAuth2Client, ConfigError> {
        let client_id = self.client_id.ok_or(ConfigError::MissingClientId)?;

        let auth_url = self
            .auth_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(ConfigError::InvalidAuthUrl)?;

        let token_url = self
            .token_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(ConfigError::InvalidTokenUrl)?;

        let redirect_url = self
            .redirect_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(ConfigError::InvalidRedirectUrl)?;

        let http = self.http;
        #[cfg(feature = "reqwest")]
        let http = http.or_else(|| {
            Some(HttpClient::Reqwest(
                crate::http::dep_reqwest::default_client(),
            ))
        });

        Ok(OAuth2Client {
            client_id,
            client_secret: self.client_secret,
            auth_url,
            token_url,
            redirect_url,
            scopes: self.scopes,
            pkce: self.pkce,
            http,
        })
    }
}

/// Errors from [`OAuth2ClientBuilder::try_build`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    MissingClientId,
    InvalidAuthUrl(url::ParseError),
    InvalidTokenUrl(url::ParseError),
    InvalidRedirectUrl(url::ParseError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingClientId => f.write_str("client id is missing"),
            ConfigError::InvalidAuthUrl(parse_error) => {
                write!(f, "could not parse authorization url: {parse_error}")
            }
            ConfigError::InvalidTokenUrl(parse_error) => {
                write!(f, "could not parse token url: {parse_error}")
            }
            ConfigError::InvalidRedirectUrl(parse_error) => {
                write!(f, "could not parse redirect url: {parse_error}")
            }
        }
    }
}

impl StdError for ConfigError {}
