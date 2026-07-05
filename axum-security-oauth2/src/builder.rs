use std::{error::Error as StdError, fmt};

use url::Url;

use crate::{
    client::{AuthType, OAuth2Client},
    http::HttpClient,
};

/// Builds an [`OAuth2Client`]. Created with
/// [`OAuth2Client::builder()`](OAuth2Client::builder) or a provider
/// shortcut ([`OAuth2Client::github()`](OAuth2Client::github),
/// [`google()`](OAuth2Client::google), ...) that presets the endpoints.
///
/// `client_id`, `auth_url` and `token_url` are required; the rest is
/// optional. [`try_build`](Self::try_build) validates everything up
/// front, so the client's methods never fail on configuration.
pub struct OAuth2ClientBuilder {
    client_id: Option<String>,
    client_secret: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    redirect_url: Option<String>,
    introspection_url: Option<String>,
    revocation_url: Option<String>,
    scopes: Vec<String>,
    auth_type: AuthType,
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
            introspection_url: None,
            revocation_url: None,
            scopes: Vec::new(),
            auth_type: AuthType::default(),
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
        self.client_secret = Some(client_secret.into());
        self
    }

    /// The authorization endpoint, parsed in [`build`](Self::build).
    /// Required.
    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    /// The token endpoint, parsed in [`build`](Self::build). Required.
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

    /// The token introspection endpoint (RFC 7662), parsed in
    /// [`build`](Self::build). Optional — required only to call
    /// [`introspect`](crate::OAuth2Client::introspect).
    pub fn introspection_url(mut self, introspection_url: impl Into<String>) -> Self {
        self.introspection_url = Some(introspection_url.into());
        self
    }

    /// The token revocation endpoint (RFC 7009), parsed in
    /// [`build`](Self::build). Optional — required only to call
    /// [`revoke`](crate::OAuth2Client::revoke).
    pub fn revocation_url(mut self, revocation_url: impl Into<String>) -> Self {
        self.revocation_url = Some(revocation_url.into());
        self
    }

    /// The scopes requested on every login. Replaces any previously set
    /// scopes; the default is none.
    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|scope| scope.to_string()).collect();
        self
    }

    /// Authenticate to the token endpoint with HTTP Basic (RFC 6749
    /// §2.3.1). This is the default; call this only to undo a prior
    /// [`request_body`](Self::request_body).
    pub fn basic_auth(mut self) -> Self {
        self.auth_type = AuthType::BasicAuth;
        self
    }

    /// Send `client_id` and `client_secret` in the request body instead of
    /// an HTTP Basic header, for providers that don't support Basic.
    pub fn request_body(mut self) -> Self {
        self.auth_type = AuthType::RequestBody;
        self
    }

    /// The HTTP backend for token requests. Defaults to a reqwest client
    /// that never follows redirects and times out after 10 seconds (when
    /// the `reqwest` feature is enabled); without any backend feature,
    /// [`try_build`](Self::try_build) fails with
    /// [`ConfigError::NoHttpClient`].
    // Without a backend feature `HttpClient` is uninhabited and this
    // method cannot be reached.
    #[cfg_attr(not(feature = "reqwest"), allow(unreachable_code, unused_mut))]
    pub fn http_client(mut self, http_client: impl Into<HttpClient>) -> Self {
        self.http = Some(http_client.into());
        self
    }

    /// Sets the client id in place. See [`client_id`](Self::client_id).
    pub fn set_client_id(&mut self, client_id: impl Into<String>) {
        self.client_id = Some(client_id.into());
    }

    /// Sets the client secret in place. See
    /// [`client_secret`](Self::client_secret).
    pub fn set_client_secret(&mut self, client_secret: impl Into<String>) {
        self.client_secret = Some(client_secret.into());
    }

    /// Sets the authorization endpoint in place. See
    /// [`auth_url`](Self::auth_url).
    pub fn set_auth_url(&mut self, auth_url: impl Into<String>) {
        self.auth_url = Some(auth_url.into());
    }

    /// Sets the token endpoint in place. See [`token_url`](Self::token_url).
    pub fn set_token_url(&mut self, token_url: impl Into<String>) {
        self.token_url = Some(token_url.into());
    }

    /// Sets the redirect URL in place. See
    /// [`redirect_url`](Self::redirect_url).
    pub fn set_redirect_url(&mut self, redirect_url: impl Into<String>) {
        self.redirect_url = Some(redirect_url.into());
    }

    /// Sets the introspection endpoint in place. See
    /// [`introspection_url`](Self::introspection_url).
    pub fn set_introspection_url(&mut self, introspection_url: impl Into<String>) {
        self.introspection_url = Some(introspection_url.into());
    }

    /// Sets the revocation endpoint in place. See
    /// [`revocation_url`](Self::revocation_url).
    pub fn set_revocation_url(&mut self, revocation_url: impl Into<String>) {
        self.revocation_url = Some(revocation_url.into());
    }

    /// Sets the requested scopes in place. See [`scopes`](Self::scopes).
    pub fn set_scopes(&mut self, scopes: &[&str]) {
        self.scopes = scopes.iter().map(|scope| scope.to_string()).collect();
    }

    /// Sets the HTTP backend in place. See
    /// [`http_client`](Self::http_client).
    #[cfg_attr(not(feature = "reqwest"), allow(unreachable_code))]
    pub fn set_http_client(&mut self, http_client: impl Into<HttpClient>) {
        self.http = Some(http_client.into());
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

        let auth_url = Url::parse(&self.auth_url.ok_or(ConfigError::MissingAuthUrl)?)
            .map_err(ConfigError::InvalidAuthUrl)?;

        let token_url = Url::parse(&self.token_url.ok_or(ConfigError::MissingTokenUrl)?)
            .map_err(ConfigError::InvalidTokenUrl)?;

        let redirect_url = self
            .redirect_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(ConfigError::InvalidRedirectUrl)?;

        let introspection_url = self
            .introspection_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(ConfigError::InvalidIntrospectionUrl)?;

        let revocation_url = self
            .revocation_url
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(ConfigError::InvalidRevocationUrl)?;

        let http = self.http;
        #[cfg(feature = "reqwest")]
        let http = http.or_else(|| {
            Some(HttpClient::Reqwest(
                crate::http::dep_reqwest::default_client(),
            ))
        });
        let http = http.ok_or(ConfigError::NoHttpClient)?;

        Ok(OAuth2Client {
            client_id,
            client_secret: self.client_secret,
            auth_url,
            token_url,
            redirect_url,
            introspection_url,
            revocation_url,
            scopes: self.scopes,
            auth_type: self.auth_type,
            http,
        })
    }
}

/// Errors from [`OAuth2ClientBuilder::try_build`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfigError {
    MissingClientId,
    MissingAuthUrl,
    MissingTokenUrl,
    InvalidAuthUrl(url::ParseError),
    InvalidTokenUrl(url::ParseError),
    InvalidRedirectUrl(url::ParseError),
    InvalidIntrospectionUrl(url::ParseError),
    InvalidRevocationUrl(url::ParseError),
    /// No backend feature (such as `reqwest`) is enabled and no client was
    /// set with [`http_client`](OAuth2ClientBuilder::http_client).
    NoHttpClient,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingClientId => f.write_str("client id is missing"),
            ConfigError::MissingAuthUrl => f.write_str("authorization url is missing"),
            ConfigError::MissingTokenUrl => f.write_str("token url is missing"),
            ConfigError::InvalidAuthUrl(parse_error) => {
                write!(f, "could not parse authorization url: {parse_error}")
            }
            ConfigError::InvalidTokenUrl(parse_error) => {
                write!(f, "could not parse token url: {parse_error}")
            }
            ConfigError::InvalidRedirectUrl(parse_error) => {
                write!(f, "could not parse redirect url: {parse_error}")
            }
            ConfigError::InvalidIntrospectionUrl(parse_error) => {
                write!(f, "could not parse introspection url: {parse_error}")
            }
            ConfigError::InvalidRevocationUrl(parse_error) => {
                write!(f, "could not parse revocation url: {parse_error}")
            }
            ConfigError::NoHttpClient => f.write_str(
                "no HTTP client available (enable a backend feature such as `reqwest`, or set one with `http_client`)",
            ),
        }
    }
}

impl StdError for ConfigError {}

// Without a backend feature there is no default HTTP client and no way to
// provide one, so building must fail.
#[cfg(all(test, not(feature = "reqwest")))]
mod tests {
    use super::*;

    #[test]
    fn no_backend_is_a_config_error() {
        let result = OAuth2ClientBuilder::new()
            .client_id("id")
            .auth_url("https://provider.example/authorize")
            .token_url("https://provider.example/token")
            .try_build();
        assert!(matches!(result, Err(ConfigError::NoHttpClient)));
    }
}
