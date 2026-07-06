use std::{fmt, time::Duration};

use axum_security_oauth2::{ConfigError, HttpClient, OAuth2Client};
use jsonwebtoken::Algorithm;
use url::Url;

#[cfg(feature = "reqwest")]
use crate::providers;
use crate::{
    client::OidcClient, error::DiscoveryError, jwks::JwksCache, metadata::ProviderMetadata,
};

impl OidcClient {
    /// A builder with manually-configured endpoints — no discovery round-trip.
    ///
    /// Set `issuer_url`, `auth_url`, `token_url`, and `jwks_url` yourself, then
    /// [`try_build`](OidcClientBuilder::try_build). The HTTP backend defaults to
    /// a reqwest client (the `reqwest` feature); override it with
    /// [`http_client`](OidcClientBuilder::http_client). Prefer
    /// [`discover`](Self::discover) when the provider publishes metadata.
    pub fn builder() -> OidcClientBuilder {
        OidcClientBuilder::new()
    }

    /// A builder auto-configured from the provider's discovery document
    /// (`{issuer_url}/.well-known/openid-configuration`), fetched over `http`.
    ///
    /// `http` accepts anything convertible into an [`HttpClient`] (e.g. a
    /// `reqwest::Client`) and is reused for token and JWKS requests, so the
    /// whole flow shares one connection pool.
    pub async fn discover(
        issuer_url: &str,
        http: impl Into<HttpClient>,
    ) -> Result<OidcClientBuilder, DiscoveryError> {
        let http = http.into();
        let metadata = ProviderMetadata::discover(issuer_url, &http).await?;
        Ok(OidcClientBuilder::from_metadata(metadata, http))
    }

    /// A builder discovered from Google's issuer, over a default reqwest client.
    #[cfg(feature = "reqwest")]
    pub async fn google() -> Result<OidcClientBuilder, DiscoveryError> {
        Self::discover(providers::google::ISSUER_URL, HttpClient::default_reqwest()).await
    }

    /// A builder discovered from Microsoft's multi-tenant (`common`) issuer.
    #[cfg(feature = "reqwest")]
    pub async fn microsoft() -> Result<OidcClientBuilder, DiscoveryError> {
        Self::discover(
            providers::microsoft::ISSUER_URL_COMMON,
            HttpClient::default_reqwest(),
        )
        .await
    }

    /// A builder discovered from Apple's issuer.
    #[cfg(feature = "reqwest")]
    pub async fn apple() -> Result<OidcClientBuilder, DiscoveryError> {
        Self::discover(providers::apple::ISSUER_URL, HttpClient::default_reqwest()).await
    }

    /// A builder discovered from a Keycloak realm at `{base_url}/realms/{realm}`.
    #[cfg(feature = "reqwest")]
    pub async fn keycloak(
        base_url: &str,
        realm: &str,
    ) -> Result<OidcClientBuilder, DiscoveryError> {
        let issuer_url = format!("{}/realms/{}", base_url.trim_end_matches('/'), realm);
        Self::discover(&issuer_url, HttpClient::default_reqwest()).await
    }
}

/// Builds an [`OidcClient`]. Created with [`OidcClient::builder`],
/// [`OidcClient::discover`], or a provider shortcut.
///
/// `client_id` and `redirect_url` are always required; the endpoints
/// (`issuer_url`, `auth_url`, `token_url`, `jwks_url`) are filled by discovery
/// or set manually. [`openid`] is added to the scopes automatically.
///
/// [`openid`]: https://openid.net/specs/openid-connect-core-1_0.html
pub struct OidcClientBuilder {
    issuer: Option<String>,
    auth_url: Option<String>,
    token_url: Option<String>,
    jwks_url: Option<String>,
    end_session_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    redirect_url: Option<String>,
    scopes: Vec<String>,
    algorithms: Option<Vec<Algorithm>>,
    min_refetch_interval: Option<Duration>,
    http: Option<HttpClient>,
}

impl OidcClientBuilder {
    fn new() -> Self {
        Self {
            issuer: None,
            auth_url: None,
            token_url: None,
            jwks_url: None,
            end_session_endpoint: None,
            client_id: None,
            client_secret: None,
            redirect_url: None,
            scopes: Vec::new(),
            algorithms: None,
            min_refetch_interval: None,
            http: None,
        }
    }

    fn from_metadata(metadata: ProviderMetadata, http: HttpClient) -> Self {
        let mut builder = Self::new();
        builder.http = Some(http);
        builder.issuer = Some(metadata.issuer);
        builder.auth_url = Some(metadata.authorization_endpoint);
        builder.token_url = Some(metadata.token_endpoint);
        builder.jwks_url = Some(metadata.jwks_uri);
        builder.end_session_endpoint = metadata.end_session_endpoint;
        builder
    }

    /// The OAuth2 client id. Required.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// The OAuth2 client secret. When set, token requests authenticate via
    /// HTTP Basic (RFC 6749 §2.3.1).
    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    /// The redirect URL sent on both legs of the flow. Required.
    pub fn redirect_url(mut self, redirect_url: impl Into<String>) -> Self {
        self.redirect_url = Some(redirect_url.into());
        self
    }

    /// The scopes requested on every login. `openid` is added automatically.
    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|scope| scope.to_string()).collect();
        self
    }

    /// The issuer identifier (`iss`), also used as the discovery prefix. Filled
    /// by [`discover`](OidcClient::discover); set it for the manual path.
    pub fn issuer_url(mut self, issuer_url: impl Into<String>) -> Self {
        self.issuer = Some(issuer_url.into());
        self
    }

    /// The authorization endpoint. Filled by discovery.
    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    /// The token endpoint. Filled by discovery.
    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(token_url.into());
        self
    }

    /// The JWK Set URL. Filled by discovery.
    pub fn jwks_url(mut self, jwks_url: impl Into<String>) -> Self {
        self.jwks_url = Some(jwks_url.into());
        self
    }

    /// The RP-initiated logout endpoint. Filled by discovery when advertised.
    pub fn end_session_url(mut self, end_session_url: impl Into<String>) -> Self {
        self.end_session_endpoint = Some(end_session_url.into());
        self
    }

    /// Restrict the accepted ID-token signing algorithms. Defaults to the
    /// asymmetric allow-list (RS/PS 256-512, ES256, ES384, EdDSA).
    pub fn algorithms(mut self, algorithms: &[Algorithm]) -> Self {
        self.algorithms = Some(algorithms.to_vec());
        self
    }

    /// The minimum interval between rotation-triggered JWKS refetches (see
    /// [`JwksCache::min_refetch_interval`]). Defaults to 60 seconds.
    pub fn min_refetch_interval(mut self, interval: Duration) -> Self {
        self.min_refetch_interval = Some(interval);
        self
    }

    /// The HTTP backend for token, JWKS, and discovery requests. Accepts
    /// anything convertible into an [`HttpClient`] (e.g. a `reqwest::Client`).
    /// Defaults to a reqwest client (the `reqwest` feature); the whole flow
    /// shares one pool.
    pub fn http_client(mut self, http: impl Into<HttpClient>) -> Self {
        self.http = Some(http.into());
        self
    }

    /// Build the client, panicking on invalid configuration. Use
    /// [`try_build`](Self::try_build) to handle the error.
    pub fn build(self) -> OidcClient {
        self.try_build().unwrap()
    }

    /// Validate the configuration and build the client.
    pub fn try_build(mut self) -> Result<OidcClient, OidcBuilderError> {
        let client_id = self.client_id.ok_or(OidcBuilderError::MissingClientId)?;
        let issuer = self.issuer.ok_or(OidcBuilderError::MissingIssuerUrl)?;
        let auth_url = self.auth_url.ok_or(OidcBuilderError::MissingAuthUrl)?;
        let token_url = self.token_url.ok_or(OidcBuilderError::MissingTokenUrl)?;
        let jwks_url = self.jwks_url.ok_or(OidcBuilderError::MissingJwksUrl)?;
        let jwks_url = Url::parse(&jwks_url).map_err(OidcBuilderError::InvalidJwksUrl)?;
        let redirect_url = self
            .redirect_url
            .ok_or(OidcBuilderError::MissingRedirectUrl)?;

        // OpenID Connect requires the `openid` scope.
        if !self.scopes.iter().any(|scope| scope == "openid") {
            self.scopes.insert(0, "openid".to_string());
        }
        let scope_refs: Vec<&str> = self.scopes.iter().map(String::as_str).collect();

        // Resolve the HTTP backend once and share it between the token exchange
        // (OAuth2 client) and the JWKS fetch, so they reuse one connection pool.
        let http = self.http;
        #[cfg(feature = "reqwest")]
        let http = http.or_else(|| Some(HttpClient::default_reqwest()));
        let http = http.ok_or(OidcBuilderError::NoHttpClient)?;

        let mut oauth2 = OAuth2Client::builder()
            .client_id(client_id.clone())
            .auth_url(auth_url)
            .token_url(token_url)
            .redirect_url(redirect_url)
            .scopes(&scope_refs)
            .http_client(http.clone());
        if let Some(client_secret) = self.client_secret {
            oauth2.set_client_secret(client_secret);
        }
        let oauth2 = oauth2.try_build().map_err(OidcBuilderError::OAuth2)?;

        let mut verifier = JwksCache::new(issuer, client_id, jwks_url, http);
        if let Some(algorithms) = &self.algorithms {
            verifier = verifier.algorithms(algorithms);
        }
        if let Some(interval) = self.min_refetch_interval {
            verifier = verifier.min_refetch_interval(interval);
        }

        let end_session_endpoint = self
            .end_session_endpoint
            .map(|url| Url::parse(&url))
            .transpose()
            .map_err(OidcBuilderError::InvalidEndSessionUrl)?;

        Ok(OidcClient::from_parts(
            oauth2,
            verifier,
            end_session_endpoint,
        ))
    }
}

/// Errors from [`OidcClientBuilder::try_build`].
#[derive(Debug)]
#[non_exhaustive]
pub enum OidcBuilderError {
    MissingClientId,
    MissingRedirectUrl,
    MissingIssuerUrl,
    MissingAuthUrl,
    MissingTokenUrl,
    MissingJwksUrl,
    InvalidJwksUrl(url::ParseError),
    InvalidEndSessionUrl(url::ParseError),
    /// No HTTP backend was configured and the `reqwest` feature is disabled.
    NoHttpClient,
    /// The underlying OAuth2 client could not be built.
    OAuth2(ConfigError),
}

impl fmt::Display for OidcBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcBuilderError::MissingClientId => f.write_str("client id is missing"),
            OidcBuilderError::MissingRedirectUrl => f.write_str("redirect url is missing"),
            OidcBuilderError::MissingIssuerUrl => f.write_str("issuer url is missing"),
            OidcBuilderError::MissingAuthUrl => f.write_str("authorization url is missing"),
            OidcBuilderError::MissingTokenUrl => f.write_str("token url is missing"),
            OidcBuilderError::MissingJwksUrl => f.write_str("JWKS url is missing"),
            OidcBuilderError::InvalidJwksUrl(e) => write!(f, "could not parse JWKS url: {e}"),
            OidcBuilderError::InvalidEndSessionUrl(e) => {
                write!(f, "could not parse end-session url: {e}")
            }
            OidcBuilderError::NoHttpClient => f.write_str(
                "no HTTP client configured; enable the `reqwest` feature or call `http_client`",
            ),
            OidcBuilderError::OAuth2(e) => write!(f, "could not build the OAuth2 client: {e}"),
        }
    }
}

impl std::error::Error for OidcBuilderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            OidcBuilderError::InvalidJwksUrl(e) | OidcBuilderError::InvalidEndSessionUrl(e) => {
                Some(e)
            }
            OidcBuilderError::OAuth2(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use super::*;

    const ISSUER: &str = "https://issuer.example";
    const AUTH: &str = "https://issuer.example/auth";
    const TOKEN: &str = "https://issuer.example/token";
    const JWKS: &str = "https://issuer.example/jwks";
    const REDIRECT: &str = "https://app.example/callback";

    fn manual() -> OidcClientBuilder {
        OidcClient::builder()
            .issuer_url(ISSUER)
            .auth_url(AUTH)
            .token_url(TOKEN)
            .jwks_url(JWKS)
            .redirect_url(REDIRECT)
    }

    #[test]
    fn builds_with_manual_endpoints() {
        let client = manual().client_id("id").scopes(&["email"]).build();
        assert_eq!(client.client_id(), "id");
        // `openid` is forced in, ahead of the requested scopes.
        assert_eq!(client.scopes(), ["openid", "email"]);
    }

    #[test]
    fn openid_scope_not_duplicated() {
        let client = manual()
            .client_id("id")
            .scopes(&["openid", "email"])
            .build();
        assert_eq!(client.scopes(), ["openid", "email"]);
    }

    #[test]
    fn missing_client_id() {
        let result = manual().try_build();
        assert!(matches!(result, Err(OidcBuilderError::MissingClientId)));
    }

    #[test]
    fn missing_jwks_url() {
        let result = OidcClient::builder()
            .client_id("id")
            .issuer_url(ISSUER)
            .auth_url(AUTH)
            .token_url(TOKEN)
            .redirect_url(REDIRECT)
            .try_build();
        assert!(matches!(result, Err(OidcBuilderError::MissingJwksUrl)));
    }

    #[test]
    fn invalid_jwks_url() {
        let result = manual().jwks_url("not a url").client_id("id").try_build();
        assert!(matches!(result, Err(OidcBuilderError::InvalidJwksUrl(_))));
    }

    #[test]
    fn builds_without_discovery_or_explicit_http() {
        // `builder()` takes no HTTP client: the manual path defaults to reqwest.
        let client = manual().client_id("id").build();
        assert_eq!(client.client_id(), "id");
    }
}
