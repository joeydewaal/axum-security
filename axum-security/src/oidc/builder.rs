use std::{borrow::Cow, error::Error, fmt::Display, sync::Arc, time::Duration};

use axum_security_oidc::{
    ConfigError, DiscoveryError, HttpClient, OidcBuilderError as CrateBuilderError, OidcClient,
    OidcClientBuilder,
};
use cookie_monster::CookieBuilder;

use crate::utils::get_env;

use super::{OidcContext, OidcHandler, context::OidcContextInner, cookie::OidcCookieBuilder};

/// Builder for an [`OidcContext`]. Wraps the `axum-security-oidc`
/// [`OidcClientBuilder`] with axum-security's signed-cookie and route config.
pub struct OidcContextBuilder {
    cookie_builder: OidcCookieBuilder,
    login_path: Option<Cow<'static, str>>,
    logout_path: Option<Cow<'static, str>>,
    post_logout_redirect_url: Option<String>,
    client: OidcClientBuilder,
}

impl OidcContextBuilder {
    pub fn new(provider_name: Cow<'static, str>) -> Self {
        Self {
            cookie_builder: OidcCookieBuilder::new(provider_name),
            login_path: None,
            logout_path: None,
            post_logout_redirect_url: None,
            client: OidcClient::builder(),
        }
    }

    pub(crate) async fn discover(
        provider_name: Cow<'static, str>,
        issuer_url: &str,
    ) -> Result<Self, OidcBuilderError> {
        let client = OidcClient::discover(issuer_url, HttpClient::default_reqwest())
            .await
            .map_err(|e| OidcBuilderError::DiscoveryError(e.to_string()))?;

        Ok(Self {
            cookie_builder: OidcCookieBuilder::new(provider_name),
            login_path: None,
            logout_path: None,
            post_logout_redirect_url: None,
            client,
        })
    }

    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.client = self.client.redirect_url(url);
        self
    }

    pub fn redirect_uri_env(self, name: &str) -> Self {
        self.redirect_url(get_env(name))
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client = self.client.client_id(client_id);
        self
    }

    pub fn client_id_env(self, name: &str) -> Self {
        self.client_id(get_env(name))
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client = self.client.client_secret(client_secret);
        self
    }

    pub fn client_secret_env(self, name: &str) -> Self {
        self.client_secret(get_env(name))
    }

    pub fn issuer_url(mut self, url: impl Into<String>) -> Self {
        self.client = self.client.issuer_url(url);
        self
    }

    pub fn auth_url(mut self, url: impl Into<String>) -> Self {
        self.client = self.client.auth_url(url);
        self
    }

    pub fn token_url(mut self, url: impl Into<String>) -> Self {
        self.client = self.client.token_url(url);
        self
    }

    pub fn jwks_url(mut self, url: impl Into<String>) -> Self {
        self.client = self.client.jwks_url(url);
        self
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.client = self.client.scopes(scopes);
        self
    }

    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_builder.cookie_builder.apply_cookie(f);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_builder.cookie_builder.apply_dev_cookie(f);
        self
    }

    pub fn login_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.login_path = Some(path.into());
        self
    }

    pub fn logout_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.logout_path = Some(path.into());
        self
    }

    pub fn post_logout_redirect_url(mut self, url: impl Into<String>) -> Self {
        self.post_logout_redirect_url = Some(url.into());
        self
    }

    pub fn end_session_url(mut self, url: impl Into<String>) -> Self {
        self.client = self.client.end_session_url(url);
        self
    }

    pub fn use_dev_cookies(mut self, dev: bool) -> Self {
        self.cookie_builder.cookie_builder.dev = dev;
        self
    }

    pub fn http_client(mut self, http_client: HttpClient) -> Self {
        self.client = self.client.http_client(http_client);
        self
    }

    /// Minimum interval between JWKS refetch attempts on the manual
    /// (hard-coded endpoint) path.
    ///
    /// An ID token with an unknown signing key (key rotation) triggers a JWKS
    /// refetch, at most one attempt per this interval. Defaults to 60 seconds.
    pub fn jwks_min_refetch_interval(mut self, interval: Duration) -> Self {
        self.client = self.client.min_refetch_interval(interval);
        self
    }

    pub fn cookie_secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.cookie_builder.secret = Some(secret.as_ref().to_vec());
        self
    }

    pub fn max_login_duration(mut self, duration: Duration) -> Self {
        self.cookie_builder
            .set_max_login_duration_secs(duration.as_secs());
        self
    }

    pub fn max_login_duration_minutes(self, minutes: u64) -> Self {
        self.max_login_duration(Duration::from_mins(minutes))
    }

    pub fn build<T>(self, handler: T) -> OidcContext<T>
    where
        T: OidcHandler,
    {
        self.try_build(handler).unwrap()
    }

    pub fn try_build<T>(self, handler: T) -> Result<OidcContext<T>, OidcBuilderError>
    where
        T: OidcHandler,
    {
        // Build the OIDC client first (client-config errors), then the signed
        // cookie (provider-name errors) — matching the old ordering.
        let client = self.client.try_build().map_err(OidcBuilderError::from)?;
        let session = self.cookie_builder.try_build()?;

        Ok(OidcContext(Arc::new(OidcContextInner {
            client,
            handler,
            session,
            login_path: self.login_path,
            logout_path: self.logout_path,
            post_logout_redirect_url: self.post_logout_redirect_url,
        })))
    }
}

#[derive(Debug)]
pub enum OidcBuilderError {
    MissingClientId,
    MissingRedirectUrl,
    MissingAuthUrl,
    MissingTokenUrl,
    MissingIssuerUrl,
    MissingJwksUrl,
    InvalidRedirectUrl(url::ParseError),
    InvalidAuthUrl(url::ParseError),
    InvalidTokenUrl(url::ParseError),
    InvalidJwksUrl(url::ParseError),
    InvalidEndSessionUrl(url::ParseError),
    WhitespaceInProviderName,
    DiscoveryError(String),
    /// Another OAuth2 client configuration error.
    Config(String),
}

impl From<CrateBuilderError> for OidcBuilderError {
    fn from(error: CrateBuilderError) -> Self {
        match error {
            CrateBuilderError::MissingClientId => Self::MissingClientId,
            CrateBuilderError::MissingRedirectUrl => Self::MissingRedirectUrl,
            CrateBuilderError::MissingIssuerUrl => Self::MissingIssuerUrl,
            CrateBuilderError::MissingAuthUrl => Self::MissingAuthUrl,
            CrateBuilderError::MissingTokenUrl => Self::MissingTokenUrl,
            CrateBuilderError::MissingJwksUrl => Self::MissingJwksUrl,
            CrateBuilderError::InvalidJwksUrl(e) => Self::InvalidJwksUrl(e),
            CrateBuilderError::InvalidEndSessionUrl(e) => Self::InvalidEndSessionUrl(e),
            CrateBuilderError::OAuth2(config) => match config {
                ConfigError::InvalidAuthUrl(e) => Self::InvalidAuthUrl(e),
                ConfigError::InvalidTokenUrl(e) => Self::InvalidTokenUrl(e),
                ConfigError::InvalidRedirectUrl(e) => Self::InvalidRedirectUrl(e),
                ConfigError::MissingClientId => Self::MissingClientId,
                ConfigError::MissingAuthUrl => Self::MissingAuthUrl,
                ConfigError::MissingTokenUrl => Self::MissingTokenUrl,
                other => Self::Config(other.to_string()),
            },
            other => Self::Config(other.to_string()),
        }
    }
}

impl From<DiscoveryError> for OidcBuilderError {
    fn from(error: DiscoveryError) -> Self {
        OidcBuilderError::DiscoveryError(error.to_string())
    }
}

impl Error for OidcBuilderError {}

impl Display for OidcBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcBuilderError::MissingClientId => f.write_str("client id is missing"),
            OidcBuilderError::MissingRedirectUrl => f.write_str("redirect url is missing"),
            OidcBuilderError::MissingAuthUrl => f.write_str("authorization url is missing"),
            OidcBuilderError::MissingTokenUrl => f.write_str("token url is missing"),
            OidcBuilderError::MissingIssuerUrl => f.write_str("issuer url is missing"),
            OidcBuilderError::MissingJwksUrl => f.write_str("JWKS url is missing"),
            OidcBuilderError::InvalidRedirectUrl(e) => {
                write!(f, "could not parse redirect url: {e}")
            }
            OidcBuilderError::InvalidAuthUrl(e) => {
                write!(f, "could not parse authorization url: {e}")
            }
            OidcBuilderError::InvalidTokenUrl(e) => write!(f, "could not parse token url: {e}"),
            OidcBuilderError::InvalidJwksUrl(e) => write!(f, "could not parse JWKS url: {e}"),
            OidcBuilderError::InvalidEndSessionUrl(e) => {
                write!(f, "could not parse end-session url: {e}")
            }
            OidcBuilderError::WhitespaceInProviderName => {
                f.write_str("provider name can't contain whitespaces")
            }
            OidcBuilderError::DiscoveryError(e) => write!(f, "OIDC discovery failed: {e}"),
            OidcBuilderError::Config(e) => write!(f, "OIDC client configuration error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        after_login::AfterLoginCookies,
        oidc::{OidcBuilderError, OidcContext, OidcHandler, OidcTokenResponse},
    };
    use axum::response::IntoResponse;

    const CLIENT_ID: &str = "test_client_id";
    const CLIENT_SECRET: &str = "test_client_secret";
    const REDIRECT_URL: &str = "http://localhost:3000/auth/callback";
    const ISSUER_URL: &str = "https://accounts.google.com";
    const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

    struct TestHandler;

    impl OidcHandler for TestHandler {
        async fn after_login(
            &self,
            _token_res: OidcTokenResponse<'_>,
            _context: &mut AfterLoginCookies<'_>,
        ) -> impl IntoResponse {
            ()
        }
    }

    #[test]
    fn builder_ok_manual() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(res.is_ok());
    }

    #[test]
    fn missing_client_id() {
        let res = OidcContext::builder("google")
            .client_secret(CLIENT_SECRET)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingClientId)));
    }

    #[test]
    fn missing_redirect_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingRedirectUrl)));
    }

    #[test]
    fn missing_issuer_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingIssuerUrl)));
    }

    #[test]
    fn missing_auth_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingAuthUrl)));
    }

    #[test]
    fn missing_token_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingTokenUrl)));
    }

    #[test]
    fn missing_jwks_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::MissingJwksUrl)));
    }

    #[test]
    fn invalid_redirect_url() {
        let res = OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url("not an url")
            .try_build(TestHandler);

        assert!(matches!(res, Err(OidcBuilderError::InvalidRedirectUrl(_))));
    }

    #[test]
    fn provider_name_whitespace() {
        let res = OidcContext::builder("google ")
            .client_id(CLIENT_ID)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler);

        assert!(matches!(
            res,
            Err(OidcBuilderError::WhitespaceInProviderName)
        ));
    }
}
