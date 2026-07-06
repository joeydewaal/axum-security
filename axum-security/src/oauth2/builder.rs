use std::{borrow::Cow, error::Error, fmt::Display, sync::Arc, time::Duration};

use axum_security_oauth2::{ConfigError, HttpClient, OAuth2Client, OAuth2ClientBuilder};
use cookie_monster::CookieBuilder;

use crate::{
    oauth2::{
        OAuth2Context, OAuth2Handler, context::OAuth2ContextInner, cookie::OAuthCookieBuilder,
    },
    utils::get_env,
};

pub struct OAuth2ContextBuilder {
    cookie_builder: OAuthCookieBuilder,
    login_path: Option<Cow<'static, str>>,
    client_builder: OAuth2ClientBuilder,
    auth_params: Vec<(String, String)>,
    flow_type: FlowType,
}

impl OAuth2ContextBuilder {
    pub fn new(oauth2_provider_name: impl Into<Cow<'static, str>>) -> OAuth2ContextBuilder {
        Self {
            cookie_builder: OAuthCookieBuilder::new(oauth2_provider_name.into()),
            login_path: None,
            client_builder: OAuth2Client::builder(),
            auth_params: Vec::new(),
            flow_type: FlowType::AuthorizationCodeFlowPkce,
        }
    }

    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.client_builder.set_redirect_url(url);
        self
    }

    pub fn redirect_uri_env(self, name: &str) -> Self {
        self.redirect_url(get_env(name))
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_builder.set_client_id(client_id);
        self
    }

    pub fn client_id_env(self, name: &str) -> Self {
        self.client_id(get_env(name))
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_builder.set_client_secret(client_secret);
        self
    }

    pub fn client_secret_env(self, name: &str) -> Self {
        self.client_secret(get_env(name))
    }

    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.client_builder.set_auth_url(auth_url);
        self
    }

    pub fn auth_url_env(self, name: &str) -> Self {
        self.auth_url(get_env(name))
    }

    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.client_builder.set_token_url(token_url);
        self
    }

    pub fn token_url_env(self, name: &str) -> Self {
        self.token_url(get_env(name))
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.client_builder.set_scopes(scopes);
        self
    }

    /// Appends an extra query parameter to every authorization redirect —
    /// provider-specific knobs like Google's `access_type=offline` +
    /// `prompt=consent` (required to receive a refresh token) or GitHub's
    /// `allow_signup=false`.
    pub fn auth_param(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth_params.push((name.into(), value.into()));
        self
    }

    /// Authenticate to the token endpoint with HTTP Basic (RFC 6749
    /// §2.3.1). This is the default; call this only to undo a prior
    /// [`request_body`](Self::request_body).
    pub fn basic_auth(mut self) -> Self {
        self.client_builder = self.client_builder.basic_auth();
        self
    }

    /// Send `client_id` and `client_secret` in the request body instead of
    /// an HTTP Basic header, for providers that don't support Basic.
    pub fn request_body(mut self) -> Self {
        self.client_builder = self.client_builder.request_body();
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

    pub fn use_dev_cookies(mut self, dev: bool) -> Self {
        self.cookie_builder.cookie_builder.dev = dev;
        self
    }

    pub fn use_normal_cookies(self, prod: bool) -> Self {
        self.use_dev_cookies(!prod)
    }

    pub fn http_client(mut self, http_client: impl Into<HttpClient>) -> Self {
        self.client_builder.set_http_client(http_client);
        self
    }

    /// Sets the secret used to sign the login state cookie.
    ///
    /// A secret is **required**: [`try_build`](Self::try_build) fails with
    /// [`OAuth2BuilderError::MissingCookieSecret`] if none is set. Use a
    /// stable secret (e.g. from the environment) so that in-flight logins
    /// survive restarts and work across instances; for local development
    /// [`random_cookie_secret`](Self::random_cookie_secret) opts into an
    /// ephemeral one.
    pub fn cookie_secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.cookie_builder.secret = Some(secret.as_ref().to_vec());
        self
    }

    /// Signs the login state cookie with a fresh random per-process secret.
    ///
    /// The secret is regenerated on every restart and differs between
    /// instances, so a login begun on one process cannot be completed on
    /// another. Only appropriate for local development or single-instance
    /// deployments; otherwise set a stable [`cookie_secret`](Self::cookie_secret).
    pub fn random_cookie_secret(mut self) -> Self {
        self.cookie_builder.use_random_secret();
        self
    }

    /// max length of the entire login flow.
    pub fn max_login_duration(mut self, duration: Duration) -> Self {
        self.cookie_builder
            .set_max_login_duration_secs(duration.as_secs());
        self
    }

    /// max length of the entire login flow.
    pub fn max_login_duration_minutes(self, minutes: u64) -> Self {
        self.max_login_duration(Duration::from_mins(minutes))
    }

    pub fn authorization_code_flow(mut self) -> Self {
        self.flow_type = FlowType::AuthorizationCodeFlow;
        self
    }

    /// The default
    pub fn authorization_code_flow_with_pkce(mut self) -> Self {
        self.flow_type = FlowType::AuthorizationCodeFlowPkce;
        self
    }

    pub fn build<T>(self, inner: T) -> OAuth2Context<T>
    where
        T: OAuth2Handler,
    {
        self.try_build(inner).unwrap()
    }

    pub fn try_build<T>(self, inner: T) -> Result<OAuth2Context<T>, OAuth2BuilderError>
    where
        T: OAuth2Handler,
    {
        let client = self.client_builder.try_build()?;

        // The protocol crate treats redirect_url as optional; here the
        // callback route is derived from it, so it is required.
        if client.redirect_url().is_none() {
            return Err(OAuth2BuilderError::MissingRedirectUrl);
        }

        Ok(OAuth2Context(Arc::new(OAuth2ContextInner {
            client,
            inner,
            session: self.cookie_builder.try_build()?,
            login_path: self.login_path,
            auth_params: self.auth_params,
            flow_type: self.flow_type,
        })))
    }
}

impl From<ConfigError> for OAuth2BuilderError {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::MissingClientId => OAuth2BuilderError::MissingClientId,
            ConfigError::MissingAuthUrl => OAuth2BuilderError::MissingAuthUrl,
            ConfigError::MissingTokenUrl => OAuth2BuilderError::MissingTokenUrl,
            ConfigError::InvalidAuthUrl(e) => OAuth2BuilderError::InvalidAuthUrl(e),
            ConfigError::InvalidTokenUrl(e) => OAuth2BuilderError::InvalidTokenUrl(e),
            ConfigError::InvalidRedirectUrl(e) => OAuth2BuilderError::InvalidRedirectUrl(e),
            // The reqwest backend is always enabled here, so a default
            // HTTP client always exists; `#[non_exhaustive]` forces the arm.
            _ => unreachable!("unexpected oauth2 config error: {error}"),
        }
    }
}

pub(crate) enum FlowType {
    AuthorizationCodeFlow,
    AuthorizationCodeFlowPkce,
}

#[derive(Debug)]
pub enum OAuth2BuilderError {
    MissingClientId,
    MissingRedirectUrl,
    MissingAuthUrl,
    MissingTokenUrl,
    InvalidRedirectUrl(url::ParseError),
    InvalidAuthUrl(url::ParseError),
    InvalidTokenUrl(url::ParseError),
    WhitespaceInProviderName,
    /// No cookie signing secret was set. Provide one with `cookie_secret`
    /// or opt into an ephemeral one with `random_cookie_secret`.
    MissingCookieSecret,
}

impl Error for OAuth2BuilderError {}

impl Display for OAuth2BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuth2BuilderError::MissingClientId => f.write_str("client id is missing"),
            OAuth2BuilderError::MissingRedirectUrl => f.write_str("redirect url is missing"),
            OAuth2BuilderError::MissingAuthUrl => f.write_str("authorization url is missing"),
            OAuth2BuilderError::MissingTokenUrl => f.write_str("token url is missing"),
            OAuth2BuilderError::InvalidRedirectUrl(parse_error) => {
                write!(f, "could not parse redirect url: {}", parse_error)
            }
            OAuth2BuilderError::InvalidAuthUrl(parse_error) => {
                write!(f, "could not parse authorization url: {}", parse_error)
            }
            OAuth2BuilderError::InvalidTokenUrl(parse_error) => {
                write!(f, "could not parse token url: {}", parse_error)
            }
            OAuth2BuilderError::WhitespaceInProviderName => {
                f.write_str("provider name can't contain whitespaces")
            }
            OAuth2BuilderError::MissingCookieSecret => f.write_str(
                "cookie signing secret is missing (set one with `cookie_secret`, or opt into an ephemeral one with `random_cookie_secret`)",
            ),
        }
    }
}

#[cfg(test)]
mod builder {
    use axum::response::IntoResponse;

    use crate::oauth2::{
        AfterLoginCookies, OAuth2BuilderError, OAuth2Context, OAuth2Handler, TokenResponse,
        providers::github,
    };

    const CLIENT_ID: &str = "test_client_id";
    const CLIENT_SECRET: &str = "test_client_secret";
    const REDIRECT_URL: &str = "http://rust-lang.org/redirect";
    const AUTH_URL: &str = github::AUTH_URL;
    const TOKEN_URL: &str = github::TOKEN_URL;

    struct TestHandler {}

    impl OAuth2Handler for TestHandler {
        async fn after_login(
            &self,
            _token_res: TokenResponse,
            _context: &mut AfterLoginCookies<'_>,
        ) -> impl IntoResponse {
            ()
        }
    }

    #[test]
    fn builder_errors() {
        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .random_cookie_secret()
            .try_build(TestHandler {});

        assert!(res.is_ok());

        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .random_cookie_secret()
            .try_build(TestHandler {});

        assert!(res.is_ok());
    }

    #[test]
    fn missing_cookie_secret() {
        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingCookieSecret)));
    }

    #[test]
    fn client_id() {
        let res = OAuth2Context::builder("github")
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingClientId)));
    }

    #[test]
    fn auth_url() {
        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingAuthUrl)));

        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url("not an url")
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::InvalidAuthUrl(_))));
    }

    #[test]
    fn token_url() {
        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingTokenUrl)));

        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url("not an url")
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::InvalidTokenUrl(_))));
    }

    #[test]
    fn redirect_url() {
        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingRedirectUrl)));

        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url("not an url")
            .try_build(TestHandler {});

        assert!(matches!(
            res,
            Err(OAuth2BuilderError::InvalidRedirectUrl(_))
        ));
    }

    #[test]
    fn provider_name() {
        let res = OAuth2Context::builder("github ")
            .client_id(CLIENT_ID)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(
            res,
            Err(OAuth2BuilderError::WhitespaceInProviderName)
        ));
    }
}
