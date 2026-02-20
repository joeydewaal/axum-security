use std::{borrow::Cow, error::Error, fmt::Display, sync::Arc, time::Duration};

use cookie_monster::CookieBuilder;
use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl,
    reqwest::Client as HttpClient, url,
};

use crate::{
    http::default_reqwest_client,
    oauth2::{
        OAuth2Context, OAuth2Handler, context::OAuth2ContextInner, cookie::OAuthCookieBuilder,
    },
    utils::get_env,
};

pub struct OAuth2ContextBuilder {
    cookie_builder: OAuthCookieBuilder,
    login_path: Option<Cow<'static, str>>,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Vec<Scope>,
    auth_url: Option<String>,
    token_url: Option<String>,
    http_client: Option<HttpClient>,
    flow_type: FlowType,
}

impl OAuth2ContextBuilder {
    pub fn new(oauth2_provider_name: impl Into<Cow<'static, str>>) -> OAuth2ContextBuilder {
        Self {
            cookie_builder: OAuthCookieBuilder::new(oauth2_provider_name.into()),
            login_path: None,
            redirect_url: None,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            auth_url: None,
            token_url: None,
            http_client: None,
            flow_type: FlowType::AuthorizationCodeFlowPkce,
        }
    }

    pub fn redirect_url(mut self, url: impl Into<String>) -> Self {
        self.redirect_url = Some(url.into());
        self
    }

    pub fn redirect_uri_env(self, name: &str) -> Self {
        self.redirect_url(get_env(name))
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn client_id_env(self, name: &str) -> Self {
        self.client_id(get_env(name))
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    pub fn client_secret_env(self, name: &str) -> Self {
        self.client_secret(get_env(name))
    }

    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    pub fn auth_url_env(self, name: &str) -> Self {
        self.auth_url(get_env(name))
    }

    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(token_url.into());
        self
    }

    pub fn token_url_env(self, name: &str) -> Self {
        self.token_url(get_env(name))
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| Scope::new(s.to_string())).collect();
        self
    }

    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_builder.cookie_builder = self.cookie_builder.cookie_builder.cookie(f);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_builder.cookie_builder = self.cookie_builder.cookie_builder.dev_cookie(f);
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

    pub fn http_client(mut self, http_client: HttpClient) -> Self {
        self.http_client = Some(http_client);
        self
    }

    pub fn cookie_secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.cookie_builder.secret = Some(secret.as_ref().to_vec());
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
        let client_id = self
            .client_id
            .ok_or(OAuth2BuilderError::MissingClientId)
            .map(ClientId::new)?;

        let redirect_url = self
            .redirect_url
            .ok_or(OAuth2BuilderError::MissingRedirectUrl)?;

        let redirect_url =
            RedirectUrl::new(redirect_url).map_err(OAuth2BuilderError::InvalidRedirectUrl)?;

        let auth_url = self.auth_url.ok_or(OAuth2BuilderError::MissingAuthUrl)?;

        let auth_url = AuthUrl::new(auth_url).map_err(OAuth2BuilderError::InvalidAuthUrl)?;

        let token_url = self.token_url.ok_or(OAuth2BuilderError::MissingTokenUrl)?;

        let token_url = TokenUrl::new(token_url).map_err(OAuth2BuilderError::InvalidTokenUrl)?;

        let mut basic_client = Client::new(client_id)
            .set_redirect_uri(redirect_url)
            .set_auth_uri(auth_url)
            .set_token_uri(token_url);

        if let Some(client_secret) = self.client_secret {
            basic_client = basic_client.set_client_secret(ClientSecret::new(client_secret));
        }

        Ok(OAuth2Context(Arc::new(OAuth2ContextInner {
            client: basic_client,
            inner,
            session: self.cookie_builder.try_build()?,
            login_path: self.login_path,
            http_client: self.http_client.unwrap_or_else(default_reqwest_client),
            scopes: self.scopes,
            flow_type: self.flow_type,
        })))
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
            .try_build(TestHandler {});

        assert!(res.is_ok());

        let res = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(res.is_ok());
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
