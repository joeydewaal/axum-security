use std::{borrow::Cow, error::Error, fmt::Display, sync::Arc};

use cookie_monster::{Cookie, CookieBuilder, SameSite};
use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl,
    reqwest::Client as HttpClient, url,
};

use crate::{
    cookie::{CookieContext, CookieSessionBuilder, CookieStore},
    http::default_reqwest_client,
    oauth2::{
        OAuth2Context, OAuth2Handler, OAuthState, context::OAuth2ContextInner,
        handler::ErasedOAuth2Handler,
    },
    utils::get_env,
};

static DEFAULT_COOKIE_NAME: &str = "oauth2-session";

pub struct OAuth2ContextBuilder<S> {
    cookie_session: CookieSessionBuilder<S>,
    login_path: Option<Cow<'static, str>>,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Vec<Scope>,
    auth_url: Option<String>,
    token_url: Option<String>,
    http_client: HttpClient,
}

impl<S> OAuth2ContextBuilder<S> {
    pub fn new(store: S) -> OAuth2ContextBuilder<S> {
        // Make sure to use "/" as path so all paths can see the cookie in dev mode.
        let dev_cookie = Cookie::named(DEFAULT_COOKIE_NAME).path("/");

        let cookie = Cookie::named(DEFAULT_COOKIE_NAME)
            .http_only()
            .same_site(SameSite::Strict)
            .secure();

        Self {
            cookie_session: CookieContext::<()>::builder()
                .store(store)
                .cookie(|_| cookie)
                .dev_cookie(|_| dev_cookie),
            login_path: None,
            redirect_url: None,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            auth_url: None,
            token_url: None,
            http_client: default_reqwest_client(),
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
        self.cookie_session = self.cookie_session.cookie(f);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_session = self.cookie_session.dev_cookie(f);
        self
    }

    pub fn login_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.login_path = Some(path.into());
        self
    }

    pub fn use_dev_cookies(mut self, dev: bool) -> Self {
        self.cookie_session = self.cookie_session.use_dev_cookie(dev);
        self
    }

    pub fn use_normal_cookies(self, prod: bool) -> Self {
        self.use_dev_cookies(!prod)
    }

    pub fn store<S1>(self, store: S1) -> OAuth2ContextBuilder<S1> {
        OAuth2ContextBuilder {
            cookie_session: self.cookie_session.store(store),
            login_path: self.login_path,
            redirect_url: self.redirect_url,
            client_id: self.client_id,
            client_secret: self.client_secret,
            scopes: self.scopes,
            auth_url: self.auth_url,
            token_url: self.token_url,
            http_client: self.http_client,
        }
    }

    pub fn build<T>(self, inner: T) -> OAuth2Context<S>
    where
        S: CookieStore<State = OAuthState>,
        T: OAuth2Handler,
    {
        self.try_build(inner).unwrap()
    }

    pub fn try_build<T>(self, inner: T) -> Result<OAuth2Context<S>, OAuth2BuilderError>
    where
        S: CookieStore<State = OAuthState>,
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
            inner: ErasedOAuth2Handler::new(inner),
            session: self.cookie_session.build(),
            login_path: self.login_path,
            http_client: self.http_client,
            scopes: self.scopes,
        })))
    }
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
        }
    }
}

#[cfg(test)]
mod builder {
    use axum::response::IntoResponse;

    use crate::oauth2::{
        AfterLoginContext, OAuth2BuilderError, OAuth2Context, OAuth2Handler, TokenResponse,
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
            _context: AfterLoginContext<'_>,
        ) -> impl IntoResponse {
            ()
        }
    }

    #[test]
    fn builder_errors() {
        let res = OAuth2Context::builder()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(res.is_ok());

        let res = OAuth2Context::builder()
            .client_id(CLIENT_ID)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(res.is_ok());
    }

    #[test]
    fn client_id() {
        let res = OAuth2Context::builder()
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingClientId)));
    }

    #[test]
    fn auth_url() {
        let res = OAuth2Context::builder()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingAuthUrl)));

        let res = OAuth2Context::builder()
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
        let res = OAuth2Context::builder()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .redirect_url(REDIRECT_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingTokenUrl)));

        let res = OAuth2Context::builder()
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
        let res = OAuth2Context::builder()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .try_build(TestHandler {});

        assert!(matches!(res, Err(OAuth2BuilderError::MissingRedirectUrl)));

        let res = OAuth2Context::builder()
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
}
