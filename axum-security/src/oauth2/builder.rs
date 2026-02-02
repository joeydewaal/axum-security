use std::{borrow::Cow, sync::Arc};

use cookie_monster::{Cookie, CookieBuilder, SameSite};
use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl, reqwest::Client, url,
};

use crate::{
    cookie::{CookieContext, CookieSessionBuilder, CookieStore},
    http::default_reqwest_client,
    oauth2::{OAuth2Context, OAuthState, context::OAuth2ContextInner},
    utils::get_env,
};

static DEFAULT_COOKIE_NAME: &str = "oauth2-session";

pub struct OAuth2ContextBuilder<S> {
    session: CookieSessionBuilder<S>,
    login_path: Option<Cow<'static, str>>,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Vec<Scope>,
    auth_url: Option<String>,
    token_url: Option<String>,
    http_client: Client,
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
            session: CookieContext::<()>::builder()
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

    pub fn redirect_uri(mut self, url: impl Into<String>) -> Self {
        self.redirect_url = Some(url.into());
        self
    }

    pub fn redirect_uri_env(self, name: &str) -> Self {
        self.redirect_uri(get_env(name))
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
        self.session = self.session.cookie(f);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.session = self.session.dev_cookie(f);
        self
    }

    pub fn login_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        self.login_path = Some(path.into());
        self
    }

    pub fn use_dev_cookies(mut self, dev: bool) -> Self {
        self.session = self.session.use_dev_cookie(dev);
        self
    }

    pub fn use_normal_cookies(self, prod: bool) -> Self {
        self.use_dev_cookies(!prod)
    }

    pub fn store<S1>(self, store: S1) -> OAuth2ContextBuilder<S1> {
        OAuth2ContextBuilder {
            session: self.session.store(store),
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

    pub fn build<T>(self, inner: T) -> OAuth2Context<T, S>
    where
        S: CookieStore<State = OAuthState>,
    {
        self.try_build(inner).unwrap()
    }

    pub fn try_build<T>(self, inner: T) -> Result<OAuth2Context<T, S>, OAuth2BuilderError>
    where
        S: CookieStore<State = OAuthState>,
    {
        let client_id = self
            .client_id
            .ok_or_else(|| OAuth2BuilderError::MissingClientId)
            .map(ClientId::new)?;

        let redirect_url = self
            .redirect_url
            .ok_or_else(|| OAuth2BuilderError::MissingRedirectId)?;

        let redirect_url =
            RedirectUrl::new(redirect_url).map_err(OAuth2BuilderError::InvalidRedirectUrl)?;

        let auth_url = self
            .auth_url
            .ok_or_else(|| OAuth2BuilderError::MissingAuthUrl)?;

        let auth_url = AuthUrl::new(auth_url).map_err(OAuth2BuilderError::InvalidAuthUrl)?;

        let token_url = self
            .token_url
            .ok_or_else(|| OAuth2BuilderError::MissingTokenUrl)?;

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
            session: self.session.build(),
            login_path: self.login_path,
            http_client: self.http_client,
            scopes: self.scopes,
        })))
    }
}

#[derive(Debug)]
pub enum OAuth2BuilderError {
    MissingClientId,
    MissingRedirectId,
    MissingAuthUrl,
    MissingTokenUrl,
    InvalidRedirectUrl(url::ParseError),
    InvalidAuthUrl(url::ParseError),
    InvalidTokenUrl(url::ParseError),
}
