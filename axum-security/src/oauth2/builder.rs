use std::{borrow::Cow, sync::Arc};

use anyhow::Context;
use cookie_monster::{Cookie, CookieBuilder, SameSite};
use oauth2::{AuthUrl, Client, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl};

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
}

impl<S> OAuth2ContextBuilder<S> {
    pub fn new(store: S) -> OAuth2ContextBuilder<S> {
        let dev_cookie = Cookie::named(DEFAULT_COOKIE_NAME);

        let cookie = dev_cookie
            .clone()
            .secure()
            .http_only()
            .same_site(SameSite::Strict);

        Self {
            session: CookieContext::builder_with_store(store)
                .cookie(|_| cookie)
                .dev_cookie(|_| dev_cookie),
            login_path: None,
            redirect_url: None,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            auth_url: None,
            token_url: None,
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

    pub fn dev(mut self, dev: bool) -> Self {
        self.session = self.session.dev(dev);
        self
    }

    pub fn prod(self, prod: bool) -> Self {
        self.dev(!prod)
    }

    pub fn build<T>(self, inner: T) -> OAuth2Context<T, S>
    where
        S: CookieStore<State = OAuthState>,
    {
        self.try_build(inner).unwrap()
    }

    pub fn try_build<T>(self, inner: T) -> crate::Result<OAuth2Context<T, S>>
    where
        S: CookieStore<State = OAuthState>,
    {
        let mut basic_client =
            Client::new(ClientId::new(self.client_id.context("client id missing")?))
                .set_redirect_uri(RedirectUrl::new(
                    self.redirect_url.context("redirect url mmissing")?,
                )?)
                .set_auth_uri(AuthUrl::new(self.auth_url.context("auth uri missing")?)?)
                .set_token_uri(TokenUrl::new(self.token_url.context("token uri missing")?)?);

        if let Some(client_secret) = self.client_secret {
            basic_client = basic_client.set_client_secret(ClientSecret::new(client_secret));
        }

        Ok(OAuth2Context(Arc::new(OAuth2ContextInner {
            client: basic_client,
            inner,
            session: self.session.build(),
            login_path: self.login_path,
            http_client: default_reqwest_client(),
            scopes: self.scopes,
        })))
    }
}
