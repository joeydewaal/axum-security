use std::{borrow::Cow, sync::Arc};

use anyhow::Context;
use cookie_monster::{Cookie, CookieBuilder, SameSite};
use oauth2::{AuthUrl, Client, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl};

use crate::{
    http::default_reqwest_client,
    oauth2::{OAuth2Context, OAuthSessionState, context::OAuth2ContextInner},
    session::{CookieSession, CookieSessionBuilder},
    store::SessionStore,
};

pub struct OAuth2ContextBuilder<S> {
    name: Cow<'static, str>,
    session: CookieSessionBuilder<S>,
    start_challenge_path: Option<Cow<'static, str>>,
    redirect_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Vec<Scope>,
    auth_url: Option<String>,
    token_url: Option<String>,
}

impl<S> OAuth2ContextBuilder<S> {
    pub fn new(name: impl Into<Cow<'static, str>>, store: S) -> OAuth2ContextBuilder<S> {
        let name = name.into();

        let cookie = Cookie::named(name.clone())
            .secure()
            .http_only()
            .same_site(SameSite::Strict);

        let dev_cookie = Cookie::named(name.clone());

        Self {
            name,
            session: CookieSession::builder_with_store(store)
                .cookie(|_| cookie)
                .dev_cookie(|_| dev_cookie),
            start_challenge_path: None,
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

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(client_secret.into());
        self
    }

    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(auth_url.into());
        self
    }

    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(token_url.into());
        self
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

    pub fn start_challenge_path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
        let path = path.into();
        self.start_challenge_path = Some(path.clone());
        self.session = self.session.cookie(|c| c.path(path));
        self
    }

    pub fn build<T>(self, inner: T, dev: bool) -> OAuth2Context<T, S>
    where
        S: SessionStore<State = OAuthSessionState>,
    {
        self.try_build(inner, dev).unwrap()
    }

    pub fn try_build<T>(mut self, inner: T, dev: bool) -> crate::Result<OAuth2Context<T, S>>
    where
        S: SessionStore<State = OAuthSessionState>,
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
            session: self.session.build(dev),
            start_challenge_path: self.start_challenge_path,
            http_client: default_reqwest_client(),
            scopes: self.scopes,
        })))
    }
}

fn default_dev_cookie(name: Cow<'static, str>) -> CookieBuilder {
    Cookie::named(name)
}

fn default_secure_cookie(
    name: Cow<'static, str>,
    start_challenge_path: Option<&str>,
) -> CookieBuilder {
    let mut builder = default_dev_cookie(name)
        .secure()
        .http_only()
        .same_site(SameSite::Strict);

    if let Some(login_path) = start_challenge_path {
        builder.path(login_path.to_string())
    } else {
        builder
    }
}
