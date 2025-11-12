use std::sync::Arc;

use cookie_monster::{Cookie, CookieBuilder};
use oauth2::{
    AuthUrl, Client, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl,
    reqwest::redirect::Policy,
};

use crate::{
    oauth2::OAuthSessionState,
    session::{CookieSession, CookieSessionBuilder, SessionStore},
};

use super::{OAuth2ClientTyped, OAuth2Context, OAuth2ContextInner};

static DEFAULT_SESSION_COOKIE_NAME: &str = "oauth2-session";

pub struct OAuth2ContextBuilder<S> {
    session: CookieSessionBuilder<S>,
    cookie_opts: Option<CookieBuilder>,
    start_challenge_path: Option<String>,
    redirect_url: Option<RedirectUrl>,
    client_id: Option<ClientId>,
    client_secret: Option<ClientSecret>,
    scopes: Vec<Scope>,
    auth_url: Option<AuthUrl>,
    token_url: Option<TokenUrl>,
}

impl<S> OAuth2ContextBuilder<S> {
    pub fn new(store: S) -> OAuth2ContextBuilder<S> {
        Self {
            session: CookieSession::builder_with_store(store),
            cookie_opts: None,
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
        self.redirect_url = Some(RedirectUrl::new(url.into()).unwrap());
        self
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(ClientId::new(client_id.into()));
        self
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.client_secret = Some(ClientSecret::new(client_secret.into()));
        self
    }

    pub fn auth_url(mut self, auth_url: impl Into<String>) -> Self {
        self.auth_url = Some(AuthUrl::new(auth_url.into()).unwrap());
        self
    }

    pub fn token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = Some(TokenUrl::new(token_url.into()).unwrap());
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

    pub fn dev(mut self, dev_cookie: bool) -> Self {
        self.session = self.session.dev(dev_cookie);
        self
    }

    pub fn start_challenge_path(mut self, path: impl Into<String>) -> Self {
        self.start_challenge_path = Some(path.into());
        self
    }

    pub fn build<T>(self, inner: T) -> OAuth2Context<T, S>
    where
        S: SessionStore<State = OAuthSessionState>,
    {
        let mut basic_client: OAuth2ClientTyped = Client::new(self.client_id.unwrap())
            .set_redirect_uri(self.redirect_url.unwrap())
            .set_auth_uri(self.auth_url.unwrap())
            .set_token_uri(self.token_url.unwrap());

        if let Some(client_secret) = self.client_secret {
            basic_client = basic_client.set_client_secret(client_secret);
        }

        OAuth2Context(Arc::new(OAuth2ContextInner {
            client: basic_client,
            inner,
            session: self.session.build(),
            cookie_opts: self.cookie_opts.unwrap_or(default_cookie()),
            start_challenge_path: self.start_challenge_path,
            http_client: ::oauth2::reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .unwrap(),
            scopes: self.scopes,
        }))
    }
}

fn default_cookie() -> CookieBuilder {
    Cookie::build("oauth2-session", DEFAULT_SESSION_COOKIE_NAME).http_only()
}
