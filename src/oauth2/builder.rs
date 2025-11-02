use std::borrow::Cow;

use cookie_monster::{Cookie, CookieBuilder};

use crate::{
    oauth2::{
        OAuth2Context, OAuth2ContextInner,
        client::{OAuth2Client, OAuth2ClientBuilder},
    },
    store::MemoryStore,
};

static DEFAULT_SESSION_COOKIE_NAME: &str = "oauth2-session";

pub struct Oauth2ContextBuilder {
    pub(super) builder: OAuth2ClientBuilder,
    pub(super) cookie_opts: Option<CookieBuilder>,
    pub(super) start_challenge_path: Option<String>,
}

impl Oauth2ContextBuilder {
    pub fn builder() -> Oauth2ContextBuilder {
        Self {
            builder: OAuth2Client::build(),
            cookie_opts: None,
            start_challenge_path: None,
        }
    }

    pub fn redirect_uri(mut self, url: impl Into<String>) -> Self {
        self.builder.set_redirect_uri(url);
        self
    }

    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.builder.set_client_id(client_id);
        self
    }

    pub fn client_secret(mut self, client_secret: impl Into<String>) -> Self {
        self.builder.set_client_secret(client_secret);
        self
    }

    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.builder.set_scopes(scopes);
        self
    }

    pub fn cookie_opts(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts = Some(f(Cookie::build(DEFAULT_SESSION_COOKIE_NAME, "")));
        self
    }

    pub fn start_challenge_path(mut self, path: impl Into<String>) -> Self {
        self.start_challenge_path = Some(path.into());
        self
    }

    pub fn build<T>(self, inner: T) -> OAuth2Context<T> {
        OAuth2Context(
            OAuth2ContextInner {
                inner,
                client: self.builder.build(),
                store: MemoryStore::new(),
                cookie_opts: self.cookie_opts.unwrap_or(default_cookie()),
                start_challenge_path: self.start_challenge_path,
            }
            .into(),
        )
    }
}

fn default_cookie() -> CookieBuilder {
    Cookie::build("oauth2-session", DEFAULT_SESSION_COOKIE_NAME).http_only()
}
