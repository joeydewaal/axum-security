use std::{borrow::Cow, sync::Arc};

use axum::http::request::Parts;
use cookie_monster::{CookieBuilder, CookieJar, SameSite};

use crate::{
    session::{HttpSession, Session, SessionId, SessionStore},
    store::MemoryStore,
};

pub struct CookieSession<S>(Arc<CookieSessionInner<S>>);

impl<S> Clone for CookieSession<S> {
    fn clone(&self) -> Self {
        CookieSession(self.0.clone())
    }
}

struct CookieSessionInner<S> {
    store: S,
    cookie_opts: CookieBuilder,
}

impl CookieSession<()> {
    pub fn builder<T>() -> CookieSessionBuilder<MemoryStore<T>> {
        CookieSessionBuilder::new(MemoryStore::new())
    }

    pub fn builder_with_store<S>(store: S) -> CookieSessionBuilder<S> {
        CookieSessionBuilder::new(store)
    }
}

impl<S: SessionStore> CookieSession<S> {
    pub async fn store_session(
        &self,
        state: <S as SessionStore>::State,
    ) -> Session<<S as SessionStore>::State> {
        todo!();
    }

    pub async fn remove_session(
        &self,
        session_id: &SessionId,
    ) -> Option<Session<<S as SessionStore>::State>> {
        todo!();
    }
}

impl<S> CookieSession<S> {}

static DEFAULT_SESSION_COOKIE_NAME: &str = "session";

pub struct CookieSessionBuilder<S> {
    store: S,
    dev_cookie: CookieBuilder,
    cookie: CookieBuilder,
    dev: bool,
}

impl<S> CookieSessionBuilder<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            dev_cookie: CookieBuilder::new(DEFAULT_SESSION_COOKIE_NAME, "")
                .same_site(SameSite::None)
                .http_only(),
            cookie: CookieBuilder::new(DEFAULT_SESSION_COOKIE_NAME, "")
                .same_site(SameSite::Strict)
                .http_only()
                .secure(),
            dev: false,
        }
    }

    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie = f(self.cookie);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.dev_cookie = f(self.dev_cookie);
        self
    }

    pub fn dev(mut self, dev_cookie: bool) -> Self {
        self.dev = dev_cookie;
        self
    }

    pub fn cookie_name(mut self, cookie_name: impl Into<Cow<'static, str>>) -> Self {
        self.cookie = self.cookie.name(cookie_name);
        self
    }
}

impl<S: SessionStore> CookieSessionBuilder<S> {
    pub fn build<T>(self) -> CookieSession<S>
    where
        S: SessionStore<State = T>,
    {
        CookieSession(Arc::new(CookieSessionInner {
            store: self.store,
            cookie_opts: if self.dev {
                self.dev_cookie
            } else {
                self.cookie
            },
        }))
    }
}

impl<S: SessionStore> HttpSession for CookieSession<S> {
    type State = S::State;

    async fn load_from_request_parts(&self, parts: &mut Parts) -> Option<Session<S::State>> {
        let cookies = CookieJar::from_headers(&parts.headers);

        let cookie = cookies.get(self.0.cookie_opts.get_name())?;

        let session_id = SessionId::from_cookie(&cookie);

        self.0.store.load_session(&session_id).await
    }
}
