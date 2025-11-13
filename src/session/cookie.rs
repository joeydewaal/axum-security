use std::sync::Arc;

use axum::http::request::Parts;
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};

use crate::{
    session::{HttpSession, Session, SessionId},
    store::{MemoryStore, SessionStore},
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
    pub fn get_cookie(&self, session_id: SessionId) -> Cookie {
        self.0
            .cookie_opts
            .clone()
            .value(session_id.into_inner())
            .build()
    }
    pub async fn store_session(&self, state: <S as SessionStore>::State) -> Cookie {
        let session_id = self.0.store.store_state(state).await;
        self.get_cookie(session_id)
    }

    pub async fn remove_session(
        &self,
        jar: &CookieJar,
    ) -> Option<Session<<S as SessionStore>::State>> {
        let session_id = self.session_id_from_jar(jar)?;

        self.0.store.remove_session(&session_id).await
    }

    pub(crate) fn session_id_from_jar(&self, jar: &CookieJar) -> Option<SessionId> {
        let cookie = jar.get(self.0.cookie_opts.get_name())?;

        Some(SessionId::from_cookie(cookie))
    }
}

impl<S> CookieSession<S> {}

static DEFAULT_SESSION_COOKIE_NAME: &str = "session";

pub struct CookieSessionBuilder<S> {
    store: S,
    pub(crate) dev_cookie: CookieBuilder,
    pub(crate) cookie: CookieBuilder,
}

impl<S> CookieSessionBuilder<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            dev_cookie: Cookie::named(DEFAULT_SESSION_COOKIE_NAME)
                .same_site(SameSite::None)
                .http_only(),
            cookie: Cookie::named(DEFAULT_SESSION_COOKIE_NAME)
                .same_site(SameSite::Strict)
                .http_only()
                .secure(),
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
}

impl<S: SessionStore> CookieSessionBuilder<S> {
    pub fn build<T>(self, dev: bool) -> CookieSession<S>
    where
        S: SessionStore<State = T>,
    {
        CookieSession(Arc::new(CookieSessionInner {
            store: self.store,
            cookie_opts: if dev { self.dev_cookie } else { self.cookie },
        }))
    }
}

impl<S: SessionStore> HttpSession for CookieSession<S> {
    type State = S::State;

    async fn load_from_request_parts(&self, parts: &mut Parts) -> Option<Session<S::State>> {
        let cookies = CookieJar::from_headers(&parts.headers);

        let session_id = self.session_id_from_jar(&cookies)?;

        self.0.store.load_session(&session_id).await
    }
}
