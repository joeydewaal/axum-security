use std::sync::Arc;

use axum::http::HeaderMap;
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};

use crate::cookie::{CookieSession, CookieStore, MemoryStore, SessionId};

pub struct CookieContext<S>(Arc<CookieContextInner<S>>);

impl<S> Clone for CookieContext<S> {
    fn clone(&self) -> Self {
        CookieContext(self.0.clone())
    }
}

struct CookieContextInner<S> {
    store: S,
    cookie_opts: CookieBuilder,
}

impl CookieContext<()> {
    pub fn builder<T>() -> CookieSessionBuilder<MemoryStore<T>> {
        CookieSessionBuilder::new(MemoryStore::new())
    }

    pub fn builder_with_store<S>(store: S) -> CookieSessionBuilder<S> {
        CookieSessionBuilder::new(store)
    }
}

impl<S: CookieStore> CookieContext<S> {
    pub fn get_cookie(&self, session_id: SessionId) -> Cookie {
        self.0.cookie_opts.clone().value(session_id).build()
    }

    pub(crate) async fn load_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Option<CookieSession<S::State>> {
        let cookies = CookieJar::from_headers(headers);

        self.load_from_jar(&cookies).await
    }

    pub(crate) async fn load_from_jar(
        &self,
        cookies: &CookieJar,
    ) -> Option<CookieSession<S::State>> {
        let session_id = self.session_id_from_jar(cookies)?;

        self.0.store.load_session(&session_id).await
    }

    pub async fn store_session(&self, state: <S as CookieStore>::State) -> Cookie {
        let session_id = self.0.store.store_state(state).await;
        self.get_cookie(session_id)
    }

    pub async fn remove_session(
        &self,
        jar: &CookieJar,
    ) -> Option<CookieSession<<S as CookieStore>::State>> {
        let session_id = self.session_id_from_jar(jar)?;

        self.0.store.remove_session(&session_id).await
    }

    pub(crate) fn session_id_from_jar(&self, jar: &CookieJar) -> Option<SessionId> {
        let cookie = jar.get(self.0.cookie_opts.get_name())?;

        Some(SessionId::from_cookie(cookie))
    }
}

static DEFAULT_SESSION_COOKIE_NAME: &str = "session";

pub struct CookieSessionBuilder<S> {
    store: S,
    pub(crate) dev: bool,
    pub(crate) dev_cookie: CookieBuilder,
    pub(crate) cookie: CookieBuilder,
}

impl<S> CookieSessionBuilder<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            dev: false,
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

    pub fn dev(mut self, dev: bool) -> Self {
        self.dev = dev;
        self
    }

    pub fn prod(self, prod: bool) -> Self {
        self.dev(!prod)
    }
}

impl<S: CookieStore> CookieSessionBuilder<S> {
    pub fn build<T>(self) -> CookieContext<S>
    where
        S: CookieStore<State = T>,
    {
        CookieContext(Arc::new(CookieContextInner {
            store: self.store,
            cookie_opts: if self.dev {
                self.dev_cookie
            } else {
                self.cookie
            },
        }))
    }
}
