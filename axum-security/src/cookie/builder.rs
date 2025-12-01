use std::{borrow::Cow, sync::Arc, time::Duration};

use axum::http::HeaderMap;
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};

use crate::cookie::{CookieSession, CookieStore, SessionId, expiry::SessionExpiry};

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
    pub fn builder() -> CookieSessionBuilder<()> {
        CookieSessionBuilder::new()
    }
}

impl<S: CookieStore> CookieContext<S> {
    pub fn get_cookie(&self, session_id: SessionId) -> Cookie {
        self.0.cookie_opts.clone().value(session_id).build()
    }

    pub(crate) async fn load_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<CookieSession<S::State>>, S::Error> {
        let cookies = CookieJar::from_headers(headers);

        self.load_from_jar(&cookies).await
    }

    pub(crate) async fn load_from_jar(
        &self,
        cookies: &CookieJar,
    ) -> Result<Option<CookieSession<S::State>>, S::Error> {
        let Some(session_id) = self.session_id_from_jar(cookies) else {
            return Ok(None);
        };

        self.0.store.load_session(&session_id).await
    }

    pub async fn create_session(
        &self,
        state: <S as CookieStore>::State,
    ) -> Result<Cookie, S::Error> {
        let session_id = self.0.store.create_session(state).await?;
        Ok(self.get_cookie(session_id))
    }

    pub async fn remove_session(
        &self,
        jar: &CookieJar,
    ) -> Result<Option<CookieSession<<S as CookieStore>::State>>, S::Error> {
        let Some(session_id) = self.session_id_from_jar(jar) else {
            return Ok(None);
        };

        self.0.store.remove_session(&session_id).await
    }

    pub(crate) fn session_id_from_jar(&self, jar: &CookieJar) -> Option<SessionId> {
        let cookie = jar.get(self.0.cookie_opts.get_name())?;

        Some(SessionId::from_cookie(cookie))
    }

    pub fn build_cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.cookie_opts.clone().name(name)
    }

    pub fn cookie_builder(&self) -> &CookieBuilder {
        &self.0.cookie_opts
    }

    pub async fn remove_after(&self, deadline: u64) -> Result<(), <S as CookieStore>::Error> {
        self.0.store.remove_after(deadline).await
    }
}

static DEFAULT_SESSION_COOKIE_NAME: &str = "session";

pub struct CookieSessionBuilder<S> {
    store: S,
    pub(crate) dev: bool,
    pub(crate) dev_cookie: CookieBuilder,
    pub(crate) cookie: CookieBuilder,
    pub(crate) expiry: Option<SessionExpiry>,
}

impl CookieSessionBuilder<()> {
    pub fn new() -> CookieSessionBuilder<()> {
        Self {
            store: (),
            dev: false,
            expiry: None,
            dev_cookie: Cookie::named(DEFAULT_SESSION_COOKIE_NAME)
                .same_site(SameSite::None)
                .http_only(),
            cookie: Cookie::named(DEFAULT_SESSION_COOKIE_NAME)
                .same_site(SameSite::Strict)
                .http_only()
                .secure(),
        }
    }
}

impl<S> CookieSessionBuilder<S> {
    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie = f(self.cookie);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.dev_cookie = f(self.dev_cookie);
        self
    }

    pub fn enable_dev_cookie(mut self, dev: bool) -> Self {
        self.dev = dev;
        self
    }

    pub fn disable_dev_cookie(self, prod: bool) -> Self {
        self.enable_dev_cookie(!prod)
    }

    pub fn expires_max_age(mut self) -> Self {
        self.expiry = Some(SessionExpiry::CookieMaxAge);
        self
    }

    pub fn expires_after(mut self, session_duration: Duration) -> Self {
        self.expiry = Some(SessionExpiry::Duration(session_duration));
        self
    }

    pub fn expires_none(mut self) -> Self {
        self.expiry = None;
        self
    }

    pub fn store<S1>(self, store: S1) -> CookieSessionBuilder<S1> {
        CookieSessionBuilder {
            store,
            dev: self.dev,
            dev_cookie: self.dev_cookie,
            cookie: self.cookie,
            expiry: self.expiry,
        }
    }
}

impl<S> CookieSessionBuilder<S> {
    pub fn build<T>(self) -> CookieContext<S>
    where
        T: Send + Sync + 'static,
        S: CookieStore<State = T>,
    {
        let session_expiry = self.expiry.map(|e| match e {
            SessionExpiry::CookieMaxAge => self.cookie.get_max_age().expect("No max-age set"),
            SessionExpiry::Duration(duration) => duration,
        });

        let cookie_context = CookieContext(Arc::new(CookieContextInner {
            store: self.store,
            cookie_opts: if self.dev {
                self.dev_cookie
            } else {
                self.cookie
            },
        }));

        if let Some(e) = session_expiry
            && cookie_context.0.store.spawn_maintenance_task()
        {
            let this = cookie_context.clone();
            tokio::spawn(super::expiry::maintenance_task(this, e));
        }

        cookie_context
    }
}
