mod builder;
mod expiry;
mod id;
mod service;
mod session;
mod store;

use std::{borrow::Cow, sync::Arc};

use axum::http::HeaderMap;
pub use builder::CookieSessionBuilder;
pub use id::SessionId;
pub use session::CookieSession;
pub use store::{CookieStore, MemStore};

pub use cookie_monster::{Cookie, CookieBuilder, CookieJar, Error, Expires, SameSite};

pub struct CookieContext<S>(Arc<CookieContextInner<S>>);

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

    pub fn build_cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.cookie_opts.clone().name(name)
    }

    pub fn cookie_builder(&self) -> &CookieBuilder {
        &self.0.cookie_opts
    }

    pub async fn remove_after(&self, deadline: u64) -> Result<(), <S as CookieStore>::Error> {
        self.0.store.remove_before(deadline).await
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

    pub(crate) fn session_id_from_jar(&self, jar: &CookieJar) -> Option<SessionId> {
        let cookie = jar.get(self.0.cookie_opts.get_name())?;

        Some(SessionId::from_cookie(cookie))
    }
}

impl<S> Clone for CookieContext<S> {
    fn clone(&self) -> Self {
        CookieContext(self.0.clone())
    }
}
