mod builder;
mod expiry;
mod id;
mod service;
mod session;
mod store;

use std::{borrow::Cow, convert::Infallible, error::Error, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
};
pub use builder::CookieSessionBuilder;
pub use id::SessionId;
pub use session::CookieSession;
pub use store::{CookieStore, MemStore};

pub use cookie_monster::{Cookie, CookieBuilder, CookieJar, Expires, SameSite};
use tokio::task::JoinHandle;

use crate::{
    cookie::store::{BoxDynError, ErasedStore},
    utils::utc_now,
};

pub struct CookieContext<S>(Arc<CookieContextInner<S>>);

struct CookieContextInner<S> {
    store: ErasedStore<S>,
    cookie_opts: CookieBuilder,
    handle: Option<JoinHandle<()>>,
}

impl CookieContext<()> {
    pub fn builder() -> CookieSessionBuilder<()> {
        CookieSessionBuilder::new()
    }
}

impl<S: 'static> CookieContext<S> {
    pub fn get_cookie(&self, session_id: SessionId) -> Cookie {
        self.0.cookie_opts.clone().value(session_id).build()
    }

    pub async fn create_session(
        &self,
        state: S,
    ) -> Result<Cookie, Box<dyn Error + Send + 'static>> {
        let session_id = SessionId::new();
        tracing::debug!("Storing {session_id:?} in cookie store");
        let now = utc_now().as_secs();
        let session = CookieSession::new(session_id.clone(), now, state);
        self.0.store.store_session(session).await?;

        Ok(self.get_cookie(session_id))
    }

    pub async fn remove_session_jar(
        &self,
        jar: &CookieJar,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        let Some(session_id) = self.session_id_from_jar(jar) else {
            return Ok(None);
        };

        self.0.store.remove_session(&session_id).await
    }

    pub async fn remove_session_cookie(
        &self,
        cookie: &Cookie,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        let session_id = SessionId::from_cookie(cookie);
        self.remove_session(&session_id).await
    }

    pub async fn remove_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        self.0.store.remove_session(session_id).await
    }

    pub fn build_cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.cookie_opts.clone().name(name)
    }

    pub fn cookie_builder(&self) -> &CookieBuilder {
        &self.0.cookie_opts
    }

    pub async fn remove_before(&self, deadline: u64) -> Result<(), BoxDynError> {
        self.0.store.remove_before(deadline).await
    }

    pub(crate) async fn load_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        let cookies = CookieJar::from_headers(headers);

        self.load_from_jar(&cookies).await
    }

    pub(crate) async fn load_from_jar(
        &self,
        cookies: &CookieJar,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        let Some(session_id) = self.session_id_from_jar(cookies) else {
            return Ok(None);
        };

        self.0.store.load_session(&session_id).await
    }

    pub(crate) fn session_id_from_jar(&self, jar: &CookieJar) -> Option<SessionId> {
        let cookie = jar.get(self.0.cookie_opts.get_name())?;

        Some(SessionId::from_cookie(cookie))
    }

    pub async fn load_from_cookie(
        &self,
        cookie: &Cookie,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        let session_id = SessionId::from_cookie(cookie);

        self.0.store.load_session(&session_id).await
    }
}

impl<S, U> FromRequestParts<S> for CookieContext<U>
where
    CookieContext<U>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}

impl<S> Drop for CookieContextInner<S> {
    fn drop(&mut self) {
        // Make sure to cancel the bg task if the cookie context is dropped. This is only
        // implemented for the Inner type because we don't to cancel the task if a weak reference
        // is dropped.
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}
impl<S> Clone for CookieContext<S> {
    fn clone(&self) -> Self {
        CookieContext(self.0.clone())
    }
}
