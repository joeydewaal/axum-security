//! Server-side cookie session management.
//!
//! This module provides [`CookieContext`], which manages sessions backed by a
//! pluggable [`CookieStore`]. Sessions are identified by a cookie containing
//! a unique [`SessionId`]. The session state lives server-side in your store.
//!
//! Use [`CookieContext`] as a Tower [`Layer`](tower::Layer) to automatically
//! load sessions from incoming requests. Then extract [`CookieSession<S>`] in
//! handlers to access the session data.
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use axum_security::cookie::{CookieContext, CookieSession, MemStore};
//!
//! #[derive(Clone)]
//! struct User { name: String }
//!
//! let cookie_ctx = CookieContext::builder()
//!     .store(MemStore::new())
//!     .build::<User>();
//!
//! let app = Router::new()
//!     .route("/", get(|session: CookieSession<User>| async move {
//!         format!("Hello, {}!", session.state.name)
//!     }))
//!     .layer(cookie_ctx);
//! ```

mod builder;
mod expiry;
mod id;
mod service;
mod session;
mod store;

use std::{borrow::Cow, convert::Infallible, sync::Arc, time::Duration};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
    response::Response,
};

pub use builder::CookieSessionBuilder;
pub use id::SessionId;
pub use session::CookieSession;
pub use store::{CookieStore, MemStore};

pub use cookie_monster::{Cookie, CookieBuilder, CookieJar, Expires, SameSite};
use tokio::task::JoinHandle;

use crate::{cookie::store::ErasedStore, utils::utc_now};

/// Manages server-side sessions identified by a cookie.
///
/// Construct with [`CookieContext::builder`]. Use as a Tower [`Layer`](tower::Layer)
/// to load sessions from incoming requests, then extract [`CookieSession<S>`] in handlers.
///
/// Also implements [`FromRequestParts`] (via [`FromRef`]) so you can extract it
/// in handlers to create or remove sessions.
pub struct CookieContext<S>(Arc<CookieContextInner<S>>);

struct CookieContextInner<S> {
    store: ErasedStore<S>,
    cookie_opts: CookieBuilder,
    session_expiry: Option<Duration>,
    handle: Option<JoinHandle<()>>,
}

impl CookieContext<()> {
    /// Create a [`CookieSessionBuilder`] to configure the session store and cookie options.
    pub fn builder() -> CookieSessionBuilder<()> {
        CookieSessionBuilder::new()
    }
}

impl<S: 'static> CookieContext<S> {
    /// Build a cookie for the given session ID using the configured cookie options.
    pub fn get_cookie(&self, session_id: SessionId) -> Cookie {
        self.0.cookie_opts.clone().value(session_id).build()
    }

    /// Create a new session, store it, and return a `Set-Cookie` cookie.
    pub async fn create_session(&self, state: S) -> Result<Cookie, Response> {
        let session_id = SessionId::new();
        crate::debug!("Storing {session_id:?} in cookie store");
        let now = utc_now().as_secs();
        let session = CookieSession::new(session_id.clone(), now, state);
        self.0.store.store_session(session).await?;

        Ok(self.get_cookie(session_id))
    }

    /// Remove the session identified by the cookie in the given jar.
    pub async fn remove_session_jar(
        &self,
        jar: &CookieJar,
    ) -> Result<Option<CookieSession<S>>, Response> {
        let Some(session_id) = self.session_id_from_jar(jar) else {
            return Ok(None);
        };

        self.0.store.remove_session(&session_id).await
    }

    /// Remove the session identified by the given cookie.
    pub async fn remove_session_cookie(
        &self,
        cookie: &Cookie,
    ) -> Result<Option<CookieSession<S>>, Response> {
        let session_id = SessionId::from_cookie(cookie);
        self.remove_session(&session_id).await
    }

    /// Remove the session with the given ID from the store.
    pub async fn remove_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<CookieSession<S>>, Response> {
        self.0.store.remove_session(session_id).await
    }

    /// Create a cookie builder with the configured options and a custom name.
    pub fn build_cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.cookie_opts.clone().name(name)
    }

    /// Return a reference to the underlying cookie builder.
    pub fn cookie_builder(&self) -> &CookieBuilder {
        &self.0.cookie_opts
    }

    /// Remove all sessions created before `deadline` (Unix timestamp in seconds).
    pub async fn remove_before(&self, deadline: u64) -> Result<(), Response> {
        self.0.store.remove_before(deadline).await
    }

    pub(crate) async fn load_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<CookieSession<S>>, Response> {
        let cookies = CookieJar::from_headers(headers);

        self.load_from_jar(&cookies).await
    }

    pub(crate) async fn load_from_jar(
        &self,
        cookies: &CookieJar,
    ) -> Result<Option<CookieSession<S>>, Response> {
        let Some(session_id) = self.session_id_from_jar(cookies) else {
            return Ok(None);
        };

        self.load_session(&session_id).await
    }

    pub(crate) fn session_id_from_jar(&self, jar: &CookieJar) -> Option<SessionId> {
        let cookie = jar.get(self.0.cookie_opts.get_name())?;

        Some(SessionId::from_cookie(cookie))
    }

    /// Load a session from the store using a cookie's value as the session ID.
    pub async fn load_from_cookie(
        &self,
        cookie: &Cookie,
    ) -> Result<Option<CookieSession<S>>, Response> {
        let session_id = SessionId::from_cookie(cookie);

        self.load_session(&session_id).await
    }

    async fn load_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<CookieSession<S>>, Response> {
        let session = self.0.store.load_session(session_id).await?;

        if let (Some(session), Some(expiry)) = (&session, self.0.session_expiry)
            && expiry::is_expired(session.created_at, expiry)
        {
            self.0.store.remove_session(session_id).await?;
            return Ok(None);
        }

        Ok(session)
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
