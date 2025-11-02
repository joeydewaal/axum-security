use std::{borrow::Cow, hash::Hash};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use cookie_monster::{Cookie, CookieJar};
use uuid::Uuid;

#[derive(Hash, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    pub fn new_uuid_v7() -> Self {
        SessionId(Uuid::now_v7().to_string())
    }

    pub fn from_cookie(cookie: &Cookie) -> Self {
        SessionId(cookie.value().to_string())
    }
}

impl From<SessionId> for Cow<'static, str> {
    fn from(value: SessionId) -> Self {
        Cow::Owned(value.0)
    }
}

#[derive(Clone)]
pub struct Session<S> {
    id: SessionId,
    value: S,
}

impl<S> Session<S> {
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn new(id: SessionId, value: S) -> Self {
        Self { id, value }
    }

    pub fn state(&self) -> &S {
        &self.value
    }

    pub fn into_state(self) -> S {
        self.value
    }
}

pub trait SessionStore: Send + Sync + 'static {
    type State: Send + Sync + 'static;

    fn store_session(&self, session: Session<Self::State>) -> impl Future<Output = ()> + Send;

    fn remove_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Option<Session<Self::State>>> + Send;

    fn load_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Option<Session<Self::State>>> + Send {
        async { None }
    }
}

impl<S> Hash for Session<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl<S> Eq for Session<S> {}

impl<S> PartialEq for Session<S> {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl<S: Send + Sync, T: Send + Sync + 'static> FromRequestParts<S> for Session<T> {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, StatusCode> {
        if let Some(session) = parts.extensions.remove::<Session<T>>() {
            Ok(session)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
