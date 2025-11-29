use std::{
    hash::Hash,
    ops::{Deref, DerefMut},
};

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

use crate::cookie::SessionId;

#[derive(Clone)]
#[non_exhaustive]
pub struct CookieSession<S> {
    pub session_id: SessionId,
    pub created_at: u64,
    pub state: S,
}

impl<S> Deref for CookieSession<S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<S> DerefMut for CookieSession<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl<S> CookieSession<S> {
    pub fn new(id: SessionId, created_at: u64, value: S) -> Self {
        Self {
            session_id: id,
            created_at,
            state: value,
        }
    }
}

impl<S> Hash for CookieSession<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.session_id.hash(state)
    }
}

impl<S> Eq for CookieSession<S> {}

impl<S> PartialEq for CookieSession<S> {
    fn eq(&self, other: &Self) -> bool {
        self.session_id == other.session_id
    }
}

impl<S, T> FromRequestParts<S> for CookieSession<T>
where
    S: Send + Sync,
    T: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, StatusCode> {
        if let Some(session) = parts.extensions.remove::<CookieSession<T>>() {
            Ok(session)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
