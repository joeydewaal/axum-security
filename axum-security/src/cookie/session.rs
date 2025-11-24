use std::hash::Hash;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

use crate::cookie::SessionId;

#[derive(Clone)]
#[non_exhaustive]
pub struct CookieSession<S> {
    pub id: SessionId,
    pub state: S,
}

impl<S> CookieSession<S> {
    pub fn new(id: SessionId, value: S) -> Self {
        Self { id, state: value }
    }
}

impl<S> Hash for CookieSession<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl<S> Eq for CookieSession<S> {}

impl<S> PartialEq for CookieSession<S> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
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
