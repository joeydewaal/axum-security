use std::hash::Hash;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

use crate::cookie::SessionId;

#[derive(Clone)]
pub struct CookieSession<S> {
    id: SessionId,
    value: S,
}

impl<S> CookieSession<S> {
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

impl<S> Hash for CookieSession<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state)
    }
}

impl<S> Eq for CookieSession<S> {}

impl<S> PartialEq for CookieSession<S> {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl<S: Send + Sync, T: Send + Sync + 'static> FromRequestParts<S> for CookieSession<T> {
    type Rejection = StatusCode;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, StatusCode> {
        if let Some(session) = parts.extensions.remove::<CookieSession<T>>() {
            Ok(session)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
