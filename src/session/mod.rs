use std::hash::Hash;

mod cookie;
mod id;
mod jwt;

pub use cookie::{CookieSession, CookieSessionBuilder};
pub use id::SessionId;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

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

pub trait HttpSession: Send + Sync + 'static {
    type State: Send + Sync + 'static;

    fn load_from_request_parts(
        &self,
        parts: &mut Parts,
    ) -> impl Future<Output = Option<Session<Self::State>>> + Send;
}
