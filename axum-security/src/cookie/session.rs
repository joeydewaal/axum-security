use std::hash::Hash;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

use crate::cookie::SessionId;

#[derive(Clone, Debug)]
pub struct CookieSession<S> {
    pub session_id: SessionId,
    pub created_at: u64,
    pub state: S,
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

#[cfg(test)]
mod extract_cookie {
    use axum::{
        extract::FromRequestParts,
        http::{Request, StatusCode},
    };

    use crate::cookie::{CookieSession, SessionId};

    #[tokio::test]
    async fn extract() {
        let cookie = CookieSession::new(SessionId::new(), 0, ());

        let (mut parts, _) = Request::builder()
            .extension(cookie.clone())
            .body(())
            .unwrap()
            .into_parts();

        let extracted_cookie = CookieSession::<()>::from_request_parts(&mut parts, &())
            .await
            .unwrap();

        assert!(cookie.session_id == extracted_cookie.session_id);
        assert!(cookie.created_at == extracted_cookie.created_at);
    }

    #[tokio::test]
    async fn extract_rejection() {
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();

        let rejection = CookieSession::<()>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();

        assert!(rejection == StatusCode::UNAUTHORIZED);
    }
}
