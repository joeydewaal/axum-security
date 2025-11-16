use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};

#[derive(Clone)]
pub struct JwtSession<T>(pub T);

impl<S, T> FromRequestParts<S> for JwtSession<T>
where
    S: Send + Sync,
    T: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(session) = parts.extensions.remove::<JwtSession<T>>() {
            Ok(session)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
