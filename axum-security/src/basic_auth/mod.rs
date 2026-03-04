mod layer;
pub use layer::{BasicAuthLayer, BasicAuthService};

use std::{convert::Infallible, future::Future};

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{Extensions, StatusCode, request::Parts},
    response::IntoResponse,
};

/// Implement this trait to verify Basic Auth credentials.
///
/// Return `Ok(Some(user))` on success, `Ok(None)` when credentials are wrong,
/// and `Err(e)` when the verification itself fails (e.g. database error).
pub trait BasicAuthenticator: Send + Sync {
    type User: Clone + Send + Sync + 'static;
    type Error: IntoResponse + Send + 'static;

    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;
}

/// Holds the authenticated user extracted from the Basic Auth header.
/// Put this in handler parameters to require authentication.
#[derive(Clone, Debug)]
pub struct BasicAuth<U>(pub U);

impl<U: Send + Sync + 'static> BasicAuth<U> {
    fn from_extensions(ext: &mut Extensions) -> Option<Self> {
        ext.remove()
    }
}

impl<S, U> FromRequestParts<S> for BasicAuth<U>
where
    S: Send + Sync,
    U: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Self::from_extensions(&mut parts.extensions).ok_or(StatusCode::UNAUTHORIZED)
    }
}

impl<S, U> OptionalFromRequestParts<S> for BasicAuth<U>
where
    S: Send + Sync,
    U: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(Self::from_extensions(&mut parts.extensions))
    }
}
