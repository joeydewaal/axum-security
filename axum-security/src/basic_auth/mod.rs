//! HTTP Basic Authentication middleware and extractor.
//!
//! This module provides [`BasicAuthLayer`], a Tower middleware that decodes the
//! `Authorization: Basic ...` header, calls your [`BasicAuthenticator`] implementation
//! to verify credentials, and stores the authenticated user in request extensions.
//! Use [`BasicAuth<U>`] to extract the user in handlers.
//!
//! # Example
//!
//! ```rust,no_run
//! use axum::{Router, http::StatusCode, routing::get};
//! use axum_security::basic_auth::{BasicAuth, BasicAuthLayer, BasicAuthenticator};
//!
//! #[derive(Clone)]
//! struct User {
//!     username: String,
//! }
//!
//! struct MyAuth;
//!
//! impl BasicAuthenticator for MyAuth {
//!     type User = User;
//!     type Error = StatusCode;
//!
//!     async fn authenticate(
//!         &self,
//!         username: &str,
//!         password: &str,
//!     ) -> Result<Option<User>, StatusCode> {
//!         if username == "admin" && password == "secret" {
//!             Ok(Some(User { username: username.to_owned() }))
//!         } else {
//!             Ok(None)
//!         }
//!     }
//! }
//!
//! async fn hello(BasicAuth(user): BasicAuth<User>) -> String {
//!     format!("Hello, {}!", user.username)
//! }
//!
//! let app = Router::new()
//!     .route("/hello", get(hello))
//!     .layer(BasicAuthLayer::new(MyAuth));
//! ```

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
///
/// # Example
///
/// ```rust
/// use axum::http::StatusCode;
/// use axum_security::basic_auth::BasicAuthenticator;
///
/// #[derive(Clone)]
/// struct User {
///     username: String,
/// }
///
/// struct MyAuth;
///
/// impl BasicAuthenticator for MyAuth {
///     type User = User;
///     type Error = StatusCode;
///
///     async fn authenticate(
///         &self,
///         username: &str,
///         password: &str,
///     ) -> Result<Option<User>, StatusCode> {
///         if username == "admin" && password == "secret" {
///             Ok(Some(User { username: username.to_owned() }))
///         } else {
///             Ok(None)
///         }
///     }
/// }
/// ```
pub trait BasicAuthenticator: Send + Sync {
    type User: Clone + Send + Sync + 'static;
    type Error: IntoResponse + Send + 'static;

    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send;
}

/// Authenticated user extracted from the Basic Auth header.
///
/// Use this as a handler parameter to require authentication. Returns
/// `401 Unauthorized` if no valid credentials were provided.
///
/// For optional authentication, use `Option<BasicAuth<U>>` instead — it
/// never rejects and returns `None` when the user is unauthenticated.
///
/// # Examples
///
/// Require authentication:
///
/// ```rust,ignore
/// async fn handler(BasicAuth(user): BasicAuth<User>) -> String {
///     format!("Hello, {}!", user.username)
/// }
/// ```
///
/// Optional authentication:
///
/// ```rust,ignore
/// async fn handler(auth: Option<BasicAuth<User>>) -> String {
///     if let Some(BasicAuth(user)) = auth {
///         format!("Welcome back, {}!", user.username)
///     } else {
///         "Welcome, guest!".to_owned()
///     }
/// }
/// ```
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
