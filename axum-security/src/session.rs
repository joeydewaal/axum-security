//! Unified session type across authentication methods.
//!
//! [`Session<U>`] is an enum that wraps the user type from whichever
//! authentication layer ran: JWT, cookie, or basic auth. It implements
//! [`Deref`](std::ops::Deref) to `U`, so you can access the inner user
//! directly.
//!
//! This type is used internally by the [`rbac`](crate::rbac),
//! [`pbac`](crate::pbac) module to work with any authentication method.
//!
//! You can also use it as a handler extractor when you support multiple
//! auth methods and don't care which one was used.

use axum::{
    extract::FromRequestParts,
    http::{Extensions, StatusCode, request::Parts},
};

/// A session extracted from request extensions, wrapping the authenticated user.
///
/// Variants are gated behind their respective features (`jwt`, `cookie`, `basic-auth`).
/// Implements `Deref<Target = U>` for direct access to the inner user type.
///
/// Returns `401 Unauthorized` when used as a handler extractor if no session is present.
#[derive(Clone)]
pub enum Session<U> {
    #[cfg(feature = "jwt")]
    Jwt(crate::jwt::Jwt<U>),
    #[cfg(feature = "cookie")]
    Cookie(crate::cookie::CookieSession<U>),
    #[cfg(feature = "basic-auth")]
    Basic(crate::basic_auth::BasicAuth<U>),
}

impl<U: Clone + Send + Sync + 'static> Session<U> {
    /// Extract a session from request extensions, trying each enabled auth method.
    pub fn from_extensions(extensions: &mut Extensions) -> Option<Session<U>> {
        #[cfg(feature = "jwt")]
        if let Some(jwt) = extensions.remove::<crate::jwt::Jwt<U>>() {
            return Some(Session::Jwt(jwt));
        }

        #[cfg(feature = "cookie")]
        if let Some(c) = extensions.remove::<crate::cookie::CookieSession<U>>() {
            return Some(Session::Cookie(c));
        }

        #[cfg(feature = "basic-auth")]
        if let Some(b) = extensions.remove::<crate::basic_auth::BasicAuth<U>>() {
            return Some(Session::Basic(b));
        }

        None
    }

    /// Re-insert this session into request extensions (restores the original variant).
    pub fn insert_into(self, extensions: &mut Extensions) {
        match self {
            #[cfg(feature = "jwt")]
            Self::Jwt(jwt) => {
                extensions.insert(jwt);
            }
            #[cfg(feature = "cookie")]
            Self::Cookie(c) => {
                extensions.insert(c);
            }
            #[cfg(feature = "basic-auth")]
            Self::Basic(b) => {
                extensions.insert(b);
            }
        };
    }
}

impl<S: Sync, U: Clone + Send + Sync + 'static> FromRequestParts<S> for Session<U> {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        Session::from_extensions(&mut parts.extensions).ok_or(StatusCode::UNAUTHORIZED)
    }
}
impl<U> std::ops::Deref for Session<U> {
    type Target = U;

    fn deref(&self) -> &U {
        match self {
            #[cfg(feature = "jwt")]
            Self::Jwt(jwt) => &jwt.0,
            #[cfg(feature = "cookie")]
            Self::Cookie(c) => &c.state,
            #[cfg(feature = "basic-auth")]
            Self::Basic(b) => &b.0,
        }
    }
}

impl<U> std::ops::DerefMut for Session<U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            #[cfg(feature = "jwt")]
            Self::Jwt(jwt) => &mut jwt.0,
            #[cfg(feature = "cookie")]
            Self::Cookie(c) => &mut c.state,
            #[cfg(feature = "basic-auth")]
            Self::Basic(b) => &mut b.0,
        }
    }
}
