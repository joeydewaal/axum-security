use axum::{
    extract::FromRequestParts,
    http::{Extensions, StatusCode, request::Parts},
};

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
    pub fn insert_into(self, extensions: &mut Extensions) {
        match self {
            #[cfg(feature = "jwt")]
            Self::Jwt(jwt) => extensions.insert(jwt),
            #[cfg(feature = "cookie")]
            Self::Cookie(c) => extensions.insert(c),
            #[cfg(feature = "basic-auth")]
            Self::Basic(b) => extensions.insert(b),
        };
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

impl<S: Sync, U: Clone + Send + Sync + 'static> FromRequestParts<S> for Session<U> {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, StatusCode> {
        #[cfg(feature = "jwt")]
        if let Some(jwt) = parts.extensions.remove::<crate::jwt::Jwt<U>>() {
            return Ok(Session::Jwt(jwt));
        }

        #[cfg(feature = "cookie")]
        if let Some(c) = parts.extensions.remove::<crate::cookie::CookieSession<U>>() {
            return Ok(Session::Cookie(c));
        }

        #[cfg(feature = "basic-auth")]
        if let Some(b) = parts.extensions.remove::<crate::basic_auth::BasicAuth<U>>() {
            return Ok(Session::Basic(b));
        }

        Err(StatusCode::UNAUTHORIZED)
    }
}
