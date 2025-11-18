use axum::{
    Extension, Router, extract::Request, middleware::Next, response::Response,
    routing::MethodRouter,
};
use serde::de::DeserializeOwned;

use crate::{
    cookie::{CookieContext, CookieStore},
    jwt::{Jwt, JwtContext},
    oauth2::{OAuth2Context, OAuth2Handler, OAuthSessionState, callback, start_login},
};

pub trait AuthInjector {
    fn inject_into_router<S: Send + Sync + Clone + 'static>(self, router: Router<S>) -> Router<S>;
}

pub trait RouterExt<S> {
    fn with_auth(self, auth: impl AuthInjector) -> Router<S>;
}

impl<S> RouterExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_auth(self, auth: impl AuthInjector) -> Router<S> {
        auth.inject_into_router(self)
    }
}
