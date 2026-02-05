use std::{borrow::Cow, pin::Pin};

use axum::response::{IntoResponse, Response};
use cookie_monster::{CookieBuilder, CookieJar};

pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub trait OAuth2Handler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: TokenResponse,
        _context: AfterLoginContext<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}

pub struct AfterLoginContext<'a> {
    pub cookies: &'a mut CookieJar,
    pub(crate) cookie_opts: &'a CookieBuilder,
}

impl AfterLoginContext<'_> {
    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.cookie_opts.clone().name(name)
    }
}

trait DynOAuth2Handler: Send + Sync + 'static {
    fn after_login_boxed<'a>(
        &'a self,
        token_res: TokenResponse,
        context: AfterLoginContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>>;
}

impl<T> DynOAuth2Handler for T
where
    T: OAuth2Handler,
{
    fn after_login_boxed<'a>(
        &'a self,
        token_res: TokenResponse,
        context: AfterLoginContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
        Box::pin(async move { self.after_login(token_res, context).await.into_response() })
    }
}

pub(crate) struct ErasedOAuth2Handler(Box<dyn DynOAuth2Handler>);

impl ErasedOAuth2Handler {
    pub fn new<T: OAuth2Handler>(handler: T) -> Self {
        Self(Box::new(handler))
    }

    pub async fn after_login<'a>(
        &'a self,
        res: TokenResponse,
        context: AfterLoginContext<'a>,
    ) -> Response {
        self.0.after_login_boxed(res, context).await
    }
}
