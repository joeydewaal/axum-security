use std::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    extract::{FromRequestParts, Query},
    http::Request,
    response::{IntoResponse, Response},
};
use cookie_monster::CookieJar;
use serde::Deserialize;
use tower::Service;

use crate::oauth2::{OAuth2Context, OAuth2Handler};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// The callback query, which is either a success (`code` + `state`) or an
/// authorization error (`error` [+ `error_description`/`error_uri`], with the
/// `state` echoed back). `code` is a secret — no Debug derive.
#[derive(Deserialize)]
pub struct OAuth2Params {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
    pub(crate) error_uri: Option<String>,
}

pub(crate) struct OAuth2RedirectService<H> {
    context: OAuth2Context<H>,
}

impl<H> Clone for OAuth2RedirectService<H> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}

impl<H> OAuth2RedirectService<H> {
    pub(crate) fn new(context: OAuth2Context<H>) -> Self {
        Self { context }
    }
}

impl<H: OAuth2Handler> Service<Request<Body>> for OAuth2RedirectService<H> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move {
            let (mut parts, _body) = req.into_parts();

            let query = match Query::<OAuth2Params>::from_request_parts(&mut parts, &()).await {
                Ok(Query(params)) => params,
                Err(rejection) => return Ok(rejection.into_response()),
            };

            let jar = match CookieJar::from_request_parts(&mut parts, &()).await {
                Ok(jar) => jar,
                Err(rejection) => return Ok(rejection.into_response()),
            };

            Ok(context.on_callback(jar, query).await)
        })
    }
}

pub(crate) struct OAuth2LoginService<H> {
    context: OAuth2Context<H>,
}

impl<H> Clone for OAuth2LoginService<H> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}

impl<H> OAuth2LoginService<H> {
    pub(crate) fn new(context: OAuth2Context<H>) -> Self {
        Self { context }
    }
}

impl<H: OAuth2Handler> Service<Request<Body>> for OAuth2LoginService<H> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move { Ok(context.start_challenge().await) })
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::StatusCode, response::IntoResponse};
    use tower::ServiceExt;

    use crate::oauth2::{
        AfterLoginCookies, OAuth2Context, OAuth2Handler, TokenResponse, providers::github,
    };

    use super::{OAuth2LoginService, OAuth2RedirectService};

    const CLIENT_ID: &str = "test_client_id";
    const CLIENT_SECRET: &str = "test_client_secret";
    const REDIRECT_URL: &str = "http://rust-lang.org/redirect";
    const AUTH_URL: &str = github::AUTH_URL;
    const TOKEN_URL: &str = github::TOKEN_URL;

    struct TestHandler;

    impl OAuth2Handler for TestHandler {
        async fn after_login(
            &self,
            _token_res: TokenResponse,
            _context: &mut AfterLoginCookies<'_>,
        ) -> impl IntoResponse {
            ()
        }
    }

    fn test_context() -> OAuth2Context<TestHandler> {
        OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .random_cookie_secret()
            .build(TestHandler)
    }

    #[tokio::test]
    async fn login_service_returns_redirect() {
        let service = OAuth2LoginService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("github.com"));
    }

    #[tokio::test]
    async fn login_redirect_carries_auth_params() {
        let context = OAuth2Context::google()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .redirect_url(REDIRECT_URL)
            .auth_param("access_type", "offline")
            .auth_param("prompt", "consent")
            .random_cookie_secret()
            .build(TestHandler);

        let service = OAuth2LoginService::new(context);
        let req = axum::http::Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("accounts.google.com"), "{location}");
        assert!(location.contains("access_type=offline"), "{location}");
        assert!(location.contains("prompt=consent"), "{location}");
    }

    #[tokio::test]
    async fn redirect_service_rejects_missing_params() {
        let service = OAuth2RedirectService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/redirect")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn redirect_service_rejects_invalid_state() {
        let service = OAuth2RedirectService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/redirect?code=test_code&state=invalid_state")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    /// A provider error on the callback (RFC 6749 §4.1.2.1) reaches
    /// `on_error`, which by default returns `401`.
    #[tokio::test]
    async fn redirect_service_default_on_error_is_unauthorized() {
        let service = OAuth2RedirectService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/redirect?error=access_denied&state=whatever")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    /// A handler can override `on_error` to render its own response, and the
    /// reported error code reaches it.
    #[tokio::test]
    async fn redirect_service_custom_on_error() {
        use crate::oauth2::AuthorizationErrorResponse;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct ErrHandler(Arc<Mutex<Option<String>>>);

        impl OAuth2Handler for ErrHandler {
            async fn after_login(
                &self,
                _token_res: TokenResponse,
                _context: &mut AfterLoginCookies<'_>,
            ) -> impl IntoResponse {
                ()
            }

            async fn on_error(&self, error: AuthorizationErrorResponse) -> impl IntoResponse {
                *self.0.lock().unwrap() = Some(error.error);
                StatusCode::IM_A_TEAPOT
            }
        }

        let seen = Arc::new(Mutex::new(None));
        let context = OAuth2Context::builder("github")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .redirect_url(REDIRECT_URL)
            .random_cookie_secret()
            .build(ErrHandler(seen.clone()));

        let service = OAuth2RedirectService::new(context);
        let req = axum::http::Request::builder()
            .uri("/redirect?error=access_denied&error_description=nope&state=x")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(seen.lock().unwrap().as_deref(), Some("access_denied"));
    }
}
