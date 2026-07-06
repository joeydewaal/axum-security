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

use super::{OidcContext, OidcHandler};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Deserialize, Debug)]
pub struct OidcParams {
    code: String,
    state: String,
}

pub(crate) struct OidcRedirectService<H: OidcHandler> {
    context: OidcContext<H>,
}

impl<H: OidcHandler> Clone for OidcRedirectService<H> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}

impl<H: OidcHandler> OidcRedirectService<H> {
    pub(crate) fn new(context: OidcContext<H>) -> Self {
        Self { context }
    }
}

impl<H: OidcHandler> Service<Request<Body>> for OidcRedirectService<H> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: axum::http::Request<Body>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move {
            let (mut parts, _body) = req.into_parts();

            let query = match Query::<OidcParams>::from_request_parts(&mut parts, &()).await {
                Ok(Query(params)) => params,
                Err(rejection) => return Ok(rejection.into_response()),
            };

            let jar = match CookieJar::from_request_parts(&mut parts, &()).await {
                Ok(jar) => jar,
                Err(rejection) => return Ok(rejection.into_response()),
            };

            Ok(context.on_redirect(jar, query.code, query.state).await)
        })
    }
}

pub(crate) struct OidcLogoutService<H: OidcHandler> {
    context: OidcContext<H>,
}

impl<H: OidcHandler> Clone for OidcLogoutService<H> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}

impl<H: OidcHandler> OidcLogoutService<H> {
    pub(crate) fn new(context: OidcContext<H>) -> Self {
        Self { context }
    }
}

impl<H: OidcHandler> Service<Request<Body>> for OidcLogoutService<H> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move {
            let (parts, _) = _req.into_parts();
            let logout_context = context.build_logout_context(parts.extensions);
            Ok(context
                .0
                .handler
                .logout(logout_context)
                .await
                .into_response())
        })
    }
}

pub(crate) struct OidcLoginService<H: OidcHandler> {
    context: OidcContext<H>,
}

impl<H: OidcHandler> Clone for OidcLoginService<H> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
        }
    }
}

impl<H: OidcHandler> OidcLoginService<H> {
    pub(crate) fn new(context: OidcContext<H>) -> Self {
        Self { context }
    }
}

impl<H: OidcHandler> Service<Request<Body>> for OidcLoginService<H> {
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

    use crate::{
        after_login::AfterLoginCookies,
        oidc::{OidcContext, OidcHandler, OidcTokenResponse},
    };

    use super::{OidcLoginService, OidcRedirectService};

    const CLIENT_ID: &str = "test_client_id";
    const CLIENT_SECRET: &str = "test_client_secret";
    const REDIRECT_URL: &str = "http://localhost:3000/auth/callback";
    const ISSUER_URL: &str = "https://accounts.google.com";
    const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

    struct TestHandler;

    impl OidcHandler for TestHandler {
        async fn after_login(
            &self,
            _token_res: OidcTokenResponse<'_>,
            _context: &mut AfterLoginCookies<'_>,
        ) -> impl IntoResponse {
            ()
        }
    }

    fn test_context() -> OidcContext<TestHandler> {
        OidcContext::builder("google")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .issuer_url(ISSUER_URL)
            .auth_url(AUTH_URL)
            .token_url(TOKEN_URL)
            .jwks_url(JWKS_URL)
            .redirect_url(REDIRECT_URL)
            .random_cookie_secret()
            .build(TestHandler)
    }

    #[tokio::test]
    async fn login_service_returns_redirect() {
        let service = OidcLoginService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("accounts.google.com"));
    }

    #[tokio::test]
    async fn redirect_service_rejects_missing_params() {
        let service = OidcRedirectService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/redirect")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn redirect_service_rejects_invalid_state() {
        let service = OidcRedirectService::new(test_context());
        let req = axum::http::Request::builder()
            .uri("/redirect?code=test_code&state=invalid_state")
            .body(Body::empty())
            .unwrap();

        let res = service.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
}
