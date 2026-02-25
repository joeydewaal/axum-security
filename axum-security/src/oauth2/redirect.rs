use std::{convert::Infallible, future::Future, pin::Pin};

use axum::{
    body::Body,
    extract::{FromRequestParts, Query},
    response::{IntoResponse, Response},
};
use cookie_monster::CookieJar;
use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;
use tower::Service;

use crate::oauth2::{OAuth2Context, OAuth2Handler};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Deserialize, Debug)]
pub struct OAuth2Params {
    code: AuthorizationCode,
    state: CsrfToken,
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

impl<H: OAuth2Handler> Service<axum::http::Request<Body>> for OAuth2RedirectService<H> {
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

            let query = match Query::<OAuth2Params>::from_request_parts(&mut parts, &()).await {
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

impl<H: OAuth2Handler> Service<axum::http::Request<Body>> for OAuth2LoginService<H> {
    type Response = Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Response, Infallible>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: axum::http::Request<Body>) -> Self::Future {
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
}
