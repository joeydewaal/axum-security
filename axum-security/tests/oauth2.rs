#![cfg(feature = "oauth2")]

use std::error::Error;
use tower::ServiceExt;

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode},
};
use axum_security::oauth2::{OAuth2Context, OAuth2Ext, OAuth2Handler, providers::github};
use serde::Deserialize;
use url::Url;

const CLIENT_ID: &str = "test_client_id";
const CLIENT_SECRET: &str = "test_client_secret";
const REDIRECT_URL: &str = "http://rust-lang.org/redirect";
const AUTH_URL: &str = github::AUTH_URL;
const TOKEN_URL: &str = github::TOKEN_URL;

struct TestHandler;

impl OAuth2Handler for TestHandler {
    async fn after_login(
        &self,
        _token_res: axum_security::oauth2::TokenResponse,
        _context: &mut axum_security::oauth2::AfterLoginContext<'_>,
    ) -> impl axum::response::IntoResponse {
        ()
    }
}

#[allow(unused)]
#[derive(Deserialize)]
struct PkceQueryParams {
    client_id: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    redirect_uri: String,
}

async fn is_pkce_start(res: Response<Body>) -> Result<(), Box<dyn Error>> {
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    let location = &res.headers()["location"];
    let url = Url::parse(location.to_str()?)?;

    let params: PkceQueryParams = serde_urlencoded::from_str(url.query().unwrap())?;

    assert_eq!(params.client_id, CLIENT_ID);
    assert_eq!(params.redirect_uri, REDIRECT_URL);
    Ok(())
}

#[tokio::test]
async fn basic() -> Result<(), Box<dyn Error>> {
    let oauth2_context = OAuth2Context::builder()
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .redirect_url(REDIRECT_URL)
        .auth_url(AUTH_URL)
        .token_url(TOKEN_URL)
        .build(TestHandler);

    let res = oauth2_context.start_challenge().await;
    is_pkce_start(res).await?;

    Ok(())
}

#[tokio::test]
async fn login_path() -> Result<(), Box<dyn Error>> {
    const LOGIN_PATH: &str = "/login-testing";

    let oauth2_context = OAuth2Context::builder()
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .redirect_url(REDIRECT_URL)
        .auth_url(AUTH_URL)
        .token_url(TOKEN_URL)
        .login_path(LOGIN_PATH)
        .build(TestHandler);

    let router = Router::<()>::new().with_oauth2(oauth2_context);

    let req = Request::get(LOGIN_PATH).body(Body::empty())?;

    let res = router.oneshot(req).await?;

    is_pkce_start(res).await?;
    Ok(())
}
