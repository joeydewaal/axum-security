#![cfg(feature = "basic-auth")]

use std::{convert::Infallible, error::Error, net::SocketAddr};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
    routing::get,
};
use axum_security::basic_auth::{BasicAuth, BasicAuthLayer, BasicAuthenticator};
use reqwest::Client;
use tokio::net::TcpListener;
use tower::Service;

struct ErrorAuth;

impl BasicAuthenticator for ErrorAuth {
    type User = String;
    type Error = (StatusCode, &'static str);

    async fn authenticate(
        &self,
        _username: &str,
        _password: &str,
    ) -> Result<Option<String>, (StatusCode, &'static str)> {
        Err((StatusCode::INTERNAL_SERVER_ERROR, "db unavailable"))
    }
}
struct TestAuth;

impl BasicAuthenticator for TestAuth {
    type User = String;
    type Error = Infallible;

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<String>, Infallible> {
        Ok((password == "secret").then(|| username.to_owned()))
    }
}

fn make_basic_header(username: &str, password: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    let encoded = BASE64.encode(format!("{username}:{password}"));
    format!("Basic {encoded}")
}

async fn require_auth(BasicAuth(user): BasicAuth<String>) -> String {
    user
}

async fn optional_auth(auth: Option<BasicAuth<String>>) -> StatusCode {
    if auth.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    }
}

fn test_router() -> Router<()> {
    Router::new()
        .route("/required", get(require_auth))
        .route("/optional", get(optional_auth))
        .layer(BasicAuthLayer::new(TestAuth))
}

#[tokio::test]
async fn valid_credentials_returns_200() -> Result<(), Box<dyn Error>> {
    let mut router = test_router();

    let req = Request::get("/required")
        .header(AUTHORIZATION, make_basic_header("alice", "secret"))
        .body(Body::empty())?;

    let res = router.call(req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn auth_scheme_is_case_insensitive() -> Result<(), Box<dyn Error>> {
    let mut router = test_router();
    let header = make_basic_header("alice", "secret").replacen("Basic", "basic", 1);
    let req = Request::get("/required")
        .header(AUTHORIZATION, header)
        .body(Body::empty())?;

    let res = router.call(req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn missing_header_returns_401() -> Result<(), Box<dyn Error>> {
    let mut router = test_router();

    let req = Request::get("/required").body(Body::empty())?;

    let res = router.call(req).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn wrong_password_returns_401() -> Result<(), Box<dyn Error>> {
    let mut router = test_router();

    let req = Request::get("/required")
        .header(AUTHORIZATION, make_basic_header("alice", "wrong"))
        .body(Body::empty())?;

    let res = router.call(req).await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn optional_auth_none_for_unauthenticated() -> Result<(), Box<dyn Error>> {
    let mut router = test_router();

    let req = Request::get("/optional").body(Body::empty())?;

    let res = router.call(req).await?;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn optional_auth_some_for_authenticated() -> Result<(), Box<dyn Error>> {
    let mut router = test_router();

    let req = Request::get("/optional")
        .header(AUTHORIZATION, make_basic_header("bob", "secret"))
        .body(Body::empty())?;

    let res = router.call(req).await?;
    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

struct TestServer {
    addr: SocketAddr,
}

impl TestServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async { axum::serve(listener, test_router()).await });
        Self { addr }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

#[tokio::test]
async fn reqwest_valid_credentials() -> Result<(), Box<dyn Error>> {
    let server = TestServer::start().await;
    let client = Client::new();

    let res = client
        .get(server.url("/required"))
        .basic_auth("alice", Some("secret"))
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn reqwest_missing_header() -> Result<(), Box<dyn Error>> {
    let server = TestServer::start().await;
    let client = Client::new();

    let res = client.get(server.url("/required")).send().await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn reqwest_wrong_password() -> Result<(), Box<dyn Error>> {
    let server = TestServer::start().await;
    let client = Client::new();

    let res = client
        .get(server.url("/required"))
        .basic_auth("alice", Some("wrong"))
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn reqwest_optional_unauthenticated() -> Result<(), Box<dyn Error>> {
    let server = TestServer::start().await;
    let client = Client::new();

    let res = client.get(server.url("/optional")).send().await?;

    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn reqwest_authenticator_error_returns_500() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route("/", get(|| async { StatusCode::OK }))
        .layer(BasicAuthLayer::new(ErrorAuth));
    tokio::spawn(async { axum::serve(listener, router).await });

    let res = Client::new()
        .get(format!("http://{addr}/"))
        .basic_auth("alice", Some("secret"))
        .send()
        .await?;

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}
