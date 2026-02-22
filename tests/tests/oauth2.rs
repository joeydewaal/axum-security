#![cfg(feature = "oauth2")]

use base64::{Engine as _, engine::general_purpose};
use reqwest::{Client, redirect::Policy};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use tower::ServiceExt;

use axum::{
    Router,
    body::Body,
    http::{Request, Response, StatusCode},
};
use axum_security::oauth2::{OAuth2Context, OAuth2Ext, OAuth2Handler, providers::github};
use serde::{Deserialize, Serialize};
use url::Url;
use wiremock::{
    Mock, MockServer, Request as WireRequest, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "test_client_id";
const CLIENT_SECRET: &str = "test_client_secret";
const REDIRECT_URL: &str = "http://localhost/redirect";
const AUTH_URL: &str = github::AUTH_URL;
const TOKEN_URL: &str = github::TOKEN_URL;
const LOGIN_PATH: &str = "/login-testing";
const REDIRECT_PATH: &str = "/redirect";

struct TestHandler;

impl OAuth2Handler for TestHandler {
    async fn after_login(
        &self,
        _token_res: axum_security::oauth2::TokenResponse,
        _context: &mut axum_security::oauth2::AfterLoginCookies<'_>,
    ) -> impl axum::response::IntoResponse {
        StatusCode::CREATED
    }
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
struct PkceQueryParams {
    client_id: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
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
    let oauth2_context = OAuth2Context::builder("test")
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
async fn basic_login_path() -> Result<(), Box<dyn Error>> {
    let oauth2_context = OAuth2Context::builder("test")
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

    is_pkce_start(res).await
}

#[allow(unused)]
#[derive(Clone)]
struct ChallengeData {
    code_challenge: Option<String>,
    client_id: String,
    redirect_uri: String,
}

type ChallengeStore = Arc<Mutex<HashMap<String, ChallengeData>>>;

async fn install_mock_oauth_server(pkce: bool) -> (MockServer, String, String) {
    const AUTH_URL_PATH: &str = "/oauth2/authorize";
    const TOKEN_URL_PATH: &str = "/oauth2/access_token";

    let mock_server = MockServer::start().await;

    let auth_url = format!("http://{}{AUTH_URL_PATH}", mock_server.address());
    let token_url = format!("http://{}{TOKEN_URL_PATH}", mock_server.address());

    let oauth_state: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
    let oauth_state_token = oauth_state.clone();
    let oauth_state_exchange = oauth_state.clone();

    Mock::given(method("GET"))
        .and(path(AUTH_URL_PATH))
        .respond_with(move |req: &WireRequest| {
            tracing::debug!("oauth2: auth url");

            if pkce {
                let query = req.url.query().unwrap();
                assert!(query.contains("response_type=code"));
                assert!(query.contains("code_challenge_method=S256"));
            }

            let Some(query) = req.url.query() else {
                tracing::debug!("no query found in url");
                return ResponseTemplate::new(400);
            };

            let Ok(pkce_params) = serde_urlencoded::from_str::<PkceQueryParams>(query) else {
                tracing::debug!("could not deseerialize query params");
                return ResponseTemplate::new(400);
            };

            if pkce_params.client_id != CLIENT_ID {
                tracing::debug!("client_id doesn't match");
                return ResponseTemplate::new(400);
            }

            let auth_code = format!("AUTH_CODE_{}", uuid::Uuid::now_v7());

            if pkce {
                assert!(pkce_params.code_challenge.is_some());
                assert!(pkce_params.code_challenge_method.is_some());
            }

            {
                let mut challenges = oauth_state_token.lock().unwrap();
                challenges.insert(
                    auth_code.clone(),
                    ChallengeData {
                        code_challenge: pkce_params.code_challenge.clone(),
                        client_id: pkce_params.client_id.clone(),
                        redirect_uri: pkce_params.redirect_uri.clone(),
                    },
                );
            }

            let redirect_url = format!(
                "{}?code={}&state={}",
                pkce_params.redirect_uri, auth_code, pkce_params.state
            );

            ResponseTemplate::new(302).insert_header("Location", redirect_url)
        })
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path(TOKEN_URL_PATH))
        .respond_with(move |req: &WireRequest| {
            tracing::debug!("oauth2: token url");

            let auth_header = req
                .headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok());

            if let Some(header) = auth_header {
                if !header.starts_with("Basic ") {
                    return ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Basic");
                }

                let encoded = &header[6..];
                let decoded = general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());

                let expected_creds = format!("{}:{}", CLIENT_ID, CLIENT_SECRET);
                if decoded != Some(expected_creds) {
                    return ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Basic");
                }
            } else {
                return ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Basic");
            }

            let body = std::str::from_utf8(&req.body).unwrap();

            #[allow(unused)]
            #[derive(Debug, Deserialize)]
            struct TokenUrlParams {
                grant_type: String,
                code: String,
                redirect_uri: String,
                code_verifier: Option<String>,
            }

            let Ok(params) = serde_urlencoded::from_str::<TokenUrlParams>(body) else {
                return ResponseTemplate::new(400);
            };

            let challenge_data = {
                let challenges = oauth_state_exchange.lock().unwrap();
                challenges.get(&params.code).cloned()
            };

            let Some(challenge_data) = challenge_data else {
                return ResponseTemplate::new(400);
            };

            if challenge_data.redirect_uri != params.redirect_uri {
                return ResponseTemplate::new(400);
            }

            if let Some(code_challenge) = challenge_data.code_challenge && let Some(verifier) = &params.code_verifier
                && pkce
            {
            let computed_challenge = generate_code_challenge(verifier);
                if computed_challenge != code_challenge {
                    tracing::error!("PKCE validation failed: expected={code_challenge}, computed={computed_challenge}");
                    return ResponseTemplate::new(400);
                }
            }

            tracing::debug!("PKCE validation passed!");

            {
                let mut challenges = oauth_state_exchange.lock().unwrap();
                challenges.remove(&params.code);
            }

            #[derive(Serialize)]
            struct TokenResp {
                access_token: String,
                token_type: &'static str,
                expires_in: i32,
            }

            ResponseTemplate::new(200).set_body_json(TokenResp {
                access_token: "my-token".into(),
                token_type: "Bearer",
                expires_in: 1000,
            })
        })
        .mount(&mock_server)
        .await;

    (mock_server, auth_url, token_url)
}

fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

struct TestServer {
    _mock: MockServer,
    addr: SocketAddr,
}

impl TestServer {
    async fn pkce() -> Self {
        Self::build(true).await
    }

    async fn authorization_code() -> Self {
        Self::build(false).await
    }

    async fn build(pkce: bool) -> Self {
        let (mock, auth_url, token_url) = install_mock_oauth_server(pkce).await;
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let redirect_url = format!("http://{addr}{REDIRECT_PATH}");

        let mut builder = OAuth2Context::builder("test")
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .redirect_url(redirect_url)
            .auth_url(auth_url)
            .token_url(token_url)
            .login_path(LOGIN_PATH)
            .use_dev_cookies(true);

        if !pkce {
            builder = builder.authorization_code_flow();
        }

        let router = Router::<()>::new().with_oauth2(builder.build(TestHandler));
        tokio::spawn(async { axum::serve(socket, router).await });
        TestServer { _mock: mock, addr }
    }

    fn cookie_client(&self) -> Client {
        Client::builder()
            .redirect(Policy::none())
            .cookie_store(true)
            .build()
            .unwrap()
    }

    fn bare_client(&self) -> Client {
        Client::builder().redirect(Policy::none()).build().unwrap()
    }

    fn login_url(&self) -> String {
        format!("http://{}{LOGIN_PATH}", self.addr)
    }

    async fn login_to_callback(&self, client: &Client) -> String {
        let res = client.get(self.login_url()).send().await.unwrap();
        let oauth_url = res.headers()["location"].to_str().unwrap().to_owned();
        let res = client.get(&oauth_url).send().await.unwrap();
        res.headers()["location"].to_str().unwrap().to_owned()
    }

    async fn complete_login(&self, client: &Client) -> reqwest::Response {
        let callback_url = self.login_to_callback(client).await;
        client.get(&callback_url).send().await.unwrap()
    }
}

#[tokio::test]
async fn login_path() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::pkce().await;
    let client = server.cookie_client();
    assert_eq!(
        server.complete_login(&client).await.status(),
        StatusCode::CREATED
    );
    Ok(())
}

#[tokio::test]
async fn invalid_state() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::pkce().await;
    let client = server.cookie_client();
    let callback_url = server.login_to_callback(&client).await;

    let mut url = Url::parse(&callback_url)?;
    url.query_pairs_mut().append_pair("state", "too-many-state");
    assert_eq!(
        client.get(url.as_str()).send().await?.status(),
        StatusCode::BAD_REQUEST
    );

    let bad_url = callback_url.replace("state=", "state=bad-state");
    assert_eq!(
        client.get(&bad_url).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[tokio::test]
async fn no_session_cookie() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::pkce().await;
    let callback_url = server.login_to_callback(&server.cookie_client()).await;
    let res = server.bare_client().get(&callback_url).send().await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn invalid_session_cookie() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::pkce().await;
    let callback_url = server.login_to_callback(&server.cookie_client()).await;
    let res = server
        .bare_client()
        .get(&callback_url)
        .header("Cookie", "oauth2.session.test=!!!not_base64!!!")
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn auth_flow() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::authorization_code().await;
    let client = server.cookie_client();
    assert_eq!(
        server.complete_login(&client).await.status(),
        StatusCode::CREATED
    );
    Ok(())
}
