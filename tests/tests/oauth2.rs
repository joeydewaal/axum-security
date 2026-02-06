#![cfg(feature = "oauth2")]

use base64::{Engine as _, engine::general_purpose};
use reqwest::{Client, redirect::Policy};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, LazyLock, Mutex},
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
    matchers::{method, path, query_param},
};

const CLIENT_ID: &str = "test_client_id";
const CLIENT_SECRET: &str = "test_client_secret";
const REDIRECT_URL: &str = "http://localhost/redirect";
const AUTH_URL: &str = github::AUTH_URL;
const TOKEN_URL: &str = github::TOKEN_URL;
const LOGIN_PATH: &str = "/login-testing";

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
async fn basic_login_path() -> Result<(), Box<dyn Error>> {
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

    is_pkce_start(res).await
}

#[allow(unused)]
#[derive(Clone)]
struct ChallengeData {
    code_challenge: String,
    client_id: String,
    redirect_uri: String,
}

type ChallengeStore = Arc<Mutex<HashMap<String, ChallengeData>>>;

// Static global state
static OAUTH_STATE: LazyLock<ChallengeStore> =
    LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

async fn install_mock_pkce_server() -> (MockServer, String, String) {
    const AUTH_URL_PATH: &str = "/oauth2/authorize";
    const TOKEN_URL_PATH: &str = "/oauth2/access_token";

    let mock_server = MockServer::start().await;

    let auth_url = format!("http://{}{AUTH_URL_PATH}", mock_server.address());
    let token_url = format!("http://{}{TOKEN_URL_PATH}", mock_server.address());

    // 1. Authorization endpoint - store code_challenge
    Mock::given(method("GET"))
        .and(path(AUTH_URL_PATH))
        .and(query_param("response_type", "code"))
        .and(query_param("code_challenge_method", "S256"))
        .respond_with(|req: &WireRequest| {
            tracing::debug!("oauth2: auth url");

            let Some(query) = req.url.query() else {
                tracing::debug!("no query found in url");
                return ResponseTemplate::new(400);
            };

            let Ok(pkce_params) = serde_urlencoded::from_str::<PkceQueryParams>(query) else {
                return ResponseTemplate::new(400);
            };

            if pkce_params.client_id != CLIENT_ID {
                tracing::debug!("client_id doesn't match");
                return ResponseTemplate::new(400);
            }

            // Generate authorization code
            let auth_code = format!("AUTH_CODE_{}", uuid::Uuid::now_v7());

            // Store code_challenge in global state
            {
                let mut challenges = OAUTH_STATE.lock().unwrap();
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

    // 2. Token endpoint - validate code_verifier
    Mock::given(method("POST"))
        .and(path(TOKEN_URL_PATH))
        .respond_with(|req: &WireRequest| {
            tracing::debug!("oauth2: token url");

            // Validate Basic Auth
            let auth_header = req
                .headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok());

            if let Some(header) = auth_header {
                if !header.starts_with("Basic ") {
                    return ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Basic");
                }

                // Decode Basic auth
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

            // Parse request body
            let body = std::str::from_utf8(&req.body).unwrap();

            #[allow(unused)]
            #[derive(Debug, Deserialize)]
            struct TokenUrlParams {
                grant_type: String,
                code: String,
                redirect_uri: String,
                code_verifier: String,
            }

            let Ok(params) = serde_urlencoded::from_str::<TokenUrlParams>(body) else {
                return ResponseTemplate::new(400);
            };

            // Look up stored challenge from global state
            let challenge_data = {
                let challenges = OAUTH_STATE.lock().unwrap();
                challenges.get(&params.code).cloned()
            };

            let Some(challenge_data) = challenge_data else {
                return ResponseTemplate::new(400);
            };

            // Validate redirect_uri matches
            if challenge_data.redirect_uri != params.redirect_uri {
                return ResponseTemplate::new(400);
            }

            // **VALIDATE CODE_VERIFIER**
            let computed_challenge = generate_code_challenge(&params.code_verifier);

            if computed_challenge != challenge_data.code_challenge {
                tracing::error!(
                    "PKCE validation failed: expected={}, computed={}",
                    challenge_data.code_challenge,
                    computed_challenge
                );
                return ResponseTemplate::new(400);
            }

            tracing::debug!("PKCE validation passed!");

            // Clean up used auth code (one-time use)
            {
                let mut challenges = OAUTH_STATE.lock().unwrap();
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

// Helper function to generate code_challenge from code_verifier
fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();

    // Base64 URL encode without padding (S256 method)
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

#[tokio::test]
async fn login_path() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    const REDIRECT_PATH: &str = "/redirect";
    let (_, auth_url, token_url) = install_mock_pkce_server().await;

    let http_client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()?;

    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let redirect_url = format!("http://{server_addr}{REDIRECT_PATH}");

    let oauth2_context = OAuth2Context::builder()
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .redirect_url(redirect_url)
        .auth_url(auth_url)
        .token_url(token_url)
        .login_path(LOGIN_PATH)
        .use_dev_cookies(true)
        .build(TestHandler);

    let router = Router::<()>::new().with_oauth2(oauth2_context);

    tokio::spawn(async { axum::serve(socket, router).await });

    // Start login flow.
    let res = http_client
        .get(format!("http://{server_addr}{LOGIN_PATH}"))
        .send()
        .await?;

    // Login with the oauth server.
    let redirect_url = res.headers()["location"].to_str()?;
    let login_result = http_client.get(redirect_url).send().await?;

    // Finish the flow on the server.
    let redirect_url = login_result.headers()["location"].to_str()?;
    let res = http_client.get(redirect_url).send().await?;

    assert_eq!(res.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
async fn invalid_state() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    const REDIRECT_PATH: &str = "/redirect";
    let (_, auth_url, token_url) = install_mock_pkce_server().await;

    let http_client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()?;

    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = socket.local_addr()?;
    let redirect_url = format!("http://{server_addr}{REDIRECT_PATH}");

    let oauth2_context = OAuth2Context::builder()
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .redirect_url(redirect_url)
        .auth_url(auth_url)
        .token_url(token_url)
        .login_path(LOGIN_PATH)
        .use_dev_cookies(true)
        .build(TestHandler);

    let router = Router::<()>::new().with_oauth2(oauth2_context);

    tokio::spawn(async { axum::serve(socket, router).await });

    // Start login flow.
    let res = http_client
        .get(format!("http://{server_addr}{LOGIN_PATH}"))
        .send()
        .await?;

    // Login with the oauth server.
    let redirect_url = res.headers()["location"].to_str()?;
    let login_result = http_client.get(redirect_url).send().await?;

    // Finish the flow on the server.
    let redirect_url = login_result.headers()["location"].to_str()?;

    // Puah another state param. (2 in total) this is one too many.
    let mut url = Url::parse(&redirect_url)?;
    url.query_pairs_mut().append_pair("state", "too-many-state");
    let res = http_client.get(url.as_str()).send().await?;

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let invalid_redirect_url = redirect_url.replace("state=", "state=bad-state");
    let res = http_client.get(&invalid_redirect_url).send().await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}
