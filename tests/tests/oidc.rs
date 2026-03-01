#![cfg(feature = "oidc")]

use std::{
    collections::HashMap,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{Router, http::StatusCode};
use axum_security::oidc::{
    AfterLoginCookies, OidcClaims, OidcContext, OidcExt, OidcHandler, OidcTokenResponse,
    UtcTimestamp,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use openidconnect::{
    Audience, EmptyAdditionalClaims, IssuerUrl, JsonWebKeyId, Nonce, PrivateSigningKey as _,
    StandardClaims, SubjectIdentifier,
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
};
use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpListener;
use url::Url;
use wiremock::{
    Mock, MockServer, Request as WireRequest, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "test_client_id";
const CLIENT_SECRET: &str = "test_client_secret";
const LOGIN_PATH: &str = "/auth/oidc/login";
const REDIRECT_PATH: &str = "/auth/oidc/callback";

const TEST_RSA_KEY: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAsRMj0YYjy7du6v1gWyKSTJx3YjBzZTG0XotRP0IaObw0k+68\n\
30dXadjL5jVhSWNdcg9OyMyTGWfdNqfdrS6ppBqlQNgjZJdloIqL9zOLBZrDm7G4\n\
+qN4KeZ4/5TyEilq2zOHHGFEzXpOq/UxqVnm3J4fhjqCNaS2nKd7HVVXGBQQ+4+F\n\
dVT+MyJXemw5maz2F/h324TQi6XoUPEwUddxBwLQFSOlzWnHYMc4/lcyZJ8MpTXC\n\
MPe/YJFNtb9CaikKUdf8x4mzwH7usSf8s2d6R4dQITzKrjrEJ0u3w3eGkBBapoMV\n\
FBGPjP3Haz5FsVtHc5VEN3FZVIDF6HrbJH1C4QIDAQABAoIBAHSS3izM+3nc7Bel\n\
8S5uRxRKmcm5je6b11u6qiVUFkHWJmMRc6QmqmSThkCq+b4/vUAe1cYZ7+l02Exo\n\
HOcrZiEULaDP6hUKGqyjKVv3wdlRtt8kFFxlC/HBufzAiNDuFVvzw0oquwnvMCXC\n\
yQvtlK+/JY/PqvM32cSt+b4o9apySsHqAtdsoHHohK82jsQqIfCi1v8XYV/xRBJB\n\
cQMCaA0Ls3tFpmJv3JdikyyQxio4kZ5tswghC63znCp1iL+qDq1wjjKzjick9MDb\n\
Qzb95X09QQP201l1FPWN7Kbhj4ybg6PJGz/VHQcvILcBCoYIc0UY/OMSBt9VN9yD\n\
wr1WlbECgYEA37difsTMcLmUEN57sicFe1q4lxH6eqnUBjmoKBflx4oMIIyRnfjF\n\
Jwsu9yIiBkJfBCP85nl2tZdcV0wfZLf6amxB/KMtdfW6r8eoTDzE472OYxSIg1F5\n\
dI4qn2nBI0Dou0g58xj+Kv0iLaym0pxtyJkSg/rxZGwKb9a+x5WAs50CgYEAyqC0\n\
NcZs2BRIiT5kEOF6+MeUvarbKh1mangKHKcTdXRrvoJ+Z5izm7FifBixo/79MYpt\n\
0VofW0IzYKtAI9KZDq2JcozEbZ+lt/ZPH5QEXO4T39QbDoAG8BbOmEP7l+6m+7QO\n\
PiQ0WSNjDnwk3W7Zihgg31DH7hyxsxQCapKLcxUCgYAwERXPiPcoDSd8DGFlYK7z\n\
1wUsKEe6DT0p7T9tBd1v5wA+ChXLbETn46Y+oQ3QbHg/yn+vAU/5KkFD3G4uVL0w\n\
Gnx/DIxa+OYYmHxXjQL8r6ClNycxl9LRsS4FPFKsAWk/u///dFI/6E1spNjfDY8k\n\
94ab5tHwsqn3Z5tsBHo3nQKBgFUmxbSXh2Qi2fy6+GhTqU7k6G/wXhvLsR9rBKzX\n\
1YiVfTXZNu+oL0ptd/q4keZeIN7x0oaY/fZm0pp8PP8Q4HtXmBxIZb+/yG+Pld6q\n\
YE8BSd7VDu3ABapdm0JHx3Iou4mpOBcLNeiDw3vx1bgsfkTXMPFHzE0XR+H+tak9\n\
nlalAoGBALAmAF7WBGdOt43Rj8hPaKOM/ahj+6z3CNwVreToNsVBHoyNmiO8q7MC\n\
+tRo4jgdrzk1pzs66OIHfbx5P1mXKPtgPZhvI5omAY8WqXEgeNqSL1Ksp6LZ2ql/\n\
ouZns5xwKc9+aRL+GWoAGNzwzcjE8cP52sBy/r0rYXTs/sZo5kgV\n\
-----END RSA PRIVATE KEY-----";

struct TestHandler;

impl OidcHandler for TestHandler {
    async fn after_login(
        &self,
        token_res: OidcTokenResponse,
        _context: &mut AfterLoginCookies<'_>,
    ) -> impl axum::response::IntoResponse {
        // Verify we got meaningful claims
        assert_eq!(token_res.claims.subject, "user-123");
        StatusCode::CREATED
    }
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
struct OidcQueryParams {
    client_id: String,
    state: String,
    nonce: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    redirect_uri: String,
    response_type: String,
    scope: String,
}

type ChallengeStore = Arc<Mutex<HashMap<String, ChallengeData>>>;

#[derive(Clone)]
struct ChallengeData {
    code_challenge: Option<String>,
    nonce: String,
    redirect_uri: String,
}

fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let result = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(result)
}

fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(
        TEST_RSA_KEY,
        Some(JsonWebKeyId::new("test-key-1".to_string())),
    )
    .unwrap()
}

fn create_id_token(issuer_url: &str, nonce: &str) -> String {
    let key = signing_key();

    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(issuer_url.to_string()).unwrap(),
        vec![Audience::new(CLIENT_ID.to_string())],
        Utc::now() + chrono::Duration::hours(1),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new("user-123".to_string())),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce.to_string())));

    let id_token = CoreIdToken::new(
        claims,
        &key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .unwrap();

    serde_json::to_value(&id_token)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

async fn install_mock_oidc_server() -> (MockServer, String) {
    let mock_server = MockServer::start().await;
    let issuer_url = mock_server.uri();

    let auth_path = "/authorize";
    let token_path = "/token";
    let jwks_path = "/.well-known/jwks.json";
    let discovery_path = "/.well-known/openid-configuration";

    let auth_url = format!("{issuer_url}{auth_path}");
    let token_url = format!("{issuer_url}{token_path}");
    let jwks_url = format!("{issuer_url}{jwks_path}");

    // Discovery endpoint
    let discovery_body = serde_json::json!({
        "issuer": issuer_url,
        "authorization_endpoint": auth_url,
        "token_endpoint": token_url,
        "jwks_uri": jwks_url,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    });

    Mock::given(method("GET"))
        .and(path(discovery_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&discovery_body)
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // JWKS endpoint
    let key = signing_key();
    let jwks = CoreJsonWebKeySet::new(vec![key.as_verification_key()]);

    Mock::given(method("GET"))
        .and(path(jwks_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(&jwks)
                .insert_header("Content-Type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    // Authorization endpoint — simulates redirect back with code + state
    let challenge_store: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
    let challenge_store_auth = challenge_store.clone();
    let challenge_store_token = challenge_store.clone();

    Mock::given(method("GET"))
        .and(path(auth_path))
        .respond_with(move |req: &WireRequest| {
            let Some(query) = req.url.query() else {
                return ResponseTemplate::new(400);
            };

            let Ok(params) = serde_urlencoded::from_str::<OidcQueryParams>(query) else {
                return ResponseTemplate::new(400);
            };

            if params.client_id != CLIENT_ID {
                return ResponseTemplate::new(400);
            }

            assert!(params.response_type.contains("code"));
            assert!(params.scope.contains("openid"));

            let auth_code = format!("OIDC_AUTH_CODE_{}", uuid::Uuid::now_v7());

            {
                let mut challenges = challenge_store_auth.lock().unwrap();
                challenges.insert(
                    auth_code.clone(),
                    ChallengeData {
                        code_challenge: params.code_challenge.clone(),
                        nonce: params.nonce.clone(),
                        redirect_uri: params.redirect_uri.clone(),
                    },
                );
            }

            let redirect_url = format!(
                "{}?code={}&state={}",
                params.redirect_uri, auth_code, params.state
            );

            ResponseTemplate::new(302).insert_header("Location", redirect_url)
        })
        .mount(&mock_server)
        .await;

    // Token endpoint — exchanges code for tokens (including signed ID token)
    let issuer_for_token = issuer_url.clone();
    Mock::given(method("POST"))
        .and(path(token_path))
        .respond_with(move |req: &WireRequest| {
            // Verify client credentials via Basic auth
            let auth_header = req
                .headers
                .get("Authorization")
                .and_then(|v| v.to_str().ok());

            if let Some(header) = auth_header {
                if !header.starts_with("Basic ") {
                    return ResponseTemplate::new(401);
                }

                let encoded = &header[6..];
                let decoded = general_purpose::STANDARD
                    .decode(encoded)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());

                let expected = format!("{CLIENT_ID}:{CLIENT_SECRET}");
                if decoded != Some(expected) {
                    return ResponseTemplate::new(401);
                }
            } else {
                return ResponseTemplate::new(401);
            }

            let body = std::str::from_utf8(&req.body).unwrap();

            #[allow(unused)]
            #[derive(Deserialize)]
            struct TokenParams {
                grant_type: String,
                code: String,
                redirect_uri: String,
                code_verifier: Option<String>,
            }

            let Ok(params) = serde_urlencoded::from_str::<TokenParams>(body) else {
                return ResponseTemplate::new(400);
            };

            let challenge_data = {
                let challenges = challenge_store_token.lock().unwrap();
                challenges.get(&params.code).cloned()
            };

            let Some(challenge_data) = challenge_data else {
                return ResponseTemplate::new(400);
            };

            if challenge_data.redirect_uri != params.redirect_uri {
                return ResponseTemplate::new(400);
            }

            // Verify PKCE
            if let Some(code_challenge) = &challenge_data.code_challenge {
                if let Some(verifier) = &params.code_verifier {
                    let computed = generate_code_challenge(verifier);
                    if &computed != code_challenge {
                        return ResponseTemplate::new(400);
                    }
                } else {
                    return ResponseTemplate::new(400);
                }
            }

            // Consume the code
            {
                let mut challenges = challenge_store_token.lock().unwrap();
                challenges.remove(&params.code);
            }

            let id_token_str = create_id_token(&issuer_for_token, &challenge_data.nonce);

            #[derive(Serialize)]
            struct TokenResp {
                access_token: String,
                token_type: &'static str,
                id_token: String,
            }

            ResponseTemplate::new(200).set_body_json(TokenResp {
                access_token: "mock-access-token".into(),
                token_type: "bearer",
                id_token: id_token_str,
            })
        })
        .mount(&mock_server)
        .await;

    (mock_server, issuer_url)
}

struct TestServer {
    _mock: MockServer,
    addr: SocketAddr,
}

impl TestServer {
    async fn new() -> Self {
        let (mock, issuer_url) = install_mock_oidc_server().await;
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let redirect_url = format!("http://{addr}{REDIRECT_PATH}");

        let oidc_context = OidcContext::discover("test-oidc", &issuer_url)
            .await
            .unwrap()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .redirect_url(redirect_url)
            .login_path(LOGIN_PATH)
            .scopes(&["openid", "email", "profile"])
            .use_dev_cookies(true)
            .build(TestHandler);

        let router = Router::<()>::new().with_oidc(oidc_context);
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
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let oauth_url = res.headers()["location"].to_str().unwrap().to_owned();
        let res = client.get(&oauth_url).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::FOUND);
        res.headers()["location"].to_str().unwrap().to_owned()
    }

    async fn complete_login(&self, client: &Client) -> reqwest::Response {
        let callback_url = self.login_to_callback(client).await;
        client.get(&callback_url).send().await.unwrap()
    }
}

#[derive(Clone)]
struct ClaimsCapture(Arc<Mutex<Option<OidcClaims>>>);

impl OidcHandler for ClaimsCapture {
    async fn after_login(
        &self,
        token_res: OidcTokenResponse,
        _context: &mut AfterLoginCookies<'_>,
    ) -> impl axum::response::IntoResponse {
        *self.0.lock().unwrap() = Some(token_res.claims);
        StatusCode::CREATED
    }
}

struct ClaimsTestServer {
    _mock: MockServer,
    addr: SocketAddr,
    claims: Arc<Mutex<Option<OidcClaims>>>,
}

impl ClaimsTestServer {
    async fn new() -> Self {
        let (mock, issuer_url) = install_mock_oidc_server().await;
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let redirect_url = format!("http://{addr}{REDIRECT_PATH}");

        let claims = Arc::new(Mutex::new(None));
        let handler = ClaimsCapture(claims.clone());

        let oidc_context = OidcContext::discover("test-oidc", &issuer_url)
            .await
            .unwrap()
            .client_id(CLIENT_ID)
            .client_secret(CLIENT_SECRET)
            .redirect_url(redirect_url)
            .login_path(LOGIN_PATH)
            .scopes(&["openid", "email", "profile"])
            .use_dev_cookies(true)
            .build(handler);

        let router = Router::<()>::new().with_oidc(oidc_context);
        tokio::spawn(async { axum::serve(socket, router).await });

        ClaimsTestServer {
            _mock: mock,
            addr,
            claims,
        }
    }

    fn cookie_client(&self) -> Client {
        Client::builder()
            .redirect(Policy::none())
            .cookie_store(true)
            .build()
            .unwrap()
    }

    fn login_url(&self) -> String {
        format!("http://{}{LOGIN_PATH}", self.addr)
    }

    async fn complete_login(&self, client: &Client) -> reqwest::Response {
        let res = client.get(self.login_url()).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let oauth_url = res.headers()["location"].to_str().unwrap().to_owned();
        let res = client.get(&oauth_url).send().await.unwrap();
        assert_eq!(res.status(), StatusCode::FOUND);
        let callback_url = res.headers()["location"].to_str().unwrap().to_owned();
        client.get(&callback_url).send().await.unwrap()
    }

    fn take_claims(&self) -> OidcClaims {
        self.claims
            .lock()
            .unwrap()
            .take()
            .expect("no claims captured")
    }
}

#[tokio::test]
async fn full_oidc_login_flow() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;
    let client = server.cookie_client();

    let res = server.complete_login(&client).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    Ok(())
}

#[tokio::test]
async fn login_returns_redirect_to_provider() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;
    let client = server.cookie_client();

    let res = client.get(server.login_url()).send().await?;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    let location = res.headers()["location"].to_str()?;
    let url = Url::parse(location)?;

    let params: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();

    assert_eq!(params.get("client_id").unwrap(), CLIENT_ID);
    assert_eq!(params.get("response_type").unwrap(), "code");
    assert!(params.get("scope").unwrap().contains("openid"));
    assert!(params.contains_key("state"));
    assert!(params.contains_key("nonce"));
    assert!(params.contains_key("code_challenge"));
    assert_eq!(params.get("code_challenge_method").unwrap(), "S256");

    Ok(())
}

#[tokio::test]
async fn invalid_state_is_rejected() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;
    let client = server.cookie_client();

    let callback_url = server.login_to_callback(&client).await;

    // Tamper with the state parameter
    let bad_url = callback_url.replace("state=", "state=tampered-");
    let res = client.get(&bad_url).send().await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn missing_session_cookie_is_rejected() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;

    // Get a valid callback URL using one client
    let callback_url = server.login_to_callback(&server.cookie_client()).await;

    // Try the callback with a fresh client (no cookies)
    let res = server.bare_client().get(&callback_url).send().await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn invalid_session_cookie_is_rejected() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;

    let callback_url = server.login_to_callback(&server.cookie_client()).await;

    let res = server
        .bare_client()
        .get(&callback_url)
        .header("Cookie", "oidc.session.test-oidc=!!!not_base64!!!")
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn missing_query_params_is_rejected() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;
    let client = server.cookie_client();

    // Hit the callback endpoint with no query params
    let res = client
        .get(format!("http://{}{REDIRECT_PATH}", server.addr))
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[tokio::test]
async fn replay_code_is_rejected() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt::try_init();
    let server = TestServer::new().await;
    let client = server.cookie_client();

    // Complete a login successfully
    let callback_url = server.login_to_callback(&client).await;
    let res = client.get(&callback_url).send().await?;
    assert_eq!(res.status(), StatusCode::CREATED);

    // Replay the same callback URL — session cookie was consumed, so it should fail
    let res = client.get(&callback_url).send().await?;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}

// ── Wiremock happy-path: timestamp conversion ──────────────────────────

#[cfg(feature = "jiff")]
#[tokio::test]
async fn claims_timestamps_convert_to_jiff() {
    let server = ClaimsTestServer::new().await;
    let client = server.cookie_client();
    let res = server.complete_login(&client).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    let claims = server.take_claims();
    let exp = claims.expiration().to_jiff();
    let iat = claims.issued_at().to_jiff();

    assert_eq!(exp.as_second(), claims.expiration().as_secs());
    assert_eq!(iat.as_second(), claims.issued_at().as_secs());
}

#[cfg(feature = "chrono")]
#[tokio::test]
async fn claims_timestamps_convert_to_chrono() {
    let server = ClaimsTestServer::new().await;
    let client = server.cookie_client();
    let res = server.complete_login(&client).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    let claims = server.take_claims();
    let exp = claims.expiration().to_chrono();
    let iat = claims.issued_at().to_chrono();

    assert_eq!(exp.timestamp(), claims.expiration().as_secs());
    assert_eq!(iat.timestamp(), claims.issued_at().as_secs());
}

#[cfg(feature = "time")]
#[tokio::test]
async fn claims_timestamps_convert_to_time() {
    let server = ClaimsTestServer::new().await;
    let client = server.cookie_client();
    let res = server.complete_login(&client).await;
    assert_eq!(res.status(), StatusCode::CREATED);

    let claims = server.take_claims();
    let exp = claims.expiration().to_time();
    let iat = claims.issued_at().to_time();

    assert_eq!(exp.unix_timestamp(), claims.expiration().as_secs());
    assert_eq!(iat.unix_timestamp(), claims.issued_at().as_secs());
}

// ── Direct serde rejection: UtcTimestamp ───────────────────────────────

#[cfg(feature = "jiff")]
#[tokio::test]
async fn utc_timestamp_rejects_out_of_range_jiff() {
    let result = serde_json::from_value::<UtcTimestamp>(serde_json::json!(i64::MAX));
    assert!(
        result.is_err(),
        "i64::MAX should be rejected with jiff feature"
    );
}

#[cfg(feature = "chrono")]
#[tokio::test]
async fn utc_timestamp_rejects_out_of_range_chrono() {
    let result = serde_json::from_value::<UtcTimestamp>(serde_json::json!(i64::MAX));
    assert!(
        result.is_err(),
        "i64::MAX should be rejected with chrono feature"
    );
}

#[cfg(feature = "time")]
#[tokio::test]
async fn utc_timestamp_rejects_out_of_range_time() {
    let result = serde_json::from_value::<UtcTimestamp>(serde_json::json!(i64::MAX));
    assert!(
        result.is_err(),
        "i64::MAX should be rejected with time feature"
    );
}

#[tokio::test]
async fn utc_timestamp_accepts_valid_value() {
    let result = serde_json::from_value::<UtcTimestamp>(serde_json::json!(1_700_000_000i64));
    assert!(result.is_ok(), "valid timestamp should be accepted");
    assert_eq!(result.unwrap().as_secs(), 1_700_000_000);
}
