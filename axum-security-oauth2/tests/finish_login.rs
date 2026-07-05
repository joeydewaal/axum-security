//! Integration tests for `finish_login` against a mock token endpoint,
//! per the phase 1 exit criteria: success, §5.2 error bodies, non-JSON
//! bodies, Basic-auth correctness and redirects-not-followed.
#![cfg(feature = "reqwest")]

use axum_security_oauth2::{Error, ErrorCode, OAuth2Client};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path},
};

const CLIENT_ID: &str = "test-client-id";
const CLIENT_SECRET: &str = "test-client-secret";

fn client(server: &MockServer, with_secret: bool) -> OAuth2Client {
    let mut builder = OAuth2Client::builder()
        .client_id(CLIENT_ID)
        .auth_url(format!("{}/authorize", server.uri()))
        .token_url(format!("{}/token", server.uri()))
        .redirect_url("https://app.example/callback");
    if with_secret {
        builder = builder.client_secret(CLIENT_SECRET);
    }
    builder.build()
}

fn tokens_body() -> serde_json::Value {
    serde_json::json!({
        "access_token": "test-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "test-refresh-token",
        "scope": "read:user"
    })
}

#[tokio::test]
async fn success_round_trip() {
    let server = MockServer::start().await;
    let client = client(&server, true);
    let login = client.start_login();

    // The request must be a form-encoded POST carrying the grant, code,
    // verifier and redirect_uri, authenticated via HTTP Basic.
    let expected_basic = format!(
        "Basic {}",
        base64_encode(&format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", expected_basic.as_str()))
        .and(header("accept", "application/json"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=test-code"))
        .and(body_string_contains("code_verifier="))
        .and(body_string_contains(
            "redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(tokens_body()))
        .expect(1)
        .mount(&server)
        .await;

    let tokens = client
        .finish_login("test-code", &login.pkce_verifier)
        .await
        .unwrap();

    assert_eq!(tokens.access_token, "test-access-token");
    assert!(tokens.is_bearer());
    assert_eq!(
        tokens.expires_in,
        Some(std::time::Duration::from_secs(3600))
    );
    assert_eq!(tokens.refresh_token.as_deref(), Some("test-refresh-token"));
    assert_eq!(tokens.scopes(), Some(&["read:user".to_string()][..]));
}

#[tokio::test]
async fn no_secret_sends_client_id_in_body() {
    let server = MockServer::start().await;
    let client = client(&server, false);

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("client_id=test-client-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tokens_body()))
        .expect(1)
        .mount(&server)
        .await;

    let login = client.start_login();
    client
        .finish_login("test-code", &login.pkce_verifier)
        .await
        .unwrap();
}

/// Matches when the request body does *not* contain the needle — wiremock
/// ships no negated `body_string_contains`.
struct BodyLacks(&'static str);

impl wiremock::Match for BodyLacks {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !String::from_utf8_lossy(&request.body).contains(self.0)
    }
}

#[tokio::test]
async fn non_pkce_round_trip() {
    let server = MockServer::start().await;
    let client = client(&server, true);
    let login = client.start_login_non_pkce();

    assert!(!login.url.as_str().contains("code_challenge"));

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=test-code"))
        .and(BodyLacks("code_verifier"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tokens_body()))
        .expect(1)
        .mount(&server)
        .await;

    let tokens = client.finish_login_non_pkce("test-code").await.unwrap();
    assert_eq!(tokens.access_token, "test-access-token");
}

/// Matches when the request carries no header with the given name.
struct HeaderAbsent(&'static str);

impl wiremock::Match for HeaderAbsent {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !request.headers.contains_key(self.0)
    }
}

#[tokio::test]
async fn refresh_tokens_round_trip() {
    let server = MockServer::start().await;
    let client = client(&server, true);

    let expected_basic = format!(
        "Basic {}",
        base64_encode(&format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("authorization", expected_basic.as_str()))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=test-refresh-token"))
        .and(BodyLacks("code="))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let tokens = client.refresh_tokens("test-refresh-token").await.unwrap();
    assert_eq!(tokens.access_token, "fresh-access-token");
    // §6: no new refresh token in the response — the caller keeps the
    // old one.
    assert_eq!(tokens.refresh_token, None);
}

/// `AuthType::RequestBody`: credentials go in the form body and no
/// Authorization header is sent.
#[tokio::test]
async fn request_body_auth_sends_credentials_in_body() {
    let server = MockServer::start().await;
    let client = OAuth2Client::builder()
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .auth_url(format!("{}/authorize", server.uri()))
        .token_url(format!("{}/token", server.uri()))
        .request_body()
        .build();

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(HeaderAbsent("authorization"))
        .and(body_string_contains("client_id=test-client-id"))
        .and(body_string_contains("client_secret=test-client-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tokens_body()))
        .expect(1)
        .mount(&server)
        .await;

    let login = client.start_login();
    client
        .finish_login("test-code", &login.pkce_verifier)
        .await
        .unwrap();
}

#[tokio::test]
async fn rfc_6749_error_body() {
    let server = MockServer::start().await;
    let client = client(&server, true);

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "the code has expired",
            "error_uri": "https://provider.example/docs"
        })))
        .mount(&server)
        .await;

    let error = client
        .finish_login("expired-code", "stored-verifier")
        .await
        .unwrap_err();

    let Error::Server(server_error) = error else {
        panic!("expected Error::Server, got: {error:?}");
    };
    assert_eq!(*server_error.code(), ErrorCode::InvalidGrant);
    assert_eq!(server_error.status(), 400);
    assert_eq!(server_error.description(), Some("the code has expired"));
    assert_eq!(server_error.uri(), Some("https://provider.example/docs"));
}

/// GitHub answers token errors with a 200 status and a §5.2-shaped body.
#[tokio::test]
async fn error_body_with_success_status() {
    let server = MockServer::start().await;
    let client = client(&server, true);

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "error": "bad_verification_code",
            "error_description": "The code passed is incorrect or expired."
        })))
        .mount(&server)
        .await;

    let error = client
        .finish_login("bad-code", "stored-verifier")
        .await
        .unwrap_err();

    let Error::Server(server_error) = error else {
        panic!("expected Error::Server, got: {error:?}");
    };
    assert_eq!(
        *server_error.code(),
        ErrorCode::Other("bad_verification_code".to_string())
    );
    assert_eq!(server_error.status(), 200);
}

#[tokio::test]
async fn non_json_body_is_a_parse_error() {
    let server = MockServer::start().await;
    let client = client(&server, true);

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw("<html>secret-body-content</html>", "text/html"),
        )
        .mount(&server)
        .await;

    let error = client
        .finish_login("test-code", "stored-verifier")
        .await
        .unwrap_err();

    let Error::Parse(parse_error) = error else {
        panic!("expected Error::Parse, got: {error:?}");
    };
    assert_eq!(parse_error.status(), 200);
    assert_eq!(parse_error.content_type(), Some("text/html"));
    assert_eq!(parse_error.body(), b"<html>secret-body-content</html>");

    // A failed success-parse can contain live tokens: neither Debug nor
    // Display may leak the body.
    assert!(!format!("{parse_error:?}").contains("secret-body-content"));
    assert!(!format!("{parse_error}").contains("secret-body-content"));
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let server = MockServer::start().await;
    let client = client(&server, true);

    // A redirect pointing at a valid token response; following it would
    // succeed, refusing it must surface the 302 itself.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/elsewhere", server.uri()).as_str()),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200).set_body_json(tokens_body()))
        .expect(0)
        .mount(&server)
        .await;

    let error = client
        .finish_login("test-code", "stored-verifier")
        .await
        .unwrap_err();

    let Error::Parse(parse_error) = error else {
        panic!("expected Error::Parse from the 302, got: {error:?}");
    };
    assert_eq!(parse_error.status(), 302);
}

/// Minimal base64 (standard alphabet, padded) so the test computes the
/// expected Basic header without depending on the crate under test.
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
