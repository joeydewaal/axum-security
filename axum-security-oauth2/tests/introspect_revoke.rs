//! Integration tests for `introspect` (RFC 7662) and `revoke` (RFC 7009)
//! against a mock server: success shapes, authentication, the
//! configured-endpoint requirement, and error bodies.
#![cfg(feature = "reqwest")]

use axum_security_oauth2::{Error, ErrorCode, OAuth2Client};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header, method, path},
};

const CLIENT_ID: &str = "test-client-id";
const CLIENT_SECRET: &str = "test-client-secret";

/// A client with the introspection and revocation endpoints wired up.
fn client(server: &MockServer) -> OAuth2Client {
    OAuth2Client::builder()
        .client_id(CLIENT_ID)
        .client_secret(CLIENT_SECRET)
        .auth_url(format!("{}/authorize", server.uri()))
        .token_url(format!("{}/token", server.uri()))
        .introspection_url(format!("{}/introspect", server.uri()))
        .revocation_url(format!("{}/revoke", server.uri()))
        .build()
}

fn expected_basic() -> String {
    format!(
        "Basic {}",
        base64_encode(&format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    )
}

#[tokio::test]
async fn introspect_active_token() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(header("authorization", expected_basic().as_str()))
        .and(header("accept", "application/json"))
        .and(body_string_contains("token=the-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "active": true,
            "scope": "read:user",
            "client_id": CLIENT_ID,
            "username": "jdoe",
            "exp": 1419356238
        })))
        .expect(1)
        .mount(&server)
        .await;

    let introspection = client.introspect("the-access-token").await.unwrap();
    assert!(introspection.is_active());
    assert_eq!(introspection.username(), Some("jdoe"));
    assert_eq!(introspection.scopes(), Some(&["read:user".to_string()][..]));
    assert_eq!(introspection.exp(), Some(1419356238));
}

/// An `active: false` body is a success, not an error.
#[tokio::test]
async fn introspect_inactive_token_is_ok() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "active": false
        })))
        .mount(&server)
        .await;

    let introspection = client.introspect("stale-token").await.unwrap();
    assert!(!introspection.is_active());
}

/// A `401` with a §5.2 error body surfaces as `Error::Server`.
#[tokio::test]
async fn introspect_unauthorized_is_a_server_error() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_client"
        })))
        .mount(&server)
        .await;

    let error = client.introspect("any-token").await.unwrap_err();
    let Error::Server(server_error) = error else {
        panic!("expected Error::Server, got: {error:?}");
    };
    assert_eq!(*server_error.code(), ErrorCode::InvalidClient);
    assert_eq!(server_error.status(), 401);
}

#[tokio::test]
async fn introspect_without_endpoint_is_missing_endpoint() {
    let server = MockServer::start().await;
    // No introspection_url configured.
    let client = OAuth2Client::builder()
        .client_id(CLIENT_ID)
        .auth_url(format!("{}/authorize", server.uri()))
        .token_url(format!("{}/token", server.uri()))
        .build();

    let error = client.introspect("any-token").await.unwrap_err();
    assert!(
        matches!(error, Error::MissingEndpoint("introspection_url")),
        "{error:?}"
    );
}

#[tokio::test]
async fn revoke_refresh_token() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(header("authorization", expected_basic().as_str()))
        .and(body_string_contains("token=the-refresh-token"))
        .and(body_string_contains("token_type_hint=refresh_token"))
        // RFC 7009 §2.2: success is an empty 200 body.
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client
        .revoke_refresh_token("the-refresh-token")
        .await
        .unwrap();
}

#[tokio::test]
async fn revoke_access_token_sends_access_hint() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("token=the-access-token"))
        .and(body_string_contains("token_type_hint=access_token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client
        .revoke_access_token("the-access-token")
        .await
        .unwrap();
}

/// `revoke` sends no `token_type_hint` (RFC 7009 makes it optional).
#[tokio::test]
async fn revoke_without_hint_omits_the_hint() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("token=some-token"))
        .and(HintAbsent)
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client.revoke("some-token").await.unwrap();
}

/// Matches when the request body carries no `token_type_hint`.
struct HintAbsent;

impl wiremock::Match for HintAbsent {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !String::from_utf8_lossy(&request.body).contains("token_type_hint")
    }
}

/// RFC 7009 §2.2.1: an error body (e.g. `unsupported_token_type`) surfaces
/// as `Error::Server`.
#[tokio::test]
async fn revoke_error_body_is_a_server_error() {
    let server = MockServer::start().await;
    let client = client(&server);

    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "unsupported_token_type"
        })))
        .mount(&server)
        .await;

    let error = client.revoke_access_token("nope").await.unwrap_err();
    let Error::Server(server_error) = error else {
        panic!("expected Error::Server, got: {error:?}");
    };
    assert_eq!(
        *server_error.code(),
        ErrorCode::Other("unsupported_token_type".to_string())
    );
    assert_eq!(server_error.status(), 400);
}

#[tokio::test]
async fn revoke_without_endpoint_is_missing_endpoint() {
    let server = MockServer::start().await;
    let client = OAuth2Client::builder()
        .client_id(CLIENT_ID)
        .auth_url(format!("{}/authorize", server.uri()))
        .token_url(format!("{}/token", server.uri()))
        .build();

    let error = client.revoke_refresh_token("any").await.unwrap_err();
    assert!(
        matches!(error, Error::MissingEndpoint("revocation_url")),
        "{error:?}"
    );
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
