//! End-to-end tests for phase 3: the full OpenID Connect login flow.
//!
//! A `wiremock` server plays the provider — discovery, JWKS, and the token
//! endpoint — so `discover` → `start_login` → `finish_login` runs against real
//! HTTP round-trips.

use std::time::{SystemTime, UNIX_EPOCH};

use axum_security_oidc::{HttpClient, OidcClient, OidcError};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "test-client-id";
const REDIRECT: &str = "https://app.example/callback";
const KID: &str = "kid-1";
const PRIV_PEM: &str = include_str!("../src/testdata/rsa_priv_pem.txt");
const N: &str = include_str!("../src/testdata/rsa_modulus_b64u.txt");

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_id_token(issuer: &str, nonce: &str) -> String {
    let claims = json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "exp": now() + 3600,
        "iat": now(),
        "nonce": nonce,
        "email": "user@example.com",
        "email_verified": true,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    let key = EncodingKey::from_rsa_pem(PRIV_PEM.as_bytes()).expect("valid PEM");
    encode(&header, &claims, &key).expect("encode")
}

fn jwks_json() -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"{KID}","alg":"RS256","n":"{N}","e":"AQAB"}}]}}"#
    )
}

fn discovery_doc(issuer: &str) -> String {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/auth"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "end_session_endpoint": format!("{issuer}/logout"),
        "id_token_signing_alg_values_supported": ["RS256"],
    })
    .to_string()
}

/// Mount discovery + JWKS; return a client built via discovery.
async fn discovered_client(server: &MockServer) -> OidcClient {
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string(discovery_doc(&issuer)))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json()))
        .mount(server)
        .await;

    OidcClient::discover(&issuer, HttpClient::default_reqwest())
        .await
        .unwrap()
        .client_id(CLIENT_ID)
        .redirect_url(REDIRECT)
        .scopes(&["email"])
        .build()
}

/// Mount a token endpoint that returns `id_token` alongside the OAuth2 tokens.
async fn mount_token_endpoint(server: &MockServer, id_token: &str) {
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token-abc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token-xyz",
            "id_token": id_token,
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn full_login_flow() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client = discovered_client(&server).await;

    // Leg 1: the authorization URL carries the standard params, the forced
    // `openid` scope, and a nonce.
    let login = client.start_login();
    let query: std::collections::HashMap<_, _> = login.url.query_pairs().into_owned().collect();
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["scope"], "openid email");
    assert_eq!(query["nonce"], login.nonce);
    assert_eq!(login.csrf_token, query["state"]);
    assert!(query.contains_key("code_challenge"));

    // The provider signs an ID token bound to this login's nonce.
    mount_token_endpoint(&server, &sign_id_token(&issuer, &login.nonce)).await;

    // Leg 2: exchange the code and verify the ID token.
    let tokens = client
        .finish_login("auth-code", &login.pkce_verifier, &login.nonce)
        .await
        .unwrap();

    assert_eq!(tokens.access_token(), "access-token-abc");
    assert_eq!(tokens.refresh_token(), Some("refresh-token-xyz"));
    let claims = tokens.claims().unwrap();
    assert_eq!(claims.subject, "user-123");
    assert_eq!(claims.email, Some("user@example.com"));
    assert_eq!(claims.nonce, Some(login.nonce.as_str()));
}

#[tokio::test]
async fn rejects_nonce_mismatch() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client = discovered_client(&server).await;

    let login = client.start_login();
    // Token is signed with a different nonce than the login generated.
    mount_token_endpoint(&server, &sign_id_token(&issuer, "not-the-login-nonce")).await;

    let err = client
        .finish_login("auth-code", &login.pkce_verifier, &login.nonce)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            OidcError::Verify(axum_security_oidc::VerifyError::NonceMismatch)
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn missing_id_token_is_an_error() {
    let server = MockServer::start().await;
    let client = discovered_client(&server).await;

    let login = client.start_login();
    // A plain OAuth2 token response — no id_token field.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token-abc",
            "token_type": "Bearer",
        })))
        .mount(&server)
        .await;

    let err = client
        .finish_login("auth-code", &login.pkce_verifier, &login.nonce)
        .await
        .unwrap_err();
    assert!(matches!(err, OidcError::NoIdToken), "{err:?}");
}

#[tokio::test]
async fn logout_url_uses_discovered_end_session_endpoint() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    let client = discovered_client(&server).await;

    let url = client
        .logout_url()
        .expect("end_session_endpoint discovered")
        .id_token_hint("the.id.token")
        .post_logout_redirect_uri("https://app.example/")
        .build();

    assert!(url.as_str().starts_with(&format!("{issuer}/logout")));
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    // client_id is seeded automatically by `logout_url`.
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["id_token_hint"], "the.id.token");
    assert_eq!(query["post_logout_redirect_uri"], "https://app.example/");
}
