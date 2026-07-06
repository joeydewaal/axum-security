//! End-to-end tests for phase 2: provider discovery + JWKS fetch/cache.
//!
//! A `wiremock` server plays the OpenID provider — serving the discovery
//! document and JWKS — so the whole "discover, fetch keys, verify a token"
//! path runs against a real HTTP round-trip.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum_security_oidc::{HttpClient, JwksCache, ProviderMetadata, VerifyError};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const CLIENT_ID: &str = "test-client-id";
const PRIV_PEM: &str = include_str!("../src/testdata/rsa_priv_pem.txt");
const N: &str = include_str!("../src/testdata/rsa_modulus_b64u.txt");

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign an ID token with the test private key under header `kid`.
fn sign(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    let key = EncodingKey::from_rsa_pem(PRIV_PEM.as_bytes()).expect("valid PEM");
    encode(&header, claims, &key).expect("encode")
}

fn id_token(issuer: &str, nonce: &str, kid: &str) -> String {
    sign(
        &json!({
            "iss": issuer,
            "aud": CLIENT_ID,
            "sub": "user-123",
            "exp": now() + 3600,
            "iat": now(),
            "nonce": nonce,
            "email": "user@example.com",
        }),
        kid,
    )
}

/// A JWKS document exposing the test public key under `kid`.
fn jwks_json(kid: &str) -> String {
    format!(
        r#"{{"keys":[{{"kty":"RSA","use":"sig","kid":"{kid}","alg":"RS256","n":"{N}","e":"AQAB"}}]}}"#
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

async fn mount_discovery(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_string(discovery_doc(&server.uri())))
        .mount(server)
        .await;
}

#[tokio::test]
async fn discovers_then_verifies_with_lazily_fetched_keys() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    mount_discovery(&server).await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json("kid-1")))
        .mount(&server)
        .await;

    let http = HttpClient::default_reqwest();

    // Discover, then verify a token — keys are fetched on first verify.
    let metadata = ProviderMetadata::discover(&issuer, &http).await.unwrap();
    assert_eq!(metadata.issuer, issuer);
    assert_eq!(metadata.jwks_uri, format!("{issuer}/jwks"));

    let cache = JwksCache::new(
        metadata.issuer.clone(),
        CLIENT_ID,
        Url::parse(&metadata.jwks_uri).unwrap(),
        http,
    );

    let token = id_token(&issuer, "the-nonce", "kid-1");
    let verified = cache.verify(&token, "the-nonce").await.unwrap();
    let claims = verified.claims().unwrap();
    assert_eq!(claims.subject, "user-123");
    assert_eq!(claims.email, Some("user@example.com"));

    // A second verify uses the cached keys (no second /jwks call is required).
    cache.verify(&token, "the-nonce").await.unwrap();
}

#[tokio::test]
async fn refetches_on_key_rotation() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json("kid-1")))
        .mount(&server)
        .await;

    // Zero interval so a rotation refetch is not rate-limited within the test.
    let cache = JwksCache::new(
        issuer.clone(),
        CLIENT_ID,
        Url::parse(&format!("{issuer}/jwks")).unwrap(),
        HttpClient::default_reqwest(),
    )
    .min_refetch_interval(Duration::ZERO);

    // First token (kid-1) fetches and caches the current key set.
    cache
        .verify(&id_token(&issuer, "n", "kid-1"), "n")
        .await
        .unwrap();

    // Provider rotates: same key material, new `kid`.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json("kid-2")))
        .mount(&server)
        .await;

    // A kid-2 token is unknown to the cache → triggers a refetch → verifies.
    cache
        .verify(&id_token(&issuer, "n", "kid-2"), "n")
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cold_verifies_fetch_jwks_once() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    // `expect(1)`: the lock is held across the fetch, so a burst of cold
    // callers coalesces onto a single JWKS request. Verified when the server
    // drops — without coalescing each caller would fetch and this would fail.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json("kid-1")))
        .expect(1)
        .mount(&server)
        .await;

    let cache = Arc::new(JwksCache::new(
        issuer.clone(),
        CLIENT_ID,
        Url::parse(&format!("{issuer}/jwks")).unwrap(),
        HttpClient::default_reqwest(),
    ));
    let token = Arc::new(id_token(&issuer, "n", "kid-1"));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let cache = cache.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            cache.verify(&token, "n").await.unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn warm_populates_cache_so_verify_reuses_it() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    // `expect(1)`: warm() fetches once, then verify() reuses the cached keys.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json("kid-1")))
        .expect(1)
        .mount(&server)
        .await;

    let cache = JwksCache::new(
        issuer.clone(),
        CLIENT_ID,
        Url::parse(&format!("{issuer}/jwks")).unwrap(),
        HttpClient::default_reqwest(),
    );

    cache.warm().await.unwrap();
    cache
        .verify(&id_token(&issuer, "n", "kid-1"), "n")
        .await
        .unwrap();
}

#[tokio::test]
async fn rate_limit_blocks_rotation_refetch() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_string(jwks_json("kid-1")))
        .mount(&server)
        .await;

    // Default 60s interval: the first fetch claims the slot, so an immediate
    // rotation refetch is suppressed and the unknown-key token is rejected.
    let cache = JwksCache::new(
        issuer.clone(),
        CLIENT_ID,
        Url::parse(&format!("{issuer}/jwks")).unwrap(),
        HttpClient::default_reqwest(),
    );

    cache
        .verify(&id_token(&issuer, "n", "kid-1"), "n")
        .await
        .unwrap();

    let err = cache
        .verify(&id_token(&issuer, "n", "kid-2"), "n")
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::UnknownKey), "{err:?}");
}

#[tokio::test]
async fn discovery_rejects_non_2xx() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = ProviderMetadata::discover(&server.uri(), &HttpClient::default_reqwest())
        .await
        .unwrap_err();
    assert!(
        matches!(err, axum_security_oidc::DiscoveryError::Status(404)),
        "{err:?}"
    );
}

#[tokio::test]
async fn discovery_rejects_issuer_mismatch() {
    let server = MockServer::start().await;
    // The document claims a different issuer than the one we requested.
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(discovery_doc("https://evil.example")),
        )
        .mount(&server)
        .await;

    let err = ProviderMetadata::discover(&server.uri(), &HttpClient::default_reqwest())
        .await
        .unwrap_err();
    assert!(
        matches!(err, axum_security_oidc::DiscoveryError::IssuerMismatch),
        "{err:?}"
    );
}

#[tokio::test]
async fn jwks_fetch_failure_is_unavailable() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let cache = JwksCache::new(
        issuer.clone(),
        CLIENT_ID,
        Url::parse(&format!("{issuer}/jwks")).unwrap(),
        HttpClient::default_reqwest(),
    );

    let err = cache
        .verify(&id_token(&issuer, "n", "kid-1"), "n")
        .await
        .unwrap_err();
    assert!(matches!(err, VerifyError::JwksUnavailable), "{err:?}");
}
