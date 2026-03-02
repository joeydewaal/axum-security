#![cfg(feature = "rate-limit")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use axum_security::rate_limit::RateLimitLayer;
use tower::ServiceExt;

fn make_request(path: &str) -> Request<Body> {
    Request::get(path).body(Body::empty()).unwrap()
}

fn limiter(
    max: u64,
    window_secs: u64,
) -> RateLimitLayer<impl axum_security::rate_limit::KeyExtractor> {
    // Use a closure key extractor that always returns the same key,
    // so we don't need ConnectInfo<SocketAddr> in tests.
    RateLimitLayer::builder()
        .max_requests(max)
        .window_secs(window_secs)
        .key_extractor(|_req: &mut axum::extract::Request| Some("test-key".to_string()))
        .build()
}

fn token_bucket_limiter(
    burst: u64,
    refill: f64,
) -> RateLimitLayer<impl axum_security::rate_limit::KeyExtractor> {
    RateLimitLayer::builder()
        .token_bucket(burst, refill)
        .key_extractor(|_req: &mut axum::extract::Request| Some("test-key".to_string()))
        .build()
}

#[tokio::test]
async fn fixed_window_allows_within_limit() {
    let layer = limiter(3, 60);
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    for _ in 0..3 {
        let res = app.clone().oneshot(make_request("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().get("ratelimit").is_some());
    }
}

#[tokio::test]
async fn fixed_window_returns_429_when_exceeded() {
    let layer = limiter(2, 60);
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    // Use up the limit
    for _ in 0..2 {
        let res = app.clone().oneshot(make_request("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    // Next request should be rate limited
    let res = app.clone().oneshot(make_request("/")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Check headers on 429 response
    assert!(res.headers().get("ratelimit").is_some());
    assert!(res.headers().get("retry-after").is_some());

    // Check body
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"Too Many Requests");
}

#[tokio::test]
async fn ratelimit_header_contains_expected_fields() {
    let layer = limiter(5, 60);
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let res = app.clone().oneshot(make_request("/")).await.unwrap();
    let header = res.headers()["ratelimit"].to_str().unwrap();

    assert!(header.contains("limit=5"));
    assert!(header.contains("remaining=4"));
    assert!(header.contains("reset="));
}

#[tokio::test]
async fn remaining_decrements() {
    let layer = limiter(3, 60);
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let res = app.clone().oneshot(make_request("/")).await.unwrap();
    let header = res.headers()["ratelimit"].to_str().unwrap();
    assert!(header.contains("remaining=2"));

    let res = app.clone().oneshot(make_request("/")).await.unwrap();
    let header = res.headers()["ratelimit"].to_str().unwrap();
    assert!(header.contains("remaining=1"));

    let res = app.clone().oneshot(make_request("/")).await.unwrap();
    let header = res.headers()["ratelimit"].to_str().unwrap();
    assert!(header.contains("remaining=0"));
}

#[tokio::test]
async fn token_bucket_allows_burst() {
    let layer = token_bucket_limiter(3, 1.0);
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    for _ in 0..3 {
        let res = app.clone().oneshot(make_request("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn token_bucket_returns_429_after_burst() {
    let layer = token_bucket_limiter(2, 1.0);
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    // Exhaust burst
    for _ in 0..2 {
        let res = app.clone().oneshot(make_request("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    let res = app.clone().oneshot(make_request("/")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_key_passes_through() {
    // Extractor that always returns None — request should pass through
    let layer = RateLimitLayer::builder()
        .max_requests(1)
        .window_secs(60)
        .key_extractor(|_req: &mut axum::extract::Request| -> Option<String> { None })
        .build();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    // Even though limit is 1, all requests pass because no key is extracted
    for _ in 0..5 {
        let res = app.clone().oneshot(make_request("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        // No ratelimit header when key extraction fails
        assert!(res.headers().get("ratelimit").is_none());
    }
}

#[tokio::test]
async fn different_keys_have_separate_limits() {
    let layer = RateLimitLayer::builder()
        .max_requests(1)
        .window_secs(60)
        .key_extractor(|req: &mut axum::extract::Request| Some(req.uri().path().to_string()))
        .build();

    let app = Router::new()
        .route("/a", get(|| async { "a" }))
        .route("/b", get(|| async { "b" }))
        .layer(layer);

    // Each path gets its own limit
    let res = app.clone().oneshot(make_request("/a")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app.clone().oneshot(make_request("/b")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Second request to /a should be rate limited
    let res = app.clone().oneshot(make_request("/a")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Second request to /b should also be rate limited
    let res = app.clone().oneshot(make_request("/b")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn per_route_rate_limit() {
    let layer = limiter(1, 60);

    let app = Router::new()
        .route("/limited", get(|| async { "limited" }).layer(layer))
        .route("/unlimited", get(|| async { "unlimited" }));

    // First request to /limited succeeds
    let res = app.clone().oneshot(make_request("/limited")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Second request to /limited is rate limited
    let res = app.clone().oneshot(make_request("/limited")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // /unlimited is never rate limited
    let res = app
        .clone()
        .oneshot(make_request("/unlimited"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn global_rate_limit() {
    let layer = limiter(2, 60);

    let app = Router::new()
        .route("/a", get(|| async { "a" }))
        .route("/b", get(|| async { "b" }))
        .layer(layer);

    // All routes share the same key and limit
    let res = app.clone().oneshot(make_request("/a")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app.clone().oneshot(make_request("/b")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Third request to any route is rate limited (same key)
    let res = app.clone().oneshot(make_request("/a")).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn smart_ip_uses_x_forwarded_for() {
    let layer = RateLimitLayer::builder()
        .max_requests(1)
        .window_secs(60)
        .for_smart_ip()
        .build();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    // First request from "1.2.3.4:1234" via X-Forwarded-For
    let req = Request::get("/")
        .header("x-forwarded-for", "1.2.3.4:1234, 10.0.0.1:80")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Second request from same addr should be rate limited
    let req = Request::get("/")
        .header("x-forwarded-for", "1.2.3.4:1234, 10.0.0.2:80")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    // Different addr should be allowed
    let req = Request::get("/")
        .header("x-forwarded-for", "5.6.7.8:5678")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn smart_ip_uses_x_real_ip() {
    let layer = RateLimitLayer::builder()
        .max_requests(1)
        .window_secs(60)
        .for_smart_ip()
        .build();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    let req = Request::get("/")
        .header("x-real-ip", "9.8.7.6:4321")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = Request::get("/")
        .header("x-real-ip", "9.8.7.6:4321")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn smart_ip_no_headers_no_connect_info_passes_through() {
    let layer = RateLimitLayer::builder()
        .max_requests(1)
        .window_secs(60)
        .for_smart_ip()
        .build();

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(layer);

    // No X-Forwarded-For, no X-Real-Ip, no ConnectInfo — key extraction returns None
    for _ in 0..3 {
        let res = app.clone().oneshot(make_request("/")).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
