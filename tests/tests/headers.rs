#![cfg(feature = "headers")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get,
};
use axum_security::headers::{
    ContentSecurityPolicy, ContentTypeOptions, CrossOriginOpenerPolicy, CspSource,
    DnsPrefetchControl, FrameOptions, ReferrerPolicy, SecurityHeaders, StrictTransportSecurity,
    XssProtection,
};
use tower::ServiceExt;

async fn call(router: Router, path: &str) -> axum::http::Response<Body> {
    router
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn csp_layer_sets_header() {
    let csp = ContentSecurityPolicy::builder()
        .default_src(CspSource::SELF)
        .script_src([CspSource::SELF, CspSource::UNSAFE_INLINE])
        .build();

    let router = Router::new().route("/", get(|| async { "ok" })).layer(csp);

    let res = call(router, "/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()["content-security-policy"],
        "default-src 'self'; script-src 'self' 'unsafe-inline'"
    );
}

#[tokio::test]
async fn csp_with_hosts_and_schemes() {
    let csp = ContentSecurityPolicy::builder()
        .default_src(CspSource::NONE)
        .img_src([CspSource::SELF, CspSource::host("https://cdn.example.com")])
        .font_src(CspSource::scheme("data:"))
        .build();

    let router = Router::new().route("/", get(|| async { "ok" })).layer(csp);

    let res = call(router, "/").await;
    assert_eq!(
        res.headers()["content-security-policy"],
        "default-src 'none'; img-src 'self' https://cdn.example.com; font-src data:"
    );
}

#[tokio::test]
async fn csp_upgrade_insecure_requests() {
    let csp = ContentSecurityPolicy::builder()
        .default_src(CspSource::SELF)
        .upgrade_insecure_requests()
        .build();

    let router = Router::new().route("/", get(|| async { "ok" })).layer(csp);

    let res = call(router, "/").await;
    assert_eq!(
        res.headers()["content-security-policy"],
        "default-src 'self'; upgrade-insecure-requests"
    );
}

#[tokio::test]
async fn security_headers_recommended_sets_all() {
    let headers = SecurityHeaders::recommended();
    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(headers);

    let res = call(router, "/").await;
    assert_eq!(res.status(), StatusCode::OK);

    // Check a few of the recommended headers
    assert_eq!(res.headers()["cross-origin-opener-policy"], "same-origin");
    assert_eq!(res.headers()["cross-origin-resource-policy"], "same-origin");
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    assert_eq!(res.headers()["x-frame-options"], "SAMEORIGIN");
    assert_eq!(res.headers()["x-xss-protection"], "0");
    assert_eq!(res.headers()["referrer-policy"], "no-referrer");
    assert_eq!(res.headers()["origin-agent-cluster"], "?1");
    assert!(
        res.headers()["strict-transport-security"]
            .to_str()
            .unwrap()
            .starts_with("max-age=")
    );
}

#[tokio::test]
async fn security_headers_add_overrides() {
    let headers = SecurityHeaders::new()
        .add(CrossOriginOpenerPolicy::SAME_ORIGIN)
        .add(CrossOriginOpenerPolicy::UNSAFE_NONE);

    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(headers);

    let res = call(router, "/").await;
    assert_eq!(res.headers()["cross-origin-opener-policy"], "unsafe-none");
}

#[tokio::test]
async fn security_headers_try_add_does_not_override() {
    let headers = SecurityHeaders::new()
        .add(CrossOriginOpenerPolicy::SAME_ORIGIN)
        .try_add(CrossOriginOpenerPolicy::UNSAFE_NONE);

    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(headers);

    let res = call(router, "/").await;
    assert_eq!(res.headers()["cross-origin-opener-policy"], "same-origin");
}

#[tokio::test]
async fn security_headers_with_csp() {
    let csp = ContentSecurityPolicy::builder()
        .default_src(CspSource::SELF)
        .build();

    let headers = SecurityHeaders::new().add(XssProtection::ZERO).add(csp);

    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(headers);

    let res = call(router, "/").await;
    assert_eq!(res.headers()["x-xss-protection"], "0");
    assert_eq!(
        res.headers()["content-security-policy"],
        "default-src 'self'"
    );
}

#[tokio::test]
async fn security_headers_dev_mode_sets_no_headers() {
    let headers = SecurityHeaders::recommended().use_dev_headers(true);

    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(headers);

    let res = call(router, "/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get("x-xss-protection").is_none());
    assert!(res.headers().get("cross-origin-opener-policy").is_none());
    assert!(res.headers().get("strict-transport-security").is_none());
}

#[tokio::test]
async fn individual_header_layer() {
    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(ContentTypeOptions::NO_SNIFF);

    let res = call(router, "/").await;
    assert_eq!(res.headers()["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn hsts_layer() {
    let hsts = StrictTransportSecurity::builder()
        .max_age_years(1)
        .include_subdomains()
        .preload()
        .build();

    let router = Router::new().route("/", get(|| async { "ok" })).layer(hsts);

    let res = call(router, "/").await;
    assert_eq!(
        res.headers()["strict-transport-security"],
        "max-age=31536000; includeSubDomains; preload"
    );
}

#[tokio::test]
async fn multiple_individual_layers() {
    let router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(FrameOptions::DENY)
        .layer(DnsPrefetchControl::OFF)
        .layer(ReferrerPolicy::STRICT_ORIGIN);

    let res = call(router, "/").await;
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    assert_eq!(res.headers()["x-dns-prefetch-control"], "off");
    assert_eq!(res.headers()["referrer-policy"], "strict-origin");
}

#[tokio::test]
async fn per_route_header() {
    let router = Router::new()
        .route(
            "/strict",
            get(|| async { "strict" }).layer(FrameOptions::DENY),
        )
        .route("/open", get(|| async { "open" }));

    let res = call(router.clone(), "/strict").await;
    assert_eq!(res.headers()["x-frame-options"], "DENY");

    let res = call(router, "/open").await;
    assert!(res.headers().get("x-frame-options").is_none());
}
