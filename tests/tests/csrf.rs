#![cfg(feature = "csrf")]

use axum::{
    Router,
    body::Body,
    http::{self, Method, Request, StatusCode},
    routing::{delete, get, patch, post, put},
};
use axum_security::csrf::{Csrf, CsrfToken};
use tower::ServiceExt;

fn make_layer() -> Csrf {
    Csrf::builder()
        .secret("test-secret-key-for-csrf-testing")
        .use_dev_cookie(true)
        .build()
}

fn extract_csrf_cookie(res: &http::Response<Body>) -> Option<String> {
    for val in res.headers().get_all("set-cookie") {
        let s: &str = val.to_str().unwrap();
        if s.starts_with("csrf-token=") {
            let token = s.split('=').nth(1).unwrap().split(';').next().unwrap();
            return Some(token.to_owned());
        }
    }
    None
}

fn app() -> Router {
    Router::new()
        .route(
            "/",
            get(|token: CsrfToken| async move { token.as_str().to_owned() }),
        )
        .route("/submit", post(|| async { "ok" }))
        .route("/update", put(|| async { "ok" }))
        .route("/patch", patch(|| async { "ok" }))
        .route("/remove", delete(|| async { "ok" }))
        .layer(make_layer())
}

#[tokio::test]
async fn get_sets_cookie_and_extractor_works() {
    let res = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let cookie_token = extract_csrf_cookie(&res).expect("CSRF cookie should be set");
    assert!(!cookie_token.is_empty());

    // The body should contain the same token (returned by the handler via CsrfToken extractor)
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_token = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(cookie_token, body_token);
}

#[tokio::test]
async fn post_with_matching_header_token_succeeds() {
    // First GET to obtain a token
    let res = app()
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let token = extract_csrf_cookie(&res).unwrap();

    // POST with matching token in header and cookie
    let res = app()
        .oneshot(
            Request::post("/submit")
                .header("cookie", format!("csrf-token={token}"))
                .header("x-csrf-token", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn post_with_matching_form_field_succeeds() {
    // First GET to obtain a token
    let res = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let token = extract_csrf_cookie(&res).unwrap();

    // POST with token in query string (form field fallback)
    let uri = format!("/submit?_csrf={token}");
    let res = app()
        .oneshot(
            Request::post(&uri)
                .header("cookie", format!("csrf-token={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn post_with_no_token_returns_403() {
    let res = app()
        .oneshot(Request::post("/submit").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn post_with_wrong_token_returns_403() {
    // GET to obtain a valid token
    let res = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let token = extract_csrf_cookie(&res).unwrap();

    // POST with cookie but wrong header token
    let res = app()
        .oneshot(
            Request::post("/submit")
                .header("cookie", format!("csrf-token={token}"))
                .header("x-csrf-token", "completely-wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_patch_delete_are_validated() {
    for (method, path) in [
        (Method::PUT, "/update"),
        (Method::PATCH, "/patch"),
        (Method::DELETE, "/remove"),
    ] {
        // Without token → 403
        let res = app()
            .oneshot(
                Request::builder()
                    .method(&method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {path} should be forbidden without CSRF token"
        );

        // With valid token → 200
        let get_res = app()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let token = extract_csrf_cookie(&get_res).unwrap();

        let res = app()
            .oneshot(
                Request::builder()
                    .method(&method)
                    .uri(path)
                    .header("cookie", format!("csrf-token={token}"))
                    .header("x-csrf-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "{method} {path} should succeed with valid CSRF token"
        );
    }
}

#[tokio::test]
async fn get_requests_are_never_blocked() {
    // GET without any cookies/tokens should work fine
    let res = app()
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}
