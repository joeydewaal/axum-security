use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, COOKIE},
    },
    routing::get,
};
use axum_security::{
    RouterExt,
    jwt::{Jwt, JwtContext, get_current_timestamp},
};
use serde::{Deserialize, Serialize};
use tower::Service;

const JWT_SECRET: &str = "test";

#[derive(Clone, Serialize, Deserialize)]
struct AccessToken {
    foo: u8,
    exp: u64,
}

async fn authorized(Jwt(_): Jwt<AccessToken>) -> StatusCode {
    StatusCode::OK
}

fn test_router() -> Router<()> {
    Router::new().route("/", get(authorized))
}

#[tokio::test]
async fn jwt_default() -> anyhow::Result<()> {
    let context = JwtContext::builder()
        .jwt_secret(JWT_SECRET)
        .build::<AccessToken>();

    let jwt = context.encode_token(&AccessToken {
        foo: 1,
        exp: get_current_timestamp() + 1000,
    })?;

    let mut router = test_router().with_auth(context);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method(Method::GET)
        .header(AUTHORIZATION, &format!("Bearer {jwt}"))
        .uri("/")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn jwt_header() -> anyhow::Result<()> {
    let context = JwtContext::builder()
        .jwt_secret(JWT_SECRET)
        .extract_header("x-api-token")
        .build::<AccessToken>();

    let jwt = context.encode_token(&AccessToken {
        foo: 1,
        exp: get_current_timestamp() + 1000,
    })?;

    let mut router = test_router().with_auth(context);

    let req = Request::builder()
        .method(Method::GET)
        .header("x-api-token", jwt)
        .uri("/")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn jwt_header_with_prefix() -> anyhow::Result<()> {
    let context = JwtContext::builder()
        .jwt_secret(JWT_SECRET)
        .extract_header_with_prefix("x-api-token", "Bearer ")
        .build::<AccessToken>();

    let jwt = context.encode_token(&AccessToken {
        foo: 1,
        exp: get_current_timestamp() + 1000,
    })?;

    let mut router = test_router().with_auth(context);

    let req = Request::builder()
        .method(Method::GET)
        .header("x-api-token", &format!("Bearer {jwt}"))
        .uri("/")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn jwt_cookie() -> anyhow::Result<()> {
    let context = JwtContext::builder()
        .jwt_secret(JWT_SECRET)
        .extract_cookie("session-cookie")
        .build::<AccessToken>();

    let jwt = context.encode_token(&AccessToken {
        foo: 1,
        exp: get_current_timestamp() + 1000,
    })?;

    let mut router = test_router().with_auth(context);

    let req = Request::builder()
        .method(Method::GET)
        .header(COOKIE, &format!("session-cookie={jwt}"))
        .uri("/")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn jwt_default_method_router() -> anyhow::Result<()> {
    let jwt_context = JwtContext::builder()
        .jwt_secret(JWT_SECRET)
        .build::<AccessToken>();

    let jwt = jwt_context.encode_token(&AccessToken {
        foo: 1,
        exp: get_current_timestamp() + 1000,
    })?;

    let mut router = Router::new()
        .route("/", get(|| async move { StatusCode::OK }))
        .route("/auth", get(authorized).with_auth(jwt_context));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::OK);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/auth")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method(Method::GET)
        .header(AUTHORIZATION, &format!("Bearer {jwt}"))
        .uri("/auth")
        .body(Body::empty())?;

    let res = router.call(req).await?;

    assert_eq!(res.status(), StatusCode::OK);
    Ok(())
}

#[test]
fn jwt_compiles() {
    let jwt_context = JwtContext::builder()
        .jwt_secret(JWT_SECRET)
        .build::<AccessToken>();

    let _ = Router::<()>::new()
        .route("/", get(|| async move { StatusCode::OK }))
        .route("/auth", get(authorized).layer(jwt_context.clone()))
        .layer(jwt_context);
}
