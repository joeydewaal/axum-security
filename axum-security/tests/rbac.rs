use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    serve,
};
use axum_security::{
    RouterExt,
    jwt::{Jwt, JwtContext, get_current_timestamp},
    rbac::{RBAC, RBACExt},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
enum UserRole {
    Admin,
    User,
}

impl RBAC for UserRole {
    type Resource = AccessToken;

    fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self> {
        &resource.roles
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct AccessToken {
    username: String,
    email: Option<String>,
    exp: u64,
    roles: HashSet<UserRole>,
}

#[derive(Deserialize, Serialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

#[axum_security::rbac::requires_any(crate::UserRole::Admin, UserRole::User)]
async fn authorized3(Jwt(user): Jwt<AccessToken>, _string: String) -> Json<AccessToken> {
    Json(user)
}

#[axum_security::rbac::requires(UserRole::Admin, UserRole::User)]
async fn authorized2(Jwt(user): Jwt<AccessToken>, _string: String) -> Json<AccessToken> {
    Json(user)
}

#[axum_security::rbac::requires(UserRole::Admin)]
async fn authorized1(Jwt(user): Jwt<AccessToken>, _string: String) -> Json<AccessToken> {
    Json(user)
}

async fn login(
    State(session): State<JwtContext<AccessToken>>,
    Query(login): Query<LoginAttempt>,
) -> impl IntoResponse {
    if login.username == "admin" && login.password == "admin" {
        let at = AccessToken {
            username: login.username,
            email: None,
            exp: get_current_timestamp() + 10_000,
            roles: HashSet::from_iter([UserRole::Admin]),
        };

        let token = session.encode_token(&at).unwrap();
        Json(token).into_response()
    } else {
        "failed to log in".into_response()
    }
}

#[tokio::test]
async fn test_jwt() -> anyhow::Result<()> {
    let jwt = JwtContext::builder()
        .jwt_secret("TEST")
        .build::<AccessToken>();

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/login", get(login))
        .route(
            "/authorized/admin",
            get(authorized1).requires(UserRole::Admin),
        )
        .route(
            "/authorized/any",
            get(authorized2).requires_any([UserRole::Admin, UserRole::User]),
        )
        .with_auth(&jwt)
        .with_state(jwt);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
