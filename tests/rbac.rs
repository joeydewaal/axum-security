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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum Role {
    Admin = 1,
    User = 0,
}

impl RBAC for Role {
    type Resource = AccessToken;

    fn has_role(resource: &Self::Resource, role: &Self) -> bool {
        resource.roles.contains(role)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct AccessToken {
    username: String,
    email: Option<String>,
    exp: u64,
    roles: Vec<Role>,
}

#[derive(Deserialize, Serialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn authorized(Jwt(user): Jwt<AccessToken>) -> Json<AccessToken> {
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
            roles: vec![Role::Admin],
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
        .route("/authorized/admin", get(authorized).requires(Role::Admin))
        .route(
            "/authorized/any",
            get(authorized).requires_any([Role::Admin, Role::User]),
        )
        .with_auth(&jwt)
        .with_state(jwt);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
