use axum::{
    Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    serve,
};
use axum_security::{
    cookie::{CookieContext, MemoryStore},
    jwt::{JwtContext, JwtSession},
    oauth2::RouterExt,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone, Serialize, Deserialize)]
struct User {
    username: String,
    email: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn login(
    State(session): State<CookieContext<MemoryStore<User>>>,
    Query(login): Query<LoginAttempt>,
) -> impl IntoResponse {
    if login.username == "admin" && login.password == "admin" {
        let user = User {
            username: login.username,
            email: None,
        };

        let cookie = session.store_session(user).await;

        (cookie, "Logged in").into_response()
    } else {
        "failed to log in".into_response()
    }
}

#[tokio::test]
async fn test_jwt() -> anyhow::Result<()> {
    let jwt = JwtContext::builder().jwt_secret("").build::<User>();

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .with_jwt_session(jwt);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
