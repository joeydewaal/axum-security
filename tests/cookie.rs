use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    serve,
};
use axum_security::{
    oauth2::RouterExt,
    session::{CookieSession, Session},
    store::MemoryStore,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone, Serialize)]
struct User {
    username: String,
    email: Option<String>,
}

async fn authorized(user: Session<User>) -> Json<User> {
    Json(user.into_state())
}

#[derive(Deserialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn login(
    State(session): State<CookieSession<MemoryStore<User>>>,
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
async fn test_cookie() -> anyhow::Result<()> {
    let session = CookieSession::builder()
        .cookie(|c| {
            c.name("session")
                .domain("www.rust-lang.com")
                .path("/")
                .max_age(Duration::from_mins(15))
        })
        .dev_cookie(|c| c.path("/"))
        .build::<User>(true);

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .with_session(session.clone())
        .with_state(session);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}

#[tokio::test]
async fn test_cookie_simple() -> anyhow::Result<()> {
    let session = CookieSession::builder().build::<User>(true);

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .with_session(session.clone())
        .with_state(session);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
