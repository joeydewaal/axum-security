use std::{error::Error, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
};
use axum_security::cookie::{CookieContext, CookieJar, CookieSession, MemStore, SameSite};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone, Serialize)]
struct User {
    username: String,
    email: Option<String>,
    created_at: Timestamp,
}

async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

#[derive(Deserialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn login(
    State(session): State<CookieContext<MemStore<User>>>,
    Query(login): Query<LoginAttempt>,
) -> impl IntoResponse {
    if login.username == "admin" && login.password == "admin" {
        let user = User {
            username: login.username,
            email: None,
            created_at: Timestamp::now(),
        };

        let cookie = session.create_session(user).await.unwrap();

        (Some(cookie), "Logged in")
    } else {
        (None, "failed to log in")
    }
}

async fn logout(
    jar: CookieJar,
    State(context): State<CookieContext<MemStore<User>>>,
) -> impl IntoResponse {
    match context.remove_session_jar(&jar).await.unwrap() {
        Some(e) => format!("Removed: {}", e.state.username),
        None => "No session found".to_string(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cookie_service = CookieContext::builder()
        // The default cookie that is used.
        .cookie(|c| {
            c.name("session")
                .max_age(Duration::from_hours(24))
                .secure()
                .http_only()
                .same_site(SameSite::Strict)
        })
        // The cookie that is used in dev mode.
        .dev_cookie(|c| c.name("dev-session"))
        // Enable dev cookie when we are using the debug profile.
        .use_dev_cookie(cfg!(debug_assertions))
        // Store the cookies in memory for now. You should not use this in a production scenario.
        .store(MemStore::new())
        // A sessions expires at the same time as the max age setting of the cookie that is used.
        .expires_max_age()
        // A `User` is connected to a session.
        .build::<User>();

    // The cookie service is also used as state to create cookies.
    let state = cookie_service.clone();

    let router = Router::new()
        .route("/me", get(authorized))
        .route("/login", get(login))
        .route("/logout", get(logout))
        // Inject the cookie service into this router.
        .layer(cookie_service)
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    axum::serve(listener, router).await?;
    Ok(())
}
