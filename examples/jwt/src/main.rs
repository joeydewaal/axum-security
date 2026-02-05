use std::error::Error;

use axum::{Json, Router, extract::Query, http::StatusCode, routing::get};
use axum_security::jwt::{Jwt, JwtContext};
use jiff::{Timestamp, ToSpan};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

static JWT_SECRET: &str = "test-jwt-secret";

#[derive(Clone, Serialize, Deserialize)]
struct AccessToken {
    username: String,
    emailadres: Option<String>,
    created_at: Timestamp,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    exp: Timestamp,
}

async fn authorized(Jwt(token): Jwt<AccessToken>) -> Json<AccessToken> {
    Json(token)
}

async fn maybe_authorized(token: Option<Jwt<AccessToken>>) -> String {
    if let Some(Jwt(token)) = token {
        format!("Hi, {}", token.username)
    } else {
        "You are not logged in.".to_string()
    }
}

#[derive(Deserialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn login(
    Query(login): Query<LoginAttempt>,
    context: JwtContext<AccessToken>,
) -> Result<String, StatusCode> {
    if login.username == "admin" && login.password == "admin" {
        let now = Timestamp::now();

        // This token is only valid for 1 day.
        let expires = now + 24.hours();

        let user = AccessToken {
            username: login.username,
            emailadres: None,
            created_at: now,
            exp: expires,
        };

        context
            .encode_token(&user)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // By default the `JwtContext` looks for a bearer token in the `AUTHORIZATION` header.
    let jwt_service = JwtContext::builder()
        // The secret we're using for the jwt token.
        .jwt_secret(JWT_SECRET)
        // Infer the type of the token.
        .build::<AccessToken>();

    // The jwt service is also used as state to create jwt's.
    let state = jwt_service.clone();

    let router = Router::new()
        .route("/", get(maybe_authorized))
        .route("/me", get(authorized))
        .route("/login", get(login))
        .layer(jwt_service)
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    axum::serve(listener, router).await?;
    Ok(())
}
