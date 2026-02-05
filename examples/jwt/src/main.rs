use std::error::Error;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use axum_security::jwt::{Jwt, JwtContext};
use jiff::{Timestamp, ToSpan, Zoned};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

const JWT_SECRET: &str = "test-jwt-secret";

#[derive(Clone, Serialize, Deserialize)]
struct AccessToken {
    username: String,
    emailadres: Option<String>,
    created_at: Zoned,
    #[serde(with = "jiff::fmt::serde::timestamp::second::required")]
    exp: Timestamp,
}

async fn authorized(Jwt(token): Jwt<AccessToken>) -> Json<AccessToken> {
    Json(token)
}

#[derive(Deserialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn login(
    session: JwtContext<AccessToken>,
    Query(login): Query<LoginAttempt>,
) -> Result<String, StatusCode> {
    if login.username == "admin" && login.password == "admin" {
        let now = Zoned::now();

        // This token is only valid for 1 day.
        let expires = &now + 1.day();

        let user = AccessToken {
            username: login.username,
            emailadres: None,
            created_at: now,
            exp: expires.timestamp(),
        };

        session
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
        .route("/me", get(authorized))
        .route("/login", get(login))
        .layer(jwt_service)
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    axum::serve(listener, router).await?;
    Ok(())
}
