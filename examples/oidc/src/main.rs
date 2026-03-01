use std::{error::Error, time::Duration};

use axum::{
    Json, Router,
    response::{IntoResponse, Redirect},
    routing::get,
};
use axum_security::{
    cookie::{CookieContext, CookieSession, MemStore},
    oidc::{AfterLoginCookies, OidcContext, OidcExt, OidcHandler, OidcTokenResponse},
};
use serde::Serialize;
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize)]
struct User {
    subject: String,
    email: Option<String>,
    name: Option<String>,
}

struct LoginHandler {
    cookie_service: CookieContext<User>,
}

impl OidcHandler for LoginHandler {
    async fn after_login(
        &self,
        token_res: OidcTokenResponse,
        cookies: &mut AfterLoginCookies<'_>,
    ) -> impl IntoResponse {
        let user = User {
            subject: token_res.claims.subject,
            email: token_res.claims.email,
            name: token_res.claims.name,
        };

        let session_cookie = self
            .cookie_service
            .create_session(user)
            .await
            .unwrap();

        cookies.add(session_cookie);
        Redirect::to("/")
    }
}

async fn me(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

async fn index(user: Option<CookieSession<User>>) -> Result<Json<User>, &'static str> {
    if let Some(user) = user {
        Ok(Json(user.state))
    } else {
        Err("You are not logged in, go to http://localhost:3000/login")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cookie_service = CookieContext::builder()
        .dev_cookie(|c| c.name("session").max_age(Duration::from_mins(30)))
        .use_dev_cookie(true)
        .store(MemStore::new())
        .build();

    let handler = LoginHandler {
        cookie_service: cookie_service.clone(),
    };

    let oidc_context = OidcContext::google()
        .await?
        .client_id_env("GOOGLE_CLIENT_ID")
        .client_secret_env("GOOGLE_CLIENT_SECRET")
        .redirect_url("http://localhost:3000/auth/oidc/callback")
        .login_path("/login")
        .scopes(&["openid", "email", "profile"])
        .use_dev_cookies(true)
        .build(handler);

    let router = Router::new()
        .route("/", get(index))
        .route("/me", get(me))
        .layer(cookie_service)
        .with_oidc(oidc_context);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on http://localhost:3000");

    axum::serve(listener, router).await?;
    Ok(())
}
