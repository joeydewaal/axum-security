use std::error::Error;

use axum::{
    Json, Router,
    response::{IntoResponse, Redirect},
    routing::get,
};
use axum_security::{
    cookie::{CookieContext, CookieSession, MemStore},
    oauth2::{
        AfterLoginContext, OAuth2Context, OAuth2Ext, OAuth2Handler, TokenResponse,
        providers::github,
    },
};
use jiff::Timestamp;
use reqwest::{Client, StatusCode, header::USER_AGENT};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

struct LoginHandler {
    cookie_service: CookieContext<MemStore<User>>,
    http_client: Client,
}

#[derive(Debug, Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
    email: Option<String>,
}

#[derive(Clone, Serialize)]
struct User {
    user_id: u64,
    username: String,
    email: Option<String>,
    created_at: Timestamp,
}

impl OAuth2Handler for LoginHandler {
    async fn after_login(
        &self,
        token_res: TokenResponse,
        context: &mut AfterLoginContext<'_>,
    ) -> impl IntoResponse {
        // Retrieve the info of the user from the github api.
        let Ok(resp) = self
            .http_client
            .get("https://api.github.com/user")
            .header(USER_AGENT, "axum-security") // required by the github api.
            .bearer_auth(token_res.access_token)
            .send()
            .await
        else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        let Ok(user_info) = resp.json::<GithubUser>().await else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        let user = User {
            user_id: user_info.id,
            username: user_info.login,
            email: user_info.email,
            created_at: Timestamp::now(),
        };

        // Create a new session for the user.
        let session_cookie = self
            .cookie_service
            .create_session(user)
            .await
            .expect("MemStore doesn't return an error");

        // Make sure to add the session cookie to the cookiejar.
        context.cookies.add(session_cookie);

        // Redirect the user back to the app.
        Ok(Redirect::to("/"))
    }
}

async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cookie_service = CookieContext::builder()
        .cookie(|c| c.name("session"))
        .store(MemStore::new())
        .build();

    let handler = LoginHandler {
        cookie_service: cookie_service.clone(),
        http_client: Client::new(),
    };

    let oauth2_service = OAuth2Context::builder()
        .auth_url(github::AUTH_URL)
        .token_url(github::TOKEN_URL)
        .client_id_env("CLIENT_ID")
        .client_secret_env("CLIENT_SECRET")
        // Where the app is redirected to after login in.
        .redirect_uri("http://localhost:3000/redirect")
        // Where the user should go to to start the login flow.
        .login_path("/login")
        // e
        .cookie(|c| c.path("/login"))
        .dev(true)
        .store(MemStore::new())
        .build(handler);

    let router = Router::new()
        .route("/me", get(authorized))
        .layer(cookie_service)
        .with_oauth2(oauth2_service);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    axum::serve(listener, router).await?;
    Ok(())
}
