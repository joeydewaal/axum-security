use std::error::Error;

use axum::{
    Json, Router,
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    serve,
};
use axum_security::{
    cookie::{CookieContext, CookieSession, MemStore},
    oauth2::{
        AfterLoginContext, OAuth2Context, OAuth2Ext, OAuth2Handler, TokenResponse,
        providers::github,
    },
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Serialize, Clone)]
struct User {
    id: String,
    username: String,
}

#[derive(Deserialize)]
struct NextUrl {
    after_login: Option<String>,
}

async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

async fn login(oauth: OAuth2Context, Query(query): Query<NextUrl>) -> impl IntoResponse {
    let cookie = query
        .after_login
        .map(|path| oauth.cookie("after-login-redirect").value(path).build());

    let res = oauth.start_challenge().await;

    (cookie, res)
}

struct OAuth2Backend {
    session: CookieContext<User>,
}

impl OAuth2Backend {
    pub fn new(session: CookieContext<User>) -> Self {
        OAuth2Backend { session }
    }
}

impl OAuth2Handler for OAuth2Backend {
    async fn after_login(
        &self,
        res: TokenResponse,
        context: &mut AfterLoginContext<'_>,
    ) -> impl IntoResponse {
        println!("user logged in");
        println!("at: {}", res.access_token);
        println!("refresh token:: {:?}", res.refresh_token);

        let id = "".into();
        let username = "user".into();

        let user = User { id, username };

        let cookie = self.session.create_session(user).await.unwrap();

        context.cookie_jar.add(cookie);

        let redirect_cookie = context.cookie("after-login-url");

        if let Some(c) = context.cookie_jar.remove(redirect_cookie) {
            Redirect::to(c.value())
        } else {
            Redirect::to("/")
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let session = CookieContext::builder()
        .use_dev_cookie(true)
        .store(MemStore::new())
        .build();

    let context = OAuth2Context::builder()
        .client_id_env("CLIENT_ID")
        .client_secret_env("CLIENT_SECRET")
        .redirect_uri_env("REDIRECT_URL")
        .token_url(github::TOKEN_URL)
        .auth_url(github::AUTH_URL)
        .cookie(|c| c.path("/login"))
        .use_dev_cookies(true)
        .store(MemStore::new())
        .build(OAuth2Backend::new(session.clone()));

    let router = Router::new()
        .route("/", get(|_u: CookieSession<User>| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .with_oauth2(context.clone())
        .layer(session)
        .with_state(context);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
