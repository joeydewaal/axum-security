use std::env;

use axum::{
    Json, Router,
    response::{IntoResponse, Redirect},
    routing::get,
    serve,
};
use axum_auth_utils::{
    oauth2::{OAuth2Context, OAuth2Handler, RouterOAuthExt, TokenResponse},
    session::{CookieSession, Session},
    store::MemoryStore,
};
use serde::Serialize;
use tokio::net::TcpListener;

struct Oauth2Backend {
    session: CookieSession<MemoryStore<User>>,
}

impl Oauth2Backend {
    pub fn new(session: CookieSession<MemoryStore<User>>) -> Self {
        Oauth2Backend { session }
    }
}

#[derive(Serialize, Clone)]
struct User {
    id: String,
    username: String,
}

impl OAuth2Handler for Oauth2Backend {
    async fn after_login(&self, res: TokenResponse) -> impl IntoResponse {
        println!("user logged in");
        println!("at: {}", res.access_token());
        println!("refresh token:: {:?}", res.refresh_token());

        let id = "".into();
        let username = "user".into();

        let user = User { id, username };

        let session = self.session.store_session(user).await;

        (session.cookie(), Redirect::to("/"))
    }
}

#[tokio::test]
async fn test1() -> anyhow::Result<()> {
    let session = CookieSession::builder().build();

    let context = OAuth2Context::builder()
        .client_id(env::var("CLIENT_ID").unwrap())
        .client_secret(env::var("CLIENT_SECRET").unwrap())
        .redirect_uri(env::var("REDIRECT_URL").unwrap())
        .token_url("https://github.com/login/oauth/access_token")
        .auth_url("https://github.com/login/oauth/authorize")
        .start_challenge_path("/login")
        .cookie(|c| c.http_only().secure())
        .build(Oauth2Backend::new(session.clone()));

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .with_oauth2(&context)
        .with_session(session);

    async fn authorized(user: Session<User>) -> Json<User> {
        Json(user.into_state())
    }

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
