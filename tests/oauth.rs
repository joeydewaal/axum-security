use axum::{
    Json, Router,
    response::{IntoResponse, Redirect},
    routing::get,
    serve,
};
use axum_security::{
    RouterExt,
    cookie::{CookieContext, CookieSession, MemoryStore},
    oauth2::{OAuth2Context, OAuth2Handler, TokenResponse, providers::github},
};
use serde::Serialize;
use tokio::net::TcpListener;

struct Oauth2Backend {
    session: CookieContext<MemoryStore<User>>,
}

impl Oauth2Backend {
    pub fn new(session: CookieContext<MemoryStore<User>>) -> Self {
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

        let cookie = self.session.store_session(user).await;

        (cookie, Redirect::to("/"))
    }
}

#[tokio::test]
async fn test1() -> anyhow::Result<()> {
    let session = CookieContext::builder().build(true);

    let context = OAuth2Context::builder()
        .client_id_env("CLIENT_ID")
        .client_secret_env("CLIENT_SECRET")
        .redirect_uri_env("REDIRECT_URL")
        .token_url(github::TOKEN_URL)
        .auth_url(github::AUTH_URL)
        .login_path("/login")
        .cookie(|c| c.http_only().secure())
        .build(Oauth2Backend::new(session.clone()), true);

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .with_auth(context)
        .with_auth(session);

    async fn authorized(user: CookieSession<User>) -> Json<User> {
        Json(user.into_state())
    }

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
