use std::error::Error;

use axum::{
    Json, Router,
    extract::Query,
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
    id: i32,
    username: String,
}

async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

static AFTER_LOGIN_COOKIE: &str = "after-login-path";

#[derive(Deserialize)]
struct NextUrl {
    after_login: Option<String>,
}

async fn login(oauth: OAuth2Context, Query(query): Query<NextUrl>) -> impl IntoResponse {
    // The after_login query param is the path where the user should be redirected to after the
    // login flow is done.
    //
    // To do so we store the path in a cookie and after the flow is done, check for the cookie and
    // redirect.
    let cookie = if let Some(path) = query.after_login {
        // Creates a cookie with the same _settings_ as the oauth2 context.
        Some(oauth.cookie(AFTER_LOGIN_COOKIE).value(path).build())
    } else {
        None
    };

    (cookie, oauth.start_challenge().await)
}

struct OAuth2Backend {
    session: CookieContext<User>,
}

impl OAuth2Backend {
    pub fn new(session: CookieContext<User>) -> Self {
        OAuth2Backend { session }
    }

    pub async fn fetch_user(&self, _token: &str) -> User {
        User {
            id: 1,
            username: "user".into(),
        }
    }
}

impl OAuth2Handler for OAuth2Backend {
    async fn after_login(
        &self,
        res: TokenResponse,
        context: &mut AfterLoginContext<'_>,
    ) -> impl IntoResponse {
        // Fetch the user based on the access token.
        let user = self.fetch_user(&res.access_token).await;

        // Create a session for the user and store the session cookie.
        let cookie = self.session.create_session(user).await.unwrap();
        context.cookie_jar.add(cookie);

        // See if we should redirect the user to a different path than "/".
        if let Some(c) = context.remove(AFTER_LOGIN_COOKIE) {
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
        .route("/", get(|_: CookieSession<User>| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .with_oauth2(context.clone())
        .layer(session)
        .with_state(context);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    serve(listener, router).await?;
    Ok(())
}
