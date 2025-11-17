use axum::{
    Json, Router,
    extract::{Query, State},
    response::IntoResponse,
    routing::get,
    serve,
};
use axum_security::{
    RouterExt,
    cookie::{CookieContext, CookieSession, CookieStore, SessionId},
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::net::TcpListener;

#[derive(Clone, Serialize)]
struct User {
    username: String,
    email: Option<String>,
}

async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.into_state())
}

#[derive(Deserialize)]
struct LoginAttempt {
    username: String,
    password: String,
}

async fn login(
    State(session): State<CookieContext<SqlxStore>>,
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
async fn test_cookie_simple() -> anyhow::Result<()> {
    let store = SqlxStore {
        pool: SqlitePool::connect(":memory:").await?,
    };

    let session = CookieContext::builder_with_store(store).build::<User>(true);

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .with_auth(session.clone())
        .with_state(session);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}

struct SqlxStore {
    #[allow(unused)]
    pool: SqlitePool,
}

impl CookieStore for SqlxStore {
    type State = User;

    async fn load_session(&self, _id: &SessionId) -> Option<CookieSession<User>> {
        todo!();
    }

    async fn store_session(&self, _session: CookieSession<User>) -> () {
        todo!();
    }

    async fn remove_session(&self, _id: &SessionId) -> Option<CookieSession<User>> {
        todo!();
    }
}
