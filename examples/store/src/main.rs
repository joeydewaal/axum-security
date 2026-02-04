use std::error::Error;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    serve,
};
use axum_security::cookie::{CookieContext, CookieSession, CookieStore, SessionId};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqliteExecutor, SqlitePool};
use tokio::net::TcpListener;

#[derive(Clone, Serialize, FromRow)]
struct User {
    user_id: i32,
    username: String,
    email: Option<String>,
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
    State(session): State<CookieContext<SqlxStore>>,
    Query(login): Query<LoginAttempt>,
) -> impl IntoResponse {
    if login.username == "admin" && login.password == "admin" {
        let user = User {
            username: login.username,
            email: None,
            user_id: 1,
        };

        let Ok(cookie) = session.create_session(user).await else {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };

        (cookie, "Logged in").into_response()
    } else {
        "failed to log in".into_response()
    }
}

struct SqlxStore {
    pool: SqlitePool,
}

#[derive(FromRow)]
struct UserWithSession {
    #[sqlx(flatten)]
    user: User,
    #[sqlx(try_from = "String")]
    session_id: SessionId,
    #[sqlx(try_from = "i64")]
    created_at: u64,
}

async fn load_user(
    id: &SessionId,
    exec: impl SqliteExecutor<'_>,
) -> sqlx::Result<Option<UserWithSession>> {
    sqlx::query_as(
        "
        SELECT
            user_id,
            username,
            emailadres,
            session_id,
            created_at
        FROM users
        JOIN user_ssessions using (user_id)
        WHERE session_id = $1
            ",
    )
    .bind(id.as_str())
    .fetch_optional(exec)
    .await
}

impl CookieStore for SqlxStore {
    type State = User;
    type Error = sqlx::Error;

    async fn load_session(
        &self,
        id: &SessionId,
    ) -> sqlx::Result<Option<CookieSession<Self::State>>> {
        let user = load_user(id, &self.pool).await?;

        let Some(user) = user else {
            return Ok(None);
        };

        Ok(Some(CookieSession::new(
            user.session_id,
            user.created_at,
            user.user,
        )))
    }

    async fn store_session(&self, session: CookieSession<User>) -> sqlx::Result<()> {
        sqlx::query(
            "
        INSERT INTO user_sessions(
            user_id,
            session_id,
            created_at
        )
        VALUES ($1, $2, $3)
        ",
        )
        .bind(session.state.user_id)
        .bind(session.session_id.as_str())
        .bind(session.created_at as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn remove_session(&self, id: &SessionId) -> sqlx::Result<Option<CookieSession<User>>> {
        let mut tx = self.pool.begin().await?;

        let user = load_user(id, &mut *tx).await?;

        if user.is_some() {
            sqlx::query("DELETE FROM user_sessions WHERE session_id = $1")
                .bind(id.as_str())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;

        Ok(user.map(|u| CookieSession::new(u.session_id, u.created_at, u.user)))
    }

    async fn remove_before(&self, deadline: u64) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM user_sessions WHERE created_at < $1")
            .bind(deadline as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let store = SqlxStore {
        pool: SqlitePool::connect(":memory:").await?,
    };

    let session = CookieContext::builder()
        .use_dev_cookie(true)
        .store(store)
        .build::<User>();

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .layer(session.clone())
        .with_state(session);

    let listener = TcpListener::bind("0.0.0.0:8081").await?;

    serve(listener, router).await?;
    Ok(())
}
