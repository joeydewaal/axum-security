use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    serve,
};
use axum_security::{
    RouterExt,
    cookie::{CookieContext, CookieSession, CookieStore, SessionId},
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
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

#[tokio::test]
async fn test_cookie_simple() -> anyhow::Result<()> {
    let store = SqlxStore {
        pool: SqlitePool::connect(":memory:").await?,
    };

    let session = CookieContext::builder()
        .enable_dev_cookie(true)
        .store(store)
        .build::<User>();

    let router = Router::new()
        .route("/", get(|| async { "hello world" }))
        .route("/authorized", get(authorized))
        .route("/login", get(login))
        .with_auth(&session)
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
    type Error = sqlx::Error;

    async fn load_session(
        &self,
        id: &SessionId,
    ) -> sqlx::Result<Option<CookieSession<Self::State>>> {
        #[derive(FromRow)]
        struct UserWithSession {
            #[sqlx(flatten)]
            user: User,
            session_id: String,
            created_at: i64,
        }

        let user: Option<UserWithSession> = sqlx::query_as(
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
        .fetch_optional(&self.pool)
        .await?;

        let Some(user) = user else {
            return Ok(None);
        };

        let session_id = SessionId::new(user.session_id);

        Ok(Some(CookieSession::new(
            session_id,
            user.created_at as u64,
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
        .bind(session.user_id)
        .bind(session.session_id.as_str())
        .bind(session.created_at as i64)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn remove_session(&self, id: &SessionId) -> sqlx::Result<Option<CookieSession<User>>> {
        let session_id: Option<String> =
            sqlx::query_scalar("DELETE FROM user_sessions WHERE session_id = $1")
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await?;

        let Some(session_id) = session_id else {
            return Ok(None);
        };

        let session_id = SessionId::new(session_id);
        // TODO!!
        self.load_session(&session_id).await
    }

    async fn remove_after(&self, deadline: u64) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM user_sessions WHERE created_at < $1")
            .bind(deadline as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
