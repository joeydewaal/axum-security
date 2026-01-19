use std::error::Error;

use axum::{
    Router,
    extract::{Path, State},
    response::IntoResponse,
    routing::get,
};
use axum_security::{
    cookie::{CookieContext, CookieSession, MemStore},
    rbac::RBAC,
};
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Clone)]
struct User {
    role: Role,
    name: String,
}

impl RBAC for Role {
    type Resource = User;

    fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self> {
        Some(&resource.role)
    }
}

#[derive(Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
enum Role {
    #[serde(alias = "admin")]
    Admin,
    #[serde(alias = "user")]
    User,
}

async fn set_role(
    State(cookie): State<CookieContext<MemStore<User>>>,
    Path(role): Path<Role>,
) -> impl IntoResponse {
    let user = User {
        role,
        name: "user1".into(),
    };

    cookie.create_session(user).await.unwrap()
}

#[axum_security::rbac::requires(Role::Admin)]
async fn admin_only(cookie: CookieSession<User>) -> String {
    format!("hi admin: {}", cookie.state.name)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cookie_service = CookieContext::builder()
        .enable_dev_cookie(true)
        .dev_cookie(|c| c.name("rbac-cookie"))
        .store(MemStore::new())
        .build::<User>();

    let state = cookie_service.clone();

    let router = Router::new()
        .route("/role/{role}", get(set_role))
        .route("/admin", get(admin_only))
        .layer(cookie_service)
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;

    axum::serve(listener, router).await?;
    Ok(())
}
