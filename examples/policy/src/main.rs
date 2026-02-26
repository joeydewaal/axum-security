use std::error::Error;

use axum::{Router, extract::Path, http::StatusCode, response::IntoResponse, routing::get};
use axum_security::{
    cookie::{CookieContext, MemStore},
    pbac::{HasRole, PolicyExt, PolicyRouterExt},
    rbac::RBAC,
};
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Deserialize, Clone, Copy, Eq, PartialEq, Debug)]
enum Role {
    #[serde(alias = "admin")]
    Admin,
    #[serde(alias = "mod")]
    Mod,
    #[serde(alias = "user")]
    User,
}

impl RBAC for Role {
    type Resource = AppUser;

    fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self> {
        &resource.roles
    }
}

#[derive(Clone)]
struct AppUser {
    name: String,
    banned: bool,
    roles: Vec<Role>,
}

fn is_not_banned(u: &AppUser) -> bool {
    !u.banned
}

async fn set_role(cookie: CookieContext<AppUser>, Path(role): Path<Role>) -> impl IntoResponse {
    let user = AppUser {
        name: "user1".into(),
        banned: false,
        roles: vec![role],
    };
    cookie.create_session(user).await.unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cookie_service = CookieContext::builder()
        .use_dev_cookie(true)
        .dev_cookie(|c| c.name("policy-cookie"))
        .store(MemStore::new())
        .build::<AppUser>();

    let state = cookie_service.clone();

    let admin_and_not_banned = HasRole::new(Role::Admin).and(is_not_banned);

    let mod_access = HasRole::new(Role::Admin)
        .or(HasRole::new(Role::Mod))
        .and(is_not_banned);

    let router = Router::new()
        .route("/role/{role}", get(set_role))
        .route(
            "/not-banned",
            get(|| async { StatusCode::OK }).with_policy(is_not_banned),
        )
        .route(
            "/admin",
            get(|| async { "admin area" }).with_policy(admin_and_not_banned),
        )
        .route(
            "/mod-area",
            get(|| async { "mod area" }).with_policy(mod_access),
        )
        .layer(cookie_service)
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    println!("Listening on http://0.0.0.0:3000");
    println!("  GET /role/admin     — set role to admin");
    println!("  GET /not-banned     — accessible if not banned");
    println!("  GET /admin          — requires Admin + not banned");
    println!("  GET /mod-area       — requires Admin or Mod + not banned");

    axum::serve(listener, router).await?;
    Ok(())
}
