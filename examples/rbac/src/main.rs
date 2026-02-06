use std::error::Error;

use axum::{Router, extract::Path, response::IntoResponse, routing::get};
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

async fn set_role(cookie: CookieContext<User>, Path(role): Path<Role>) -> impl IntoResponse {
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
        .use_dev_cookie(true)
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

// use std::collections::HashSet;

// use axum::{
//     Json, Router,
//     extract::{Query, State},
//     response::IntoResponse,
//     routing::get,
//     serve,
// };
// use axum_security::{
//     jwt::{Jwt, JwtContext, get_current_timestamp},
//     rbac::{RBAC, RBACExt},
// };
// use serde::{Deserialize, Serialize};
// use tokio::net::TcpListener;

// #[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Debug)]
// enum UserRole {
//     Admin,
//     User,
// }

// impl RBAC for UserRole {
//     type Resource = AccessToken;

//     fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self> {
//         &resource.roles
//     }
// }

// #[derive(Clone, Serialize, Deserialize)]
// struct AccessToken {
//     username: String,
//     email: Option<String>,
//     exp: u64,
//     roles: HashSet<UserRole>,
// }

// #[derive(Deserialize, Serialize)]
// struct LoginAttempt {
//     username: String,
//     password: String,
// }

// #[axum_security::rbac::requires_any(crate::UserRole::Admin, UserRole::User)]
// async fn authorized3(Jwt(user): Jwt<AccessToken>, _string: String) -> Json<AccessToken> {
//     Json(user)
// }

// #[axum_security::rbac::requires(UserRole::Admin, UserRole::User)]
// async fn authorized2(Jwt(user): Jwt<AccessToken>, _string: String) -> Json<AccessToken> {
//     Json(user)
// }

// #[axum_security::rbac::requires(UserRole::Admin)]
// async fn authorized1(Jwt(user): Jwt<AccessToken>, _string: String) -> Json<AccessToken> {
//     Json(user)
// }

// async fn login(
//     State(session): State<JwtContext<AccessToken>>,
//     Query(login): Query<LoginAttempt>,
// ) -> impl IntoResponse {
//     if login.username == "admin" && login.password == "admin" {
//         let at = AccessToken {
//             username: login.username,
//             email: None,
//             exp: get_current_timestamp() + 10_000,
//             roles: HashSet::from_iter([UserRole::Admin]),
//         };

//         let token = session.encode_token(&at).unwrap();
//         Json(token).into_response()
//     } else {
//         "failed to log in".into_response()
//     }
// }

// #[tokio::test]
// async fn test_jwt() -> anyhow::Result<()> {
//     let jwt = JwtContext::builder()
//         .jwt_secret("TEST")
//         .build::<AccessToken>();

//     let router = Router::new()
//         .route("/", get(|| async { "hello world" }))
//         .route("/login", get(login))
//         .route(
//             "/authorized/admin",
//             get(authorized1).requires(UserRole::Admin),
//         )
//         .route(
//             "/authorized/any",
//             get(authorized2).requires_any([UserRole::Admin, UserRole::User]),
//         )
//         .layer(jwt.clone())
//         .with_state(jwt);

//     let listener = TcpListener::bind("0.0.0.0:3000").await?;

//     serve(listener, router).await?;
//     Ok(())
// }
