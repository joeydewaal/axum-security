#![cfg(feature = "rbac")]

use std::error::Error;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get as route_get,
};
use axum_security::{
    cookie::{CookieSession, SessionId},
    rbac::{RBAC, RBACExt},
    session::Session,
};
use tower::{Layer, Service, ServiceExt as _};

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
enum Role {
    Admin,
    Mod,
    User,
}

#[derive(Clone)]
struct UserData {
    roles: Vec<Role>,
}

impl RBAC for Role {
    type Resource = UserData;

    fn extract_roles(r: &UserData) -> impl IntoIterator<Item = &Role> {
        &r.roles
    }
}

#[derive(Clone)]
struct SeedLayer(Option<UserData>);

impl<S> Layer<S> for SeedLayer {
    type Service = SeedService<S>;
    fn layer(&self, inner: S) -> SeedService<S> {
        SeedService {
            user: self.0.clone(),
            inner,
        }
    }
}

#[derive(Clone)]
struct SeedService<S> {
    user: Option<UserData>,
    inner: S,
}

impl<S> Service<Request<Body>> for SeedService<S>
where
    S: Service<Request<Body>, Response = axum::response::Response> + Clone + Send + 'static,
    S::Error: Send,
    S::Future: Send,
{
    type Response = axum::response::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        if let Some(user) = &self.user {
            let session = CookieSession::new(SessionId::new(), 0, user.clone());
            req.extensions_mut().insert(session);
        }
        let fut = self.inner.call(req);
        Box::pin(fut)
    }
}

fn make_router(user: Option<UserData>) -> Router {
    Router::new()
        .route(
            "/admin",
            route_get(|| async { StatusCode::OK }).requires(Role::Admin),
        )
        .route(
            "/admin-or-mod",
            route_get(|| async { StatusCode::OK }).requires_any([Role::Admin, Role::Mod]),
        )
        .route(
            "/admin-and-mod",
            route_get(|| async { StatusCode::OK }).requires_all([Role::Admin, Role::Mod]),
        )
        .route(
            "/session",
            route_get(|session: Session<UserData>| async move {
                let _ = session.roles.len();
                StatusCode::OK
            })
            .requires(Role::Admin),
        )
        .layer(SeedLayer(user))
}

async fn call(router: Router, path: &str) -> StatusCode {
    let req = Request::get(path).body(Body::empty()).unwrap();
    router.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn requires_admin_with_admin_passes() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::Admin],
    };
    assert_eq!(
        call(make_router(Some(user)), "/admin").await,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn requires_admin_with_user_fails() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::User],
    };
    assert_eq!(
        call(make_router(Some(user)), "/admin").await,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn requires_admin_with_no_roles_fails() -> Result<(), Box<dyn Error>> {
    let user = UserData { roles: vec![] };
    assert_eq!(
        call(make_router(Some(user)), "/admin").await,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn requires_admin_with_no_session_fails() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        call(make_router(None), "/admin").await,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

#[tokio::test]
async fn requires_all_with_both_passes() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::Admin, Role::Mod],
    };
    assert_eq!(
        call(make_router(Some(user)), "/admin-and-mod").await,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn requires_all_with_only_admin_fails() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::Admin],
    };
    assert_eq!(
        call(make_router(Some(user)), "/admin-and-mod").await,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn requires_any_with_mod_passes() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::User, Role::Mod],
    };
    assert_eq!(
        call(make_router(Some(user)), "/admin-or-mod").await,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn requires_any_with_only_user_fails() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::User],
    };
    assert_eq!(
        call(make_router(Some(user)), "/admin-or-mod").await,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn session_extractable_after_rbac_layer() -> Result<(), Box<dyn Error>> {
    let user = UserData {
        roles: vec![Role::Admin],
    };
    assert_eq!(
        call(make_router(Some(user)), "/session").await,
        StatusCode::OK
    );
    Ok(())
}

#[cfg(feature = "rbac-macros")]
mod macro_tests {
    use super::*;

    #[axum_security::rbac::requires(Role::Admin)]
    async fn admin_only() -> StatusCode {
        StatusCode::OK
    }

    #[axum_security::rbac::requires_any(Role::Admin, Role::Mod)]
    async fn admin_or_mod() -> StatusCode {
        StatusCode::OK
    }

    #[axum_security::rbac::requires(Role::Admin, Role::Mod)]
    async fn admin_and_mod() -> StatusCode {
        StatusCode::OK
    }

    fn make_macro_router(user: Option<UserData>) -> Router {
        Router::new()
            .route("/admin", route_get(admin_only))
            .route("/admin-or-mod", route_get(admin_or_mod))
            .route("/admin-and-mod", route_get(admin_and_mod))
            .layer(SeedLayer(user))
    }

    #[tokio::test]
    async fn macro_requires_admin_passes() {
        let user = UserData {
            roles: vec![Role::Admin],
        };
        assert_eq!(
            call(make_macro_router(Some(user)), "/admin").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn macro_requires_admin_with_user_fails() {
        let user = UserData {
            roles: vec![Role::User],
        };
        assert_eq!(
            call(make_macro_router(Some(user)), "/admin").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn macro_requires_any_mod_passes() {
        let user = UserData {
            roles: vec![Role::Mod],
        };
        assert_eq!(
            call(make_macro_router(Some(user)), "/admin-or-mod").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn macro_requires_any_user_fails() {
        let user = UserData {
            roles: vec![Role::User],
        };
        assert_eq!(
            call(make_macro_router(Some(user)), "/admin-or-mod").await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn macro_requires_admin_and_mod_with_both_passes() {
        let user = UserData {
            roles: vec![Role::Admin, Role::Mod],
        };
        assert_eq!(
            call(make_macro_router(Some(user)), "/admin-and-mod").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn macro_requires_admin_and_mod_with_only_admin_fails() {
        let user = UserData {
            roles: vec![Role::Admin],
        };
        assert_eq!(
            call(make_macro_router(Some(user)), "/admin-and-mod").await,
            StatusCode::FORBIDDEN
        );
    }
}
