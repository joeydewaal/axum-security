#![cfg(feature = "pbac")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::get as route_get,
};
use axum_security::{
    cookie::{CookieSession, SessionId},
    pbac::{Allow, Deny, PolicyExt, PolicyRouterExt},
    session::Session,
};
use tower::{Layer, Service, ServiceExt as _};

#[derive(Clone)]
struct UserData {
    admin: bool,
    banned: bool,
    #[cfg(feature = "rbac")]
    roles: Vec<Role>,
}

#[cfg(feature = "rbac")]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
enum Role {
    Admin,
    Mod,
    User,
}

#[cfg(feature = "rbac")]
impl axum_security::rbac::RBAC for Role {
    type Resource = UserData;
    fn extract_roles(r: &UserData) -> impl IntoIterator<Item = &Role> {
        &r.roles
    }
}

fn is_admin(u: &UserData) -> bool {
    u.admin
}

fn is_not_banned(u: &UserData) -> bool {
    !u.banned
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

fn default_user() -> UserData {
    UserData {
        admin: true,
        banned: false,
        #[cfg(feature = "rbac")]
        roles: vec![Role::Admin],
    }
}

fn make_user(admin: bool, banned: bool) -> UserData {
    UserData {
        admin,
        banned,
        #[cfg(feature = "rbac")]
        roles: if admin {
            vec![Role::Admin]
        } else {
            vec![Role::User]
        },
    }
}

async fn call(router: Router, path: &str) -> StatusCode {
    let req = Request::get(path).body(Body::empty()).unwrap();
    router.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn closure_policy_passes() {
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(is_admin),
        )
        .layer(SeedLayer(Some(default_user())));

    assert_eq!(call(router, "/test").await, StatusCode::OK);
}

#[tokio::test]
async fn closure_policy_fails_returns_403() {
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(is_admin),
        )
        .layer(SeedLayer(Some(make_user(false, false))));

    assert_eq!(call(router, "/test").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_session_returns_401() {
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(is_admin),
        )
        .layer(SeedLayer(None));

    assert_eq!(call(router, "/test").await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn all_of_combinator_both_pass() {
    let policy = is_admin.and(is_not_banned);
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(policy),
        )
        .layer(SeedLayer(Some(make_user(true, false))));

    assert_eq!(call(router, "/test").await, StatusCode::OK);
}

#[tokio::test]
async fn all_of_combinator_one_fails() {
    let policy = is_admin.and(is_not_banned);
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(policy),
        )
        .layer(SeedLayer(Some(UserData {
            admin: true,
            banned: true,
            #[cfg(feature = "rbac")]
            roles: vec![Role::Admin],
        })));

    assert_eq!(call(router, "/test").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn any_of_combinator_one_passes() {
    let policy = is_admin.or(is_not_banned);
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(policy),
        )
        .layer(SeedLayer(Some(UserData {
            admin: true,
            banned: true,
            #[cfg(feature = "rbac")]
            roles: vec![Role::Admin],
        })));

    assert_eq!(call(router, "/test").await, StatusCode::OK);
}

#[tokio::test]
async fn not_combinator() {
    let policy = (is_admin as fn(&UserData) -> bool).not();
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(policy),
        )
        .layer(SeedLayer(Some(default_user())));

    assert_eq!(call(router, "/test").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allow_always_passes() {
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy::<_, UserData>(Allow),
        )
        .layer(SeedLayer(Some(make_user(false, true))));

    assert_eq!(call(router, "/test").await, StatusCode::OK);
}

#[tokio::test]
async fn deny_always_fails() {
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy::<_, UserData>(Deny),
        )
        .layer(SeedLayer(Some(default_user())));

    assert_eq!(call(router, "/test").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_extractable_after_policy_layer() {
    let router = Router::new()
        .route(
            "/test",
            route_get(|session: Session<UserData>| async move {
                if session.admin {
                    StatusCode::OK
                } else {
                    StatusCode::IM_A_TEAPOT
                }
            })
            .with_policy(is_admin),
        )
        .layer(SeedLayer(Some(default_user())));

    assert_eq!(call(router, "/test").await, StatusCode::OK);
}

#[cfg(feature = "rbac")]
#[tokio::test]
async fn has_role_bridge() {
    use axum_security::pbac::HasRole;

    let policy = HasRole::new(Role::Admin);
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(policy),
        )
        .layer(SeedLayer(Some(default_user())));

    assert_eq!(call(router, "/test").await, StatusCode::OK);
}

#[cfg(feature = "rbac")]
#[tokio::test]
async fn has_role_bridge_fails() {
    use axum_security::pbac::HasRole;

    let policy = HasRole::new(Role::Mod);
    let router = Router::new()
        .route(
            "/test",
            route_get(|| async { StatusCode::OK })
                .with_policy(policy),
        )
        .layer(SeedLayer(Some(default_user())));

    assert_eq!(call(router, "/test").await, StatusCode::FORBIDDEN);
}
