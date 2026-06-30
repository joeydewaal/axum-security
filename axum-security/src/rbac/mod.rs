//! Role-based access control (RBAC).
//!
//! Define a role enum, implement [`RBAC`] to extract roles from your user type,
//! then protect routes using the [`RBACExt`] trait on [`MethodRouter`].
//!
//! Requires an active session (from the `jwt`, `cookie`, or `basic-auth` feature).
//! Returns `401` if no session is present, `403` if the user lacks the required roles.
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use axum_security::rbac::{RBAC, RBACExt};
//!
//! #[derive(Clone, Copy, Debug, PartialEq, Eq)]
//! enum Role { Admin, User }
//!
//! impl RBAC for Role {
//!     type Resource = MyUser;
//!     fn extract_roles(user: &MyUser) -> impl IntoIterator<Item = &Role> {
//!         &user.roles
//!     }
//! }
//!
//! let app = Router::new()
//!     .route("/admin", get(admin_handler).requires(Role::Admin))
//!     .route("/any", get(handler).allows([Role::Admin, Role::User]));
//! ```

use std::{convert::Infallible, fmt::Debug, future::Future, marker::PhantomData, pin::Pin};

use axum::{
    extract::{FromRequestParts, Request},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::MethodRouter,
};
use tower::{Layer, Service};

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
use crate::session::Session;

/// Tower [`Layer`] that enforces role requirements on a route.
///
/// Prefer using the [`RBACExt`] trait methods instead of constructing this directly.
pub struct RbacLayer<R: RBAC> {
    required: AuthType<R>,
}

impl<R: RBAC> Clone for RbacLayer<R> {
    fn clone(&self) -> Self {
        RbacLayer {
            required: self.required.clone(),
        }
    }
}

impl<R: RBAC, S> Layer<S> for RbacLayer<R> {
    type Service = RbacService<R, S>;

    fn layer(&self, inner: S) -> RbacService<R, S> {
        RbacService {
            required: self.required.clone(),
            inner,
        }
    }
}

/// The [`Service`] created by [`RbacLayer`]. You don't need to construct this directly.
pub struct RbacService<R: RBAC, S> {
    required: AuthType<R>,
    inner: S,
}

impl<R: RBAC, S: Clone> Clone for RbacService<R, S> {
    fn clone(&self) -> Self {
        RbacService {
            required: self.required.clone(),
            inner: self.inner.clone(),
        }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<R, S> Service<Request> for RbacService<R, S>
where
    R: RBAC + 'static,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Send,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response, S::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let required = self.required.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let Some(session) = Session::<R::Resource>::from_extensions(req.extensions_mut())
            else {
                return Ok(StatusCode::UNAUTHORIZED.into_response());
            };

            let user_roles: Vec<R> = R::extract_roles(&session).into_iter().copied().collect();

            let ok = match &required {
                AuthType::RequiresAll(roles) => roles.iter().all(|r| user_roles.contains(r)),
                AuthType::Allows(roles) => user_roles.iter().any(|r| roles.contains(r)),
            };

            if !ok {
                return Ok(StatusCode::FORBIDDEN.into_response());
            }

            session.insert_into(req.extensions_mut());
            inner.call(req).await
        })
    }
}

/// Trait for role types. Implement this on your role enum to define how roles
/// are extracted from a user (the `Resource` type).
pub trait RBAC: Send + Sync + 'static + Clone + Eq + Copy + Debug {
    /// The user type that holds roles.
    type Resource: Clone + Send + Sync + 'static;

    /// Return the roles that `resource` has.
    fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self>;
}

#[derive(Clone)]
enum AuthType<T: RBAC> {
    RequiresAll(Vec<T>),
    Allows(Vec<T>),
}

/// Extension trait on [`MethodRouter`] for adding role requirements.
pub trait RBACExt {
    /// Require the user to have this single role.
    fn requires<T: RBAC>(self, role: T) -> Self;
    /// Require the user to have **all** of the given roles.
    fn requires_all<T: RBAC>(self, roles: impl Into<Vec<T>>) -> Self;
    /// Require the user to have **any** of the given roles.
    fn allows<T: RBAC>(self, roles: impl Into<Vec<T>>) -> Self;
}

impl<S: Clone + 'static> RBACExt for MethodRouter<S, Infallible> {
    fn requires<T: RBAC>(self, role: T) -> Self {
        self.layer(RbacLayer {
            required: AuthType::RequiresAll(vec![role]),
        })
    }

    fn requires_all<T: RBAC>(self, roles: impl Into<Vec<T>>) -> Self {
        self.layer(RbacLayer {
            required: AuthType::RequiresAll(roles.into()),
        })
    }

    fn allows<T: RBAC>(self, roles: impl Into<Vec<T>>) -> Self {
        self.layer(RbacLayer {
            required: AuthType::Allows(roles.into()),
        })
    }
}

/// Extractor that provides the user's roles. Used internally by the `requires` macros.
#[doc(hidden)]
pub struct RolesExtractor<T: RBAC> {
    pub roles: Vec<T>,
    _p: PhantomData<T>,
}

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
fn extract_roles__<R: RBAC + Copy>(parts: &mut Parts) -> Option<Vec<R>> {
    let session = Session::<R::Resource>::from_extensions(&mut parts.extensions)?;
    let roles: Vec<R> = R::extract_roles(&session).into_iter().copied().collect();
    session.insert_into(&mut parts.extensions);
    Some(roles)
}

#[cfg(not(any(feature = "jwt", feature = "cookie", feature = "basic-auth")))]
fn extract_roles__<R: RBAC + Copy>(parts: &mut Parts) -> Option<Vec<R>> {
    None
}

impl<S: Send + Sync, R: RBAC + Copy> FromRequestParts<S> for RolesExtractor<R> {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(roles) = extract_roles__(parts) else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        Ok(RolesExtractor {
            roles,
            _p: PhantomData,
        })
    }
}

pub fn __requires<T: RBAC>(resource: RolesExtractor<T>, roles: &[T]) -> Option<Response> {
    if roles.iter().all(|r| resource.roles.contains(r)) {
        None
    } else {
        Some(StatusCode::FORBIDDEN.into_response())
    }
}

pub fn __allows<T: RBAC>(resource: RolesExtractor<T>, roles: &[T]) -> Option<Response> {
    if resource.roles.iter().any(|r| roles.contains(r)) {
        None
    } else {
        Some(StatusCode::FORBIDDEN.into_response())
    }
}

#[cfg(feature = "macros")]
pub use axum_security_macros::{allows, requires};

#[doc(hidden)]
pub mod __private {
    pub use super::__allows;
    pub use super::__requires;
    pub use super::RolesExtractor;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Eq, PartialEq, Debug)]
    enum Role {
        Admin,
        Mod,
        #[allow(dead_code)]
        User,
    }

    #[derive(Clone)]
    struct FakeUser {
        roles: Vec<Role>,
    }

    impl RBAC for Role {
        type Resource = FakeUser;
        fn extract_roles(r: &FakeUser) -> impl IntoIterator<Item = &Role> {
            &r.roles
        }
    }

    fn make_extractor(roles: Vec<Role>) -> RolesExtractor<Role> {
        RolesExtractor {
            roles,
            _p: PhantomData,
        }
    }

    #[test]
    fn requires_exact_match() {
        let ext = make_extractor(vec![Role::Admin]);
        assert!(
            __requires(ext, &[Role::Admin]).is_none(),
            "Admin with required=[Admin] should pass"
        );
    }

    #[test]
    fn requires_missing_role() {
        let ext = make_extractor(vec![Role::Admin]);
        assert!(
            __requires(ext, &[Role::Admin, Role::Mod]).is_some(),
            "Admin with required=[Admin, Mod] should fail"
        );
    }

    #[test]
    fn requires_superset_passes() {
        let ext = make_extractor(vec![Role::Admin, Role::Mod]);
        assert!(
            __requires(ext, &[Role::Admin]).is_none(),
            "[Admin, Mod] with required=[Admin] should pass"
        );
    }

    #[test]
    fn allows_match() {
        let ext = make_extractor(vec![Role::Mod]);
        assert!(
            __allows(ext, &[Role::Admin, Role::Mod]).is_none(),
            "Mod with any=[Admin, Mod] should pass"
        );
    }

    #[test]
    fn allows_no_match() {
        let ext = make_extractor(vec![Role::User]);
        assert!(
            __allows(ext, &[Role::Admin, Role::Mod]).is_some(),
            "User with any=[Admin, Mod] should fail"
        );
    }
}
