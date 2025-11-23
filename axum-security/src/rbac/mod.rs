use std::{convert::Infallible, marker::PhantomData};

use axum::{
    Extension,
    extract::{FromRequestParts, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::MethodRouter,
};
pub use axum_security_macros::{requires, requires_any};

use crate::{cookie::CookieSession, jwt::Jwt};

pub fn __requires<T: RBAC>(resource: RolesExtractor<T>, roles: &[T]) -> Option<Response> {
    if resource.roles.iter().all(|r| roles.contains(r)) {
        None
    } else {
        Some(StatusCode::UNAUTHORIZED.into_response())
    }
}

pub fn __requires_any<T: RBAC>(resource: RolesExtractor<T>, roles: &[T]) -> Option<Response> {
    if resource.roles.iter().any(|r| roles.contains(r)) {
        None
    } else {
        Some(StatusCode::UNAUTHORIZED.into_response())
    }
}

pub struct RolesExtractor<T: RBAC> {
    roles: Vec<T>,
    _p: PhantomData<T>,
}

impl<S: Send + Sync, R: RBAC> FromRequestParts<S> for RolesExtractor<R>
where
    R::Resource: Clone + Send + Sync + 'static,
    R: Copy,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(resource) = parts.extensions.remove::<R::Resource>() {
            let roles: Vec<R> = R::extract_roles(&resource).into_iter().copied().collect();
            parts.extensions.insert(resource);

            Ok(RolesExtractor {
                roles,
                _p: PhantomData,
            })
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

pub trait RBAC: Send + Sync + 'static + Clone + Eq + Copy {
    type Resource: Send + Sync + 'static;

    fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self>;
}

pub trait RBACExt {
    fn requires<T: RBAC>(self, rol: T) -> Self;

    fn requires_all<T: RBAC>(self, rol: impl Into<Vec<T>>) -> Self;

    fn requires_any<T: RBAC>(self, rol: impl Into<Vec<T>>) -> Self;
}

#[derive(Clone)]
enum AuthType<T: RBAC> {
    RequiresAll(Vec<T>),
    RequiresAny(Vec<T>),
}

impl<S: Clone + 'static> RBACExt for MethodRouter<S, Infallible> {
    fn requires<T: RBAC>(self, rol: T) -> Self {
        let middleware = axum::middleware::from_fn(rbac_layer::<T>);

        self.layer::<_, Infallible>(middleware)
            .layer(Extension(AuthType::RequiresAll(vec![rol])))
    }

    fn requires_all<T: RBAC>(self, rol: impl Into<Vec<T>>) -> Self {
        let middleware = axum::middleware::from_fn(rbac_layer::<T>);

        self.layer::<_, Infallible>(middleware)
            .layer(Extension(AuthType::RequiresAll(rol.into())))
    }

    fn requires_any<T: RBAC>(self, rol: impl Into<Vec<T>>) -> Self {
        let middleware = axum::middleware::from_fn(rbac_layer::<T>);

        self.layer::<_, Infallible>(middleware)
            .layer(Extension(AuthType::RequiresAny(rol.into())))
    }
}

fn extract_resource<R: RBAC>(req: &mut Request) -> Result<R::Resource, Response> {
    if let Some(user) = req.extensions_mut().remove::<Jwt<R::Resource>>() {
        Ok(user.0)
    } else if let Some(user) = req.extensions_mut().remove::<CookieSession<R::Resource>>() {
        Ok(user.into_state())
    } else {
        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}

async fn rbac_layer<R: RBAC>(mut req: Request, next: Next) -> Response {
    let resource = match extract_resource::<R>(&mut req) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let auth_type = req.extensions_mut().remove::<AuthType<R>>().unwrap();

    match auth_type {
        AuthType::RequiresAll(roles) => {
            let mut extracted_roles = R::extract_roles(&resource).into_iter();

            if extracted_roles.any(|r| !roles.contains(r)) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
        AuthType::RequiresAny(roles) => {
            let mut extracted_roles = R::extract_roles(&resource).into_iter();

            if extracted_roles.all(|r| !roles.contains(r)) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    }

    next.run(req).await
}
