use std::{convert::Infallible, marker::PhantomData};

use axum::{
    Extension,
    extract::{FromRequestParts, Request, State},
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
        let auth_type = AuthType::RequiresAll(vec![rol]);
        let middleware = axum::middleware::from_fn_with_state(auth_type, rbac_layer::<T>);

        self.layer::<_, Infallible>(middleware)
    }

    fn requires_all<T: RBAC>(self, rol: impl Into<Vec<T>>) -> Self {
        let auth_type = AuthType::RequiresAll(rol.into());
        let middleware = axum::middleware::from_fn_with_state(auth_type, rbac_layer::<T>);

        self.layer::<_, Infallible>(middleware)
    }

    fn requires_any<T: RBAC>(self, rol: impl Into<Vec<T>>) -> Self {
        let auth_type = AuthType::RequiresAny(rol.into());
        let middleware = axum::middleware::from_fn_with_state(auth_type, rbac_layer::<T>);

        self.layer::<_, Infallible>(middleware)
    }
}

fn extract_resource<R: RBAC>(req: &mut Request) -> Result<R::Resource, Response> {
    if let Some(user) = req.extensions_mut().remove::<Jwt<R::Resource>>() {
        Ok(user.0)
    } else if let Some(user) = req.extensions_mut().remove::<CookieSession<R::Resource>>() {
        Ok(user.state)
    } else {
        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}

async fn rbac_layer<R: RBAC>(
    State(auth_type): State<AuthType<R>>,
    mut req: Request,
    next: Next,
) -> Response {
    let resource = match extract_resource::<R>(&mut req) {
        Ok(r) => r,
        Err(e) => return e,
    };

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
