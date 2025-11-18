use std::convert::Infallible;

use axum::{
    Extension, Router,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::MethodRouter,
};

use crate::{cookie::CookieSession, jwt::Jwt};

pub trait RBAC: Send + Sync + 'static + Clone {
    type Resource: Send + Sync + 'static;

    fn has_role(resource: &Self::Resource, role: &Self) -> bool;
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
            if roles.iter().any(|role| !R::has_role(&resource, role)) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
        AuthType::RequiresAny(roles) => {
            if roles.iter().all(|role| !R::has_role(&resource, role)) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    }

    next.run(req).await
}
