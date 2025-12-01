use std::convert::Infallible;

use axum::{
    Router,
    extract::{Request, State},
    middleware::Next,
    response::Response,
    routing::MethodRouter,
};
use serde::de::DeserializeOwned;

use crate::{
    jwt::{Jwt, JwtContext},
    router_ext::AuthInjector,
};

impl<T, S> AuthInjector<Router<S>> for JwtContext<T>
where
    S: Send + Sync + Clone + 'static,
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    fn inject_into(self, router: Router<S>) -> axum::Router<S> {
        let middleware = axum::middleware::from_fn_with_state(self, jwt_session_layer::<T>);

        router.layer(middleware)
    }
}

impl<T, S> AuthInjector<MethodRouter<S, Infallible>> for JwtContext<T>
where
    S: Send + Sync + Clone + 'static,
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    fn inject_into(self, router: MethodRouter<S, Infallible>) -> MethodRouter<S, Infallible> {
        let middleware = axum::middleware::from_fn_with_state(self, jwt_session_layer::<T>);

        router.layer(middleware)
    }
}

async fn jwt_session_layer<T>(
    State(session): State<JwtContext<T>>,
    mut req: Request,
    next: Next,
) -> Response
where
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    if let Some(user) = session.decode_from_headers(req.headers()) {
        req.extensions_mut().insert(Jwt(user));
    }

    next.run(req).await
}
