use axum::{Extension, Router, extract::Request, middleware::Next, response::Response};
use serde::de::DeserializeOwned;

use crate::{
    jwt::{Jwt, JwtContext},
    router_ext::AuthInjector,
};

impl<T> AuthInjector for JwtContext<T>
where
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    fn inject_into_router<S: Send + Sync + Clone + 'static>(
        self,
        router: Router<S>,
    ) -> axum::Router<S> {
        let middleware = axum::middleware::from_fn(jwt_session_layer::<T>);

        router.layer(middleware).layer(Extension(self))
    }
}

async fn jwt_session_layer<T>(mut req: Request, next: Next) -> Response
where
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    let session = req.extensions_mut().remove::<JwtContext<T>>().unwrap();

    if let Some(user) = session.decode_from_headers(req.headers()) {
        req.extensions_mut().insert(Jwt(user));
    }

    next.run(req).await
}
