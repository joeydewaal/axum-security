use axum::{Extension, Router, extract::Request, middleware::Next, response::Response};

use crate::{
    cookie::{CookieContext, CookieStore},
    router_ext::AuthInjector,
};

impl<STORE> AuthInjector for CookieContext<STORE>
where
    STORE: CookieStore,
    STORE::State: Clone,
{
    fn inject_into_router<S: Send + Sync + Clone + 'static>(self, router: Router<S>) -> Router<S> {
        let middleware = axum::middleware::from_fn(cookie_session_layer::<STORE>);

        router.layer(middleware).layer(Extension(self))
    }
}

async fn cookie_session_layer<S: CookieStore>(mut req: Request, next: Next) -> Response
where
    S::State: Send + Sync + 'static + Clone,
{
    let session = req.extensions_mut().remove::<CookieContext<S>>().unwrap();

    if let Some(session) = session.load_from_headers(req.headers()).await {
        req.extensions_mut().insert(session);
    };

    next.run(req).await
}
