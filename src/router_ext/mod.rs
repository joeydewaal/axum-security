use axum::{
    Extension, Router, extract::Request, middleware::Next, response::Response,
    routing::MethodRouter,
};
use serde::de::DeserializeOwned;

use crate::{
    cookie::{CookieContext, CookieStore},
    jwt::{JwtContext, JwtSession},
    oauth2::{OAuth2Context, OAuth2Handler, OAuthSessionState, callback, start_login},
};

pub trait RouterExt<S> {
    fn with_oauth2<T: OAuth2Handler, STORE: CookieStore<State = OAuthSessionState>>(
        self,
        oauth2: OAuth2Context<T, STORE>,
    ) -> Router<S>;

    fn with_cookie_session<STORE>(self, session: CookieContext<STORE>) -> Router<S>
    where
        STORE: CookieStore,
        STORE::State: Clone;

    fn with_jwt_session<T>(self, session: JwtContext<T>) -> Router<S>
    where
        T: DeserializeOwned + Send + Sync + 'static + Clone;
}

impl<S> RouterExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_oauth2<T, STORE>(mut self, oauth2: OAuth2Context<T, STORE>) -> Router<S>
    where
        T: OAuth2Handler,
        STORE: CookieStore<State = OAuthSessionState>,
    {
        if let Some(start_challenge_path) = oauth2.get_start_challenge_path() {
            let challenge_route = MethodRouter::new()
                .get(start_login::<T, STORE>)
                .layer(Extension(oauth2.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new()
            .get(callback::<T, STORE>)
            .layer(Extension(oauth2.clone()));

        self.route(oauth2.callback_url(), route)
    }

    fn with_cookie_session<STORE>(self, session: CookieContext<STORE>) -> Router<S>
    where
        STORE: CookieStore,
        STORE::State: Clone,
    {
        let middleware = axum::middleware::from_fn(cookie_session_layer::<STORE>);

        self.layer(middleware).layer(Extension(session))
    }

    fn with_jwt_session<T>(self, session: JwtContext<T>) -> Router<S>
    where
        T: DeserializeOwned + Send + Sync + 'static + Clone,
    {
        let middleware = axum::middleware::from_fn(jwt_session_layer::<T>);

        self.layer(middleware).layer(Extension(session))
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

async fn jwt_session_layer<T>(mut req: Request, next: Next) -> Response
where
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    let session = req.extensions_mut().remove::<JwtContext<T>>().unwrap();

    if let Some(user) = session.decode_token(req.headers()) {
        req.extensions_mut().insert(JwtSession(user));
    }

    next.run(req).await
}
