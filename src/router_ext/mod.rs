use axum::{
    Extension, Router, extract::Request, middleware::Next, response::Response,
    routing::MethodRouter,
};

use crate::{
    cookie::{CookieContext, SessionStore},
    oauth2::{OAuth2Context, OAuth2Handler, OAuthSessionState, callback, start_login},
    session::HttpSession,
};

pub trait RouterExt<S> {
    fn with_oauth2<T: OAuth2Handler, STORE: SessionStore<State = OAuthSessionState>>(
        self,
        oauth2: OAuth2Context<T, STORE>,
    ) -> Router<S>;

    fn with_cookie_session<STORE: SessionStore>(self, session: CookieContext<STORE>) -> Router<S>
    where
        STORE::State: Clone;
}

impl<S> RouterExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_oauth2<T, STORE>(mut self, oauth2: OAuth2Context<T, STORE>) -> Router<S>
    where
        T: OAuth2Handler,
        STORE: SessionStore<State = OAuthSessionState>,
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

    fn with_cookie_session<STORE: SessionStore>(self, session: CookieContext<STORE>) -> Router<S>
    where
        STORE::State: Clone,
    {
        let middleware = axum::middleware::from_fn(session_layer::<STORE>);

        self.layer(middleware).layer(Extension(session))
    }
}

async fn session_layer<S: SessionStore>(mut req: Request, next: Next) -> Response
where
    S::State: Send + Sync + 'static + Clone,
{
    let session = req.extensions_mut().remove::<CookieContext<S>>().unwrap();

    let (mut parts, body) = req.into_parts();

    if let Some(session) = session.load_from_request_parts(&mut parts).await {
        parts.extensions.insert(session);
    };

    let req = Request::from_parts(parts, body);

    next.run(req).await
}
