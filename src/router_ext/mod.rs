use axum::{
    Extension, Router, extract::Request, middleware::Next, response::Response,
    routing::MethodRouter,
};

use crate::{
    oauth2::{OAuth2Context, OAuth2Handler, OAuthSessionState, callback, start_challenge},
    session::HttpSession,
    store::SessionStore,
};

pub trait RouterExt<S> {
    fn with_oauth2<T: OAuth2Handler, STORE: SessionStore<State = OAuthSessionState>>(
        self,
        oauth2: &OAuth2Context<T, STORE>,
    ) -> Router<S>;

    fn with_session<SES: HttpSession + Clone>(self, session: SES) -> Router<S>
    where
        SES::State: Clone;
}

impl<S> RouterExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_oauth2<T, STORE>(mut self, oauth2: &OAuth2Context<T, STORE>) -> Router<S>
    where
        T: OAuth2Handler,
        STORE: SessionStore<State = OAuthSessionState>,
    {
        if let Some(start_challenge_path) = oauth2.get_start_challenge_path() {
            let challenge_route = MethodRouter::new()
                .get(start_challenge::<T, STORE>)
                .layer(Extension(oauth2.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new()
            .get(callback::<T, STORE>)
            .layer(Extension(oauth2.clone()));

        self.route(&oauth2.callback_url(), route)
    }

    fn with_session<SES: HttpSession + Clone>(self, session: SES) -> Router<S>
    where
        SES::State: Clone,
    {
        let middleware = axum::middleware::from_fn(session_layer::<SES>);

        self.layer(middleware).layer(Extension(session))
    }
}

async fn session_layer<S: HttpSession + Clone>(mut req: Request, next: Next) -> Response
where
    S::State: Send + Sync + 'static + Clone,
{
    let session = req.extensions_mut().remove::<S>().unwrap();

    let (mut parts, body) = req.into_parts();

    if let Some(session) = session.load_from_request_parts(&mut parts).await {
        parts.extensions.insert(session);
    };

    let req = Request::from_parts(parts, body);

    next.run(req).await
}
