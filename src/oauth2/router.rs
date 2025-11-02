use axum::{
    Extension, Router,
    extract::{FromRef, FromRequestParts, Request},
    middleware::{AddExtension, Next},
    response::Response,
    routing::{MethodRouter, get},
};
use cookie_monster::CookieJar;

use crate::{
    oauth2::{OAuth2Context, OAuth2Handler, callback},
    session::{SessionId, SessionStore},
};

pub trait RouterOAuthExt<S> {
    fn with_oauth2<T: OAuth2Handler>(self, oauth2: &OAuth2Context<T>) -> Router<S>;

    fn with_session<SES: SessionStore + Clone>(self, session: SES) -> Router<S>
    where
        SES::State: Clone;
}

impl<S> RouterOAuthExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_oauth2<T>(mut self, oauth2: &OAuth2Context<T>) -> Router<S>
    where
        T: OAuth2Handler,
    {
        if let Some(start_challenge_path) = &oauth2.0.start_challenge_path {
            let challenge_route = MethodRouter::new()
                .get(callback::<T>)
                .layer(Extension(oauth2.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new()
            .get(callback::<T>)
            .layer(Extension(oauth2.clone()));

        self.route(&oauth2.0.client.callback_url(), route)
    }

    fn with_session<SES: SessionStore + Clone>(self, session: SES) -> Router<S>
    where
        SES::State: Clone,
    {
        let middleware = axum::middleware::from_fn(session_layer::<SES>);

        self.layer(middleware).layer(Extension(session))
    }
}

async fn session_layer<S: SessionStore + 'static + Send + Sync>(
    mut req: Request,
    next: Next,
) -> Response
where
    S::State: Send + Sync + 'static + Clone,
{
    let session = req.extensions_mut().remove::<S>().unwrap();

    let cookies = CookieJar::from_headers(req.headers());

    let Some(cookie) = cookies.get("session") else {
        return next.run(req).await;
    };

    let session_id = SessionId::from_cookie(&cookie);

    let Some(session) = session.load_session(&session_id).await else {
        return next.run(req).await;
    };

    req.extensions_mut().insert(session);

    return next.run(req).await;
}
