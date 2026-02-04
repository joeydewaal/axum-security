use axum::{Extension, Router, routing::MethodRouter};

use crate::{
    cookie::CookieStore,
    oauth2::{OAuth2Context, OAuth2Handler, OAuthState, on_redirect, start_login},
};

pub trait OAuth2Ext {
    fn with_oauth2<T, S>(self, context: OAuth2Context<T, S>) -> Self
    where
        S: CookieStore<State = OAuthState>,
        T: OAuth2Handler;
}

impl<STATE> OAuth2Ext for Router<STATE>
where
    STATE: Clone + Send + Sync + 'static,
{
    fn with_oauth2<T, S>(mut self, context: OAuth2Context<T, S>) -> Self
    where
        T: OAuth2Handler,
        S: CookieStore<State = OAuthState>,
    {
        if let Some(start_challenge_path) = context.get_start_challenge_path() {
            let challenge_route = MethodRouter::new()
                .get(start_login::<T, S>)
                .layer(Extension(context.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new()
            .get(on_redirect::<T, S>)
            .layer(Extension(context.clone()));

        self.route(context.callback_url(), route)
    }
}
