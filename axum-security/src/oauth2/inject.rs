use axum::{Extension, Router, routing::MethodRouter};

use crate::oauth2::{OAuth2Context, on_redirect, start_login};

pub trait OAuth2Ext {
    fn with_oauth2(self, context: OAuth2Context) -> Self;
}

impl<STATE> OAuth2Ext for Router<STATE>
where
    STATE: Clone + Send + Sync + 'static,
{
    fn with_oauth2(mut self, context: OAuth2Context) -> Self {
        if let Some(start_challenge_path) = context.get_start_challenge_path() {
            let challenge_route = MethodRouter::new()
                .get(start_login)
                .layer(Extension(context.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new()
            .get(on_redirect)
            .layer(Extension(context.clone()));

        self.route(context.callback_url(), route)
    }
}
