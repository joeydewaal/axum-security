use axum::{Router, routing::MethodRouter};

use crate::oauth2::{
    OAuth2Context, OAuth2Handler,
    redirect::{OAuth2LoginService, OAuth2RedirectService},
};

pub trait OAuth2Ext {
    fn with_oauth2<H: OAuth2Handler>(self, context: OAuth2Context<H>) -> Self;
}

impl<S> OAuth2Ext for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_oauth2<H: OAuth2Handler>(mut self, context: OAuth2Context<H>) -> Self {
        if let Some(start_challenge_path) = context.get_start_challenge_path() {
            let challenge_route =
                MethodRouter::new().get_service(OAuth2LoginService::new(context.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new().get_service(OAuth2RedirectService::new(context.clone()));

        self.route(context.callback_url(), route)
    }
}
