use axum::{Router, routing::MethodRouter};

use super::{
    OidcContext, OidcHandler,
    redirect::{OidcLoginService, OidcRedirectService},
};

pub trait OidcExt {
    fn with_oidc<H: OidcHandler>(self, context: OidcContext<H>) -> Self;
}

impl<S> OidcExt for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn with_oidc<H: OidcHandler>(mut self, context: OidcContext<H>) -> Self {
        if let Some(start_challenge_path) = context.get_start_challenge_path() {
            let challenge_route =
                MethodRouter::new().get_service(OidcLoginService::new(context.clone()));

            self = self.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new().get_service(OidcRedirectService::new(context.clone()));

        self.route(context.callback_url(), route)
    }
}
