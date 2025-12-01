use axum::{Extension, Router, routing::MethodRouter};

use crate::{
    cookie::CookieStore,
    oauth2::{OAuth2Context, OAuth2Handler, OAuthState, callback, start_login},
    router_ext::AuthInjector,
};

impl<T, STORE, S> AuthInjector<Router<S>> for OAuth2Context<T, STORE>
where
    S: Send + Sync + 'static + Clone,
    T: OAuth2Handler,
    STORE: CookieStore<State = OAuthState>,
{
    fn inject_into(self, mut router: Router<S>) -> Router<S> {
        if let Some(start_challenge_path) = self.get_start_challenge_path() {
            let challenge_route = MethodRouter::new()
                .get(start_login::<T, STORE>)
                .layer(Extension(self.clone()));

            router = router.route(start_challenge_path, challenge_route);
        }

        let route = MethodRouter::new()
            .get(callback::<T, STORE>)
            .layer(Extension(self.clone()));

        router.route(self.callback_url(), route)
    }
}
