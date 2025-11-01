use axum::{
    Extension, Router,
    extract::FromRef,
    middleware::AddExtension,
    routing::{MethodRouter, get},
};

use crate::oauth2::{OAuth2Context, OAuth2Handler, callback};

pub trait RouterOAuthExt<S> {
    fn with_oauth2<T: OAuth2Handler>(self, oauth2: &OAuth2Context<T>) -> Router<S>;
}

impl<S> RouterOAuthExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_oauth2<T>(self, oauth2: &OAuth2Context<T>) -> Router<S>
    where
        T: OAuth2Handler,
    {
        let route = MethodRouter::new()
            .get(callback::<T>)
            .layer(Extension(oauth2.clone()));

        self.route(oauth2.0.client.callback_url(), route)
    }
}

// use axum::{
//     Extension, Router,
//     extract::FromRef,
//     middleware::AddExtension,
//     routing::{MethodRouter, get},
// };

// use crate::oauth2::{OAuth2Context, OAuth2Handler, callback};

// pub trait RouterOAuthExt<S, T: OAuth2Handler> {
//     fn with_oauth2(self, oauth2: OAuth2Context<T>) -> Router<S>;
// }

// impl<S, T: OAuth2Handler> RouterOAuthExt<S, T> for Router<OAuth2Context<T>>
// where
//     S: Send + Sync + Clone + 'static,
// {
//     fn with_oauth2(self, oauth2: OAuth2Context<T>) -> Router<S> {
//         self.route(oauth2.0.client.callback_url(), get(callback::<T>))
//             .with_state(oauth2)
//     }
// }

// pub trait RouterOAuthExt2<S, S2, T: OAuth2Handler> {
//     fn with_oauth2_from_state(self, state: S) -> Router<S2>;
// }

// impl<S, S2, T: OAuth2Handler> RouterOAuthExt2<S, S2, T> for Router<S>
// where
//     S: Send + Sync + Clone + 'static,
//     S2: Send + Sync + Clone + 'static,
//     OAuth2Context<T>: FromRef<S>,
// {
//     fn with_oauth2_from_state(self, state: S) -> Router<S2> {
//         let oauth2 = OAuth2Context::<T>::from_ref(&state);
//         self.route(oauth2.0.client.callback_url(), get(callback::<T>))
//             .with_state(state)
//     }
// }
