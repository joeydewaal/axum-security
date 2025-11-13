use std::sync::Arc;

use axum::{
    Extension,
    response::{IntoResponse, Redirect},
};

pub use builder::OAuth2ContextBuilder;
pub(crate) use callback::callback;

use cookie_monster::CookieBuilder;
use oauth2::{
    CsrfToken, EndpointNotSet, EndpointSet, PkceCodeChallenge, Scope, basic::BasicClient,
};

use crate::{
    oauth2::{OAuth2Handler, OAuthSessionState},
    session::CookieSession,
    store::{MemoryStore, SessionStore},
};

mod builder;
mod callback;

pub type OAuth2ClientTyped =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct OAuth2Context<T, S>(Arc<OAuth2ContextInner<T, S>>);

impl<T, S> Clone for OAuth2Context<T, S> {
    fn clone(&self) -> Self {
        OAuth2Context(self.0.clone())
    }
}

struct OAuth2ContextInner<T, S> {
    inner: T,
    session: CookieSession<S>,
    client: OAuth2ClientTyped,
    cookie_opts: CookieBuilder,
    start_challenge_path: Option<String>,
    scopes: Vec<Scope>,
    http_client: ::oauth2::reqwest::Client,
}
impl OAuth2Context<(), ()> {
    pub fn builder() -> OAuth2ContextBuilder<MemoryStore<OAuthSessionState>> {
        OAuth2ContextBuilder::new(MemoryStore::new())
    }

    pub fn builder_with_store<S>(store: S) -> OAuth2ContextBuilder<S> {
        OAuth2ContextBuilder::new(store)
    }
}

impl<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>> OAuth2Context<T, S> {
    pub(crate) fn callback_url(&self) -> &str {
        self.0.client.redirect_uri().unwrap().url().path()
    }

    pub fn get_start_challenge_path(&self) -> Option<&str> {
        self.0.start_challenge_path.as_deref()
    }

    async fn start_challenge(&self) -> axum::response::Response {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let req = self.0.client.authorize_url(CsrfToken::new_random);

        // Create authorize url, with csrf token
        let (url, csrf_token) = req
            .add_scopes(self.0.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        // Store CSRF token on the server somewhere temp. (session)
        let state = OAuthSessionState {
            csrf_token,
            pkce_verifier,
        };

        let session = self.0.session.store_session(state).await;

        // Send session cookie back

        (session.cookie(), Redirect::to(url.as_str())).into_response()
    }
}

pub async fn start_challenge<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>>(
    Extension(context): Extension<OAuth2Context<T, S>>,
) -> impl IntoResponse {
    context.start_challenge().await
}
