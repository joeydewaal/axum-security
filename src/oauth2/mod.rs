use std::sync::Arc;

mod builder;
mod client;
mod router;

pub use client::TokenResponse;
pub use router::RouterOAuthExt;

use ::oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};
use axum::{
    Extension,
    extract::Query,
    response::{IntoResponse, Redirect},
};
use cookie_monster::{CookieBuilder, CookieJar};
use serde::Deserialize;

use crate::{
    oauth2::builder::{OAuth2ClientTyped, Oauth2ContextBuilder},
    session::{CookieSession, SessionId, SessionStore},
    store::MemoryStore,
};

pub struct OAuth2Context<T, S>(Arc<OAuth2ContextInner<T, S>>);

impl<T, S> Clone for OAuth2Context<T, S> {
    fn clone(&self) -> Self {
        OAuth2Context(self.0.clone())
    }
}

pub struct OAuthSessionState {
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

impl Clone for OAuthSessionState {
    fn clone(&self) -> Self {
        Self {
            csrf_token: self.csrf_token.clone(),
            pkce_verifier: PkceCodeVerifier::new(self.pkce_verifier.secret().clone()),
        }
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
    pub fn builder() -> Oauth2ContextBuilder<MemoryStore<OAuthSessionState>> {
        Oauth2ContextBuilder::new(MemoryStore::new())
    }

    pub fn builder_with_store<S>(store: S) -> Oauth2ContextBuilder<S> {
        Oauth2ContextBuilder::new(store)
    }
}

impl<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>> OAuth2Context<T, S> {
    pub(crate) fn callback_url(&self) -> &str {
        self.0.client.redirect_uri().unwrap().url().path()
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

#[derive(Deserialize)]
struct OAuth2Params {
    code: AuthorizationCode,
    state: CsrfToken,
}

async fn callback<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>>(
    Extension(context): Extension<OAuth2Context<T, S>>,
    Query(params): Query<OAuth2Params>,
    jar: CookieJar,
) -> impl IntoResponse {
    // get session cookie
    let Some(cookie) = jar.get(context.0.cookie_opts.get_name()) else {
        return ().into_response();
    };

    // load session
    let session_id = SessionId::from_cookie(cookie);

    // retrieve csrf token from session
    let Some(session) = context.0.session.remove_session(&session_id).await else {
        return ().into_response();
    };

    let OAuthSessionState {
        csrf_token,
        pkce_verifier,
    } = session.into_state();

    // verify that csrf token is equal
    if csrf_token.secret() != params.state.secret() {
        // bad req
        return ().into_response();
    }

    // exchange authorization code
    let response = context
        .0
        .client
        .exchange_code(params.code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(&context.0.http_client)
        .await
        .unwrap();

    let access_token = response.access_token().secret().clone();
    let refresh_token = response.refresh_token().map(|t| t.secret().clone());

    let token_response = TokenResponse {
        access_token,
        refresh_token,
    };

    // tada, access token, maybe refresh token.

    // after login callback
    context
        .0
        .inner
        .after_login(token_response)
        .await
        .into_response()
}

pub async fn start_challenge<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>>(
    Extension(context): Extension<OAuth2Context<T, S>>,
) -> impl IntoResponse {
    context.start_challenge().await
}

pub trait OAuth2Handler: Send + Sync + 'static {
    fn generate_session_id(&self) -> SessionId {
        SessionId::new_uuid_v7()
    }

    fn after_login(
        &self,
        token_res: TokenResponse,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}

#[cfg(test)]
mod oauth2 {
    use std::{env, time::Duration};

    use axum::{
        Router,
        response::{IntoResponse, Redirect},
        routing::get,
        serve,
    };
    use tokio::{
        net::TcpListener,
        sync::mpsc::{self, Sender},
    };

    use crate::{
        oauth2::{OAuth2Context, OAuth2Handler, client::TokenResponse, router::RouterOAuthExt},
        session::{CookieSession, Session},
        store::MemoryStore,
    };
}
