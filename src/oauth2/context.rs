use std::{borrow::Cow, sync::Arc};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
};

use cookie_monster::CookieJar;
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};

use crate::{
    oauth2::{
        OAuth2ClientTyped, OAuth2Handler, OAuthSessionState, TokenResponse,
        builder::OAuth2ContextBuilder,
    },
    session::CookieSession,
    store::{MemoryStore, SessionStore},
};

pub struct OAuth2Context<T, S>(pub(super) Arc<OAuth2ContextInner<T, S>>);

impl<T, S> Clone for OAuth2Context<T, S> {
    fn clone(&self) -> Self {
        OAuth2Context(self.0.clone())
    }
}

pub(super) struct OAuth2ContextInner<T, S> {
    pub(super) inner: T,
    pub(super) session: CookieSession<S>,
    pub(super) client: OAuth2ClientTyped,
    pub(super) start_challenge_path: Option<Cow<'static, str>>,
    pub(super) scopes: Vec<Scope>,
    pub(super) http_client: ::oauth2::reqwest::Client,
}
impl OAuth2Context<(), ()> {
    pub fn builder(
        name: impl Into<Cow<'static, str>>,
    ) -> OAuth2ContextBuilder<MemoryStore<OAuthSessionState>> {
        OAuth2ContextBuilder::new(name, MemoryStore::new())
    }

    pub fn builder_with_store<S>(
        store: S,
        name: impl Into<Cow<'static, str>>,
    ) -> OAuth2ContextBuilder<S> {
        OAuth2ContextBuilder::new(name, store)
    }
}

impl<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>> OAuth2Context<T, S> {
    pub(crate) fn callback_url(&self) -> &str {
        self.0.client.redirect_uri().unwrap().url().path()
    }

    pub(crate) async fn callback(
        &self,
        jar: CookieJar,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> axum::response::Response {
        let Some(session) = self.0.session.remove_session(&jar).await else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        let OAuthSessionState {
            csrf_token,
            pkce_verifier,
        } = session.into_state();

        // verify that csrf token is equal
        if csrf_token.secret() != state.secret() {
            // bad req
            return StatusCode::UNAUTHORIZED.into_response();
        }

        // exchange authorization code
        let token_response = self.exchange_code(code, pkce_verifier).await.unwrap();
        // tada, access token, maybe refresh token.

        // after login callback
        self.after_login(token_response).await
    }

    pub(crate) async fn after_login(
        &self,
        token_response: TokenResponse,
    ) -> axum::response::Response {
        self.0
            .inner
            .after_login(token_response)
            .await
            .into_response()
    }

    pub(crate) async fn exchange_code(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> crate::Result<TokenResponse> {
        let response = self
            .0
            .client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.0.http_client)
            .await?;

        let access_token = response.access_token().secret().clone();
        let refresh_token = response.refresh_token().map(|t| t.secret().clone());

        Ok(TokenResponse {
            access_token,
            refresh_token,
        })
    }

    pub fn get_start_challenge_path(&self) -> Option<&str> {
        self.0.start_challenge_path.as_deref()
    }

    pub async fn start_challenge(&self) -> axum::response::Response {
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

        let cookie = self.0.session.store_session(state).await;

        // Send session cookie back

        (cookie, Redirect::to(url.as_str())).into_response()
    }
}
