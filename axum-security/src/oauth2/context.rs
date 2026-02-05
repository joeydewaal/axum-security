use std::{borrow::Cow, sync::Arc};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
};

use cookie_monster::{CookieBuilder, CookieJar};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};

use crate::{
    cookie::{CookieContext, CookieStore, MemStore},
    oauth2::{
        AfterLoginContext, OAuth2ClientTyped, OAuthState, TokenResponse,
        builder::OAuth2ContextBuilder, handler::ErasedOAuth2Handler,
    },
};

pub struct OAuth2Context<S>(pub(super) Arc<OAuth2ContextInner<S>>);

pub(super) struct OAuth2ContextInner<S> {
    pub(super) inner: ErasedOAuth2Handler,
    pub(super) session: CookieContext<S>,
    pub(super) client: OAuth2ClientTyped,
    pub(super) login_path: Option<Cow<'static, str>>,
    pub(super) scopes: Vec<Scope>,
    pub(super) http_client: ::oauth2::reqwest::Client,
}
impl OAuth2Context<()> {
    pub fn builder() -> OAuth2ContextBuilder<MemStore<OAuthState>> {
        OAuth2ContextBuilder::new(MemStore::new())
    }

    pub fn builder_with_store<S>(store: S) -> OAuth2ContextBuilder<S> {
        OAuth2ContextBuilder::new(store)
    }
}

impl<S: CookieStore<State = OAuthState>> OAuth2Context<S> {
    pub(crate) fn callback_url(&self) -> &str {
        self.0.client.redirect_uri().unwrap().url().path()
    }

    pub(crate) async fn on_redirect(
        &self,
        mut jar: CookieJar,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> axum::response::Response {
        tracing::debug!("handling redirect");
        let session = match self.0.session.remove_session_jar(&jar).await {
            Ok(Some(session)) => session,
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        let OAuthState {
            csrf_token,
            pkce_verifier,
        } = session.state;

        // verify that csrf token is equal
        if csrf_token.secret() != state.secret() {
            // bad req
            tracing::debug!("state does not match");
            return StatusCode::UNAUTHORIZED.into_response();
        }

        // exchange authorization code
        tracing::debug!("exchanging pkce code for an access token");
        let token_response = match self.exchange_code(code, pkce_verifier).await {
            Ok(res) => res,
            Err(e) => {
                tracing::debug!("failed to exchange code for access token: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        // tada, access token, maybe refresh token.

        // after login callback
        let context = AfterLoginContext {
            cookies: &mut jar,
            cookie_opts: self.0.session.cookie_builder(),
        };

        tracing::debug!("login flow done");
        let res = self.0.inner.after_login(token_response, context).await;

        (jar, res).into_response()
    }

    pub(crate) async fn exchange_code(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> Result<TokenResponse, String> {
        let response = self
            .0
            .client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.0.http_client)
            .await
            .map_err(|e| e.to_string())?;

        let access_token = response.access_token().secret().clone();
        let refresh_token = response.refresh_token().map(|t| t.secret().clone());

        Ok(TokenResponse {
            access_token,
            refresh_token,
        })
    }

    pub fn get_start_challenge_path(&self) -> Option<&str> {
        self.0.login_path.as_deref()
    }

    pub async fn start_challenge(&self) -> axum::response::Response {
        tracing::debug!("Starting oauth2 login flow");
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let req = self.0.client.authorize_url(CsrfToken::new_random);

        // Create authorize url, with csrf token
        let (redirect_url, csrf_token) = req
            .add_scopes(self.0.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        // Store CSRF token on the server somewhere.
        let state = OAuthState {
            csrf_token,
            pkce_verifier,
        };

        let cookie = match self.0.session.create_session(state).await {
            Ok(c) => c,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

        // Send session cookie back
        (cookie, Redirect::to(redirect_url.as_str())).into_response()
    }

    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.session.build_cookie(name)
    }
}

impl<S> Clone for OAuth2Context<S> {
    fn clone(&self) -> Self {
        OAuth2Context(self.0.clone())
    }
}
