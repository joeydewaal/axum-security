use std::{borrow::Cow, convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect},
};

use cookie_monster::{CookieBuilder, CookieJar};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};

use crate::oauth2::{
    AfterLoginCookies, OAuth2ClientTyped, OAuth2Handler, TokenResponse,
    builder::{FlowType, OAuth2ContextBuilder},
    cookie::OAuth2Cookie,
};

pub struct OAuth2Context<H>(pub(super) Arc<OAuth2ContextInner<H>>);

pub(super) struct OAuth2ContextInner<H> {
    pub(super) inner: H,
    pub(super) session: OAuth2Cookie,
    pub(super) client: OAuth2ClientTyped,
    pub(super) login_path: Option<Cow<'static, str>>,
    pub(super) scopes: Vec<Scope>,
    pub(super) http_client: ::oauth2::reqwest::Client,
    pub(super) flow_type: FlowType,
}
impl OAuth2Context<()> {
    pub fn builder(oauth2_provider_name: impl Into<Cow<'static, str>>) -> OAuth2ContextBuilder {
        OAuth2ContextBuilder::new(oauth2_provider_name.into())
    }
}

impl<H: OAuth2Handler> OAuth2Context<H> {
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

        let (csrf_token, pkce_verifier) = match self.0.session.verify_cookies(&mut jar) {
            Ok(Some(session)) => session,
            Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };

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
        let mut context = AfterLoginCookies {
            cookie_jar: jar,
            cookie_opts: &self.0.session.cookie_builder,
        };

        tracing::debug!("login flow done");
        let res = self
            .0
            .inner
            .after_login(token_response, &mut context)
            .await
            .into_response();

        (context.cookie_jar, res).into_response()
    }

    pub(crate) async fn exchange_code(
        &self,
        code: AuthorizationCode,
        pkce_verifier: Option<PkceCodeVerifier>,
    ) -> Result<TokenResponse, String> {
        let response = match self.0.flow_type {
            FlowType::AuthorizationCodeFlow => self
                .0
                .client
                .exchange_code(code)
                .request_async(&self.0.http_client)
                .await
                .map_err(|e| e.to_string())?,
            FlowType::AuthorizationCodeFlowPkce => {
                let Some(pkce_verifier) = pkce_verifier else {
                    return Err("PKCE code verifier missing from request".into());
                };

                self.0
                    .client
                    .exchange_code(code)
                    .set_pkce_verifier(pkce_verifier)
                    .request_async(&self.0.http_client)
                    .await
                    .map_err(|e| e.to_string())?
            }
        };

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

        let mut req = self.0.client.authorize_url(CsrfToken::new_random);

        // Create authorize url, with csrf token
        req = req.add_scopes(self.0.scopes.clone());
        // let (redirect_url, csrf_token) = req.add_scopes(self.0.scopes.clone());
        // .set_pkce_challenge(pkce_challenge)
        // .url();

        let pkce_verifier = if matches!(self.0.flow_type, FlowType::AuthorizationCodeFlowPkce) {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            req = req.set_pkce_challenge(pkce_challenge);
            Some(pkce_verifier)
        } else {
            None
        };

        let (redirect_url, csrf_token) = req.url();

        let cookie = self.0.session.generate_cookie(
            csrf_token.secret(),
            pkce_verifier.as_ref().map(|s| s.secret().as_ref()),
        );

        // Send session cookie back
        (cookie, Redirect::to(redirect_url.as_str())).into_response()
    }

    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.session.cookie_builder.clone().name(name.into())
    }
}

impl<S, H> FromRequestParts<S> for OAuth2Context<H>
where
    Self: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}

impl<H> Clone for OAuth2Context<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
