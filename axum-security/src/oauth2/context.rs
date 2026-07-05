use std::{borrow::Cow, convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect},
};

use axum_security_oauth2::{CsrfToken, LoginOptions, OAuth2Client};
use cookie_monster::{CookieBuilder, CookieJar};

use crate::oauth2::{
    AfterLoginCookies, OAuth2Handler, TokenResponse,
    builder::{FlowType, OAuth2ContextBuilder},
    cookie::OAuth2Cookie,
};

/// OAuth 2.0 context that manages the login flow.
///
/// Construct with [`OAuth2Context::builder`] or a provider shortcut
/// ([`github`](OAuth2Context::github), [`discord`](OAuth2Context::discord), etc.).
/// Register routes with [`OAuth2Ext::with_oauth2`](super::OAuth2Ext::with_oauth2).
pub struct OAuth2Context<H>(pub(super) Arc<OAuth2ContextInner<H>>);

pub(super) struct OAuth2ContextInner<H> {
    pub(super) inner: H,
    pub(super) session: OAuth2Cookie,
    pub(super) client: OAuth2Client,
    pub(super) login_path: Option<Cow<'static, str>>,
    pub(super) auth_params: Vec<(String, String)>,
    pub(super) flow_type: FlowType,
}
impl OAuth2Context<()> {
    pub fn builder(oauth2_provider_name: impl Into<Cow<'static, str>>) -> OAuth2ContextBuilder {
        OAuth2ContextBuilder::new(oauth2_provider_name.into())
    }

    pub fn github() -> OAuth2ContextBuilder {
        Self::builder("github")
            .auth_url(super::providers::github::AUTH_URL)
            .token_url(super::providers::github::TOKEN_URL)
    }

    pub fn google() -> OAuth2ContextBuilder {
        Self::builder("google")
            .auth_url(super::providers::google::AUTH_URL)
            .token_url(super::providers::google::TOKEN_URL)
    }

    /// Microsoft's multi-tenant (`common`) endpoints; single-tenant apps
    /// use [`builder`](Self::builder) with their tenant's URLs.
    pub fn microsoft() -> OAuth2ContextBuilder {
        Self::builder("microsoft")
            .auth_url(super::providers::microsoft::AUTH_URL)
            .token_url(super::providers::microsoft::TOKEN_URL)
    }

    /// gitlab.com's endpoints; self-hosted instances use
    /// [`builder`](Self::builder) with their own URLs.
    pub fn gitlab() -> OAuth2ContextBuilder {
        Self::builder("gitlab")
            .auth_url(super::providers::gitlab::AUTH_URL)
            .token_url(super::providers::gitlab::TOKEN_URL)
    }

    pub fn discord() -> OAuth2ContextBuilder {
        Self::builder("discord")
            .auth_url(super::providers::discord::AUTH_URL)
            .token_url(super::providers::discord::TOKEN_URL)
    }

    pub fn spotify() -> OAuth2ContextBuilder {
        Self::builder("spotify")
            .auth_url(super::providers::spotify::AUTH_URL)
            .token_url(super::providers::spotify::TOKEN_URL)
    }

    pub fn twitch() -> OAuth2ContextBuilder {
        Self::builder("twitch")
            .auth_url(super::providers::twitch::AUTH_URL)
            .token_url(super::providers::twitch::TOKEN_URL)
    }
}

impl<H: OAuth2Handler> OAuth2Context<H> {
    pub(crate) fn callback_url(&self) -> &str {
        // The builder requires a redirect_url, so it is always set.
        self.0.client.redirect_url().unwrap().path()
    }

    pub(crate) async fn on_redirect(
        &self,
        mut jar: CookieJar,
        code: String,
        state: String,
    ) -> axum::response::Response {
        crate::debug!("handling redirect");

        let Some((csrf_token, pkce_verifier)) = self.0.session.verify_cookies(&mut jar) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        // Wrap the cookie's token in `CsrfToken` so the comparison against
        // the attacker-controlled `state` query param runs in constant time
        // (its `PartialEq`), rather than `String`'s byte-by-byte short-circuit.
        let csrf_token = CsrfToken::from(csrf_token);
        if csrf_token != state {
            crate::debug!("state does not match");
            return StatusCode::UNAUTHORIZED.into_response();
        }

        // exchange authorization code
        crate::debug!("exchanging pkce code for an access token");
        let token_response = match self.exchange_code(code, pkce_verifier).await {
            Ok(res) => res,
            Err(_e) => {
                crate::debug!("failed to exchange code for access token: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        // tada, access token, maybe refresh token.

        // after login callback
        let mut context = AfterLoginCookies {
            cookie_jar: jar,
            cookie_opts: &self.0.session.cookie_builder,
        };

        crate::debug!("login flow done");
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
        code: String,
        pkce_verifier: Option<String>,
    ) -> Result<TokenResponse, String> {
        let tokens = match self.0.flow_type {
            FlowType::AuthorizationCodeFlow => self
                .0
                .client
                .finish_login_non_pkce(&code)
                .await
                .map_err(|e| e.to_string())?,
            FlowType::AuthorizationCodeFlowPkce => {
                let Some(pkce_verifier) = pkce_verifier else {
                    return Err("PKCE code verifier missing from request".into());
                };

                self.0
                    .client
                    .finish_login(&code, &pkce_verifier)
                    .await
                    .map_err(|e| e.to_string())?
            }
        };

        Ok(TokenResponse {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
        })
    }

    pub fn get_start_challenge_path(&self) -> Option<&str> {
        self.0.login_path.as_deref()
    }

    pub async fn start_challenge(&self) -> axum::response::Response {
        crate::debug!("Starting oauth2 login flow");

        let (redirect_url, cookie) = match self.0.flow_type {
            FlowType::AuthorizationCodeFlow => {
                let login = self
                    .0
                    .client
                    .start_login_non_pkce_with(|options| self.auth_params(options));
                let cookie = self
                    .0
                    .session
                    .generate_cookie(login.csrf_token.as_str(), None);
                (login.url, cookie)
            }
            FlowType::AuthorizationCodeFlowPkce => {
                let login = self
                    .0
                    .client
                    .start_login_with(|options| self.auth_params(options));
                let cookie = self
                    .0
                    .session
                    .generate_cookie(login.csrf_token.as_str(), Some(&login.pkce_verifier));
                (login.url, cookie)
            }
        };

        // Send session cookie back
        (cookie, Redirect::to(redirect_url.as_str())).into_response()
    }

    /// Applies the builder's `auth_param` extras to a login.
    fn auth_params(&self, mut options: LoginOptions) -> LoginOptions {
        for (name, value) in &self.0.auth_params {
            options = options.param(name, value);
        }
        options
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
