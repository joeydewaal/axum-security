use std::{borrow::Cow, convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect},
};

use axum_security_oidc::{CsrfToken, LogoutUrl, OidcClient, OidcError, VerifyError};
use cookie_monster::{CookieBuilder, CookieJar};
use http::Extensions;
use url::Url;

use crate::{
    after_login::AfterLoginCookies,
    oidc::{OidcBuilderError, builder::OidcContextBuilder},
};

use super::{OidcHandler, OidcTokenResponse, cookie::OidcCookie};

/// OIDC context that manages the login/logout flow.
///
/// Construct with [`OidcContext::discover`] (auto-discovery) or
/// [`OidcContext::builder`] (manual endpoints). Provider shortcuts:
/// [`google`](OidcContext::google), [`microsoft`](OidcContext::microsoft),
/// [`apple`](OidcContext::apple), [`keycloak`](OidcContext::keycloak).
///
/// Register routes with [`OidcExt::with_oidc`](super::OidcExt::with_oidc).
pub struct OidcContext<H>(pub(super) Arc<OidcContextInner<H>>);

pub(super) struct OidcContextInner<H> {
    pub(super) handler: H,
    pub(super) session: OidcCookie,
    pub(super) client: OidcClient,
    pub(super) login_path: Option<Cow<'static, str>>,
    pub(super) logout_path: Option<Cow<'static, str>>,
    pub(super) post_logout_redirect_url: Option<String>,
}

impl OidcContext<()> {
    pub fn builder(provider_name: impl Into<Cow<'static, str>>) -> OidcContextBuilder {
        OidcContextBuilder::new(provider_name.into())
    }

    pub async fn discover(
        provider_name: impl Into<Cow<'static, str>>,
        issuer_url: &str,
    ) -> Result<OidcContextBuilder, OidcBuilderError> {
        OidcContextBuilder::discover(provider_name.into(), issuer_url).await
    }

    pub async fn google() -> Result<OidcContextBuilder, OidcBuilderError> {
        Self::discover("google", super::providers::google::ISSUER_URL).await
    }

    pub async fn microsoft() -> Result<OidcContextBuilder, OidcBuilderError> {
        Self::discover("microsoft", super::providers::microsoft::ISSUER_URL_COMMON).await
    }

    pub async fn apple() -> Result<OidcContextBuilder, OidcBuilderError> {
        Self::discover("apple", super::providers::apple::ISSUER_URL).await
    }

    pub async fn keycloak(
        base_url: &str,
        realm: &str,
    ) -> Result<OidcContextBuilder, OidcBuilderError> {
        let issuer_url = format!("{}/realms/{}", base_url.trim_end_matches('/'), realm);
        Self::discover("keycloak", &issuer_url).await
    }
}

impl<H: OidcHandler> OidcContext<H> {
    pub(crate) fn callback_url(&self) -> &str {
        self.0
            .client
            .redirect_url()
            .expect("redirect_uri must be set")
            .path()
    }

    pub(crate) fn get_start_challenge_path(&self) -> Option<&str> {
        self.0.login_path.as_deref()
    }

    pub(crate) async fn start_challenge(&self) -> axum::response::Response {
        crate::debug!("Starting OIDC login flow");

        let login = self.0.client.start_login();
        let cookie = self.0.session.generate_cookie(
            login.csrf_token.as_str(),
            &login.pkce_verifier,
            &login.nonce,
        );

        (cookie, Redirect::to(login.url.as_str())).into_response()
    }

    pub(crate) async fn on_redirect(
        &self,
        mut jar: CookieJar,
        code: String,
        state: String,
    ) -> axum::response::Response {
        crate::debug!("handling OIDC redirect");

        let Some((csrf_token, pkce_verifier, nonce)) = self.0.session.verify_cookies(&mut jar)
        else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        // Wrap the cookie's token so the comparison against the
        // attacker-controlled `state` runs in constant time.
        let csrf_token = CsrfToken::from(csrf_token);
        if csrf_token != state {
            crate::debug!("state does not match");
            return StatusCode::UNAUTHORIZED.into_response();
        }

        crate::debug!("exchanging authorization code for tokens");

        let tokens = match self
            .0
            .client
            .finish_login(&code, &pkce_verifier, &nonce)
            .await
        {
            Ok(tokens) => tokens,
            // A verification failure (bad signature, nonce, expiry, unknown key)
            // is an auth failure; an exchange/no-id_token failure is a 500.
            Err(OidcError::Verify(_e)) => {
                crate::debug!("id_token verification failed: {_e}");
                return StatusCode::UNAUTHORIZED.into_response();
            }
            Err(_e) => {
                crate::debug!("OIDC login failed: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let claims = match tokens.claims() {
            Ok(claims) => claims,
            Err(_e) => {
                crate::debug!("failed to deserialize claims: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let oidc_response = OidcTokenResponse {
            id_token: tokens.id_token(),
            claims,
            access_token: tokens.access_token().to_string(),
            refresh_token: tokens.refresh_token().map(String::from),
        };

        let mut context = AfterLoginCookies {
            cookie_jar: jar,
            cookie_opts: &self.0.session.cookie_builder,
        };

        crate::debug!("OIDC login flow done");
        let res = self
            .0
            .handler
            .after_login(oidc_response, &mut context)
            .await
            .into_response();

        (context.cookie_jar, res).into_response()
    }

    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.0.session.cookie_builder.clone().name(name.into())
    }

    /// Fetch and cache the provider's JWKS now instead of lazily on the first
    /// login. [`OidcContext`] is cheap to clone, so warm it in the background at
    /// startup:
    ///
    /// ```no_run
    /// # async fn f<H: axum_security::oidc::OidcHandler + 'static>(
    /// #     oidc: axum_security::oidc::OidcContext<H>,
    /// # ) {
    /// let oidc = oidc.clone();
    /// tokio::spawn(async move {
    ///     if let Err(e) = oidc.warm_jwks().await {
    ///         eprintln!("failed to prefetch OIDC keys: {e}");
    ///     }
    /// });
    /// # }
    /// ```
    pub async fn warm_jwks(&self) -> Result<(), VerifyError> {
        self.0.client.warm_jwks().await
    }

    pub(crate) fn get_logout_path(&self) -> Option<&str> {
        self.0.logout_path.as_deref()
    }

    pub(crate) fn build_logout_context(&self, extensions: Extensions) -> LogoutContext {
        LogoutContext {
            extensions,
            end_session_endpoint: self.0.client.end_session_endpoint().cloned(),
            post_logout_redirect_url: self.0.post_logout_redirect_url.clone(),
            id_token_hint: None,
            logout_hint: None,
            client_id: Some(self.0.client.client_id().to_string()),
            state: None,
        }
    }
}

/// Context passed to [`OidcHandler::logout`](super::OidcHandler::logout).
///
/// Provides access to request extensions and methods to customize the
/// logout redirect (ID token hint, logout hint, post-logout redirect URI).
/// Call [`default_redirect`](LogoutContext::default_redirect) to build the
/// redirect response using the configured end-session endpoint.
pub struct LogoutContext {
    extensions: Extensions,
    end_session_endpoint: Option<Url>,
    post_logout_redirect_url: Option<String>,
    id_token_hint: Option<String>,
    logout_hint: Option<String>,
    client_id: Option<String>,
    state: Option<String>,
}

impl LogoutContext {
    #[cfg(feature = "cookie")]
    pub fn cookie_session<U: Send + Sync + 'static>(
        &mut self,
    ) -> Option<crate::cookie::CookieSession<U>> {
        use crate::cookie::CookieSession;

        CookieSession::from_extensions(&mut self.extensions)
    }

    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    pub fn set_id_token_hint(&mut self, id_token_hint: impl Into<String>) {
        self.id_token_hint = Some(id_token_hint.into());
    }

    pub fn set_logout_hint(&mut self, logout_hint: impl Into<String>) {
        self.logout_hint = Some(logout_hint.into());
    }

    pub fn set_client_id(&mut self, client_id: impl Into<String>) {
        self.client_id = Some(client_id.into());
    }

    pub fn set_post_logout_redirect_uri(&mut self, post_logout_redirect_uri: impl Into<String>) {
        self.post_logout_redirect_url = Some(post_logout_redirect_uri.into());
    }

    pub fn set_state(&mut self, state: impl Into<String>) {
        self.state = Some(state.into());
    }

    pub fn default_redirect(self) -> Redirect {
        match self.end_session_endpoint {
            Some(endpoint) => {
                let mut logout = LogoutUrl::new(endpoint);
                if let Some(id_token_hint) = self.id_token_hint {
                    logout = logout.id_token_hint(id_token_hint);
                }
                if let Some(redirect) = &self.post_logout_redirect_url {
                    logout = logout.post_logout_redirect_uri(redirect);
                }
                if let Some(logout_hint) = self.logout_hint {
                    logout = logout.logout_hint(logout_hint);
                }
                if let Some(client_id) = self.client_id {
                    logout = logout.client_id(client_id);
                }
                if let Some(state) = self.state {
                    logout = logout.state(state);
                }
                Redirect::to(logout.build().as_str())
            }
            None => match &self.post_logout_redirect_url {
                Some(url) => Redirect::to(url),
                None => Redirect::to("/"),
            },
        }
    }

    pub fn end_session_url(&self) -> Option<&str> {
        self.end_session_endpoint.as_ref().map(Url::as_str)
    }

    pub fn post_logout_redirect_url(&self) -> Option<&str> {
        self.post_logout_redirect_url.as_deref()
    }
}

impl<S, H> FromRequestParts<S> for OidcContext<H>
where
    Self: FromRef<S>,
    S: Send + Sync,
    H: OidcHandler,
{
    type Rejection = Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}

impl<H> Clone for OidcContext<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use http::Extensions;
    use url::Url;

    use super::LogoutContext;

    fn ctx(
        end_session_endpoint: Option<&str>,
        post_logout_redirect_url: Option<&str>,
    ) -> LogoutContext {
        LogoutContext {
            extensions: Extensions::new(),
            end_session_endpoint: end_session_endpoint.map(|u| Url::parse(u).unwrap()),
            post_logout_redirect_url: post_logout_redirect_url.map(String::from),
            id_token_hint: None,
            logout_hint: None,
            client_id: None,
            state: None,
        }
    }

    #[test]
    fn logout_redirects_to_slash_when_nothing_configured() {
        let response = ctx(None, None).default_redirect().into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap(), "/");
    }

    #[test]
    fn logout_redirects_to_post_logout_url() {
        let response = ctx(None, Some("http://localhost:3000/"))
            .default_redirect()
            .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "http://localhost:3000/"
        );
    }

    #[test]
    fn logout_redirects_to_end_session_endpoint() {
        let response = ctx(Some("https://provider.example.com/logout"), None)
            .default_redirect()
            .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://provider.example.com/logout"));
    }

    #[test]
    fn logout_end_session_includes_post_logout_redirect() {
        let response = ctx(
            Some("https://provider.example.com/logout"),
            Some("http://localhost:3000/"),
        )
        .default_redirect()
        .into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://provider.example.com/logout"));
        assert!(location.contains("post_logout_redirect_uri="));
    }
}
