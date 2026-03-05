use std::{borrow::Cow, convert::Infallible, str::FromStr, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect},
};

use cookie_monster::{CookieBuilder, CookieJar};
use http::Extensions;
use oauth2::ClientId;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, EmptyAdditionalClaims, EndSessionUrl,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IdToken, LogoutHint, LogoutRequest, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PostLogoutRedirectUrl, Scope, TokenResponse as _,
    core::{
        CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    },
};

use crate::{
    after_login::AfterLoginCookies,
    oidc::{OidcBuilderError, OidcClaims, builder::OidcContextBuilder},
};

use super::{OidcHandler, OidcTokenResponse, cookie::OidcCookie};

pub(crate) type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct OidcContext<H>(pub(super) Arc<OidcContextInner<H>>);

pub(super) struct OidcContextInner<H> {
    pub(super) handler: H,
    pub(super) session: OidcCookie,
    pub(super) client: OidcClient,
    pub(super) login_path: Option<Cow<'static, str>>,
    pub(super) logout_path: Option<Cow<'static, str>>,
    pub(super) end_session_url: Option<EndSessionUrl>,
    pub(super) post_logout_redirect_url: Option<PostLogoutRedirectUrl>,
    pub(super) scopes: Vec<Scope>,
    pub(super) http_client: openidconnect::reqwest::Client,
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
            .redirect_uri()
            .expect("redirect_uri must be set")
            .url()
            .path()
    }

    pub(crate) fn get_start_challenge_path(&self) -> Option<&str> {
        self.0.login_path.as_deref()
    }

    pub(crate) async fn start_challenge(&self) -> axum::response::Response {
        crate::debug!("Starting OIDC login flow");

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (redirect_url, csrf_token, nonce) = self
            .0
            .client
            .authorize_url(
                AuthenticationFlow::<openidconnect::core::CoreResponseType>::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(self.0.scopes.clone())
            .url();

        let cookie = self.0.session.generate_cookie(
            csrf_token.secret(),
            pkce_verifier.secret(),
            nonce.secret(),
        );

        (cookie, Redirect::to(redirect_url.as_str())).into_response()
    }

    pub(crate) async fn on_redirect(
        &self,
        mut jar: CookieJar,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> axum::response::Response {
        crate::debug!("handling OIDC redirect");

        let Some((csrf_token, pkce_verifier, nonce)) = self.0.session.verify_cookies(&mut jar)
        else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        if csrf_token.secret() != state.secret() {
            crate::debug!("state does not match");
            return StatusCode::UNAUTHORIZED.into_response();
        }

        crate::debug!("exchanging authorization code for tokens");

        let code_request = match self.0.client.exchange_code(code) {
            Ok(req) => req,
            Err(_e) => {
                crate::debug!("token endpoint not configured: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let token_response = match code_request
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.0.http_client)
            .await
        {
            Ok(res) => res,
            Err(_e) => {
                crate::debug!("failed to exchange code for tokens: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let id_token = match token_response.id_token() {
            Some(id_token) => id_token,
            None => {
                crate::debug!("no id_token in token response");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        // Verify the token (signature, nonce, audience, expiration)
        if let Err(_e) = id_token.claims(&self.0.client.id_token_verifier(), &nonce) {
            crate::debug!("id_token verification failed: {_e}");
            return StatusCode::UNAUTHORIZED.into_response();
        }

        // Extract and deserialize the JWT payload into our own claims struct
        let jwt_str = id_token.to_string();

        let bytes = match OidcClaims::decode_token(&jwt_str) {
            Ok(claims) => claims,
            Err(_e) => {
                crate::debug!("failed to decode claims: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let claims = match OidcClaims::from_decoded_payload(&bytes) {
            Ok(claims) => claims,
            Err(_e) => {
                crate::debug!("failed to deserialize claims: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let oidc_response = OidcTokenResponse {
            id_token: &jwt_str,
            claims,
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().clone()),
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

    pub(crate) fn get_logout_path(&self) -> Option<&str> {
        self.0.logout_path.as_deref()
    }

    pub(crate) fn build_logout_context(&self, extensions: Extensions) -> LogoutContext {
        LogoutContext {
            extensions,
            end_session_url: self.0.end_session_url.clone(),
            post_logout_redirect_url: self.0.post_logout_redirect_url.clone(),
            id_token_hint: None,
            logout_hint: None,
            client_id: Some(self.0.client.client_id().to_string()),
            state: None,
        }
    }
}

pub struct LogoutContext {
    extensions: Extensions,
    end_session_url: Option<EndSessionUrl>,
    post_logout_redirect_url: Option<PostLogoutRedirectUrl>,
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
        self.post_logout_redirect_url =
            PostLogoutRedirectUrl::new(post_logout_redirect_uri.into()).ok();
    }

    pub fn set_state(&mut self, state: impl Into<String>) {
        self.state = Some(state.into());
    }

    pub fn default_redirect(self) -> Redirect {
        match self.end_session_url {
            Some(url) => {
                let mut request = LogoutRequest::from(url);
                if let Some(redirect) = self.post_logout_redirect_url {
                    request = request.set_post_logout_redirect_uri(redirect);
                }

                if let Some(id_token_hint) = &self.id_token_hint
                    // Just,.... why?
                    && let Some(token) = IdToken::<
                        EmptyAdditionalClaims,
                        CoreGenderClaim,
                        CoreJweContentEncryptionAlgorithm,
                        CoreJwsSigningAlgorithm,
                    >::from_str(id_token_hint)
                    .ok()
                {
                    request = request.set_id_token_hint(&token);
                }

                if let Some(logout_hint) = self.logout_hint {
                    request = request.set_logout_hint(LogoutHint::new(logout_hint));
                }

                if let Some(client_id) = self.client_id {
                    request = request.set_client_id(ClientId::new(client_id));
                }

                if let Some(state) = self.state {
                    request = request.set_state(CsrfToken::new(state));
                }

                Redirect::to(request.http_get_url().as_str())
            }
            None => match &self.post_logout_redirect_url {
                Some(url) => Redirect::to(url.as_str()),
                None => Redirect::to("/"),
            },
        }
    }

    pub fn end_session_url(&self) -> Option<&str> {
        self.end_session_url.as_ref().map(|e| e.as_str())
    }

    pub fn post_logout_redirect_url(&self) -> Option<&str> {
        self.post_logout_redirect_url.as_ref().map(|e| e.as_str())
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
    use openidconnect::{EndSessionUrl, PostLogoutRedirectUrl};

    use super::LogoutContext;

    #[test]
    fn logout_redirects_to_slash_when_nothing_configured() {
        let ctx = LogoutContext {
            extensions: Extensions::new(),
            end_session_url: None,
            post_logout_redirect_url: None,
            id_token_hint: None,
            logout_hint: None,
            client_id: None,
            state: None,
        };
        let response = ctx.default_redirect().into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get("location").unwrap(), "/");
    }

    #[test]
    fn logout_redirects_to_post_logout_url() {
        let ctx = LogoutContext {
            extensions: Extensions::new(),
            end_session_url: None,
            post_logout_redirect_url: Some(
                PostLogoutRedirectUrl::new("http://localhost:3000/".to_string()).unwrap(),
            ),
            id_token_hint: None,
            logout_hint: None,
            client_id: None,
            state: None,
        };
        let response = ctx.default_redirect().into_response();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "http://localhost:3000/"
        );
    }

    #[test]
    fn logout_redirects_to_end_session_endpoint() {
        let ctx = LogoutContext {
            extensions: Extensions::new(),
            end_session_url: Some(
                EndSessionUrl::new("https://provider.example.com/logout".to_string()).unwrap(),
            ),
            post_logout_redirect_url: None,
            id_token_hint: None,
            logout_hint: None,
            client_id: None,
            state: None,
        };
        let response = ctx.default_redirect().into_response();
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
        let ctx = LogoutContext {
            extensions: Extensions::new(),
            end_session_url: Some(
                EndSessionUrl::new("https://provider.example.com/logout".to_string()).unwrap(),
            ),
            post_logout_redirect_url: Some(
                PostLogoutRedirectUrl::new("http://localhost:3000/".to_string()).unwrap(),
            ),
            id_token_hint: None,
            logout_hint: None,
            client_id: None,
            state: None,
        };
        let response = ctx.default_redirect().into_response();
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
