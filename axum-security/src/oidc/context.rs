use std::{borrow::Cow, convert::Infallible, sync::Arc};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect},
};

use cookie_monster::{CookieBuilder, CookieJar};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, Nonce, OAuth2TokenResponse, PkceCodeChallenge, Scope, TokenResponse as _,
    core::CoreClient,
};

use crate::{
    after_login::AfterLoginCookies,
    oidc::{OidcBuilderError, builder::OidcContextBuilder},
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

    pub async fn auth0(domain: &str) -> Result<OidcContextBuilder, OidcBuilderError> {
        let issuer_url = format!("https://{}/", domain.trim_end_matches('/'));
        Self::discover("auth0", &issuer_url).await
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
        let claims = match super::OidcClaims::from_jwt_payload(&jwt_str) {
            Ok(claims) => claims,
            Err(_e) => {
                crate::debug!("failed to deserialize claims: {_e}");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let oidc_response = OidcTokenResponse {
            claims,
            access_token: OAuth2TokenResponse::access_token(&token_response)
                .secret()
                .clone(),
            refresh_token: OAuth2TokenResponse::refresh_token(&token_response)
                .map(|t| t.secret().clone()),
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
