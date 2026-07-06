use std::{fmt, time::Duration};

use axum_security_oauth2::{CsrfToken, LoginOptions, OAuth2Client, random_token};
use url::Url;

use crate::{
    claims::OidcClaims,
    error::{ClaimsError, OidcError, VerifyError},
    jwks::JwksCache,
    logout::LogoutUrl,
    verifier::VerifiedIdToken,
};

/// An OpenID Connect client: the OAuth2 authorization-code login flow plus
/// ID-token verification.
///
/// Build one with [`OidcClient::discover`](Self::discover) (auto-configured
/// from the provider's metadata), a provider shortcut
/// ([`google`](Self::google), [`microsoft`](Self::microsoft),
/// [`apple`](Self::apple), [`keycloak`](Self::keycloak)), or
/// [`OidcClient::builder`](Self::builder) for manual endpoints.
///
/// [`start_login`](Self::start_login) begins the flow (generating the CSRF
/// token, PKCE verifier, and `nonce`); [`finish_login`](Self::finish_login)
/// exchanges the code and verifies the returned ID token.
pub struct OidcClient {
    oauth2: OAuth2Client,
    verifier: JwksCache,
    end_session_endpoint: Option<Url>,
}

impl OidcClient {
    pub(crate) fn from_parts(
        oauth2: OAuth2Client,
        verifier: JwksCache,
        end_session_endpoint: Option<Url>,
    ) -> Self {
        Self {
            oauth2,
            verifier,
            end_session_endpoint,
        }
    }

    /// Begin a login: builds the authorization URL and generates the CSRF
    /// token, PKCE verifier, and `nonce`. Pure — no I/O.
    ///
    /// Persist [`csrf_token`](OidcLogin::csrf_token),
    /// [`pkce_verifier`](OidcLogin::pkce_verifier), and
    /// [`nonce`](OidcLogin::nonce) (e.g. in a signed cookie) until the callback,
    /// and redirect the user to [`url`](OidcLogin::url).
    pub fn start_login(&self) -> OidcLogin {
        let nonce = random_token();
        let login = self
            .oauth2
            .start_login_with(LoginOptions::new().param("nonce", &nonce));

        OidcLogin {
            url: login.url,
            csrf_token: login.csrf_token,
            pkce_verifier: login.pkce_verifier,
            nonce,
        }
    }

    /// Finish a login: exchange `code` for tokens and verify the ID token
    /// (signature, issuer, audience, expiry, and `nonce`).
    ///
    /// `pkce_verifier` and `nonce` are the values from the matching
    /// [`start_login`](Self::start_login), read back from wherever you
    /// persisted them.
    pub async fn finish_login(
        &self,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<OidcTokens, OidcError> {
        let tokens = self
            .oauth2
            .finish_login(code, pkce_verifier)
            .await
            .map_err(OidcError::Exchange)?;

        let id_token = tokens
            .extra_field::<String>("id_token")
            .ok_or(OidcError::NoIdToken)?;

        let verified = self
            .verifier
            .verify(&id_token, nonce)
            .await
            .map_err(OidcError::Verify)?;

        Ok(OidcTokens {
            id_token: verified,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
        })
    }

    /// Fetch and cache the provider's signing keys now, rather than lazily on
    /// the first login. Safe to call from a background [`tokio::spawn`] at
    /// startup; a no-op once the keys are cached.
    pub async fn warm_jwks(&self) -> Result<(), VerifyError> {
        self.verifier.warm().await
    }

    /// The configured client id.
    pub fn client_id(&self) -> &str {
        self.oauth2.client_id()
    }

    /// The redirect URL, if one was configured.
    pub fn redirect_url(&self) -> Option<&Url> {
        self.oauth2.redirect_url()
    }

    /// The requested scopes (always including `openid`).
    pub fn scopes(&self) -> &[String] {
        self.oauth2.scopes()
    }

    /// The provider's `end_session_endpoint`, if discovered or configured.
    pub fn end_session_endpoint(&self) -> Option<&Url> {
        self.end_session_endpoint.as_ref()
    }

    /// A [`LogoutUrl`] builder seeded with the end-session endpoint and this
    /// client's `client_id`, or `None` if no end-session endpoint is known.
    pub fn logout_url(&self) -> Option<LogoutUrl> {
        self.end_session_endpoint
            .as_ref()
            .map(|endpoint| LogoutUrl::new(endpoint.clone()).client_id(self.oauth2.client_id()))
    }
}

impl fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcClient")
            .field("oauth2", &self.oauth2)
            .field(
                "end_session_endpoint",
                &self.end_session_endpoint.as_ref().map(Url::as_str),
            )
            .finish_non_exhaustive()
    }
}

/// The first leg of an OpenID Connect login, created by
/// [`OidcClient::start_login`].
///
/// Redirect the user to [`url`](Self::url) and persist the rest until the
/// callback. All three secrets are redacted in `Debug`.
#[non_exhaustive]
pub struct OidcLogin {
    /// The authorization URL to redirect the user to.
    pub url: Url,
    /// The CSRF token in the URL's `state`. Compare against the callback's
    /// `state` query parameter — [`CsrfToken`]'s `==` is constant-time.
    pub csrf_token: CsrfToken,
    /// The PKCE verifier for the challenge in the URL.
    pub pkce_verifier: String,
    /// The `nonce` embedded in the authorization request; checked against the
    /// ID token in [`finish_login`](OidcClient::finish_login).
    pub nonce: String,
}

impl fmt::Debug for OidcLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The query carries `state` and `nonce`; the fields are secrets.
        let base = &self.url[..url::Position::AfterPath];
        f.debug_struct("OidcLogin")
            .field("url", &format_args!("{base}?[redacted]"))
            .field("csrf_token", &"[redacted]")
            .field("pkce_verifier", &"[redacted]")
            .field("nonce", &"[redacted]")
            .finish()
    }
}

/// The result of a successful login: the verified ID token plus the OAuth2
/// tokens. Created by [`OidcClient::finish_login`].
///
/// The access and refresh tokens are secrets; `Debug` redacts them.
pub struct OidcTokens {
    id_token: VerifiedIdToken,
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<Duration>,
}

impl OidcTokens {
    /// The verified ID token's claims (borrows the decoded payload).
    pub fn claims(&self) -> Result<OidcClaims<'_>, ClaimsError> {
        self.id_token.claims()
    }

    /// The raw ID token JWT (e.g. for an `id_token_hint` on logout).
    pub fn id_token(&self) -> &str {
        self.id_token.id_token()
    }

    /// The verified ID token.
    pub fn verified_id_token(&self) -> &VerifiedIdToken {
        &self.id_token
    }

    /// The access token.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The refresh token, if the provider issued one.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The access token's lifetime, if the provider sent `expires_in`.
    pub fn expires_in(&self) -> Option<Duration> {
        self.expires_in
    }
}

impl fmt::Debug for OidcTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcTokens")
            .field("id_token", &self.id_token)
            .field("access_token", &"[redacted]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[redacted]"),
            )
            .field("expires_in", &self.expires_in)
            .finish()
    }
}
