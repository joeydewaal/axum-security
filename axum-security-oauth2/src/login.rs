use std::fmt;

use url::{Position, Url};

/// The first leg of the authorization code flow, created by
/// [`start_login`](crate::OAuth2Client::start_login).
///
/// Redirect the user to [`url`](Login::url) and persist
/// [`csrf_token`](Login::csrf_token) and
/// [`pkce_verifier`](Login::pkce_verifier) until the callback comes in.
/// Both are secrets; `Debug` redacts them.
pub struct Login {
    pub(crate) url: Url,
    pub(crate) csrf_token: String,
    pub(crate) pkce_verifier: String,
}

impl Login {
    /// The authorization URL to redirect the user to.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The CSRF token embedded in the URL's `state` parameter. Compare it
    /// against the `state` query parameter on the callback — in constant
    /// time, since an attacker controls one side of the comparison.
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// The PKCE verifier belonging to the challenge in the URL.
    pub fn pkce_verifier(&self) -> &str {
        &self.pkce_verifier
    }

    /// Splits the login into its parts — `(url, csrf_token,
    /// pkce_verifier)` — for consumers that scatter them (secrets into a
    /// cookie, URL into a redirect) without cloning.
    pub fn into_parts(self) -> (Url, String, String) {
        (self.url, self.csrf_token, self.pkce_verifier)
    }
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The query holds the `state` secret — print the URL without it.
        let base = &self.url[..Position::AfterPath];
        f.debug_struct("Login")
            .field("url", &format_args!("{base}?[redacted]"))
            .field("csrf_token", &"[redacted]")
            .field("pkce_verifier", &"[redacted]")
            .finish()
    }
}

/// The first leg of the authorization code flow without PKCE, created by
/// [`start_login_non_pkce`](crate::OAuth2Client::start_login_non_pkce).
///
/// Redirect the user to [`url`](LoginNonPkce::url) and persist
/// [`csrf_token`](LoginNonPkce::csrf_token) until the callback comes in.
/// The token is a secret; `Debug` redacts it.
pub struct LoginNonPkce {
    pub(crate) url: Url,
    pub(crate) csrf_token: String,
}

impl LoginNonPkce {
    /// The authorization URL to redirect the user to.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The CSRF token embedded in the URL's `state` parameter. Compare it
    /// against the `state` query parameter on the callback — in constant
    /// time, since an attacker controls one side of the comparison.
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// Splits the login into its parts — `(url, csrf_token)` — for
    /// consumers that scatter them (secret into a cookie, URL into a
    /// redirect) without cloning.
    pub fn into_parts(self) -> (Url, String) {
        (self.url, self.csrf_token)
    }
}

impl fmt::Debug for LoginNonPkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The query holds the `state` secret — print the URL without it.
        let base = &self.url[..Position::AfterPath];
        f.debug_struct("LoginNonPkce")
            .field("url", &format_args!("{base}?[redacted]"))
            .field("csrf_token", &"[redacted]")
            .finish()
    }
}
