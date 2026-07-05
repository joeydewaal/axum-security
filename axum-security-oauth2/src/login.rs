use std::fmt;

use url::{Position, Url};

use crate::csrf::CsrfToken;

/// The first leg of the authorization code flow, created by
/// [`start_login`](crate::OAuth2Client::start_login).
///
/// Redirect the user to [`url`](Login::url) and persist
/// [`csrf_token`](Login::csrf_token) and
/// [`pkce_verifier`](Login::pkce_verifier) until the callback comes in.
/// Both are secrets; `Debug` redacts them.
///
/// Only [`start_login`](crate::OAuth2Client::start_login) constructs this;
/// it is `#[non_exhaustive]` so it cannot be built outside the crate.
#[non_exhaustive]
pub struct Login {
    /// The authorization URL to redirect the user to.
    pub url: Url,
    /// The CSRF token embedded in the URL's `state` parameter. Compare it
    /// against the `state` query parameter on the callback; [`CsrfToken`]'s
    /// `==` does this in constant time, since an attacker controls one side
    /// of the comparison.
    pub csrf_token: CsrfToken,
    /// The PKCE verifier belonging to the challenge in the URL.
    pub pkce_verifier: String,
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
///
/// Only [`start_login_non_pkce`](crate::OAuth2Client::start_login_non_pkce)
/// constructs this; it is `#[non_exhaustive]` so it cannot be built outside
/// the crate.
#[non_exhaustive]
pub struct LoginNonPkce {
    /// The authorization URL to redirect the user to.
    pub url: Url,
    /// The CSRF token embedded in the URL's `state` parameter. Compare it
    /// against the `state` query parameter on the callback; [`CsrfToken`]'s
    /// `==` does this in constant time, since an attacker controls one side
    /// of the comparison.
    pub csrf_token: CsrfToken,
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
