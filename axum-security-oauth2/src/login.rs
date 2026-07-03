use std::fmt;

use url::{Position, Url};

use crate::secret::{CsrfToken, PkceVerifier};

/// The first leg of the authorization code flow, created by
/// [`start_login`](crate::OAuth2Client::start_login).
///
/// Redirect the user to [`url`](Login::url) and persist
/// [`csrf_token`](Login::csrf_token) (and the PKCE verifier when present)
/// until the callback comes in.
pub struct Login {
    pub(crate) url: Url,
    pub(crate) csrf_token: CsrfToken,
    pub(crate) pkce_verifier: Option<PkceVerifier>,
}

impl Login {
    /// The authorization URL to redirect the user to.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The CSRF token embedded in the URL's `state` parameter. Compare it
    /// against the `state` query parameter on the callback.
    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    /// The PKCE verifier belonging to the challenge in the URL; `None`
    /// when PKCE is disabled on the client.
    pub fn pkce_verifier(&self) -> Option<&PkceVerifier> {
        self.pkce_verifier.as_ref()
    }

    /// Splits the login into its parts, for consumers that scatter them
    /// (secrets into a cookie, URL into a redirect) without cloning.
    pub fn into_parts(self) -> (Url, CsrfToken, Option<PkceVerifier>) {
        (self.url, self.csrf_token, self.pkce_verifier)
    }
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The query holds the `state` secret — print the URL without it.
        let base = &self.url[..Position::AfterPath];
        f.debug_struct("Login")
            .field("url", &format_args!("{base}?[redacted]"))
            .field("csrf_token", &self.csrf_token)
            .field("pkce_verifier", &self.pkce_verifier)
            .finish()
    }
}
