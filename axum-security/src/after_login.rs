use std::borrow::Cow;

use cookie_monster::{Cookie, CookieBuilder, CookieJar};

/// Helper for setting cookies in [`OAuth2Handler`](crate::oauth2::OAuth2Handler) and
/// [`OidcHandler`](crate::oidc::OidcHandler) callbacks.
///
/// Provides methods to add and remove cookies that inherit the provider's cookie settings.
pub struct AfterLoginCookies<'a> {
    pub(crate) cookie_jar: CookieJar,
    pub(crate) cookie_opts: &'a CookieBuilder,
}

impl AfterLoginCookies<'_> {
    /// Create a cookie builder that inherits the provider's cookie settings.
    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.cookie_opts.clone().name(name)
    }

    /// Remove a cookie by name from the jar.
    pub fn remove(&mut self, name: impl Into<Cow<'static, str>>) -> Option<Cookie> {
        let cookie = self.cookie(name);
        self.cookie_jar.remove(cookie)
    }

    /// Add a cookie to the response.
    pub fn add(&mut self, cookie: impl Into<Cookie>) {
        self.cookie_jar.add(cookie.into());
    }
}
