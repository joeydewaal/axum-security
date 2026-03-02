use cookie_monster::CookieBuilder;
#[cfg(any(feature = "cookie", feature = "oauth2", feature = "oidc"))]
use cookie_monster::{Cookie, SameSite};

pub(crate) struct CookieOptionsBuilder {
    pub(crate) dev: bool,
    pub(crate) dev_cookie: CookieBuilder,
    pub(crate) cookie: CookieBuilder,
}

impl CookieOptionsBuilder {
    #[cfg(feature = "cookie")]
    pub fn new() -> Self {
        Self {
            dev: false,
            // Make sure to use "/" as path so all paths can see the cookie in dev mode.
            dev_cookie: Cookie::named("dev-session")
                .same_site(SameSite::Lax)
                .max_age(std::time::Duration::from_hours(24)),
            cookie: Cookie::named("session")
                .same_site(SameSite::Strict)
                .http_only()
                .secure(),
        }
    }

    #[cfg(feature = "jwt")]
    pub(crate) fn set_name(&mut self, name: std::borrow::Cow<'static, str>) {
        self.dev_cookie.set_name(name.clone());
        self.cookie.set_name(name);
    }

    #[cfg(any(feature = "oauth2", feature = "oidc"))]
    pub(crate) fn set_max_age_secs(&mut self, duration: u64) {
        self.cookie.set_max_age_secs(duration);
        self.dev_cookie.set_max_age_secs(duration);
    }

    pub(crate) fn build(self) -> CookieBuilder {
        if self.dev {
            self.dev_cookie
        } else {
            self.cookie
        }
    }

    #[cfg(any(feature = "oauth2", feature = "oidc"))]
    pub(crate) fn apply_cookie(&mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) {
        let cookie = std::mem::replace(&mut self.cookie, Cookie::named(""));
        self.cookie = f(cookie);
    }

    #[cfg(any(feature = "oauth2", feature = "oidc"))]
    pub(crate) fn apply_dev_cookie(&mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) {
        let dev_cookie = std::mem::replace(&mut self.dev_cookie, Cookie::named(""));
        self.dev_cookie = f(dev_cookie);
    }
}
