use std::borrow::Cow;

use cookie_monster::{Cookie, CookieBuilder, CookieJar};

pub struct AfterLoginCookies<'a> {
    pub(crate) cookie_jar: CookieJar,
    pub(crate) cookie_opts: &'a CookieBuilder,
}

impl AfterLoginCookies<'_> {
    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.cookie_opts.clone().name(name)
    }

    pub fn remove(&mut self, name: impl Into<Cow<'static, str>>) -> Option<Cookie> {
        let cookie = self.cookie(name);
        self.cookie_jar.remove(cookie)
    }

    pub fn add(&mut self, cookie: impl Into<Cookie>) {
        self.cookie_jar.add(cookie.into());
    }
}
