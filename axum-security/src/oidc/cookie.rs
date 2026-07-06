use std::borrow::Cow;

use cookie_monster::{Cookie, CookieJar};
use wincode::{SchemaRead, SchemaWrite};

use crate::{
    signed_cookie::{SignedCookie, SignedCookieBuilder},
    utils::utc_now_secs,
};

use super::OidcBuilderError;

#[derive(SchemaWrite, SchemaRead, Debug)]
pub struct OidcState<'a> {
    csrf_token: &'a str,
    pkce_verifier: &'a str,
    nonce: &'a str,
    provider_name: &'a str,
    issued: u64,
    expires: u64,
}

pub(crate) struct OidcCookie {
    inner: SignedCookie,
}

impl std::ops::Deref for OidcCookie {
    type Target = SignedCookie;
    fn deref(&self) -> &SignedCookie {
        &self.inner
    }
}

impl OidcCookie {
    pub fn generate_cookie(&self, csrf_token: &str, pkce_verifier: &str, nonce: &str) -> Cookie {
        let issued = utc_now_secs();
        let expires = issued + self.inner.max_login_duration_seconds;
        let provider_name = &self.inner.provider_name;

        let state = OidcState {
            csrf_token,
            pkce_verifier,
            nonce,
            provider_name,
            issued,
            expires,
        };

        let data = wincode::serialize(&state).expect("OidcState serialization cannot fail");
        self.inner.generate_cookie(&data)
    }

    /// Returns `(csrf_token, pkce_verifier, nonce)` as plain strings.
    pub fn verify_cookies(&self, jar: &mut CookieJar) -> Option<(String, String, String)> {
        let payload = self.inner.decode_and_verify(jar)?;

        let now = utc_now_secs();
        let data = wincode::deserialize::<OidcState>(&payload).ok()?;

        if now < data.issued {
            return None;
        }

        if now > data.expires {
            return None;
        }

        Some((
            data.csrf_token.into(),
            data.pkce_verifier.into(),
            data.nonce.into(),
        ))
    }
}

pub(crate) struct OidcCookieBuilder {
    inner: SignedCookieBuilder,
}

impl OidcCookieBuilder {
    pub fn new(provider_name: Cow<'static, str>) -> Self {
        Self {
            inner: SignedCookieBuilder::new(provider_name, "oidc.session."),
        }
    }

    pub fn set_max_login_duration_secs(&mut self, max_login_duration_seconds: u64) {
        self.inner
            .set_max_login_duration_secs(max_login_duration_seconds);
    }

    pub fn try_build(self) -> Result<OidcCookie, OidcBuilderError> {
        self.inner
            .try_build(OidcBuilderError::WhitespaceInProviderName)
            .map(|inner| OidcCookie { inner })
    }
}

impl std::ops::Deref for OidcCookieBuilder {
    type Target = SignedCookieBuilder;
    fn deref(&self) -> &SignedCookieBuilder {
        &self.inner
    }
}

impl std::ops::DerefMut for OidcCookieBuilder {
    fn deref_mut(&mut self) -> &mut SignedCookieBuilder {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use cookie_monster::CookieJar;

    use crate::utils::utc_now_secs;

    fn make_handler(secret: Option<Vec<u8>>) -> OidcCookie {
        let mut builder = OidcCookieBuilder::new("test".into());
        builder.cookie_builder.dev = true;
        if let Some(s) = secret {
            builder.secret = Some(s);
        }
        builder.try_build().unwrap()
    }

    fn make_jar(cookie: cookie_monster::Cookie) -> CookieJar {
        let mut jar = CookieJar::new();
        jar.add(cookie);
        jar
    }

    fn build_cookie_value(handler: &OidcCookie, state: &OidcState<'_>) -> String {
        let data = wincode::serialize(state).unwrap();
        handler.inner.sign_and_encode(&data)
    }

    #[test]
    fn round_trip() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", "pkce_verifier", "test_nonce");
        let mut jar = make_jar(cookie);

        let (csrf, pkce, nonce) = handler.verify_cookies(&mut jar).unwrap();
        assert_eq!(csrf, "csrf_token");
        assert_eq!(pkce, "pkce_verifier");
        assert_eq!(nonce, "test_nonce");
    }

    #[test]
    fn cookie_is_consumed_on_verify() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf", "pkce", "nonce");
        let mut jar = make_jar(cookie);

        assert!(handler.verify_cookies(&mut jar).is_some());
        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn missing_cookie_returns_none() {
        let handler = make_handler(None);
        let mut jar = CookieJar::new();
        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn invalid_base64_returns_error() {
        let handler = make_handler(None);
        let bad = handler
            .cookie_builder
            .clone()
            .value("not!valid!base64!@#")
            .build();
        let mut jar = make_jar(bad);
        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn wrong_hmac_signature_is_rejected() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", "pkce_verifier", "nonce");
        let value = cookie.value().to_string();

        let mut decoded = BASE64_STANDARD.decode(&value).unwrap();
        let len = decoded.len();
        decoded[len - 32..].fill(0);
        let tampered = BASE64_STANDARD.encode(decoded);

        let bad = handler.cookie_builder.clone().value(tampered).build();
        let mut jar = make_jar(bad);
        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn different_secret_rejects_cookie() {
        let handler1 = make_handler(Some(b"secret_aaa_32_bytes_exactly_____".to_vec()));
        let handler2 = make_handler(Some(b"secret_bbb_32_bytes_exactly_____".to_vec()));

        let cookie = handler1.generate_cookie("csrf", "pkce", "nonce");
        let mut jar = make_jar(cookie);
        assert!(handler2.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn expired_cookie_returns_none() {
        let handler = make_handler(Some(vec![0u8; 32]));
        let now = utc_now_secs();

        let state = OidcState {
            csrf_token: "csrf_token",
            pkce_verifier: "pkce_verifier",
            nonce: "nonce",
            provider_name: "test",
            issued: now - 100,
            expires: now - 1,
        };
        let value = build_cookie_value(&handler, &state);
        let cookie = handler.cookie_builder.clone().value(value).build();
        let mut jar = make_jar(cookie);

        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn future_issued_time_returns_none() {
        let handler = make_handler(Some(vec![0u8; 32]));
        let now = utc_now_secs();

        let state = OidcState {
            csrf_token: "csrf_token",
            pkce_verifier: "pkce_verifier",
            nonce: "nonce",
            provider_name: "test",
            issued: now + 1000,
            expires: now + 2000,
        };
        let value = build_cookie_value(&handler, &state);
        let cookie = handler.cookie_builder.clone().value(value).build();
        let mut jar = make_jar(cookie);

        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn provider_name_with_whitespace_is_rejected() {
        assert!(
            OidcCookieBuilder::new("provider with spaces".into())
                .try_build()
                .is_err()
        );
    }
}
