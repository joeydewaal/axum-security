use std::borrow::Cow;

use cookie_monster::Cookie;
use cookie_monster::CookieJar;
use wincode::{SchemaRead, SchemaWrite};

use crate::{
    oauth2::OAuth2BuilderError,
    signed_cookie::{SignedCookie, SignedCookieBuilder},
    utils::utc_now_secs,
};

#[derive(SchemaWrite, SchemaRead, Debug)]
pub struct OAuthState<'a> {
    csrf_token: &'a str,
    pkce_verifier: Option<&'a str>,
    provider_name: &'a str,
    issued: u64,
    expires: u64,
}

pub(crate) struct OAuth2Cookie {
    inner: SignedCookie,
}

impl std::ops::Deref for OAuth2Cookie {
    type Target = SignedCookie;
    fn deref(&self) -> &SignedCookie {
        &self.inner
    }
}

impl OAuth2Cookie {
    pub fn generate_cookie(&self, csrf_token: &str, pkce_verifier: Option<&str>) -> Cookie {
        let issued = utc_now_secs();
        let expires = issued + self.inner.max_login_duration_seconds;
        let provider_name = &self.inner.provider_name;

        let state = OAuthState {
            csrf_token,
            pkce_verifier,
            provider_name,
            issued,
            expires,
        };

        let data = wincode::serialize(&state).expect("OAuthState serialization cannot fail");
        self.inner.generate_cookie(&data)
    }

    pub fn verify_cookies(&self, jar: &mut CookieJar) -> Option<(String, Option<String>)> {
        let payload = self.inner.decode_and_verify(jar)?;

        let now = utc_now_secs();
        let data = wincode::deserialize::<OAuthState>(&payload).ok()?;

        if now < data.issued {
            return None;
        }

        if now > data.expires {
            return None;
        }

        Some((
            data.csrf_token.to_string(),
            data.pkce_verifier.map(String::from),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, prelude::BASE64_STANDARD};
    use cookie_monster::CookieJar;

    use crate::utils::utc_now_secs;

    fn make_handler(secret: Option<Vec<u8>>) -> OAuth2Cookie {
        let mut builder = OAuthCookieBuilder::new("test".into());
        builder.inner.cookie_builder.dev = true;
        if let Some(s) = secret {
            builder.inner.secret = Some(s);
        }
        builder.try_build().unwrap()
    }

    fn make_jar(cookie: cookie_monster::Cookie) -> CookieJar {
        let mut jar = CookieJar::new();
        jar.add(cookie);
        jar
    }

    fn build_cookie_value(handler: &OAuth2Cookie, state: &OAuthState<'_>) -> String {
        let data = wincode::serialize(state).unwrap();
        handler.inner.sign_and_encode(&data)
    }

    #[test]
    fn round_trip_with_pkce() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", Some("pkce_verifier"));
        let mut jar = make_jar(cookie);

        let (csrf, pkce) = handler.verify_cookies(&mut jar).unwrap();
        assert_eq!(csrf, "csrf_token");
        assert_eq!(pkce.as_deref(), Some("pkce_verifier"));
    }

    #[test]
    fn round_trip_without_pkce() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", None);
        let mut jar = make_jar(cookie);

        let (csrf, pkce) = handler.verify_cookies(&mut jar).unwrap();
        assert_eq!(csrf, "csrf_token");
        assert!(pkce.is_none());
    }

    #[test]
    fn cookie_is_consumed_on_verify() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf", Some("pkce"));
        let mut jar = make_jar(cookie);

        assert!(handler.verify_cookies(&mut jar).is_some());
        // Second call on the same jar should find no cookie.
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
    fn no_hmac_appended_returns_error() {
        // Valid serialized state with no HMAC bytes appended must be rejected.
        let handler = make_handler(None);
        let now = utc_now_secs();
        let state = OAuthState {
            csrf_token: "csrf_token",
            pkce_verifier: Some("pkce_verifier"),
            provider_name: "test",
            issued: now,
            expires: now + 3600,
        };
        let data = wincode::serialize(&state).unwrap();
        // No signature appended — the HMAC check should catch this.
        let encoded = BASE64_STANDARD.encode(&data);
        let bad = handler.cookie_builder.clone().value(encoded).build();
        let mut jar = make_jar(bad);
        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn hmac_one_byte_short_returns_error() {
        use hmac::Mac;

        let handler = make_handler(Some(vec![0u8; 32]));
        let now = utc_now_secs();
        let state = OAuthState {
            csrf_token: "csrf_token",
            pkce_verifier: Some("pkce_verifier"),
            provider_name: "test",
            issued: now,
            expires: now + 3600,
        };
        let mut data = wincode::serialize(&state).unwrap();
        let mut hmac = handler.secret.clone();
        hmac.update(&data);
        let full_signature = hmac.finalize().into_bytes();
        // Append one byte fewer than required.
        data.extend_from_slice(&full_signature[..31]);
        let encoded = BASE64_STANDARD.encode(&data);
        let bad = handler.cookie_builder.clone().value(encoded).build();
        let mut jar = make_jar(bad);
        assert!(handler.verify_cookies(&mut jar).is_none());
    }

    #[test]
    fn wrong_hmac_signature_is_rejected() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", Some("pkce_verifier"));
        let value = cookie.value().to_string();

        let mut decoded = BASE64_STANDARD.decode(&value).unwrap();
        let len = decoded.len();
        decoded[len - 32..].fill(0);
        let tampered = BASE64_STANDARD.encode(decoded);

        let bad = handler.cookie_builder.clone().value(tampered).build();
        let mut jar = make_jar(bad);
        assert!(
            handler.verify_cookies(&mut jar).is_none(),
            "cookie with zeroed HMAC should be rejected"
        );
    }

    #[test]
    fn different_secret_rejects_cookie() {
        let handler1 = make_handler(Some(b"secret_aaa_32_bytes_exactly_____".to_vec()));
        let handler2 = make_handler(Some(b"secret_bbb_32_bytes_exactly_____".to_vec()));

        let cookie = handler1.generate_cookie("csrf", Some("pkce"));
        let mut jar = make_jar(cookie);
        assert!(
            handler2.verify_cookies(&mut jar).is_none(),
            "cookie signed with a different secret should be rejected"
        );
    }

    #[test]
    fn expired_cookie_returns_none() {
        let handler = make_handler(Some(vec![0u8; 32]));
        let now = utc_now_secs();

        let state = OAuthState {
            csrf_token: "csrf_token",
            pkce_verifier: None,
            provider_name: "test",
            issued: now - 100,
            expires: now - 1, // already past
        };
        let value = build_cookie_value(&handler, &state);
        let cookie = handler.cookie_builder.clone().value(value).build();
        let mut jar = make_jar(cookie);

        assert!(
            handler.verify_cookies(&mut jar).is_none(),
            "expired cookie should return None"
        );
    }

    #[test]
    fn future_issued_time_returns_none() {
        let handler = make_handler(Some(vec![0u8; 32]));
        let now = utc_now_secs();

        let state = OAuthState {
            csrf_token: "csrf_token",
            pkce_verifier: None,
            provider_name: "test",
            issued: now + 1000,
            expires: now + 2000,
        };
        let value = build_cookie_value(&handler, &state);
        let cookie = handler.cookie_builder.clone().value(value).build();
        let mut jar = make_jar(cookie);

        assert!(
            handler.verify_cookies(&mut jar).is_none(),
            "cookie with a future issued time should return None"
        );
    }

    #[test]
    fn provider_name_with_whitespace_is_rejected() {
        assert!(
            OAuthCookieBuilder::new("provider with spaces".into())
                .try_build()
                .is_err()
        );
    }
}

pub(crate) struct OAuthCookieBuilder {
    inner: SignedCookieBuilder,
}

impl OAuthCookieBuilder {
    pub fn new(provider_name: Cow<'static, str>) -> Self {
        Self {
            inner: SignedCookieBuilder::new(provider_name, "oauth2.session."),
        }
    }

    pub fn set_max_login_duration_secs(&mut self, max_login_duration_seconds: u64) {
        self.inner
            .set_max_login_duration_secs(max_login_duration_seconds);
    }

    pub fn try_build(self) -> Result<OAuth2Cookie, OAuth2BuilderError> {
        self.inner
            .try_build(OAuth2BuilderError::WhitespaceInProviderName)
            .map(|inner| OAuth2Cookie { inner })
    }
}

impl std::ops::Deref for OAuthCookieBuilder {
    type Target = SignedCookieBuilder;
    fn deref(&self) -> &SignedCookieBuilder {
        &self.inner
    }
}

impl std::ops::DerefMut for OAuthCookieBuilder {
    fn deref_mut(&mut self) -> &mut SignedCookieBuilder {
        &mut self.inner
    }
}
