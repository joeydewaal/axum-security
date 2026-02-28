use std::borrow::Cow;

use base64::{Engine, prelude::BASE64_STANDARD};
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};
use hmac::{Hmac, Mac};
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier};
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use wincode::{SchemaRead, SchemaWrite};

use crate::{cookie::CookieOptionsBuilder, utils::utc_now_secs};

use super::OidcBuilderError;

const HMAC_HASH_LEN: usize = 32;

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
    provider_name: Cow<'static, str>,
    pub(crate) secret: Hmac<Sha256>,
    pub(crate) cookie_builder: CookieBuilder,
    max_login_duration_seconds: u64,
}

impl OidcCookie {
    pub fn generate_cookie(&self, csrf_token: &str, pkce_verifier: &str, nonce: &str) -> Cookie {
        let issued = utc_now_secs();
        let expires = issued + self.max_login_duration_seconds;
        let provider_name = &self.provider_name;

        let state = OidcState {
            csrf_token,
            pkce_verifier,
            nonce,
            provider_name,
            issued,
            expires,
        };

        let mut data = wincode::serialize(&state).expect("OidcState serialization cannot fail");

        let mut hmac = self.secret.clone();
        hmac.update(&data);
        let signature = hmac.finalize().into_bytes();

        data.extend_from_slice(&signature);

        let encoded_data = BASE64_STANDARD.encode(data);

        self.cookie_builder.clone().value(encoded_data).build()
    }

    pub fn verify_cookies(
        &self,
        jar: &mut CookieJar,
    ) -> Option<(CsrfToken, PkceCodeVerifier, Nonce)> {
        let cookie = jar.remove(self.cookie_builder.clone())?;

        let now = utc_now_secs();

        let decoded = BASE64_STANDARD.decode(cookie.value()).ok()?;
        let data = self.verify_signature(&decoded)?;

        let data = wincode::deserialize::<OidcState>(data).ok()?;

        if now < data.issued {
            return None;
        }

        if now > data.expires {
            return None;
        }

        Some((
            CsrfToken::new(data.csrf_token.into()),
            PkceCodeVerifier::new(data.pkce_verifier.into()),
            Nonce::new(data.nonce.into()),
        ))
    }

    fn verify_signature<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        if data.len() < HMAC_HASH_LEN {
            return None;
        }

        let (payload, received_signature) = data.split_at(data.len() - HMAC_HASH_LEN);

        let mut hmac = self.secret.clone();
        hmac.update(payload);
        let signature = hmac.finalize().into_bytes();

        if received_signature.ct_ne(&signature[..]).into() {
            None
        } else {
            Some(payload)
        }
    }
}

pub(crate) struct OidcCookieBuilder {
    provider_name: Cow<'static, str>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) cookie_builder: CookieOptionsBuilder,
    max_login_duration_seconds: u64,
}

impl OidcCookieBuilder {
    pub fn new(provider_name: Cow<'static, str>) -> Self {
        let cookie_name = format!("oidc.session.{provider_name}");

        // 30 minutes
        let max_login_duration_seconds = 30 * 60;

        let dev_cookie = Cookie::named(cookie_name.clone())
            .path("/")
            .same_site(SameSite::Lax)
            .max_age_secs(max_login_duration_seconds);

        let cookie = Cookie::named(cookie_name)
            .http_only()
            .same_site(SameSite::Strict)
            .secure()
            .max_age_secs(max_login_duration_seconds);

        Self {
            provider_name,
            secret: None,
            cookie_builder: CookieOptionsBuilder {
                dev: false,
                dev_cookie,
                cookie,
            },
            max_login_duration_seconds,
        }
    }

    pub fn set_max_login_duration_secs(&mut self, max_login_duration_seconds: u64) {
        self.cookie_builder
            .set_max_age_secs(max_login_duration_seconds);
    }

    pub fn try_build(self) -> Result<OidcCookie, OidcBuilderError> {
        if self
            .provider_name
            .find(|c: char| c.is_whitespace())
            .is_some()
        {
            return Err(OidcBuilderError::WhitespaceInProviderName);
        }

        let secret = if let Some(secret) = self.secret {
            secret
        } else {
            let mut secret = [0u8; 32];
            rand::rng().fill_bytes(&mut secret);
            secret.to_vec()
        };

        let secret = Hmac::new_from_slice(&secret).expect("Hmac accepts any secret length");

        let cookie_builder = self.cookie_builder.build();

        Ok(OidcCookie {
            provider_name: self.provider_name,
            secret,
            cookie_builder,
            max_login_duration_seconds: self.max_login_duration_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut data = wincode::serialize(state).unwrap();
        let mut hmac = handler.secret.clone();
        hmac.update(&data);
        let signature = hmac.finalize().into_bytes();
        data.extend_from_slice(&signature);
        BASE64_STANDARD.encode(data)
    }

    #[test]
    fn round_trip() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", "pkce_verifier", "test_nonce");
        let mut jar = make_jar(cookie);

        let (csrf, pkce, nonce) = handler.verify_cookies(&mut jar).unwrap();
        assert_eq!(csrf.secret(), "csrf_token");
        assert_eq!(pkce.secret(), "pkce_verifier");
        assert_eq!(nonce.secret(), "test_nonce");
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
        decoded[len - HMAC_HASH_LEN..].fill(0);
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
