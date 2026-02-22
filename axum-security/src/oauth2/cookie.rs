use std::borrow::Cow;
use subtle::ConstantTimeEq;

use base64::{Engine, prelude::BASE64_STANDARD};
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};
use hmac::{Hmac, Mac};
use oauth2::{CsrfToken, PkceCodeVerifier};
use rand::Rng;
use sha2::Sha256;
use wincode::{SchemaRead, SchemaWrite};

use crate::{cookie::CookieOptionsBuilder, oauth2::OAuth2BuilderError, utils::utc_now_secs};

const HMAC_HASH_LEN: usize = 32;

#[derive(SchemaWrite, SchemaRead, Debug)]
pub struct OAuthState<'a> {
    csrf_token: &'a str,
    pkce_verifier: Option<&'a str>,
    provider_name: &'a str,
    issued: u64,
    expires: u64,
}

pub(crate) struct OAuth2Cookie {
    provider_name: Cow<'static, str>,
    pub(crate) secret: Hmac<Sha256>,
    pub(crate) cookie_builder: CookieBuilder,
    max_login_duration_seconds: u64,
}

impl OAuth2Cookie {
    pub fn generate_cookie(&self, csrf_token: &str, pkce_verifier: Option<&str>) -> Cookie {
        let issued = utc_now_secs();
        let expires = issued + self.max_login_duration_seconds;
        let provider_name = &self.provider_name;

        let state = OAuthState {
            csrf_token,
            pkce_verifier,
            provider_name,
            issued,
            expires,
        };

        let mut data = wincode::serialize(&state).unwrap();

        // get the signature
        let mut hmac = self.secret.clone();
        hmac.update(&data);
        let signature = hmac.finalize().into_bytes();

        // put the signature at the end of the payload
        data.extend_from_slice(&signature);

        // encode the payload
        let encoded_data = BASE64_STANDARD.encode(data);

        self.cookie_builder.clone().value(encoded_data).build()
    }

    pub fn verify_cookies(
        &self,
        jar: &mut CookieJar,
    ) -> Result<Option<(CsrfToken, Option<PkceCodeVerifier>)>, ()> {
        let Some(cookie) = jar.remove(self.cookie_builder.clone()) else {
            // cookie not found
            return Ok(None);
        };

        let now = utc_now_secs();

        let Ok(decoded) = BASE64_STANDARD.decode(cookie.value()) else {
            // not valid base64
            return Err(());
        };

        let Some(data) = self.verify_signature(&decoded) else {
            return Err(());
        };

        // deserialize into the state struct.
        let Ok(data) = wincode::deserialize::<OAuthState>(&data) else {
            // could not deserialize state.
            return Err(());
        };

        if now < data.issued {
            // went back in time?
            return Ok(None);
        }

        if now > data.expires {
            // expired
            return Ok(None);
        }

        Ok(Some((
            CsrfToken::new(data.csrf_token.into()),
            data.pkce_verifier.map(|v| PkceCodeVerifier::new(v.into())),
        )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use cookie_monster::CookieJar;

    use crate::utils::utc_now_secs;

    fn make_handler(secret: Option<Vec<u8>>) -> OAuth2Cookie {
        let mut builder = OAuthCookieBuilder::new("test".into());
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

    fn build_cookie_value(handler: &OAuth2Cookie, state: &OAuthState<'_>) -> String {
        let mut data = wincode::serialize(state).unwrap();
        let mut hmac = handler.secret.clone();
        hmac.update(&data);
        let signature = hmac.finalize().into_bytes();
        data.extend_from_slice(&signature);
        BASE64_STANDARD.encode(data)
    }

    #[test]
    fn round_trip_with_pkce() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", Some("pkce_verifier"));
        let mut jar = make_jar(cookie);

        let (csrf, pkce) = handler.verify_cookies(&mut jar).unwrap().unwrap();
        assert_eq!(csrf.secret(), "csrf_token");
        assert_eq!(pkce.unwrap().secret(), "pkce_verifier");
    }

    #[test]
    fn round_trip_without_pkce() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", None);
        let mut jar = make_jar(cookie);

        let (csrf, pkce) = handler.verify_cookies(&mut jar).unwrap().unwrap();
        assert_eq!(csrf.secret(), "csrf_token");
        assert!(pkce.is_none());
    }

    #[test]
    fn cookie_is_consumed_on_verify() {
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf", Some("pkce"));
        let mut jar = make_jar(cookie);

        assert!(handler.verify_cookies(&mut jar).unwrap().is_some());
        // Second call on the same jar should find no cookie.
        assert!(handler.verify_cookies(&mut jar).unwrap().is_none());
    }

    #[test]
    fn missing_cookie_returns_none() {
        let handler = make_handler(None);
        let mut jar = CookieJar::new();
        assert!(handler.verify_cookies(&mut jar).unwrap().is_none());
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
        assert!(handler.verify_cookies(&mut jar).is_err());
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
        assert!(handler.verify_cookies(&mut jar).is_err());
    }

    #[test]
    fn hmac_one_byte_short_returns_error() {
        // Valid serialized state with only HMAC_HASH_LEN-1 bytes of HMAC
        // appended must be rejected.
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
        data.extend_from_slice(&full_signature[..HMAC_HASH_LEN - 1]);
        let encoded = BASE64_STANDARD.encode(&data);
        let bad = handler.cookie_builder.clone().value(encoded).build();
        let mut jar = make_jar(bad);
        assert!(handler.verify_cookies(&mut jar).is_err());
    }

    #[test]
    fn wrong_hmac_signature_is_rejected() {
        // Zeroing the appended HMAC bytes must cause verification to fail.
        let handler = make_handler(None);
        let cookie = handler.generate_cookie("csrf_token", Some("pkce_verifier"));
        let value = cookie.value().to_string();

        let mut decoded = BASE64_STANDARD.decode(&value).unwrap();
        let len = decoded.len();
        decoded[len - HMAC_HASH_LEN..].fill(0);
        let tampered = BASE64_STANDARD.encode(decoded);

        let bad = handler.cookie_builder.clone().value(tampered).build();
        let mut jar = make_jar(bad);
        assert!(
            handler.verify_cookies(&mut jar).is_err(),
            "cookie with zeroed HMAC should be rejected"
        );
    }

    #[test]
    fn different_secret_rejects_cookie() {
        // A cookie signed by one secret must not be accepted by a handler using
        // a different secret.
        let handler1 = make_handler(Some(b"secret_aaa_32_bytes_exactly_____".to_vec()));
        let handler2 = make_handler(Some(b"secret_bbb_32_bytes_exactly_____".to_vec()));

        let cookie = handler1.generate_cookie("csrf", Some("pkce"));
        let mut jar = make_jar(cookie);
        assert!(
            handler2.verify_cookies(&mut jar).is_err(),
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
            handler.verify_cookies(&mut jar).unwrap().is_none(),
            "expired cookie should return None"
        );
    }

    #[test]
    fn future_issued_time_returns_none() {
        // `issued` in the future means the server clock went backwards or the
        // cookie was tampered with; both cases should be rejected.
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
            handler.verify_cookies(&mut jar).unwrap().is_none(),
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
    provider_name: Cow<'static, str>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) cookie_builder: CookieOptionsBuilder,
    max_login_duration_seconds: u64,
}

impl OAuthCookieBuilder {
    pub fn new(provider_name: Cow<'static, str>) -> Self {
        let cookie_name = format!("oauth2.session.{provider_name}");

        // 30 minutes
        let max_login_duration_seconds = 30 * 60 * 60;

        // Make sure to use "/" as path so all paths can see the cookie in dev mode.
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

    pub fn try_build(self) -> Result<OAuth2Cookie, OAuth2BuilderError> {
        if self
            .provider_name
            .find(|c: char| c.is_whitespace())
            .is_some()
        {
            return Err(OAuth2BuilderError::WhitespaceInProviderName);
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

        Ok(OAuth2Cookie {
            provider_name: self.provider_name,
            secret,
            cookie_builder,
            max_login_duration_seconds: self.max_login_duration_seconds,
        })
    }
}
