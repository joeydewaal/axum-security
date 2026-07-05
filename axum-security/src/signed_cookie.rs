use std::borrow::Cow;

use base64::{Engine, prelude::BASE64_STANDARD};
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::cookie_options::CookieOptionsBuilder;

const HMAC_HASH_LEN: usize = 32;

pub(crate) struct SignedCookie {
    pub(crate) provider_name: Cow<'static, str>,
    pub(crate) secret: Hmac<Sha256>,
    pub(crate) cookie_builder: CookieBuilder,
    pub(crate) max_login_duration_seconds: u64,
}

impl SignedCookie {
    pub fn sign_and_encode(&self, data: &[u8]) -> String {
        let mut hmac = self.secret.clone();
        hmac.update(data);
        let signature = hmac.finalize().into_bytes();

        let mut payload = data.to_vec();
        payload.extend_from_slice(&signature);
        BASE64_STANDARD.encode(payload)
    }

    pub fn generate_cookie(&self, data: &[u8]) -> Cookie {
        let encoded = self.sign_and_encode(data);
        self.cookie_builder.clone().value(encoded).build()
    }

    pub fn decode_and_verify(&self, jar: &mut CookieJar) -> Option<Vec<u8>> {
        let cookie = jar.remove(self.cookie_builder.clone())?;
        let decoded = BASE64_STANDARD.decode(cookie.value()).ok()?;
        let payload = self.verify_signature(&decoded)?;
        Some(payload.to_vec())
    }

    pub fn verify_signature<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
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

pub(crate) struct SignedCookieBuilder {
    pub(crate) provider_name: Cow<'static, str>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) cookie_builder: CookieOptionsBuilder,
    pub(crate) max_login_duration_seconds: u64,
}

impl SignedCookieBuilder {
    pub fn new(provider_name: Cow<'static, str>, cookie_prefix: &str) -> Self {
        let cookie_name = format!("{cookie_prefix}{provider_name}");

        // 30 minutes
        let max_login_duration_seconds = 30 * 60;

        let dev_cookie = Cookie::named(cookie_name.clone())
            .path("/")
            .same_site(SameSite::Lax)
            .max_age_secs(max_login_duration_seconds);

        // `Cookie::host` applies the `__Host-` prefix and sets `Secure` +
        // `Path=/` (the prefix's requirements). SameSite is `Lax`, not
        // `Strict`: the OAuth callback is a cross-site top-level navigation
        // from the provider, and `Strict` would withhold the cookie there,
        // breaking state validation.
        let cookie = Cookie::host(cookie_name, "")
            .http_only()
            .same_site(SameSite::Lax)
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

    pub fn try_build<E>(self, whitespace_error: E) -> Result<SignedCookie, E> {
        if self
            .provider_name
            .find(|c: char| c.is_whitespace())
            .is_some()
        {
            return Err(whitespace_error);
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

        Ok(SignedCookie {
            provider_name: self.provider_name,
            secret,
            cookie_builder,
            max_login_duration_seconds: self.max_login_duration_seconds,
        })
    }
}
