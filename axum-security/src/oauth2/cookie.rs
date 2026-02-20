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

        let data = &data[..(data.len() - HMAC_HASH_LEN)];
        let received_signature = &data[(data.len() - HMAC_HASH_LEN)..];

        let mut hmac = self.secret.clone();

        hmac.update(&data);
        let signature = hmac.finalize().into_bytes();

        if received_signature.ct_ne(&signature[..]).into() {
            Some(data)
        } else {
            None
        }
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
