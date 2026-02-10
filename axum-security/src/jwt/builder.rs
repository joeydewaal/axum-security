use std::{borrow::Cow, error::Error, fmt::Display, marker::PhantomData, sync::Arc};

use axum::http::{HeaderName, header::AUTHORIZATION};
#[cfg(feature = "cookie")]
use cookie_monster::CookieBuilder;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};

#[cfg(feature = "cookie")]
use crate::cookie::CookieSessionBuilder;
use crate::{
    jwt::{ExtractFrom, JwtContext, JwtContextInner},
    utils::get_env,
};

static PREFIX_BEARER: &str = "Bearer ";
static PREFIX_NONE: &str = "";

pub struct JwtContextBuilder {
    encoding_key: Option<EncodingKey>,
    decoding_key: Option<DecodingKey>,
    jwt_header: Header,
    validation: Validation,
    extract: ExtractFromBuilder,
}

impl Default for JwtContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtContextBuilder {
    pub fn new() -> Self {
        JwtContextBuilder {
            encoding_key: None,
            decoding_key: None,
            jwt_header: Header::default(),
            validation: Validation::default(),
            extract: ExtractFromBuilder::header_with_prefix(AUTHORIZATION, PREFIX_BEARER),
        }
    }

    pub fn encoding_key(mut self, encoding_key: EncodingKey) -> Self {
        self.encoding_key = Some(encoding_key);
        self
    }

    pub fn decoding_key(mut self, decoding_key: DecodingKey) -> Self {
        self.decoding_key = Some(decoding_key);
        self
    }

    pub fn jwt_secret(self, jwt_secret: impl AsRef<[u8]>) -> Self {
        let jwt_secret = jwt_secret.as_ref();
        self.encoding_key(EncodingKey::from_secret(jwt_secret))
            .decoding_key(DecodingKey::from_secret(jwt_secret))
    }

    pub fn jwt_secret_env(self, name: &str) -> Self {
        self.jwt_secret(get_env(name))
    }

    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = validation;
        self
    }

    pub fn jwt_header(mut self, header: Header) -> Self {
        self.jwt_header = header;
        self
    }

    pub fn extract_header_with_prefix(
        mut self,
        header: impl AsRef<[u8]>,
        prefix: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.extract = ExtractFromBuilder::header_with_prefix(
            HeaderName::from_bytes(header.as_ref())
                .expect("header value contains invalid characters"),
            prefix.into(),
        );
        self
    }

    pub fn extract_header(mut self, header: impl AsRef<str>) -> Self {
        self.extract = ExtractFromBuilder::header_with_prefix(
            HeaderName::from_bytes(header.as_ref().as_bytes())
                .expect("header value contains invalid characters"),
            PREFIX_NONE,
        );
        self
    }

    #[cfg(feature = "cookie")]
    pub fn extract_cookie(mut self, cookie_name: impl Into<Cow<'static, str>>) -> Self {
        self.extract = ExtractFromBuilder::cookie(cookie_name.into());
        self
    }

    #[cfg(feature = "cookie")]
    pub fn use_dev_cookie(mut self, dev_mode: bool) -> Self {
        self.extract = self.extract.with_cookie(|mut c| {
            c.dev = dev_mode;
            c
        });
        self
    }

    #[cfg(feature = "cookie")]
    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.extract = self.extract.with_cookie(|c| c.cookie(f));
        self
    }

    #[cfg(feature = "cookie")]
    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.extract = self.extract.with_cookie(|c| c.dev_cookie(f));
        self
    }

    pub fn try_build<T>(self) -> Result<JwtContext<T>, JwtBuilderError> {
        let encoding_key = self
            .encoding_key
            .ok_or(JwtBuilderError::EncodingKeyMissing)?;

        let decoding_key = self
            .decoding_key
            .ok_or(JwtBuilderError::DecodingKeyMissing)?;

        let extract = self.extract.into_extract();

        Ok(JwtContext(Arc::new(JwtContextInner {
            encoding_key,
            decoding_key,
            jwt_header: self.jwt_header,
            validation: self.validation,
            extract,
            data: PhantomData,
        })))
    }

    pub fn build<T>(self) -> JwtContext<T> {
        self.try_build().unwrap()
    }
}

#[derive(Debug)]
pub enum JwtBuilderError {
    EncodingKeyMissing,
    DecodingKeyMissing,
}

impl Display for JwtBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtBuilderError::EncodingKeyMissing => f.write_str("Encoding key is missing"),
            JwtBuilderError::DecodingKeyMissing => f.write_str("Decoding key is missing"),
        }
    }
}

impl Error for JwtBuilderError {}

pub(crate) enum ExtractFromBuilder {
    #[cfg(feature = "cookie")]
    Cookie(Box<CookieSessionBuilder<()>>),
    Header {
        header: HeaderName,
        prefix: Cow<'static, str>,
    },
}

impl ExtractFromBuilder {
    #[cfg(feature = "cookie")]
    fn cookie(name: Cow<'static, str>) -> Self {
        let mut builder = CookieSessionBuilder::new();
        builder.cookie = builder.cookie.name(name.clone());
        builder.dev_cookie = builder.dev_cookie.name(name.clone());
        ExtractFromBuilder::Cookie(builder.into())
    }

    fn into_extract(self) -> ExtractFrom {
        match self {
            #[cfg(feature = "cookie")]
            ExtractFromBuilder::Cookie(cookie_session_builder) => {
                if cookie_session_builder.dev {
                    ExtractFrom::Cookie(cookie_session_builder.dev_cookie.into())
                } else {
                    ExtractFrom::Cookie(cookie_session_builder.cookie.into())
                }
            }
            ExtractFromBuilder::Header { header, prefix } => ExtractFrom::Header { header, prefix },
        }
    }

    #[cfg(feature = "cookie")]
    fn with_cookie(
        self,
        f: impl FnOnce(CookieSessionBuilder<()>) -> CookieSessionBuilder<()>,
    ) -> Self {
        match self {
            ExtractFromBuilder::Cookie(cookie) => ExtractFromBuilder::Cookie(f(*cookie).into()),
            this => this,
        }
    }

    fn header_with_prefix(header: HeaderName, prefix: impl Into<Cow<'static, str>>) -> Self {
        ExtractFromBuilder::Header {
            header,
            prefix: prefix.into(),
        }
    }
}

#[cfg(test)]
mod jwt_builder {
    use crate::jwt::{DecodingKey, EncodingKey, JwtBuilderError, JwtContext};

    #[test]
    fn encoding_key_missing() {
        let result = JwtContext::builder()
            .decoding_key(DecodingKey::from_secret(b"test"))
            .try_build::<()>();

        assert!(matches!(result, Err(JwtBuilderError::EncodingKeyMissing)));
    }

    #[test]
    fn decoding_key_missing() {
        let result = JwtContext::builder()
            .encoding_key(EncodingKey::from_secret(b"test"))
            .try_build::<()>();

        assert!(matches!(result, Err(JwtBuilderError::DecodingKeyMissing)));
    }
}
