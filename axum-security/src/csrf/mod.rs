mod service;

use std::{borrow::Cow, sync::Arc};

use axum::{
    extract::FromRequestParts,
    http::{HeaderName, StatusCode, request::Parts},
};
use cookie_monster::{Cookie, CookieBuilder, SameSite};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::cookie_options::CookieOptionsBuilder;

pub use service::CsrfService;

const DEFAULT_COOKIE_NAME: &str = "csrf-token";
const DEFAULT_HEADER_NAME: HeaderName = HeaderName::from_static("x-csrf-token");
const DEFAULT_FORM_FIELD: &str = "_csrf";
const TOKEN_BYTE_LEN: usize = 32;

#[derive(Clone)]
pub struct Csrf {
    inner: Arc<CsrfConfig>,
}

pub(crate) struct CsrfConfig {
    pub(crate) secret: Hmac<Sha256>,
    pub(crate) cookie_name: Cow<'static, str>,
    pub(crate) header_name: HeaderName,
    pub(crate) form_field: Cow<'static, str>,
    pub(crate) cookie_builder: CookieBuilder,
}

impl Csrf {
    pub fn builder() -> CsrfLayerBuilder {
        CsrfLayerBuilder::new()
    }
}

impl<S> tower::Layer<S> for Csrf {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            config: self.inner.clone(),
        }
    }
}

pub struct CsrfLayerBuilder {
    secret: Option<Vec<u8>>,
    header_name: HeaderName,
    form_field: Cow<'static, str>,
    cookie_opts: CookieOptionsBuilder,
}

impl CsrfLayerBuilder {
    fn new() -> Self {
        Self {
            secret: None,
            header_name: DEFAULT_HEADER_NAME,
            form_field: DEFAULT_FORM_FIELD.into(),
            cookie_opts: CookieOptionsBuilder {
                dev: false,
                dev_cookie: Cookie::named(DEFAULT_COOKIE_NAME)
                    .path("/")
                    .same_site(SameSite::Lax),
                cookie: Cookie::named(DEFAULT_COOKIE_NAME)
                    .path("/")
                    .same_site(SameSite::Strict)
                    .http_only()
                    .secure(),
            },
        }
    }

    pub fn secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.secret = Some(secret.as_ref().to_vec());
        self
    }

    pub fn cookie_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        let name = name.into();
        self.cookie_opts.dev_cookie.set_name(name.clone());
        self.cookie_opts.cookie.set_name(name);
        self
    }

    pub fn header_name(mut self, name: HeaderName) -> Self {
        self.header_name = name;
        self
    }

    pub fn form_field(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.form_field = name.into();
        self
    }

    pub fn use_dev_cookie(mut self, dev: bool) -> Self {
        self.cookie_opts.dev = dev;
        self
    }

    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts.cookie = f(self.cookie_opts.cookie);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts.dev_cookie = f(self.cookie_opts.dev_cookie);
        self
    }

    pub fn build(self) -> Csrf {
        let secret_bytes = if let Some(s) = self.secret {
            s
        } else {
            let mut buf = [0u8; 32];
            rand::Rng::fill_bytes(&mut rand::rng(), &mut buf);
            buf.to_vec()
        };

        let secret =
            Hmac::<Sha256>::new_from_slice(&secret_bytes).expect("HMAC accepts any key length");

        let cookie_builder = self.cookie_opts.build();
        let cookie_name = Cow::from(cookie_builder.get_name().to_owned());

        Csrf {
            inner: Arc::new(CsrfConfig {
                secret,
                cookie_name,
                header_name: self.header_name,
                form_field: self.form_field,
                cookie_builder,
            }),
        }
    }
}

/// Extractor that gives handlers access to the current CSRF token for embedding in forms/meta tags.
#[derive(Clone)]
pub struct CsrfToken(pub(crate) Arc<str>);

impl CsrfToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CsrfToken {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CsrfToken>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
