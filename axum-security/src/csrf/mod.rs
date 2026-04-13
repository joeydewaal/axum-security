//! CSRF (Cross-Site Request Forgery) protection middleware.
//!
//! This module provides [`CsrfLayer`], a Tower middleware that protects against CSRF
//! attacks using the double-submit cookie pattern with HMAC-signed tokens.
//!
//! On every request, the middleware sets a signed CSRF token cookie. For state-changing
//! methods (`POST`, `PUT`, `PATCH`, `DELETE`), it verifies the token by comparing the
//! cookie value against a token submitted via the `X-Csrf-Token` header or a `_csrf`
//! form field. Requests that fail validation receive a `403 Forbidden` response.
//!
//! Use [`CsrfToken`] in handlers to get the current token for embedding in forms or
//! JavaScript fetch calls.
//!
//! # Example
//!
//! ```rust
//! use axum::{Router, response::Html, routing::{get, post}};
//! use axum_security::csrf::{CsrfLayer, CsrfToken};
//!
//! async fn form(csrf: CsrfToken) -> Html<String> {
//!     Html(format!(
//!         r#"<form method="POST" action="/submit">
//!             <input type="hidden" name="_csrf" value="{csrf}" />
//!             <button type="submit">Send</button>
//!         </form>"#
//!     ))
//! }
//!
//! async fn submit() -> &'static str {
//!     "OK"
//! }
//!
//! let csrf = CsrfLayer::builder()
//!     .secret("change-me-to-a-real-secret")
//!     .build();
//!
//! let app = Router::<()>::new()
//!     .route("/", get(form))
//!     .route("/submit", post(submit))
//!     .layer(csrf);
//! ```

mod service;

use std::{borrow::Cow, sync::Arc};

use axum::{
    extract::FromRequestParts,
    http::{HeaderName, StatusCode, request::Parts},
};
use cookie_monster::{Cookie, CookieBuilder, SameSite};
use hmac::{Hmac, KeyInit};
use sha2::Sha256;

use crate::cookie_options::CookieOptionsBuilder;

pub use service::CsrfService;

const DEFAULT_COOKIE_NAME: &str = "csrf-token";
const DEFAULT_HEADER_NAME: HeaderName = HeaderName::from_static("x-csrf-token");
const DEFAULT_FORM_FIELD: Cow<'static, str> = Cow::Borrowed("_csrf");
const TOKEN_BYTE_LEN: usize = 32;

/// Tower [`Layer`](tower::Layer) that adds CSRF protection.
///
/// Construct one with [`CsrfLayer::builder`]. See the [module docs](self) for a full example.
#[derive(Clone)]
pub struct CsrfLayer {
    inner: Arc<CsrfConfig>,
}

pub(crate) struct CsrfConfig {
    pub(crate) secret: Hmac<Sha256>,
    pub(crate) cookie_name: Cow<'static, str>,
    pub(crate) header_name: HeaderName,
    pub(crate) form_field: Cow<'static, str>,
    pub(crate) cookie_builder: CookieBuilder,
}

impl CsrfLayer {
    /// Create a [`CsrfLayerBuilder`].
    pub fn builder() -> CsrfLayerBuilder {
        CsrfLayerBuilder::new()
    }
}

impl<S> tower::Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            config: self.inner.clone(),
        }
    }
}

/// Builder for [`CsrfLayer`].
///
/// At minimum, call [`secret`](CsrfLayerBuilder::secret) to set the HMAC signing key.
/// If no secret is provided, a random one is generated (tokens won't survive restarts).
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
            form_field: DEFAULT_FORM_FIELD,
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

    /// Set the HMAC-SHA256 signing key for tokens.
    pub fn secret(mut self, secret: impl AsRef<[u8]>) -> Self {
        self.secret = Some(secret.as_ref().to_vec());
        self
    }

    /// Set the cookie name. Defaults to `"csrf-token"`.
    pub fn cookie_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        let name = name.into();
        self.cookie_opts.dev_cookie.set_name(name.clone());
        self.cookie_opts.cookie.set_name(name);
        self
    }

    /// Set the header name clients use to submit the token. Defaults to `x-csrf-token`.
    pub fn header_name(mut self, name: HeaderName) -> Self {
        self.header_name = name;
        self
    }

    /// Set the form field name for token submission. Defaults to `"_csrf"`.
    pub fn form_field(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.form_field = name.into();
        self
    }

    /// When `true`, use a relaxed cookie (no `Secure`, `SameSite=Lax`) for `localhost` development.
    pub fn use_dev_cookie(mut self, dev: bool) -> Self {
        self.cookie_opts.dev = dev;
        self
    }

    /// Customize the production cookie via a closure.
    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts.cookie = f(self.cookie_opts.cookie);
        self
    }

    /// Customize the development cookie via a closure.
    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts.dev_cookie = f(self.cookie_opts.dev_cookie);
        self
    }

    /// Build the [`CsrfLayer`]. Generates a random secret if none was provided.
    pub fn build(self) -> CsrfLayer {
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

        CsrfLayer {
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
    /// Return the token as a string slice.
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
