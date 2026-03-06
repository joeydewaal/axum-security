//! Security headers middleware.
//!
//! This module provides Tower layers that add security-related HTTP response headers.
//! Headers can be applied individually as layers or combined with [`SecurityHeaders`].
//!
//! # Available headers
//!
//! | Type | Header |
//! |------|--------|
//! | [`ContentSecurityPolicy`] | `Content-Security-Policy` |
//! | [`StrictTransportSecurity`] | `Strict-Transport-Security` |
//! | [`CrossOriginEmbedderPolicy`] | `Cross-Origin-Embedder-Policy` |
//! | [`CrossOriginOpenerPolicy`] | `Cross-Origin-Opener-Policy` |
//! | [`CrossOriginResourcePolicy`] | `Cross-Origin-Resource-Policy` |
//! | [`OriginAgentCluster`] | `Origin-Agent-Cluster` |
//! | [`ReferrerPolicy`] | `Referrer-Policy` |
//! | [`ContentTypeOptions`] | `X-Content-Type-Options` |
//! | [`DnsPrefetchControl`] | `X-DNS-Prefetch-Control` |
//! | [`FrameOptions`] | `X-Frame-Options` |
//! | [`XssProtection`] | `X-XSS-Protection` |
//!
//! Each header type implements [`Layer`](tower::Layer), so it can be applied directly
//! to a router. It also implements [`IntoSecurityHeader`], so it can be added to a
//! [`SecurityHeaders`] bundle.
//!
//! # Examples
//!
//! Apply a single header as a layer:
//!
//! ```rust
//! use axum::Router;
//! use axum_security::headers::CrossOriginOpenerPolicy;
//!
//! let app = Router::<()>::new()
//!     .layer(CrossOriginOpenerPolicy::SAME_ORIGIN);
//! ```
//!
//! Bundle multiple headers with [`SecurityHeaders`]:
//!
//! ```rust
//! use axum::Router;
//! use axum_security::headers::SecurityHeaders;
//!
//! let app = Router::<()>::new()
//!     .layer(SecurityHeaders::recommended());
//! ```
//!
//! Build a Content-Security-Policy:
//!
//! ```rust
//! use axum::Router;
//! use axum_security::headers::{ContentSecurityPolicy, CspSource};
//!
//! let csp = ContentSecurityPolicy::builder()
//!     .default_src(CspSource::SELF)
//!     .script_src([CspSource::SELF, CspSource::host("https://cdn.example.com")])
//!     .upgrade_insecure_requests()
//!     .build();
//!
//! let app = Router::<()>::new().layer(csp);
//! ```

mod csp;
mod hsts;
mod service;

use std::{borrow::Borrow, collections::HashSet, hash::Hash, sync::Arc};

pub use csp::{ContentSecurityPolicy, CspBuilder, CspSource};
pub use hsts::{StrictTransportSecurity, StrictTransportSecurityBuilderError};
use http::{HeaderName, HeaderValue};

#[macro_export]
macro_rules! define_header {
    (
        $struct_name:ident($header_name:ident = $header_value:literal),
        $($const_name:ident => $value:literal),+ $(,)?
    ) => {
        const $header_name: ::http::HeaderName = ::http::HeaderName::from_static($header_value);


        #[derive(Clone)]
        pub struct $struct_name {
            header_value: ::http::HeaderValue,
        }

        impl $struct_name {
            $(
                pub const $const_name: $struct_name = Self {
                    header_value: ::http::HeaderValue::from_static($value),
                };
            )+
        }

        impl<S> tower::Layer<S> for $struct_name {
            type Service = $crate::utils::headers::InsertHeadersService<S>;

            fn layer(&self, inner: S) -> Self::Service {
                $crate::utils::headers::InsertHeadersService {
                    header_name: $header_name,
                    header_value: self.header_value.clone(),
                    inner,
                }
            }
        }

        impl IntoSecurityHeader for $struct_name {
            fn into_header(self) -> (HeaderName, HeaderValue) {
                ($header_name, self.header_value)
            }
        }
    };
}

define_header!(
    CrossOriginEmbedderPolicy(CROSS_ORIGIN_EMBEDDER_POLICY = "cross-origin-embedder-policy"),
    UNSAFE_NONE => "unsafe-none",
    REQUIRE_CORP => "require-corp",
    CREDENTIALLESS => "credentialless",
);

define_header!(
    CrossOriginOpenerPolicy(CROSS_ORIGIN_OPENER_POLICY = "cross-origin-opener-policy"),
    UNSAFE_NONE => "unsafe-none",
    SAME_ORIGIN_ALLOW_POPUPS => "same-origin-allow-popups",
    SAME_ORIGIN => "same-origin",
    NOOPENER_ALLOW_POPUPS => "noopener-allow-popups"
);

define_header!(
    CrossOriginResourcePolicy(CROSS_ORIGIN_RESOURCE_POLICY = "cross-origin-resource-policy"),
    SAME_SITE => "same-site",
    SAME_ORIGIN => "same-origin",
    CROSS_ORIGIN => "cross-origin",
);

define_header!(
    OriginAgentCluster(ORIGIN_AGENT_CLUSTER = "origin-agent-cluster"),
    ON => "?1",
    OFF => "?0",
);

define_header!(
    ReferrerPolicy(REFERRER_POLICY = "referrer-policy"),
    NO_REFERRER => "no-referrer",
    NO_REFERRER_WHEN_DOWNGRADE => "no-referrer-when-downgrade",
    ORIGIN => "origin",
    ORIGIN_WHEN_CROSS_ORIGIN => "origin-when-cross-origin",
    SAME_ORIGIN => "same-origin",
    STRICT_ORIGIN => "strict-origin",
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN => "strict-origin-when-cross-origin",
    UNSAFE_URL => "unsafe-url",
);

define_header!(
    ContentTypeOptions(X_CONTENT_TYPE_OPTIONS = "x-content-type-options"),
    NO_SNIFF => "nosniff"
);

define_header!(
    DnsPrefetchControl(X_DNS_PREFETCH_CONTROL = "x-dns-prefetch-control"),
    ON => "on",
    OFF => "off",
);

define_header!(
    FrameOptions(X_FRAME_OPTIONS= "x-frame-options"),
    DENY => "DENY",
    SAMEORIGIN => "SAMEORIGIN",
);

define_header!(
    XssProtection(X_XSS_PROTECTION= "x-xss-protection"),
    ZERO => "0",
);

#[derive(Clone, Eq)]
struct SecurityHeader {
    name: HeaderName,
    value: HeaderValue,
}

/// Converts a header type into a `(HeaderName, HeaderValue)` pair.
///
/// All header types in this module implement this trait, allowing them to be
/// passed to [`SecurityHeaders::add`] and [`SecurityHeaders::try_add`].
pub trait IntoSecurityHeader {
    fn into_header(self) -> (HeaderName, HeaderValue);
}

impl Hash for SecurityHeader {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl PartialEq for SecurityHeader {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Borrow<HeaderName> for SecurityHeader {
    fn borrow(&self) -> &HeaderName {
        &self.name
    }
}

impl From<(HeaderName, HeaderValue)> for SecurityHeader {
    fn from(value: (HeaderName, HeaderValue)) -> Self {
        Self {
            name: value.0,
            value: value.1,
        }
    }
}

/// A bundle of security headers applied as a single Tower [`Layer`](tower::Layer).
///
/// Use [`SecurityHeaders::recommended`] for a sensible default set, or build a
/// custom set with [`SecurityHeaders::new`] and [`add`](SecurityHeaders::add).
///
/// Call [`use_dev_headers(true)`](SecurityHeaders::use_dev_headers) in development
/// to skip all headers (e.g. HSTS) that interfere with `localhost` workflows.
///
/// # Example
///
/// ```rust
/// use axum::Router;
/// use axum_security::headers::{SecurityHeaders, XssProtection};
///
/// let headers = SecurityHeaders::recommended()
///     .add(XssProtection::ZERO);
///
/// let app = Router::<()>::new().layer(headers);
/// ```
#[derive(Clone)]
pub struct SecurityHeaders {
    headers: Arc<HashSet<SecurityHeader>>,
    dev: bool,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityHeaders {
    /// Create an empty `SecurityHeaders` set.
    pub fn new() -> Self {
        Self {
            headers: HashSet::new().into(),
            dev: false,
        }
    }

    /// Create a `SecurityHeaders` set with sensible defaults.
    ///
    /// Includes: `Cross-Origin-Opener-Policy: same-origin`,
    /// `Cross-Origin-Resource-Policy: same-origin`, `Origin-Agent-Cluster: ?1`,
    /// `Referrer-Policy: no-referrer`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
    /// `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `X-XSS-Protection: 0`.
    pub fn recommended() -> Self {
        Self::new()
            .add(CrossOriginOpenerPolicy::SAME_ORIGIN)
            .add(CrossOriginResourcePolicy::SAME_ORIGIN)
            .add(OriginAgentCluster::ON)
            .add(ReferrerPolicy::NO_REFERRER)
            .add(
                StrictTransportSecurity::builder()
                    .max_age_years(1)
                    .include_subdomains(),
            )
            .add(ContentTypeOptions::NO_SNIFF)
            .add(FrameOptions::SAMEORIGIN)
            .add(XssProtection::ZERO)
    }

    /// When `true`, clears all headers so nothing is added to responses.
    ///
    /// Use this in development to avoid HSTS and other headers that interfere
    /// with `localhost` or plain HTTP.
    pub fn use_dev_headers(mut self, dev_headers: bool) -> Self {
        self.dev = dev_headers;
        Arc::make_mut(&mut self.headers).clear();
        self
    }

    /// Add a header, replacing any existing header with the same name.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, header: impl IntoSecurityHeader) -> Self {
        if !self.dev {
            Arc::make_mut(&mut self.headers).replace(header.into_header().into());
        }
        self
    }

    /// Add a header only if no header with that name exists yet.
    pub fn try_add(mut self, header: impl IntoSecurityHeader) -> Self {
        if !self.dev {
            Arc::make_mut(&mut self.headers).insert(header.into_header().into());
        }
        self
    }
}

#[cfg(test)]
mod header_tests {
    use std::collections::HashSet;

    use http::HeaderValue;

    use crate::headers::{
        CROSS_ORIGIN_OPENER_POLICY, CrossOriginOpenerPolicy, SecurityHeader, SecurityHeaders,
        X_XSS_PROTECTION,
    };

    #[test]
    fn sec_header() {
        let mut map = HashSet::new();
        map.insert(SecurityHeader {
            name: X_XSS_PROTECTION,
            value: HeaderValue::from_static("1"),
        });

        let removed = map.remove(&SecurityHeader {
            name: X_XSS_PROTECTION,
            value: HeaderValue::from_static("2"),
        });

        assert!(removed);
    }

    #[test]
    fn sec_headers() {
        let headers = SecurityHeaders::new().add(CrossOriginOpenerPolicy::SAME_ORIGIN);
        let header = headers.headers.get(&CROSS_ORIGIN_OPENER_POLICY).unwrap();
        assert!(header.value == CrossOriginOpenerPolicy::SAME_ORIGIN.header_value);

        let headers = headers.add(CrossOriginOpenerPolicy::UNSAFE_NONE);
        let header = headers.headers.get(&CROSS_ORIGIN_OPENER_POLICY).unwrap();
        assert!(header.value == CrossOriginOpenerPolicy::UNSAFE_NONE.header_value);

        let headers = headers.try_add(CrossOriginOpenerPolicy::SAME_ORIGIN);
        let header = headers.headers.get(&CROSS_ORIGIN_OPENER_POLICY).unwrap();
        assert!(header.value == CrossOriginOpenerPolicy::UNSAFE_NONE.header_value);
    }
}
