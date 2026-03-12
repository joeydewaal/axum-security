use std::borrow::Cow;
#[cfg(feature = "csp-nonce")]
use std::sync::Arc;

use http::{HeaderName, HeaderValue};
use tower::Layer;

#[cfg(feature = "csp-nonce")]
use super::nonce::{CspTemplate, NonceCspService};
use crate::{headers::IntoSecurityHeader, utils::headers::InsertHeadersService};

const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");

/// Sentinel used in nonce templates, replaced at request time.
#[cfg(feature = "csp-nonce")]
pub(crate) const NONCE_SENTINEL: &str = "\x00NONCE\x00";

/// `Content-Security-Policy` header.
///
/// Build one with [`ContentSecurityPolicy::builder`]. The result implements
/// [`Layer`] (for standalone use) and [`IntoSecurityHeader`](super::IntoSecurityHeader)
/// (for use with [`SecurityHeaders`](super::SecurityHeaders)).
///
/// # Example
///
/// ```rust
/// use axum_security::headers::{ContentSecurityPolicy, CspSource};
///
/// let csp = ContentSecurityPolicy::builder()
///     .default_src(CspSource::SELF)
///     .script_src([CspSource::SELF, CspSource::host("https://cdn.example.com")])
///     .upgrade_insecure_requests()
///     .build();
/// ```
#[derive(Clone)]
pub struct ContentSecurityPolicy {
    inner: CspInner,
}

#[derive(Clone)]
enum CspInner {
    Static(HeaderValue),
    #[cfg(feature = "csp-nonce")]
    Nonce(Arc<CspTemplate>),
}

impl ContentSecurityPolicy {
    /// Create a [`CspBuilder`] to construct a Content-Security-Policy header.
    pub fn builder() -> CspBuilder {
        CspBuilder {
            directives: Vec::new(),
        }
    }
}

/// Builder for [`ContentSecurityPolicy`].
///
/// Add directives with methods like [`default_src`](CspBuilder::default_src),
/// [`script_src`](CspBuilder::script_src), etc., then call [`build`](CspBuilder::build).
pub struct CspBuilder {
    directives: Vec<(Cow<'static, str>, Vec<CspSource>)>,
}

/// A CSP source expression.
///
/// Use the provided constants ([`SELF`](CspSource::SELF), [`NONE`](CspSource::NONE), etc.)
/// or construct one with [`host`](CspSource::host) / [`scheme`](CspSource::scheme).
///
/// Pass a single source directly or wrap multiple sources in an array:
///
/// ```rust
/// use axum_security::headers::{ContentSecurityPolicy, CspSource};
///
/// let csp = ContentSecurityPolicy::builder()
///     .default_src(CspSource::NONE) // single source
///     .script_src([CspSource::SELF, CspSource::host("https://cdn.example.com")]) // multiple
///     .build();
/// ```
pub struct CspSource(CspSourceInner);

#[derive(Clone)]
enum CspSourceInner {
    None,
    Self_,
    UnsafeInline,
    UnsafeEval,
    StrictDynamic,
    #[cfg(feature = "csp-nonce")]
    Nonce,
    Host(Cow<'static, str>),
    Scheme(Cow<'static, str>),
}

impl CspSource {
    pub const NONE: CspSource = CspSource(CspSourceInner::None);
    pub const SELF: CspSource = CspSource(CspSourceInner::Self_);
    pub const UNSAFE_INLINE: CspSource = CspSource(CspSourceInner::UnsafeInline);
    pub const UNSAFE_EVAL: CspSource = CspSource(CspSourceInner::UnsafeEval);
    pub const STRICT_DYNAMIC: CspSource = CspSource(CspSourceInner::StrictDynamic);

    #[cfg(feature = "csp-nonce")]
    pub const NONCE: CspSource = CspSource(CspSourceInner::Nonce);

    pub fn host(host: impl Into<Cow<'static, str>>) -> Self {
        Self(CspSourceInner::Host(host.into()))
    }

    pub fn scheme(scheme: impl Into<Cow<'static, str>>) -> Self {
        Self(CspSourceInner::Scheme(scheme.into()))
    }

    fn serialize(&self) -> Cow<'static, str> {
        match &self.0 {
            CspSourceInner::None => "'none'".into(),
            CspSourceInner::Self_ => "'self'".into(),
            CspSourceInner::UnsafeInline => "'unsafe-inline'".into(),
            CspSourceInner::UnsafeEval => "'unsafe-eval'".into(),
            CspSourceInner::StrictDynamic => "'strict-dynamic'".into(),
            #[cfg(feature = "csp-nonce")]
            CspSourceInner::Nonce => NONCE_SENTINEL.into(),
            CspSourceInner::Host(h) => h.clone(),
            CspSourceInner::Scheme(s) => s.clone(),
        }
    }
}

impl From<CspSource> for Vec<CspSource> {
    fn from(source: CspSource) -> Self {
        vec![source]
    }
}

impl CspBuilder {
    pub(crate) fn directive(
        mut self,
        name: impl Into<Cow<'static, str>>,
        sources: impl Into<Vec<CspSource>>,
    ) -> Self {
        self.directives.push((name.into(), sources.into()));
        self
    }

    pub fn default_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("default-src", sources)
    }

    pub fn script_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("script-src", sources)
    }

    pub fn style_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("style-src", sources)
    }

    pub fn img_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("img-src", sources)
    }

    pub fn font_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("font-src", sources)
    }

    pub fn connect_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("connect-src", sources)
    }

    pub fn frame_src(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("frame-src", sources)
    }

    pub fn frame_ancestors(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("frame-ancestors", sources)
    }

    pub fn base_uri(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("base-uri", sources)
    }

    pub fn form_action(self, sources: impl Into<Vec<CspSource>>) -> Self {
        self.directive("form-action", sources)
    }

    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.directives
            .push(("upgrade-insecure-requests".into(), Vec::new()));
        self
    }

    fn serialize_directives(&self) -> String {
        let mut buff = String::new();

        for (i, (name, sources)) in self.directives.iter().enumerate() {
            if i != 0 {
                buff.push_str("; ");
            }
            buff.push_str(name);

            if !sources.is_empty() {
                for s in sources {
                    buff.push(' ');
                    buff.push_str(&s.serialize());
                }
            }
        }

        buff
    }

    #[cfg(feature = "csp-nonce")]
    fn has_nonce(&self) -> bool {
        self.directives
            .iter()
            .any(|(_, sources)| sources.iter().any(|s| matches!(s.0, CspSourceInner::Nonce)))
    }

    pub fn build(self) -> ContentSecurityPolicy {
        #[cfg(feature = "csp-nonce")]
        assert!(
            !self.has_nonce(),
            "CspSource::NONCE requires `.build_nonce()` instead of `.build()`"
        );

        let buff = self.serialize_directives();
        let header_value =
            HeaderValue::from_str(&buff).expect("CSP header does not contain invalid bytes");

        ContentSecurityPolicy {
            inner: CspInner::Static(header_value),
        }
    }

    /// Build a `ContentSecurityPolicy` that generates a fresh nonce per request.
    ///
    /// Every occurrence of [`CspSource::NONCE`] is replaced with a random
    /// `'nonce-<base64>'` value. The nonce is also available to handlers via
    /// the [`CspNonce`](super::CspNonce) extractor.
    ///
    /// # Panics
    ///
    /// Panics if no directive contains `CspSource::NONCE`.
    #[cfg(feature = "csp-nonce")]
    pub fn build_nonce(self) -> ContentSecurityPolicy {
        assert!(
            self.has_nonce(),
            "build_nonce() called but no directive uses CspSource::NONCE"
        );

        let template = self.serialize_directives();
        ContentSecurityPolicy {
            inner: CspInner::Nonce(Arc::new(CspTemplate::new(template))),
        }
    }
}

impl<S> Layer<S> for ContentSecurityPolicy {
    #[cfg(not(feature = "csp-nonce"))]
    type Service = InsertHeadersService<S>;

    #[cfg(feature = "csp-nonce")]
    type Service = CspService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        match &self.inner {
            CspInner::Static(hv) => {
                let svc = InsertHeadersService {
                    inner,
                    header_name: CONTENT_SECURITY_POLICY,
                    header_value: hv.clone(),
                };
                #[cfg(not(feature = "csp-nonce"))]
                {
                    svc
                }
                #[cfg(feature = "csp-nonce")]
                {
                    CspService::Static(svc)
                }
            }
            #[cfg(feature = "csp-nonce")]
            CspInner::Nonce(template) => CspService::Nonce(NonceCspService {
                inner,
                template: template.clone(),
            }),
        }
    }
}

impl IntoSecurityHeader for ContentSecurityPolicy {
    fn into_header(self) -> (HeaderName, HeaderValue) {
        match self.inner {
            CspInner::Static(hv) => (CONTENT_SECURITY_POLICY, hv),
            #[cfg(feature = "csp-nonce")]
            CspInner::Nonce(_) => {
                panic!("nonce CSP cannot be used with SecurityHeaders; apply it as a layer instead")
            }
        }
    }
}

impl IntoSecurityHeader for CspBuilder {
    fn into_header(self) -> (HeaderName, HeaderValue) {
        self.build().into_header()
    }
}

#[cfg(feature = "csp-nonce")]
mod csp_service {
    use std::{
        pin::Pin,
        task::{Context, Poll, ready},
    };

    use axum::extract::Request;
    use http::Response;
    use pin_project_lite::pin_project;
    use tower::Service;

    use crate::utils::headers::{InsertHeader, InsertHeadersService};

    use crate::headers::nonce::NonceCspService;

    /// Wrapper service that dispatches to either static or nonce CSP handling.
    #[derive(Clone)]
    pub enum CspService<S> {
        Static(InsertHeadersService<S>),
        Nonce(NonceCspService<S>),
    }

    impl<S, IB, OB> Service<Request<IB>> for CspService<S>
    where
        S: Service<Request<IB>, Response = Response<OB>>,
    {
        type Response = Response<OB>;
        type Error = S::Error;
        type Future = CspFuture<S::Future>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            match self {
                CspService::Static(s) => s.poll_ready(cx),
                CspService::Nonce(s) => s.poll_ready(cx),
            }
        }

        fn call(&mut self, req: Request<IB>) -> Self::Future {
            match self {
                CspService::Static(s) => CspFuture::Static { inner: s.call(req) },
                CspService::Nonce(s) => {
                    let (future, header_value) = s.call_parts(req);
                    CspFuture::Nonce {
                        future,
                        header_value: Some(header_value),
                    }
                }
            }
        }
    }

    pin_project! {
        #[project = CspFutureProj]
        pub enum CspFuture<F> {
            Static {
                #[pin]
                inner: InsertHeader<F>,
            },
            Nonce {
                #[pin]
                future: F,
                header_value: Option<http::HeaderValue>,
            },
        }
    }

    impl<F, B, E> Future for CspFuture<F>
    where
        F: Future<Output = Result<Response<B>, E>>,
    {
        type Output = Result<Response<B>, E>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.project() {
                CspFutureProj::Static { inner } => inner.poll(cx),
                CspFutureProj::Nonce {
                    future,
                    header_value,
                } => {
                    let res = ready!(future.poll(cx));
                    let hv = header_value.take().expect("polled after completion");
                    Poll::Ready(res.map(|mut res| {
                        res.headers_mut().insert(super::CONTENT_SECURITY_POLICY, hv);
                        res
                    }))
                }
            }
        }
    }
}

#[cfg(feature = "csp-nonce")]
pub use csp_service::CspService;

#[cfg(test)]
mod csp_tests {
    fn static_header_value(csp: &super::ContentSecurityPolicy) -> &http::HeaderValue {
        match &csp.inner {
            super::CspInner::Static(hv) => hv,
            #[cfg(feature = "csp-nonce")]
            super::CspInner::Nonce(_) => panic!("expected static CSP"),
        }
    }
    use axum::{Router, body::Body, extract::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::headers::SecurityHeaders;

    #[test]
    fn default_src_none() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::NONE)
            .build();
        assert_eq!(static_header_value(&csp), "default-src 'none'");
    }

    #[test]
    fn multiple_sources() {
        let csp = ContentSecurityPolicy::builder()
            .default_src([CspSource::SELF, CspSource::host("https://example.com")])
            .build();
        assert_eq!(
            static_header_value(&csp),
            "default-src 'self' https://example.com"
        );
    }

    #[test]
    fn multiple_directives() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::SELF)
            .script_src([CspSource::SELF, CspSource::host("https://cdn.example.com")])
            .build();
        assert_eq!(
            static_header_value(&csp),
            "default-src 'self'; script-src 'self' https://cdn.example.com"
        );
    }

    #[test]
    fn upgrade_insecure_requests() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::SELF)
            .upgrade_insecure_requests()
            .build();
        assert_eq!(
            static_header_value(&csp),
            "default-src 'self'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn into_security_header() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::SELF)
            .build();
        let headers = SecurityHeaders::new().add(csp);
        let header = headers.headers.get(&CONTENT_SECURITY_POLICY).unwrap();
        assert_eq!(header.value, "default-src 'self'");
    }

    #[tokio::test]
    async fn layer() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::NONE)
            .script_src(CspSource::SELF)
            .build();

        let router = Router::<()>::new().layer(csp);

        let res = router
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            res.headers()["content-security-policy"],
            "default-src 'none'; script-src 'self'"
        );
    }

    #[cfg(feature = "csp-nonce")]
    #[test]
    fn build_nonce_template() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::SELF)
            .script_src([CspSource::SELF, CspSource::NONCE])
            .build_nonce();

        assert!(matches!(csp.inner, CspInner::Nonce(_)));
    }

    #[cfg(feature = "csp-nonce")]
    #[test]
    #[should_panic(expected = ".build_nonce()")]
    fn build_panics_with_nonce() {
        ContentSecurityPolicy::builder()
            .script_src(CspSource::NONCE)
            .build();
    }
}
