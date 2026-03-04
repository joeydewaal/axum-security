use std::borrow::Cow;

use http::{HeaderName, HeaderValue};
use tower::Layer;

use crate::{headers::IntoSecurityHeader, utils::headers::InsertHeadersService};

const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");

#[derive(Clone)]
pub struct ContentSecurityPolicy {
    header_value: HeaderValue,
}

impl ContentSecurityPolicy {
    pub fn builder() -> CspBuilder {
        CspBuilder {
            directives: Vec::new(),
        }
    }
}

pub struct CspBuilder {
    directives: Vec<(Cow<'static, str>, Vec<CspSource>)>,
}

pub struct CspSource(CspSourceInner);

#[derive(Clone)]
enum CspSourceInner {
    None,
    Self_,
    UnsafeInline,
    UnsafeEval,
    StrictDynamic,
    Host(Cow<'static, str>),
    Scheme(Cow<'static, str>),
}

impl CspSource {
    pub const NONE: CspSource = CspSource(CspSourceInner::None);
    pub const SELF: CspSource = CspSource(CspSourceInner::Self_);
    pub const UNSAFE_INLINE: CspSource = CspSource(CspSourceInner::UnsafeInline);
    pub const UNSAFE_EVAL: CspSource = CspSource(CspSourceInner::UnsafeEval);
    pub const STRICT_DYNAMIC: CspSource = CspSource(CspSourceInner::StrictDynamic);

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

    pub fn build(self) -> ContentSecurityPolicy {
        let mut parts = Vec::with_capacity(self.directives.len());

        for (name, sources) in &self.directives {
            if sources.is_empty() {
                parts.push(name.to_string());
            } else {
                let sources_str: Vec<Cow<'static, str>> =
                    sources.iter().map(|s| s.serialize()).collect();
                parts.push(format!("{} {}", name, sources_str.join(" ")));
            }
        }

        let value = parts.join("; ");
        let header_value =
            HeaderValue::from_str(&value).expect("CSP header does not contain invalid bytes");

        ContentSecurityPolicy { header_value }
    }
}

impl<S> Layer<S> for ContentSecurityPolicy {
    type Service = InsertHeadersService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InsertHeadersService {
            inner,
            header_name: CONTENT_SECURITY_POLICY,
            header_value: self.header_value.clone(),
        }
    }
}

impl IntoSecurityHeader for ContentSecurityPolicy {
    fn into_header(self) -> (HeaderName, HeaderValue) {
        (CONTENT_SECURITY_POLICY, self.header_value)
    }
}

impl IntoSecurityHeader for CspBuilder {
    fn into_header(self) -> (HeaderName, HeaderValue) {
        self.build().into_header()
    }
}

#[cfg(test)]
mod csp_tests {
    use axum::{Router, body::Body, extract::Request};
    use tower::ServiceExt;

    use super::*;
    use crate::headers::SecurityHeaders;

    #[test]
    fn default_src_none() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::NONE)
            .build();
        assert_eq!(csp.header_value, "default-src 'none'");
    }

    #[test]
    fn multiple_sources() {
        let csp = ContentSecurityPolicy::builder()
            .default_src([CspSource::SELF, CspSource::host("https://example.com")])
            .build();
        assert_eq!(csp.header_value, "default-src 'self' https://example.com");
    }

    #[test]
    fn multiple_directives() {
        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::SELF)
            .script_src([CspSource::SELF, CspSource::host("https://cdn.example.com")])
            .build();
        assert_eq!(
            csp.header_value,
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
            csp.header_value,
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
}
