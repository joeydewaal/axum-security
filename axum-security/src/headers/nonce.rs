use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::extract::{FromRequestParts, Request};
use base64::{Engine, prelude::BASE64_STANDARD};
use http::{HeaderValue, StatusCode, request::Parts};
use tower::Service;

use super::csp::NONCE_SENTINEL;

/// Per-request CSP nonce, available as an axum extractor.
///
/// Insert the nonce value into `<script>` or `<style>` tags:
///
/// ```rust,ignore
/// async fn page(nonce: CspNonce) -> Html<String> {
///     Html(format!(r#"<script nonce="{nonce}">alert('ok')</script>"#))
/// }
/// ```
#[derive(Clone)]
pub struct CspNonce(Arc<str>);

impl CspNonce {
    /// Return the nonce as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CspNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CspNonce {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CspNonce>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// Pre-serialized CSP string with `NONCE_SENTINEL` placeholders.
pub(crate) struct CspTemplate {
    template: String,
}

impl CspTemplate {
    pub(crate) fn new(template: String) -> Self {
        Self { template }
    }

    pub(crate) fn render(&self, nonce_b64: &str) -> HeaderValue {
        let value = format!("'nonce-{nonce_b64}'");
        let rendered = self.template.replace(NONCE_SENTINEL, &value);
        HeaderValue::from_str(&rendered).expect("rendered CSP contains invalid header bytes")
    }
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    BASE64_STANDARD.encode(bytes)
}

/// Service that generates a per-request nonce and injects it into the CSP header.
/// You don't need to construct this directly.
#[derive(Clone)]
pub struct NonceCspService<S> {
    pub(crate) inner: S,
    pub(crate) template: Arc<CspTemplate>,
}

impl<S, IB, OB> Service<Request<IB>> for NonceCspService<S>
where
    S: Service<Request<IB>, Response = http::Response<OB>>,
{
    type Response = http::Response<OB>;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<IB>) -> Self::Future {
        // This is only called directly when not behind CspService enum.
        // In practice CspService calls call_parts instead.
        let (future, _) = self.call_parts(req);
        future
    }
}

impl<S> NonceCspService<S> {
    /// Generate a nonce, insert it into extensions, and return the inner future
    /// along with the rendered CSP header value.
    pub(crate) fn call_parts<IB>(&mut self, mut req: Request<IB>) -> (S::Future, HeaderValue)
    where
        S: Service<Request<IB>>,
    {
        let nonce_b64 = generate_nonce();
        let header_value = self.template.render(&nonce_b64);

        req.extensions_mut().insert(CspNonce(Arc::from(nonce_b64)));

        (self.inner.call(req), header_value)
    }
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    use crate::headers::{ContentSecurityPolicy, CspSource};

    use super::*;

    #[tokio::test]
    async fn nonce_injected_in_header_and_extensions() {
        async fn handler(nonce: CspNonce) -> String {
            nonce.to_string()
        }

        let csp = ContentSecurityPolicy::builder()
            .default_src(CspSource::SELF)
            .script_src([CspSource::SELF, CspSource::NONCE])
            .build_nonce();

        let app = Router::<()>::new().route("/", get(handler)).layer(csp);

        let res = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let csp_header = res.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_owned();

        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let nonce_from_body = std::str::from_utf8(&body).unwrap();

        // The CSP header should contain the nonce
        assert!(
            csp_header.contains(&format!("'nonce-{nonce_from_body}'")),
            "CSP header {csp_header:?} should contain nonce {nonce_from_body:?}"
        );

        // Should also contain the static parts
        assert!(csp_header.starts_with("default-src 'self'; script-src 'self'"));
    }

    #[tokio::test]
    async fn each_request_gets_unique_nonce() {
        async fn handler(nonce: CspNonce) -> String {
            nonce.to_string()
        }

        let csp = ContentSecurityPolicy::builder()
            .script_src(CspSource::NONCE)
            .build_nonce();

        let app = Router::<()>::new().route("/", get(handler)).layer(csp);

        let res1 = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();

        let res2 = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();

        assert_ne!(body1, body2, "nonces should differ across requests");
    }

    #[test]
    fn template_replaces_all_sentinels() {
        let template = CspTemplate::new(format!(
            "script-src {NONCE_SENTINEL}; style-src {NONCE_SENTINEL}"
        ));
        let rendered = template.render("abc123");
        assert_eq!(
            rendered.to_str().unwrap(),
            "script-src 'nonce-abc123'; style-src 'nonce-abc123'"
        );
    }
}
