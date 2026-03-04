use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use axum::{body::Body, extract::Request};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use cookie_monster::{Cookie, CookieJar};
use hmac::Mac;
use http::{Method, Response, StatusCode};
use pin_project_lite::pin_project;
use subtle::ConstantTimeEq;
use tower::Service;

use super::{CsrfConfig, CsrfToken, TOKEN_BYTE_LEN};

const HMAC_LEN: usize = 32;

#[derive(Clone)]
pub struct CsrfService<S> {
    pub(crate) inner: S,
    pub(crate) config: Arc<CsrfConfig>,
}

impl<S> CsrfService<S> {
    fn generate_token(&self) -> String {
        let mut token_bytes = [0u8; TOKEN_BYTE_LEN];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut token_bytes);

        let mut hmac = self.config.secret.clone();
        hmac.update(&token_bytes);
        let signature = hmac.finalize().into_bytes();

        let mut payload = token_bytes.to_vec();
        payload.extend_from_slice(&signature);
        BASE64_URL_SAFE_NO_PAD.encode(payload)
    }

    fn verify_token(&self, token: &str) -> bool {
        let Ok(decoded) = BASE64_URL_SAFE_NO_PAD.decode(token) else {
            return false;
        };

        if decoded.len() != TOKEN_BYTE_LEN + HMAC_LEN {
            return false;
        }

        let (random, received_sig) = decoded.split_at(TOKEN_BYTE_LEN);

        let mut hmac = self.config.secret.clone();
        hmac.update(random);
        let expected_sig = hmac.finalize().into_bytes();

        received_sig.ct_eq(&expected_sig[..]).into()
    }

    fn extract_submitted_token<'a>(&self, req: &'a Request) -> Option<Cow<'a, str>> {
        // Check header first
        if let Some(val) = req.headers().get(&self.config.header_name)
            && let Ok(s) = val.to_str()
        {
            return Some(Cow::Borrowed(s));
        }

        // Check query string for form field fallback (url-encoded form via query is uncommon,
        // but we also check the URI query params as a convenience)
        if let Some(query) = req.uri().query() {
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                if key == self.config.form_field.as_ref() {
                    return Some(value);
                }
            }
        }

        None
    }
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn forbidden() -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from("CSRF token validation failed"))
        .unwrap()
}

impl<S> Service<Request<Body>> for CsrfService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = CsrfFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // For state-changing methods, validate the CSRF token
        if is_state_changing(req.method()) {
            // Get the cookie token
            let jar = CookieJar::from_headers(req.headers());
            let cookie_token = jar.get(&self.config.cookie_name);

            let valid = match cookie_token {
                Some(cookie) => {
                    let cookie_val = cookie.value();
                    // Verify the cookie token itself is validly signed
                    if !self.verify_token(cookie_val) {
                        false
                    } else {
                        // Get the submitted token from header or form field
                        match self.extract_submitted_token(&req) {
                            Some(submitted) => {
                                // Constant-time comparison of the two tokens
                                submitted.as_bytes().ct_eq(cookie_val.as_bytes()).into()
                            }
                            None => false,
                        }
                    }
                }
                None => false,
            };

            if !valid {
                return CsrfFuture::Forbidden;
            }
        }

        // Generate or reuse a token
        let token = {
            let jar = CookieJar::from_headers(req.headers());
            match jar.get(&self.config.cookie_name) {
                Some(cookie) if self.verify_token(cookie.value()) => cookie.value().to_owned(),
                _ => self.generate_token(),
            }
        };

        // Insert the CsrfToken extractor into extensions
        req.extensions_mut()
            .insert(CsrfToken(Arc::from(token.as_str())));

        // Build the Set-Cookie
        let cookie = self.config.cookie_builder.clone().value(token).build();

        CsrfFuture::Inner {
            future: self.inner.call(req),
            cookie: Some(cookie),
        }
    }
}

pin_project! {
    #[project = CsrfFutureProj]
    pub enum CsrfFuture<F> {
        Inner {
            #[pin]
            future: F,
            cookie: Option<Cookie>,
        },
        Forbidden,
    }
}

impl<F, E> Future for CsrfFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    type Output = Result<Response<Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CsrfFutureProj::Inner { future, cookie } => {
                let res = ready!(future.poll(cx));
                let cookie = cookie.take().expect("polled after completion");

                Poll::Ready(res.map(|mut res| {
                    if let Some(header_value) =
                        cookie.serialize_encoded().ok().and_then(|s| s.parse().ok())
                    {
                        res.headers_mut().append("set-cookie", header_value);
                    }
                    res
                }))
            }
            CsrfFutureProj::Forbidden => Poll::Ready(Ok(forbidden())),
        }
    }
}
