use std::{
    hash::Hash,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use axum::{body::Body, extract::Request};
use http::{Response, StatusCode, header::HeaderValue};
use pin_project_lite::pin_project;
use tower::Service;

use super::{KeyExtractor, store::Store};

#[derive(Clone)]
pub struct RateLimitService<K: KeyExtractor, S> {
    pub(crate) inner: S,
    pub(crate) store: Arc<Store<K::Key>>,
    pub(crate) extractor: K,
}

impl<K, S> Service<Request<Body>> for RateLimitService<K, S>
where
    K: KeyExtractor,
    K::Key: Hash + Eq + Clone + Send + Sync + 'static,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = RateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let key = match self.extractor.extract(&mut req) {
            Some(k) => k,
            None => {
                crate::debug!("rate_limit: no key extracted, passing through");
                return RateLimitFuture::Inner {
                    future: self.inner.call(req),
                    headers: None,
                };
            }
        };

        let result = self.store.check(key);

        let header_val = HeaderValue::from_str(&format!(
            "limit={}, remaining={}, reset={}",
            result.limit, result.remaining, result.reset_after_secs
        ))
        .expect("this header can't contain invalid characters");

        if result.allowed {
            crate::debug!(
                "rate_limit: allowed (remaining={}, limit={})",
                result.remaining,
                result.limit,
            );
            RateLimitFuture::Inner {
                future: self.inner.call(req),
                headers: Some(header_val),
            }
        } else {
            crate::debug!(
                "rate_limit: denied (limit={}, reset={}s)",
                result.limit,
                result.reset_after_secs,
            );
            RateLimitFuture::Limited {
                header: Some(header_val),
                reset: result.reset_after_secs,
            }
        }
    }
}

pin_project! {
    #[project = RateLimitFutureProj]
    pub enum RateLimitFuture<F> {
        Inner {
            #[pin]
            future: F,
            headers: Option<HeaderValue>,
        },
        Limited {
            header: Option<HeaderValue>,
            reset: u64,
        },
    }
}

impl<F, E> Future for RateLimitFuture<F>
where
    F: Future<Output = Result<Response<Body>, E>>,
{
    type Output = Result<Response<Body>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            RateLimitFutureProj::Inner { future, headers } => {
                let res = ready!(future.poll(cx));
                let header_val = headers.take();

                Poll::Ready(res.map(|mut res| {
                    if let Some(val) = header_val {
                        res.headers_mut().insert("ratelimit", val);
                    }
                    res
                }))
            }
            RateLimitFutureProj::Limited { header, reset } => {
                let mut res = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Body::from("Too Many Requests"))
                    .unwrap();

                res.headers_mut()
                    .insert("ratelimit", header.take().unwrap());
                res.headers_mut()
                    .insert("retry-after", HeaderValue::from(*reset));

                Poll::Ready(Ok(res))
            }
        }
    }
}
