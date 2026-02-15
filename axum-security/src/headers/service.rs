use std::{
    collections::HashSet,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use axum::extract::Request;
use http::Response;
use pin_project_lite::pin_project;
use tower::{Layer, Service};

use crate::headers::{SecurityHeader, SecurityHeaders};

impl<S> Layer<S> for SecurityHeaders {
    type Service = SecurityHeadersLayer<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersLayer {
            inner,
            headers: self.headers.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SecurityHeadersLayer<S> {
    inner: S,
    headers: Arc<HashSet<SecurityHeader>>,
}

impl<IB, OB, S> Service<Request<IB>> for SecurityHeadersLayer<S>
where
    S: Service<Request<IB>, Response = Response<OB>>,
{
    type Response = Response<OB>;

    type Error = S::Error;

    type Future = InsertHeaders<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<IB>) -> Self::Future {
        InsertHeaders {
            future: self.inner.call(req),
            header: self.headers.clone(),
        }
    }
}

pin_project! {
    pub struct InsertHeaders<F> {
        #[pin]
        future: F,
        header: Arc<HashSet<SecurityHeader>>
    }
}

impl<F, B, E> Future for InsertHeaders<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = ready!(this.future.poll(cx));

        Poll::Ready(res.map(|mut res| {
            let headers = res.headers_mut();

            for header in this.header.iter() {
                headers.insert(header.name.clone(), header.value.clone());
            }
            res
        }))
    }
}

#[cfg(test)]
mod haeders_service {
    use std::error::Error;

    use axum::{Router, body::Body};
    use http::Request;
    use tower::ServiceExt;

    use crate::headers::{
        CROSS_ORIGIN_OPENER_POLICY, CrossOriginOpenerPolicy, SecurityHeaders, X_XSS_PROTECTION,
        XssProtection,
    };

    #[tokio::test]
    async fn test() -> Result<(), Box<dyn Error>> {
        let headers = SecurityHeaders::new().add(XssProtection::ZERO);
        let router = Router::<()>::new().layer(headers);

        let res = router
            .oneshot(Request::get("/").body(Body::empty())?)
            .await
            .unwrap();

        let header = &res.headers()[X_XSS_PROTECTION];
        assert!(header == XssProtection::ZERO.header_value);
        Ok(())
    }

    #[tokio::test]
    async fn test_muliple() -> Result<(), Box<dyn Error>> {
        let headers = SecurityHeaders::new()
            .add(XssProtection::ZERO)
            .add(CrossOriginOpenerPolicy::SAME_ORIGIN);

        let router = Router::<()>::new().layer(headers);

        let res = router
            .oneshot(Request::get("/").body(Body::empty())?)
            .await
            .unwrap();

        let header = &res.headers()[X_XSS_PROTECTION];
        assert!(header == XssProtection::ZERO.header_value);

        let header = &res.headers()[CROSS_ORIGIN_OPENER_POLICY];
        assert!(header == CrossOriginOpenerPolicy::SAME_ORIGIN.header_value);

        Ok(())
    }
}
