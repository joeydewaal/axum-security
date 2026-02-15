use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use axum::http::{HeaderName, HeaderValue};
use http::{Request, Response};
use pin_project_lite::pin_project;
use tower::Service;

pin_project! {
    pub struct InsertHeader<F> {
        #[pin]
        future: F,
        header: Option<(HeaderName, HeaderValue)>
    }
}

impl<F> InsertHeader<F> {
    pub fn new(future: F, header_name: HeaderName, header_value: HeaderValue) -> Self {
        Self {
            future,
            header: Some((header_name, header_value)),
        }
    }
}

impl<F, B, E> Future for InsertHeader<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = ready!(this.future.poll(cx));
        let (header_name, header_value) = this.header.take().expect("Bug");

        Poll::Ready(res.map(|mut res| {
            res.headers_mut().insert(header_name, header_value);
            res
        }))
    }
}

#[derive(Clone)]
pub struct InsertHeadersService<S> {
    pub header_name: HeaderName,
    pub header_value: HeaderValue,
    pub inner: S,
}

impl<S, IB, OB> Service<Request<IB>> for InsertHeadersService<S>
where
    S: Service<Request<IB>, Response = Response<OB>>,
{
    type Response = Response<OB>;

    type Error = S::Error;

    type Future = InsertHeader<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<IB>) -> Self::Future {
        InsertHeader::new(
            self.inner.call(req),
            self.header_name.clone(),
            self.header_value.clone(),
        )
    }
}
