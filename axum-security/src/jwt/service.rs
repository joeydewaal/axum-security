use std::task::{Context, Poll};

use axum::extract::Request;
use serde::de::DeserializeOwned;
use tower::{Layer, Service};

use crate::jwt::{Jwt, JwtContext};

pub struct JwtService<T, SERV> {
    inner: JwtContext<T>,
    rest: SERV,
}

impl<T, SERV> Service<Request> for JwtService<T, SERV>
where
    SERV: Service<Request>,
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    type Response = <SERV>::Response;

    type Error = <SERV>::Error;

    type Future = <SERV>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.rest.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        if let Some(user) = self.inner.decode_from_headers(req.headers()) {
            req.extensions_mut().insert(Jwt(user));
        }
        self.rest.call(req)
    }
}

impl<SERV, T> Layer<SERV> for JwtContext<T>
where
    T: 'static,
{
    type Service = JwtService<T, SERV>;

    fn layer(&self, inner: SERV) -> Self::Service {
        JwtService {
            inner: self.clone(),
            rest: inner,
        }
    }
}

impl<T, SERV> Clone for JwtService<T, SERV>
where
    SERV: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            rest: self.rest.clone(),
        }
    }
}
