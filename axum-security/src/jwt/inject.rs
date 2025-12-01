use std::{
    convert::Infallible,
    task::{Context, Poll},
};

use axum::{
    Router,
    extract::{Request, State},
    middleware::Next,
    response::Response,
    routing::MethodRouter,
};
use serde::de::DeserializeOwned;
use tower::{Layer, Service};

use crate::{
    jwt::{Jwt, JwtContext},
    router_ext::AuthInjector,
};

impl<T, S> AuthInjector<Router<S>> for JwtContext<T>
where
    S: Send + Sync + Clone + 'static,
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    fn inject_into(self, router: Router<S>) -> axum::Router<S> {
        router.layer(self)
    }
}

impl<T, S> AuthInjector<MethodRouter<S, Infallible>> for JwtContext<T>
where
    S: Send + Sync + Clone + 'static,
    T: DeserializeOwned + Send + Sync + 'static + Clone,
{
    fn inject_into(self, router: MethodRouter<S, Infallible>) -> MethodRouter<S, Infallible> {
        router.layer(self)
    }
}

pub struct JwtService<T, SERV> {
    inner: JwtContext<T>,
    rest: SERV,
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
