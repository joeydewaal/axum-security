use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{extract::Request, response::IntoResponse};
use tower::{Layer, Service};

use crate::cookie::CookieContext;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub struct CookieService<S, SERV> {
    inner: CookieContext<S>,
    rest: SERV,
}

impl<S, SERV> Service<Request> for CookieService<S, SERV>
where
    SERV: Service<Request, Error = Infallible> + Clone + Send + 'static,
    <SERV as Service<Request>>::Response: IntoResponse,
    <SERV as Service<Request>>::Future: Send,
    S: Clone + Send + Sync + 'static,
{
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.rest.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move {
            match this.inner.load_from_headers(req.headers()).await {
                Ok(Some(session)) => {
                    crate::debug!("cookie: session loaded");
                    req.extensions_mut().insert(session);
                }
                Ok(None) => {
                    crate::debug!("cookie: no session in request");
                }
                Err(e) => {
                    crate::debug!("cookie: error loading session");
                    return Ok(e);
                }
            }

            this.rest.call(req).await.map(IntoResponse::into_response)
        })
    }
}

impl<SERV, T> Layer<SERV> for CookieContext<T>
where
    T: 'static,
{
    type Service = CookieService<T, SERV>;

    fn layer(&self, inner: SERV) -> Self::Service {
        CookieService {
            inner: self.clone(),
            rest: inner,
        }
    }
}

impl<T, SERV> Clone for CookieService<T, SERV>
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
