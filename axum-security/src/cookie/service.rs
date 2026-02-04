use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{extract::Request, http::StatusCode, response::IntoResponse};
use tower::{Layer, Service};

use crate::cookie::{CookieContext, CookieStore};

pub struct CookieService<STORE, SERV> {
    inner: CookieContext<STORE>,
    rest: SERV,
}

impl<STORE, SERV> Service<Request> for CookieService<STORE, SERV>
where
    SERV: Service<Request, Error = Infallible> + Clone + Send + 'static,
    <SERV as Service<Request>>::Response: IntoResponse,
    <SERV as Service<Request>>::Future: Send,
    STORE: CookieStore,
    STORE::State: Clone,
{
    type Response = axum::response::Response;

    type Error = Infallible;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.rest.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut this = self.clone();
        Box::pin(async move {
            match this.inner.load_from_headers(req.headers()).await {
                Ok(Some(session)) => {
                    req.extensions_mut().insert(session);
                }
                Ok(None) => {}
                Err(_) => return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
            }

            this.rest.call(req).await.map(|e| e.into_response())
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
