use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tower::{Layer, Service};

use super::{BasicAuth, BasicAuthenticator};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub struct BasicAuthLayer<A> {
    authenticator: Arc<A>,
}

impl<A> BasicAuthLayer<A> {
    pub fn new(authenticator: A) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
        }
    }
}

impl<A: 'static, S> Layer<S> for BasicAuthLayer<A> {
    type Service = BasicAuthService<A, S>;

    fn layer(&self, inner: S) -> Self::Service {
        BasicAuthService {
            authenticator: self.authenticator.clone(),
            inner,
        }
    }
}

pub struct BasicAuthService<A, S> {
    authenticator: Arc<A>,
    inner: S,
}

impl<A, S: Clone> Clone for BasicAuthService<A, S> {
    fn clone(&self) -> Self {
        Self {
            authenticator: self.authenticator.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<A, S> Service<Request> for BasicAuthService<A, S>
where
    A: BasicAuthenticator + 'static,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Send,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let auth = self.authenticator.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            if let Some(header) = decode_header(req.headers())
                && let Some((username, password)) = header.split_once(':')
            {
                crate::debug!("basic-auth: verifying credentials for user {username}");
                match auth.authenticate(username, password).await {
                    Ok(Some(user)) => {
                        crate::debug!("basic-auth: authenticated");
                        req.extensions_mut().insert(BasicAuth(user));
                    }
                    Ok(None) => {
                        crate::debug!("basic-auth: invalid credentials");
                    }
                    Err(e) => {
                        crate::error!("basic-auth: authenticator returned an error");
                        return Ok(e.into_response());
                    }
                }
            } else {
                crate::debug!("basic-auth: no Authorization header");
            }
            inner.call(req).await
        })
    }
}

fn decode_header(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded).ok()?;
    String::from_utf8(decoded).ok()
}

impl<A> Clone for BasicAuthLayer<A> {
    fn clone(&self) -> Self {
        Self {
            authenticator: self.authenticator.clone(),
        }
    }
}
