use std::{convert::Infallible, future::Future, marker::PhantomData, pin::Pin};

use axum::{
    Router,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::MethodRouter,
};
use tower::{Layer, Service};

use crate::session::Session;

pub trait Policy<U>: Send + Sync + 'static + Clone {
    type Error: IntoResponse + Send;

    fn evaluate(&self, user: &U) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

impl<U, F> Policy<U> for F
where
    F: Fn(&U) -> bool + Send + Sync + 'static + Clone,
{
    type Error = Infallible;

    fn evaluate(&self, user: &U) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let result = (self)(user);
        async move { Ok(result) }
    }
}

#[derive(Clone)]
pub struct AllOf<P1, P2>(pub P1, pub P2);

impl<U, P1, P2> Policy<U> for AllOf<P1, P2>
where
    U: Send + Sync + 'static,
    P1: Policy<U>,
    P2: Policy<U>,
{
    type Error = Response;

    async fn evaluate(&self, user: &U) -> Result<bool, Self::Error> {
        let a = self
            .0
            .evaluate(user)
            .await
            .map_err(IntoResponse::into_response)?;
        if !a {
            return Ok(false);
        }
        self.1
            .evaluate(user)
            .await
            .map_err(IntoResponse::into_response)
    }
}

#[derive(Clone)]
pub struct AnyOf<P1, P2>(pub P1, pub P2);

impl<U, P1, P2> Policy<U> for AnyOf<P1, P2>
where
    U: Send + Sync + 'static,
    P1: Policy<U>,
    P2: Policy<U>,
{
    type Error = Response;

    async fn evaluate(&self, user: &U) -> Result<bool, Self::Error> {
        let a = self
            .0
            .evaluate(user)
            .await
            .map_err(IntoResponse::into_response)?;
        if a {
            return Ok(true);
        }
        self.1
            .evaluate(user)
            .await
            .map_err(IntoResponse::into_response)
    }
}

#[derive(Clone)]
pub struct Not<P>(pub P);

impl<U, P> Policy<U> for Not<P>
where
    U: Send + Sync + 'static,
    P: Policy<U>,
{
    type Error = P::Error;

    async fn evaluate(&self, user: &U) -> Result<bool, Self::Error> {
        Ok(!self.0.evaluate(user).await?)
    }
}

pub trait PolicyExt<U>: Policy<U> + Sized {
    fn and<P: Policy<U>>(self, other: P) -> AllOf<Self, P> {
        AllOf(self, other)
    }

    fn or<P: Policy<U>>(self, other: P) -> AnyOf<Self, P> {
        AnyOf(self, other)
    }

    fn not(self) -> Not<Self> {
        Not(self)
    }
}

impl<U, P: Policy<U>> PolicyExt<U> for P {}

#[derive(Clone, Copy)]
pub struct Allow;

impl<U: Send + Sync + 'static> Policy<U> for Allow {
    type Error = Infallible;

    async fn evaluate(&self, _user: &U) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone, Copy)]
pub struct Deny;

impl<U: Send + Sync + 'static> Policy<U> for Deny {
    type Error = Infallible;

    async fn evaluate(&self, _user: &U) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[cfg(feature = "rbac")]
pub struct HasRole<R: crate::rbac::RBAC> {
    role: R,
}

#[cfg(feature = "rbac")]
impl<R: crate::rbac::RBAC> Clone for HasRole<R> {
    fn clone(&self) -> Self {
        HasRole { role: self.role }
    }
}

#[cfg(feature = "rbac")]
impl<R: crate::rbac::RBAC> HasRole<R> {
    pub fn new(role: R) -> Self {
        HasRole { role }
    }
}

#[cfg(feature = "rbac")]
impl<R: crate::rbac::RBAC> Policy<R::Resource> for HasRole<R> {
    type Error = Infallible;

    async fn evaluate(&self, user: &R::Resource) -> Result<bool, Self::Error> {
        Ok(R::extract_roles(user).into_iter().any(|r| *r == self.role))
    }
}

struct PolicyLayer<P, U> {
    policy: P,
    _marker: PhantomData<fn() -> U>,
}

impl<P: Clone, U> Clone for PolicyLayer<P, U> {
    fn clone(&self) -> Self {
        PolicyLayer {
            policy: self.policy.clone(),
            _marker: PhantomData,
        }
    }
}

impl<P, S, U> Layer<S> for PolicyLayer<P, U>
where
    P: Clone,
{
    type Service = PolicyService<P, S, U>;

    fn layer(&self, inner: S) -> PolicyService<P, S, U> {
        PolicyService {
            policy: self.policy.clone(),
            inner,
            _marker: PhantomData,
        }
    }
}

pub struct PolicyService<P, S, U> {
    policy: P,
    inner: S,
    _marker: PhantomData<fn() -> U>,
}

impl<P: Clone, S: Clone, U> Clone for PolicyService<P, S, U> {
    fn clone(&self) -> Self {
        PolicyService {
            policy: self.policy.clone(),
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<P, S, U> Service<Request> for PolicyService<P, S, U>
where
    P: Policy<U> + 'static,
    U: Clone + Send + Sync + 'static,
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Error: Send,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<Result<Response, S::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let policy = self.policy.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            crate::debug!("evaluating policy");

            let Some(session) = Session::<U>::from_extensions(req.extensions_mut()) else {
                crate::debug!("no session found, returning 401");
                return Ok(StatusCode::UNAUTHORIZED.into_response());
            };

            match policy.evaluate(&session).await {
                Ok(true) => {
                    session.insert_into(req.extensions_mut());
                    inner.call(req).await
                }
                Ok(false) => {
                    crate::debug!("policy denied access, returning 403");
                    session.insert_into(req.extensions_mut());
                    Ok(StatusCode::FORBIDDEN.into_response())
                }
                Err(e) => {
                    crate::debug!("policy returned error");
                    session.insert_into(req.extensions_mut());
                    Ok(e.into_response())
                }
            }
        })
    }
}

pub trait PolicyRouterExt {
    fn with_policy<P, U>(self, policy: P) -> Self
    where
        P: Policy<U> + 'static,
        U: Clone + Send + Sync + 'static;
}

impl<S: Clone + 'static> PolicyRouterExt for MethodRouter<S, Infallible> {
    fn with_policy<P, U>(self, policy: P) -> Self
    where
        P: Policy<U> + 'static,
        U: Clone + Send + Sync + 'static,
    {
        self.layer(PolicyLayer {
            policy,
            _marker: PhantomData,
        })
    }
}

impl<S: Clone + Send + Sync + 'static> PolicyRouterExt for Router<S> {
    fn with_policy<P, U>(self, policy: P) -> Self
    where
        P: Policy<U> + 'static,
        U: Clone + Send + Sync + 'static,
    {
        self.layer(PolicyLayer {
            policy,
            _marker: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct User {
        admin: bool,
        banned: bool,
    }

    fn is_admin(u: &User) -> bool {
        u.admin
    }

    fn is_not_banned(u: &User) -> bool {
        !u.banned
    }

    #[tokio::test]
    async fn closure_policy_passes() {
        let user = User {
            admin: true,
            banned: false,
        };
        assert!(is_admin.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn closure_policy_fails() {
        let user = User {
            admin: false,
            banned: false,
        };
        assert!(!is_admin.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn allow_always_passes() {
        let user = User {
            admin: false,
            banned: true,
        };
        assert!(Allow.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn deny_always_fails() {
        let user = User {
            admin: true,
            banned: false,
        };
        assert!(!Deny.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn not_combinator() {
        let user = User {
            admin: true,
            banned: false,
        };
        let policy = is_admin.not();
        assert!(!policy.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn all_of_both_pass() {
        let user = User {
            admin: true,
            banned: false,
        };
        let policy = is_admin.and(is_not_banned);
        assert!(policy.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn all_of_one_fails() {
        let user = User {
            admin: true,
            banned: true,
        };
        let policy = is_admin.and(is_not_banned);
        assert!(!policy.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn any_of_one_passes() {
        let user = User {
            admin: true,
            banned: true,
        };
        let policy = is_admin.or(is_not_banned);
        assert!(policy.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn any_of_none_pass() {
        let user = User {
            admin: false,
            banned: true,
        };
        let policy = is_admin.or(is_not_banned);
        assert!(!policy.evaluate(&user).await.unwrap());
    }

    #[tokio::test]
    async fn chained_combinators() {
        let user = User {
            admin: true,
            banned: false,
        };
        let policy = is_admin.and(is_not_banned);
        assert!(policy.evaluate(&user).await.unwrap());

        let policy2 = (is_admin as fn(&User) -> bool).not().or(is_not_banned);
        assert!(policy2.evaluate(&user).await.unwrap());
    }
}
