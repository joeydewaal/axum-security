use axum::{Router, routing::MethodRouter};

pub trait AuthInjector<I> {
    fn inject_into(self, inject: I) -> I;
}

impl<T, I> AuthInjector<I> for &T
where
    T: AuthInjector<I> + Clone,
{
    fn inject_into(self, router: I) -> I {
        <T as AuthInjector<I>>::inject_into(self.clone(), router)
    }
}

pub trait RouterExt: Sized {
    fn with_auth<I: Sized>(self, auth: I) -> Self
    where
        I: AuthInjector<Self>;
}

impl<S> RouterExt for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_auth<I>(self, auth: I) -> Router<S>
    where
        I: AuthInjector<Router<S>>,
    {
        auth.inject_into(self)
    }
}

impl<S, E> RouterExt for MethodRouter<S, E>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_auth<I>(self, auth: I) -> MethodRouter<S, E>
    where
        I: AuthInjector<MethodRouter<S, E>>,
    {
        auth.inject_into(self)
    }
}
