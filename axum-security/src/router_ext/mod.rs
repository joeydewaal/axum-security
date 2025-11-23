use axum::Router;

pub trait AuthInjector {
    fn inject_into_router<S: Send + Sync + Clone + 'static>(self, router: Router<S>) -> Router<S>;
}

impl<T> AuthInjector for &T
where
    T: AuthInjector + Clone,
{
    fn inject_into_router<S: Send + Sync + Clone + 'static>(self, router: Router<S>) -> Router<S> {
        <T as AuthInjector>::inject_into_router(self.clone(), router)
    }
}

pub trait RouterExt<S> {
    fn with_auth(self, auth: impl AuthInjector) -> Router<S>;
}

impl<S> RouterExt<S> for Router<S>
where
    S: Send + Sync + Clone + 'static,
{
    fn with_auth(self, auth: impl AuthInjector) -> Router<S> {
        auth.inject_into_router(self)
    }
}
