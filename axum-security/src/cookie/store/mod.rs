mod memory;

use std::{pin::Pin, sync::Arc};

use axum::response::{IntoResponse, Response};
pub use memory::MemStore;

use crate::cookie::{CookieSession, SessionId};

pub trait CookieStore: Send + Sync + 'static {
    type State: Send + Sync + 'static;
    type Error: IntoResponse + Send + 'static;

    fn spawn_maintenance_task(&self) -> bool {
        true
    }

    fn store_session(
        &self,
        session: CookieSession<Self::State>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    fn remove_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<CookieSession<Self::State>>, Self::Error>> + Send;

    fn load_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<Option<CookieSession<Self::State>>, Self::Error>> + Send;

    fn remove_before(&self, deadline: u64) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[allow(clippy::type_complexity)]
trait DynStore<S>: Send + Sync + 'static {
    fn spawn_maintenance_task(&self) -> bool;

    fn store_session(
        &self,
        session: CookieSession<S>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Response>> + Send + '_>>;

    fn remove_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CookieSession<S>>, Response>> + Send + 'a>>;

    fn load_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CookieSession<S>>, Response>> + Send + 'a>>;

    fn remove_before(
        &self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), Response>> + Send + '_>>;
}

impl<T> DynStore<T::State> for T
where
    T: CookieStore,
{
    fn spawn_maintenance_task(&self) -> bool {
        <T as CookieStore>::spawn_maintenance_task(self)
    }

    fn store_session(
        &self,
        session: CookieSession<T::State>,
    ) -> Pin<Box<dyn Future<Output = Result<(), Response>> + Send + '_>> {
        Box::pin(async move {
            <T as CookieStore>::store_session(self, session)
                .await
                .map_err(IntoResponse::into_response)
        })
    }

    fn remove_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CookieSession<T::State>>, Response>> + Send + 'a>>
    {
        Box::pin(async move {
            <T as CookieStore>::remove_session(self, id)
                .await
                .map_err(IntoResponse::into_response)
        })
    }

    fn load_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CookieSession<T::State>>, Response>> + Send + 'a>>
    {
        Box::pin(async move {
            <T as CookieStore>::load_session(self, id)
                .await
                .map_err(IntoResponse::into_response)
        })
    }

    fn remove_before(
        &self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), Response>> + Send + '_>> {
        Box::pin(async move {
            <T as CookieStore>::remove_before(self, deadline)
                .await
                .map_err(IntoResponse::into_response)
        })
    }
}

pub(crate) struct ErasedStore<S>(Arc<dyn DynStore<S>>);

impl<S: 'static> ErasedStore<S> {
    pub fn new(store: S) -> ErasedStore<S::State>
    where
        S: CookieStore,
    {
        ErasedStore(Arc::new(store))
    }

    pub fn spawn_maintenance_task(&self) -> bool {
        self.0.spawn_maintenance_task()
    }

    pub async fn store_session(&self, session: CookieSession<S>) -> Result<(), Response> {
        self.0.store_session(session).await
    }

    pub async fn remove_session(
        &self,
        id: &SessionId,
    ) -> Result<Option<CookieSession<S>>, Response> {
        self.0.remove_session(id).await
    }

    pub async fn load_session(&self, id: &SessionId) -> Result<Option<CookieSession<S>>, Response> {
        self.0.load_session(id).await
    }

    pub async fn remove_before(&self, deadline: u64) -> Result<(), Response> {
        self.0.remove_before(deadline).await
    }
}

impl<S> Clone for ErasedStore<S> {
    fn clone(&self) -> Self {
        ErasedStore(self.0.clone())
    }
}
