mod memory;

use std::{error::Error, pin::Pin, sync::Arc};

pub use memory::MemStore;

use crate::cookie::{CookieSession, SessionId};

pub trait CookieStore: Send + Sync + 'static {
    type State: Send + Sync + 'static;
    type Error: std::error::Error + Send + Sync + 'static;

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

pub type BoxDynError = Box<dyn Error + Send + 'static>;

trait DynStore<S>: Send + Sync + 'static {
    fn spawn_maintenance_task(&self) -> bool;

    fn store_session(
        &self,
        session: CookieSession<S>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BoxDynError>> + Send + '_>>;

    fn remove_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CookieSession<S>>, BoxDynError>> + Send + 'a>>;

    fn load_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<Box<dyn Future<Output = Result<Option<CookieSession<S>>, BoxDynError>> + Send + 'a>>;

    fn remove_before(
        &self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), BoxDynError>> + Send + '_>>;
}

impl<T> DynStore<T::State> for T
where
    T: CookieStore,
{
    fn spawn_maintenance_task(&self) -> bool {
        <T as CookieStore>::spawn_maintenance_task(&self)
    }

    fn store_session(
        &self,
        session: CookieSession<T::State>,
    ) -> Pin<Box<dyn Future<Output = Result<(), BoxDynError>> + Send + '_>> {
        Box::pin(async move {
            <T as CookieStore>::store_session(&self, session)
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
        })
    }

    fn remove_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<CookieSession<T::State>>, BoxDynError>> + Send + 'a>,
    > {
        Box::pin(async move {
            <T as CookieStore>::remove_session(&self, id)
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
        })
    }

    fn load_session<'a>(
        &'a self,
        id: &'a SessionId,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<CookieSession<T::State>>, BoxDynError>> + Send + 'a>,
    > {
        Box::pin(async move {
            <T as CookieStore>::load_session(&self, id)
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
        })
    }

    fn remove_before(
        &self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), BoxDynError>> + Send + '_>> {
        Box::pin(async move {
            <T as CookieStore>::remove_before(&self, deadline)
                .await
                .map_err(|e| Box::new(e) as Box<dyn Error + Send>)
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

    pub async fn store_session(
        &self,
        session: CookieSession<S>,
    ) -> Result<(), Box<dyn Error + Send + 'static>> {
        self.0.store_session(session).await
    }

    pub async fn remove_session(
        &self,
        id: &SessionId,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        self.0.remove_session(id).await
    }

    pub async fn load_session(
        &self,
        id: &SessionId,
    ) -> Result<Option<CookieSession<S>>, BoxDynError> {
        self.0.load_session(id).await
    }

    pub async fn remove_before(&self, deadline: u64) -> Result<(), BoxDynError> {
        self.0.remove_before(deadline).await
    }
}

impl<S> Clone for ErasedStore<S> {
    fn clone(&self) -> Self {
        ErasedStore(self.0.clone())
    }
}
