use std::{collections::HashMap, convert::Infallible, hash::Hash, sync::Arc};

use tokio::sync::RwLock;

use crate::cookie::{CookieSession, CookieStore, SessionId};

pub struct MemStore<S> {
    inner: Arc<RwLock<HashMap<SessionId, CookieSession<S>>>>,
}

impl<S> Default for MemStore<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Clone for MemStore<S> {
    fn clone(&self) -> Self {
        MemStore {
            inner: self.inner.clone(),
        }
    }
}

impl<S> MemStore<S> {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()).into(),
        }
    }
}

impl<S: Send + Sync + Clone + 'static> CookieStore for MemStore<S> {
    type State = S;
    type Error = Infallible;

    async fn store_session(&self, session: CookieSession<Self::State>) -> Result<(), Self::Error> {
        let mut lock = self.inner.write().await;
        let id = session.session_id.clone();
        lock.insert(id, session);
        Ok(())
    }

    async fn remove_session(
        &self,
        id: &SessionId,
    ) -> Result<Option<CookieSession<Self::State>>, Self::Error> {
        let mut lock = self.inner.write().await;
        Ok(lock.remove(id))
    }

    async fn load_session(
        &self,
        id: &SessionId,
    ) -> Result<Option<CookieSession<Self::State>>, Self::Error> {
        let lock = self.inner.read().await;
        Ok(lock.get(id).cloned())
    }

    async fn remove_after(&self, deadline: u64) -> Result<(), Self::Error> {
        let mut lock = self.inner.write().await;
        lock.retain(|_, v| v.created_at > deadline);
        Ok(())
    }
}
