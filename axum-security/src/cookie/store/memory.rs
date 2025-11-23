use std::{collections::HashMap, sync::Arc};

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

    async fn store_session(&self, session: CookieSession<Self::State>) {
        let mut lock = self.inner.write().await;
        let id = session.id().clone();
        lock.insert(id, session);
    }

    async fn remove_session(&self, id: &SessionId) -> Option<CookieSession<Self::State>> {
        let mut lock = self.inner.write().await;
        lock.remove(id)
    }

    async fn load_session(&self, id: &SessionId) -> Option<CookieSession<Self::State>> {
        let lock = self.inner.read().await;
        lock.get(id).cloned()
    }
}
