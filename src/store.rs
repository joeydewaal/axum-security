use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use tokio::sync::RwLock;

use crate::session::{Session, SessionId, SessionStore};

pub struct MemoryStore<S> {
    inner: Arc<RwLock<HashMap<SessionId, Session<S>>>>,
}

impl<S> Clone for MemoryStore<S> {
    fn clone(&self) -> Self {
        MemoryStore {
            inner: self.inner.clone(),
        }
    }
}

impl<S> MemoryStore<S> {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()).into(),
        }
    }

    // pub async fn read(&self, id: &str) -> Option<String> {
    //     let lock = self.inner.read().await;

    //     lock.get(id).cloned()
    // }

    // pub async fn remove(&self, id: &str) -> Option<String> {
    //     let mut lock = self.inner.write().await;
    //     lock.remove(id)
    // }

    // pub async fn write(&self, id: &str, value: &str) {
    //     let mut lock = self.inner.write().await;

    //     if let Some(session) = lock.get_mut(id) {
    //         *session = value.to_string();
    //     } else {
    //         lock.insert(id.to_string(), value.to_string());
    //     }
    // }
}

impl<S: Send + Sync + 'static> SessionStore for MemoryStore<S> {
    type State = S;

    async fn store_session(&self, session: Session<Self::State>) {
        let mut lock = self.inner.write().await;
        let id = session.id().clone();
        lock.insert(id, session);
    }

    async fn remove_session(&self, id: &SessionId) -> Option<Session<Self::State>> {
        let mut lock = self.inner.write().await;
        lock.remove(id)
    }
}
