use std::{collections::HashMap, convert::Infallible, sync::Arc};

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

    async fn remove_before(&self, deadline: u64) -> Result<(), Self::Error> {
        let mut lock = self.inner.write().await;
        lock.retain(|_, v| v.created_at >= deadline);
        Ok(())
    }
}

#[cfg(test)]
mod mem_store {
    use crate::cookie::{CookieSession, CookieStore, MemStore, SessionId};

    #[tokio::test]
    async fn create() {
        let store = MemStore::<i32>::new();

        let session_id = SessionId::new_uuid_v7();
        let created_at = 100;
        let value = 1;

        let session = CookieSession::new(session_id.clone(), created_at, value);

        store.store_session(session).await.unwrap();

        let session = store
            .load_session(&session_id)
            .await
            .unwrap()
            .expect("session to be created");

        assert!(session.created_at == created_at);
        assert!(session.state == value);

        let session = store
            .remove_session(&session_id)
            .await
            .unwrap()
            .expect("session should exists");

        assert!(session.created_at == created_at);
        assert!(session.state == value);

        let session = store.load_session(&session_id).await.unwrap();
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn remove() {
        let store = MemStore::<i32>::new();

        let session_id = SessionId::new_uuid_v7();
        let created_at = 100;
        let value = 1;

        let session = CookieSession::new(session_id.clone(), created_at, value);

        store.store_session(session).await.unwrap();

        store.remove_before(101).await;

        let session = store.load_session(&session_id).await.unwrap();
        assert!(session.is_none());
    }
}
