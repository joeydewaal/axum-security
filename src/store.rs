use std::collections::HashMap;

use tokio::sync::RwLock;

pub struct MemoryStore {
    inner: RwLock<HashMap<String, String>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub async fn read(&self, id: &str) -> Option<String> {
        let lock = self.inner.read().await;

        lock.get(id).cloned()
    }

    pub async fn remove(&self, id: &str) -> Option<String> {
        let mut lock = self.inner.write().await;
        lock.remove(id)
    }

    pub async fn write(&self, id: &str, value: &str) {
        let mut lock = self.inner.write().await;

        if let Some(session) = lock.get_mut(id) {
            *session = value.to_string();
        } else {
            lock.insert(id.to_string(), value.to_string());
        }
    }
}
