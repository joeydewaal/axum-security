mod memory;

pub use memory::MemoryStore;

use crate::cookie::{CookieSession, SessionId};

pub trait SessionStore: Send + Sync + 'static {
    type State: Send + Sync + 'static;

    fn store_state(&self, state: Self::State) -> impl Future<Output = SessionId> + Send {
        async {
            let id = SessionId::new_uuid_v7();
            let session = CookieSession::new(id.clone(), state);
            self.store_session(session).await;
            id
        }
    }

    fn store_session(&self, session: CookieSession<Self::State>)
    -> impl Future<Output = ()> + Send;

    fn remove_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Option<CookieSession<Self::State>>> + Send;

    fn load_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Option<CookieSession<Self::State>>> + Send;
}
