use crate::session::{Session, SessionId};

mod memory;

pub use memory::MemoryStore;

pub trait SessionStore: Send + Sync + 'static {
    type State: Send + Sync + 'static;

    fn store_session(&self, session: Session<Self::State>) -> impl Future<Output = ()> + Send;

    fn remove_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Option<Session<Self::State>>> + Send;

    fn load_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Option<Session<Self::State>>> + Send;
}
