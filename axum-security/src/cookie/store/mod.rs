mod memory;

pub use memory::MemStore;

use crate::{
    cookie::{CookieSession, SessionId},
    utils::utc_now_sec,
};

pub trait CookieStore: Send + Sync + 'static {
    type State: Send + Sync + 'static;
    type Error: std::error::Error + Send + Sync + 'static;

    fn spawn_maintenance_task(&self) -> bool {
        true
    }

    fn create_session(
        &self,
        state: Self::State,
    ) -> impl Future<Output = Result<SessionId, Self::Error>> + Send {
        async {
            let id = SessionId::new_uuid_v7();
            let now = utc_now_sec().as_secs();
            let session = CookieSession::new(id.clone(), now, state);
            self.store_session(session).await?;
            Ok(id)
        }
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

    fn remove_after(&self, deadline: u64) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
