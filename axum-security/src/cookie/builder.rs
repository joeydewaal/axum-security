use std::{sync::Arc, time::Duration};

use cookie_monster::CookieBuilder;

use crate::cookie::{
    CookieContext, CookieContextInner, CookieStore, expiry::SessionExpiry, store::ErasedStore,
};
pub(crate) use crate::cookie_options::CookieOptionsBuilder;

pub struct CookieSessionBuilder<S> {
    store: S,
    pub(crate) cookie_opts: CookieOptionsBuilder,
    pub(crate) expiry: Option<SessionExpiry>,
}

impl CookieSessionBuilder<()> {
    pub fn new() -> CookieSessionBuilder<()> {
        Self {
            store: (),
            cookie_opts: CookieOptionsBuilder::new(),
            expiry: None,
        }
    }
}

impl<S> CookieSessionBuilder<S> {
    pub fn cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts.cookie = f(self.cookie_opts.cookie);
        self
    }

    pub fn dev_cookie(mut self, f: impl FnOnce(CookieBuilder) -> CookieBuilder) -> Self {
        self.cookie_opts.dev_cookie = f(self.cookie_opts.dev_cookie);
        self
    }

    pub fn use_dev_cookie(mut self, dev: bool) -> Self {
        self.cookie_opts.dev = dev;
        self
    }

    pub fn use_normal_cookie(self, prod: bool) -> Self {
        self.use_dev_cookie(!prod)
    }

    pub fn expires_max_age(mut self) -> Self {
        self.expiry = Some(SessionExpiry::CookieMaxAge);
        self
    }

    pub fn expires_after(mut self, session_duration: Duration) -> Self {
        self.expiry = Some(SessionExpiry::Duration(session_duration));
        self
    }

    pub fn expires_none(mut self) -> Self {
        self.expiry = None;
        self
    }

    pub fn store<S1>(self, store: S1) -> CookieSessionBuilder<S1> {
        CookieSessionBuilder {
            store,
            cookie_opts: self.cookie_opts,
            expiry: self.expiry,
        }
    }
}

impl<S> CookieSessionBuilder<S> {
    pub fn build<T>(self) -> CookieContext<T>
    where
        T: Send + Sync + 'static,
        S: CookieStore<State = T>,
    {
        let cookie_opts = self.cookie_opts.build();

        let session_expiry = self.expiry.map(|e| match e {
            SessionExpiry::CookieMaxAge => cookie_opts.get_max_age().expect("No max-age set"),
            SessionExpiry::Duration(duration) => duration,
        });

        let store = ErasedStore::new(self.store);

        let handle = if let Some(expiry) = session_expiry
            && store.spawn_maintenance_task()
        {
            Some(tokio::spawn(super::expiry::maintenance_task(
                store.clone(),
                expiry,
            )))
        } else {
            None
        };

        CookieContext(Arc::new(CookieContextInner {
            store,
            cookie_opts,
            handle,
        }))
    }
}

impl Default for CookieSessionBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod cookie {
    use cookie_monster::CookieJar;

    use crate::cookie::{CookieContext, MemStore};

    #[derive(Clone)]
    struct User {
        id: i32,
    }

    #[tokio::test]
    async fn create() {
        let cookie_context = CookieContext::builder()
            .store(MemStore::new())
            .build::<User>();

        let test_user = User { id: 1 };
        let test_user_id = test_user.id;

        let cookie = cookie_context.create_session(test_user).await.unwrap();

        let mut jar = CookieJar::new();
        jar.add(cookie);

        let user = cookie_context.load_from_jar(&jar).await.unwrap();

        assert!(user.is_some());
        assert!(test_user_id == user.unwrap().state.id);
    }

    #[tokio::test]
    async fn delete() {
        let cookie_context = CookieContext::builder()
            .store(MemStore::new())
            .build::<User>();

        let test_user = User { id: 1 };
        let test_user_id = test_user.id;

        let cookie = cookie_context.create_session(test_user).await.unwrap();

        let user = cookie_context.remove_session_cookie(&cookie).await.unwrap();

        assert!(user.is_some());
        assert!(test_user_id == user.unwrap().state.id);

        let after = cookie_context.load_from_cookie(&cookie).await.unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn defaults() {
        let cookie = CookieContext::builder()
            .store(MemStore::new())
            .build::<()>()
            .create_session(())
            .await
            .unwrap();

        assert!(cookie.name() == "session");

        let cookie = CookieContext::builder()
            .store(MemStore::new())
            .use_dev_cookie(true)
            .build::<()>()
            .create_session(())
            .await
            .unwrap();

        assert!(cookie.name() == "dev-session");

        let cookie = CookieContext::builder()
            .store(MemStore::new())
            .cookie(|c| c.name("test"))
            .dev_cookie(|c| c.name("not-test"))
            .build::<()>()
            .create_session(())
            .await
            .unwrap();

        assert!(cookie.name() == "test");

        let cookie = CookieContext::builder()
            .store(MemStore::new())
            .cookie(|c| c.name("not-test"))
            .dev_cookie(|c| c.name("test"))
            .use_dev_cookie(true)
            .build::<()>()
            .create_session(())
            .await
            .unwrap();

        assert!(cookie.name() == "test");
    }
}
