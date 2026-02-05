use std::time::Duration;

use crate::{cookie::store::ErasedStore, utils::utc_now_secs};

pub(crate) enum SessionExpiry {
    CookieMaxAge,
    Duration(Duration),
}

pub(crate) async fn maintenance_task<S: 'static>(this: ErasedStore<S>, expires_after: Duration) {
    let mut interval = tokio::time::interval(expires_after);
    loop {
        interval.tick().await;
        this.remove_before(utc_now_secs()).await.unwrap();
    }
}

#[cfg(test)]
mod expiry {
    use std::time::Duration;

    use crate::cookie::{CookieContext, MemStore};

    #[tokio::test]
    async fn duration() {
        let cookie_context = CookieContext::builder()
            .expires_after(Duration::from_secs(1))
            .store(MemStore::new())
            .build::<()>();

        let cookie = cookie_context.create_session(()).await.unwrap();

        let session = cookie_context.load_from_cookie(&cookie).await.unwrap();
        assert!(session.is_some());

        tokio::time::sleep(Duration::from_secs(2)).await;

        let session = cookie_context.load_from_cookie(&cookie).await.unwrap();
        assert!(session.is_none());
    }

    #[tokio::test]
    async fn max_age() {
        let cookie_context = CookieContext::builder()
            .cookie(|c| c.max_age(Duration::from_secs(1)))
            .expires_max_age()
            .store(MemStore::new())
            .build::<()>();

        let cookie = cookie_context.create_session(()).await.unwrap();

        let session = cookie_context.load_from_cookie(&cookie).await.unwrap();
        assert!(session.is_some());

        tokio::time::sleep(Duration::from_secs(2)).await;

        let session = cookie_context.load_from_cookie(&cookie).await.unwrap();
        assert!(session.is_none());
    }

    #[test]
    #[should_panic]
    fn no_max_age() {
        CookieContext::builder()
            .expires_max_age()
            .store(MemStore::new())
            .build::<()>();
    }
}
