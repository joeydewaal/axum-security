use std::{cmp, time::Duration};

use crate::{cookie::store::ErasedStore, utils::utc_now_secs};

pub(crate) enum SessionExpiry {
    CookieMaxAge,
    Duration(Duration),
}

pub(crate) async fn maintenance_task<S: 'static>(this: ErasedStore<S>, expires_after: Duration) {
    let check_interval = cmp::max(expires_after / 2, Duration::from_secs(60));
    let mut interval = tokio::time::interval(check_interval);
    loop {
        interval.tick().await;
        let deadline = expiry_deadline(utc_now_secs(), expires_after);
        if let Err(_e) = this.remove_before(deadline).await {
            crate::error!("session maintenance task failed to remove expired sessions");
        }
    }
}

fn expiry_deadline(now: u64, expires_after: Duration) -> u64 {
    now.saturating_sub(expires_after.as_secs())
}

pub(crate) fn is_expired(created_at: u64, expires_after: Duration) -> bool {
    created_at <= expiry_deadline(utc_now_secs(), expires_after)
}

#[cfg(test)]
mod expiry {
    use std::time::Duration;

    use crate::cookie::{CookieContext, MemStore};

    use super::expiry_deadline;

    #[test]
    fn cleanup_deadline_accounts_for_session_duration() {
        assert_eq!(expiry_deadline(10_000, Duration::from_secs(3_600)), 6_400);
        assert_eq!(expiry_deadline(10, Duration::from_secs(20)), 0);
    }

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
