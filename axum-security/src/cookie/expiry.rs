use std::time::Duration;

use crate::{
    cookie::{CookieContext, CookieStore},
    utils::utc_now,
};

pub(crate) enum SessionExpiry {
    CookieMaxAge,
    Duration(Duration),
}

pub(crate) async fn maintenance_task<S: CookieStore>(
    this: CookieContext<S>,
    expires_after: Duration,
) {
    let deadline = utc_now() - expires_after;
    this.remove_after(deadline.as_secs()).await.unwrap();
    loop {
        tokio::time::sleep(expires_after).await;
        let deadline = utc_now() - expires_after;
        this.remove_after(deadline.as_secs()).await.unwrap();
    }
}
