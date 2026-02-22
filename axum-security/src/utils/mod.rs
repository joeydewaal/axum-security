use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[allow(unused)]
macro_rules! debug {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        tracing::debug!($($arg)*);
    }};
}
pub(crate) use debug;

#[allow(unused)]
macro_rules! error {
    ($($arg:tt)*) => {{
        #[cfg(feature = "tracing")]
        tracing::error!($($arg)*);
    }};
}
pub(crate) use error;

#[cfg(feature = "headers")]
pub mod headers;

#[allow(unused)]
pub(crate) fn get_env(name: &str) -> String {
    env::var(name)
        .map_err(|_| format!("env: {name} does not exist"))
        .unwrap()
}

#[allow(unused)]
pub fn utc_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
}
#[allow(unused)]
pub fn utc_now_secs() -> u64 {
    utc_now().as_secs()
}
