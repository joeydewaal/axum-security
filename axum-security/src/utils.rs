use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn get_env(name: &str) -> String {
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
