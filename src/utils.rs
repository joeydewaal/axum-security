use std::env;

pub fn get_env(name: &str) -> String {
    env::var(name)
        .map_err(|_| format!("env: {name} does not exist"))
        .unwrap()
}
