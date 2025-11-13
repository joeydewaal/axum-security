use oauth2::reqwest::{Client, redirect::Policy};

pub fn default_reqwest_client() -> Client {
    ::oauth2::reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap()
}
