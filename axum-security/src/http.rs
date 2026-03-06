//! HTTP client utilities for OAuth 2.0 / OIDC.

use oauth2::reqwest::{Client, redirect::Policy};

/// Create a reqwest client with redirects disabled (required for OAuth 2.0 flows).
pub fn default_reqwest_client() -> Client {
    ::oauth2::reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap()
}
