//! A minimal OAuth2 client for the authorization code flow (RFC 6749),
//! written for the [axum-security](https://crates.io/crates/axum-security)
//! family but usable on its own.
//!
//! Compared to the `oauth2` crate this one has no typestate and no type
//! parameters: configuration is validated once at
//! [`build()`](OAuth2ClientBuilder::build), so client calls only fail for
//! reasons that can occur at request time. PKCE (RFC 7636) is always on.
//! Wrapper types exist only where they are security-load-bearing (redacted
//! `Debug`, constant-time comparison); everything else is `String`,
//! [`url::Url`] or [`std::time::Duration`].
//!
//! # Features
//!
//! - `reqwest` *(default)* — the [`reqwest`] backend for the [`HttpClient`]
//!   enum, plus a default client (no redirects, 10s timeout). Without any
//!   backend feature [`try_build`](OAuth2ClientBuilder::try_build) fails
//!   with [`ConfigError::NoHttpClient`].
//! - `rustls-tls` *(default)* — TLS for the reqwest backend via rustls.
//! - `native-tls` — TLS for the reqwest backend via the platform's native
//!   TLS library.
//!
//! # Example
//!
//! ```no_run
//! use axum_security_oauth2::{AuthorizationCode, OAuth2Client};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = OAuth2Client::builder()
//!     .client_id("my-client-id")
//!     .client_secret("my-client-secret")
//!     .auth_url("https://github.com/login/oauth/authorize")
//!     .token_url("https://github.com/login/oauth/access_token")
//!     .redirect_url("https://my-app.example/callback")
//!     .scopes(&["read:user"])
//!     .build(); // or try_build() to handle ConfigError
//!
//! // Leg 1: redirect the user to `login.url()`; persist the CSRF token
//! // and PKCE verifier (e.g. in a signed cookie) for the callback.
//! let login = client.start_login();
//! let (url, csrf_token, pkce_verifier) = login.into_parts();
//!
//! // Leg 2 (on the callback route): after comparing `csrf_token` with the
//! // `state` query parameter, exchange the code for tokens.
//! let code = AuthorizationCode::new("code-from-the-query-string");
//! let tokens = client.finish_login(code, &pkce_verifier).await?;
//! tokens.access_token().secret();
//! # Ok(())
//! # }
//! ```

mod builder;
mod client;
mod error;
mod http;
mod login;
mod pkce;
mod secret;
mod tokens;

pub use builder::{ConfigError, OAuth2ClientBuilder};
pub use client::OAuth2Client;
pub use error::{Error, ErrorCode, HttpError, ParseError, ServerError};
pub use http::HttpClient;
pub use login::Login;
pub use secret::{
    AccessToken, AuthorizationCode, ClientSecret, CsrfToken, PkceVerifier, RefreshToken,
};
pub use tokens::Tokens;
