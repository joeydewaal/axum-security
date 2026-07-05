//! A minimal OAuth2 client for the authorization code flow (RFC 6749),
//! written for the [axum-security](https://crates.io/crates/axum-security)
//! family but usable on its own.
//!
//! Compared to the `oauth2` crate this one has no typestate and no type
//! parameters: configuration is validated once at
//! [`build()`](OAuth2ClientBuilder::build), so client calls only fail for
//! reasons that can occur at request time. PKCE (RFC 7636) is on for the
//! default [`start_login`](OAuth2Client::start_login)/
//! [`finish_login`](OAuth2Client::finish_login) pair; explicit `_non_pkce`
//! variants exist for providers that reject the PKCE parameters.
//! Values are plain `String`, [`url::Url`] or [`std::time::Duration`], with
//! one wrapper: [`CsrfToken`], whose `==` compares in constant time.
//! Secrets stay out of logs because every crate type that holds one (the
//! client, [`Login`], [`Tokens`], [`CsrfToken`], errors) redacts it in its
//! `Debug` output — but a secret *you* store is a plain string, so keep it
//! out of your own `Debug`/`Display` impls.
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
//! use axum_security_oauth2::OAuth2Client;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Provider shortcuts (github, google, microsoft, gitlab, discord, spotify, twitch)
//! // preset the endpoints; OAuth2Client::builder() takes them explicitly.
//! let client = OAuth2Client::github()
//!     .client_id("my-client-id")
//!     .client_secret("my-client-secret")
//!     .redirect_url("https://my-app.example/callback")
//!     .scopes(&["read:user"])
//!     .build(); // or try_build() to handle ConfigError
//!
//! // Leg 1: redirect the user to `login.url`; persist the CSRF token
//! // and PKCE verifier (e.g. in a signed cookie) for the callback.
//! let login = client.start_login();
//! let (url, csrf_token, pkce_verifier) = login.into_parts();
//!
//! // Leg 2 (on the callback route): compare `csrf_token` with the `state`
//! // query parameter (constant-time via `==`), then exchange the code.
//! let state = "state-from-the-query-string";
//! assert!(csrf_token == state); // reject the callback if this fails
//! let code = "code-from-the-query-string";
//! let tokens = client.finish_login(code, &pkce_verifier).await?;
//! let _access_token = tokens.access_token;
//! # Ok(())
//! # }
//! ```

mod builder;
mod client;
mod csrf;
mod error;
mod http;
mod login;
mod pkce;
mod rand;
mod tokens;

pub use builder::{ConfigError, OAuth2ClientBuilder};
pub use client::OAuth2Client;
pub use csrf::CsrfToken;
pub use error::{Error, ErrorCode, HttpError, ParseError, ServerError};
pub use http::HttpClient;
pub use login::{Login, LoginNonPkce};
pub use tokens::Tokens;
