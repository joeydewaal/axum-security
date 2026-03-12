//! Security middleware and extractors for [axum](https://docs.rs/axum).
//!
//! `axum-security` is a modular toolkit — enable only the features you need.
//! Every feature adds a module with Tower middleware and/or axum extractors.
//!
//! # Features
//!
//! | Feature | Module | Description |
//! |---------|--------|-------------|
//! | `cookie` | [`cookie`] | Server-side session management with pluggable stores |
//! | `jwt` | [`jwt`] | JWT authentication (header or cookie) |
//! | `basic-auth` | [`basic_auth`] | HTTP Basic Authentication |
//! | `oauth2` | [`oauth2`] | OAuth 2.0 authorization code flow |
//! | `oidc` | [`oidc`] | OpenID Connect (auto-discovery, ID token verification) |
//! | `rbac` | [`rbac`] | Role-based access control |
//! | `pbac` | [`pbac`] | Policy-based access control |
//! | `headers` | [`headers`] | Security response headers (CSP, HSTS, etc.) |
//! | `csrf` | [`csrf`] | CSRF protection (double-submit cookie) |
//! | `rate-limit` | [`rate_limit`] | Rate limiting (fixed window / token bucket) |
//!
//! Additional features: `macros`, `tracing`.
//!
//! # Session types
//!
//! The `cookie`, `jwt`, and `basic-auth` features each insert a session type
//! into request extensions. The [`session::Session`] enum unifies all three,
//! allowing downstream middleware (RBAC, PBAC, rate limiting) to work with
//! any authentication method.

#[cfg(any(feature = "oauth2", feature = "oidc"))]
pub(crate) mod after_login;

#[cfg(any(feature = "oauth2", feature = "oidc"))]
pub(crate) mod signed_cookie;

#[cfg(feature = "oauth2")]
pub mod oauth2;

#[cfg(feature = "oidc")]
pub mod oidc;

#[cfg(feature = "cookie")]
pub mod cookie;

#[cfg(feature = "jwt")]
pub mod jwt;

#[cfg(feature = "basic-auth")]
pub mod basic_auth;

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
pub mod session;

#[cfg(all(
    feature = "rbac",
    any(feature = "jwt", feature = "cookie", feature = "basic-auth")
))]
pub mod rbac;

#[cfg(all(
    feature = "pbac",
    any(feature = "jwt", feature = "cookie", feature = "basic-auth")
))]
pub mod pbac;

#[cfg(any(feature = "cookie", feature = "csrf"))]
pub(crate) mod cookie_options;

pub(crate) mod utils;
#[allow(unused)]
pub(crate) use utils::{debug, error};

#[cfg(feature = "headers")]
pub mod headers;

#[cfg(feature = "csrf")]
pub mod csrf;

#[cfg(feature = "rate-limit")]
pub mod rate_limit;
