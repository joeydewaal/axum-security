//! A minimal OpenID Connect client library, part of the
//! [axum-security](https://crates.io/crates/axum-security) workspace and
//! layered on [`axum-security-oauth2`](https://crates.io/crates/axum-security-oauth2)
//! for the OAuth2 half of the flow.
//!
//! Compared to the [`openidconnect`](https://crates.io/crates/openidconnect)
//! crate this one has no typestate and no type parameters: ID tokens are
//! verified with a single concrete [`IdTokenVerifier`], and the standard claim
//! set is a plain [`OidcClaims`] struct with `&str` fields plus an `extra` map
//! for everything nonstandard.
//!
//! This first slice is the **verification core**: given a JWK set and an ID
//! token, [`IdTokenVerifier::verify`] checks the signature (with algorithm
//! allow-listing), the `iss`/`aud`/`exp`/`nbf` claims, and the `nonce`, using
//! [`jsonwebtoken`] on top of `aws-lc-rs`. Discovery, JWKS fetching/caching, the
//! login flow, and RP-initiated logout are layered on in later phases.
//!
//! # Example
//!
//! ```
//! use axum_security_oidc::{IdTokenVerifier, JwkSet};
//!
//! # fn example(jwks_json: &str, id_token: &str, expected_nonce: &str)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! let jwks: JwkSet = serde_json::from_str(jwks_json)?;
//! let verifier = IdTokenVerifier::new("https://issuer.example", "my-client-id", jwks);
//!
//! let verified = verifier.verify(id_token, expected_nonce)?;
//! let claims = verified.claims()?;
//! let _subject = claims.subject;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - `jiff` / `chrono` / `time` — add typed timestamp accessors to
//!   [`OidcClaims`] / [`UtcTimestamp`]. Off by default; the core exposes raw
//!   unix seconds (`i64`).

mod claims;
mod error;
mod verifier;

pub use claims::{OidcAddress, OidcClaims, UtcTimestamp};
pub use error::{ClaimsError, VerifyError};
pub use verifier::{IdTokenVerifier, VerifiedIdToken};

/// Re-exported from [`jsonwebtoken`]: the signing-algorithm enum for
/// [`IdTokenVerifier::algorithms`], and the JWK-set type
/// [`IdTokenVerifier::new`] takes.
pub use jsonwebtoken::{Algorithm, jwk::JwkSet};
