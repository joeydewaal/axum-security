//! OpenID Connect (OIDC) authentication.
//!
//! This module provides [`OidcContext`], which handles the full OIDC login flow:
//! redirecting to the identity provider, exchanging the authorization code,
//! verifying the ID token (signature, nonce, audience, expiration), and calling
//! your [`OidcHandler`] with the parsed claims and tokens.
//!
//! PKCE is always enabled. Nonce-based ID token replay protection is built in.
//!
//! Use [`OidcExt::with_oidc`] on a [`Router`](axum::Router) to register the
//! login, callback, and (optionally) logout routes.
//!
//! Built-in provider shortcuts: [`OidcContext::google`], [`OidcContext::microsoft`],
//! [`OidcContext::apple`], [`OidcContext::keycloak`].
//!
//! Two builder paths are available:
//! - [`OidcContext::discover`] — auto-discovery from an issuer URL
//! - [`OidcContext::builder`] — manual endpoint configuration

mod builder;
mod claims;
mod context;
mod cookie;
mod handler;
pub mod providers;
mod redirect;
mod router;

pub use builder::OidcBuilderError;
pub use claims::{OidcAddress, OidcClaims, UtcTimestamp};
pub use context::{LogoutContext, OidcContext};
pub use handler::OidcHandler;
pub use router::OidcExt;

pub use crate::after_login::AfterLoginCookies;

/// Tokens and claims received after a successful OIDC login.
pub struct OidcTokenResponse<'a> {
    /// The raw ID token JWT string.
    pub id_token: &'a str,
    /// Parsed and verified claims from the ID token.
    pub claims: OidcClaims<'a>,
    /// The access token issued by the provider.
    pub access_token: String,
    /// The refresh token, if the provider issued one.
    pub refresh_token: Option<String>,
}
