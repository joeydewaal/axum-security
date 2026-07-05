//! OAuth 2.0 authorization code flow.
//!
//! This module provides [`OAuth2Context`], which handles the full OAuth 2.0
//! login flow: redirecting to the provider, exchanging the authorization code
//! for tokens, and calling your [`OAuth2Handler`] with the result.
//!
//! Use [`OAuth2Ext::with_oauth2`] on a [`Router`](axum::Router) to register
//! the login and callback routes.
//!
//! Built-in provider shortcuts: [`OAuth2Context::github`], [`OAuth2Context::google`],
//! [`OAuth2Context::microsoft`], [`OAuth2Context::gitlab`], [`OAuth2Context::discord`],
//! [`OAuth2Context::spotify`], [`OAuth2Context::twitch`].

mod builder;
mod context;
mod cookie;
mod handler;
pub mod providers;
mod redirect;
mod router;

pub use axum_security_oauth2::AuthType;
pub use builder::OAuth2BuilderError;
pub use context::OAuth2Context;
pub use handler::{AfterLoginCookies, OAuth2Handler, TokenResponse};
pub use router::OAuth2Ext;
