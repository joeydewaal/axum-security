// #![allow(unused)]

#[cfg(feature = "oauth2")]
pub mod oauth2;

#[cfg(feature = "cookie")]
pub mod cookie;

#[cfg(feature = "oauth2")]
pub mod http;

#[cfg(feature = "jwt")]
pub mod jwt;

#[cfg(feature = "basic-auth")]
pub mod basic_auth;

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
pub mod session;

#[cfg(feature = "rbac")]
pub mod rbac;

pub(crate) mod utils;
#[allow(unused)]
pub(crate) use utils::{debug, error};

#[cfg(feature = "headers")]
pub mod headers;
