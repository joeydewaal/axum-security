// #![allow(unused)]

type Result<O, E = anyhow::Error> = ::std::result::Result<O, E>;

#[cfg(feature = "oauth2")]
pub mod oauth2;

#[cfg(feature = "cookie")]
pub mod cookie;

#[cfg(feature = "oauth2")]
pub mod http;

#[cfg(feature = "jwt")]
pub mod jwt;

#[cfg(feature = "rbac")]
pub mod rbac;

pub(crate) mod utils;
