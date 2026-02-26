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

pub(crate) mod utils;
#[allow(unused)]
pub(crate) use utils::{debug, error};

#[cfg(feature = "headers")]
pub mod headers;
