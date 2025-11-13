#![allow(unused)]

type Result<O, E = anyhow::Error> = ::std::result::Result<O, E>;

pub mod oauth2;
mod router_ext;
pub mod session;
pub mod store;

pub mod cookie;
pub mod http;
pub mod jwt;

pub use router_ext::RouterExt;
