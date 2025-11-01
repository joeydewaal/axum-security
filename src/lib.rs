#![allow(unused)]

type Result<O, E = anyhow::Error> = ::std::result::Result<O, E>;

pub mod oauth2;
mod session;
pub mod store;
