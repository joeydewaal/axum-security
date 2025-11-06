#![allow(unused)]

type Result<O, E = anyhow::Error> = ::std::result::Result<O, E>;

pub mod oauth2;
pub mod session;
pub mod store;
