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
pub use context::OidcContext;
pub use handler::OidcHandler;
pub use router::OidcExt;

pub use crate::after_login::AfterLoginCookies;

pub struct OidcTokenResponse {
    pub claims: OidcClaims,
    pub access_token: String,
    pub refresh_token: Option<String>,
}
