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

pub struct OidcTokenResponse<'a> {
    pub id_token: &'a str,
    pub claims: OidcClaims<'a>,
    pub access_token: String,
    pub refresh_token: Option<String>,
}
