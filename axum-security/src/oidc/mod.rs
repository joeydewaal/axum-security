mod builder;
mod context;
mod cookie;
mod handler;
pub mod providers;
mod redirect;
mod router;

pub use builder::OidcBuilderError;
pub use context::OidcContext;
pub use handler::OidcHandler;
pub use router::OidcExt;

pub use crate::after_login::AfterLoginCookies;

use openidconnect::{EmptyAdditionalClaims, IdTokenClaims, core::CoreGenderClaim};

pub struct OidcTokenResponse {
    pub claims: IdTokenClaims<EmptyAdditionalClaims, CoreGenderClaim>,
    pub access_token: String,
    pub refresh_token: Option<String>,
}
