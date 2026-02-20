mod builder;
mod context;
mod cookie;
mod handler;
pub mod providers;
mod redirect;
mod router;

pub use builder::OAuth2BuilderError;
pub use context::OAuth2Context;
pub use handler::{AfterLoginCookies, OAuth2Handler, TokenResponse};
pub(crate) use redirect::{on_redirect, start_login};
pub use router::OAuth2Ext;

use oauth2::{EndpointNotSet, EndpointSet, basic::BasicClient};

pub(crate) type OAuth2ClientTyped =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;
