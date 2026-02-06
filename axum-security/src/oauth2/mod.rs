mod builder;
mod context;
mod handler;
mod inject;
pub mod providers;
mod redirect;

pub use builder::OAuth2BuilderError;
pub use context::OAuth2Context;
pub use handler::{AfterLoginCookies, OAuth2Handler, TokenResponse};
pub use inject::OAuth2Ext;
pub(crate) use redirect::{on_redirect, start_login};

use ::oauth2::{CsrfToken, PkceCodeVerifier};

use oauth2::{EndpointNotSet, EndpointSet, basic::BasicClient};
pub(crate) type OAuth2ClientTyped =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct OAuthState {
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

impl Clone for OAuthState {
    fn clone(&self) -> Self {
        Self {
            csrf_token: self.csrf_token.clone(),
            pkce_verifier: PkceCodeVerifier::new(self.pkce_verifier.secret().clone()),
        }
    }
}
