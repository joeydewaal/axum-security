mod builder;
mod context;
mod handler;
pub mod providers;
mod redirect;
mod router;

pub use builder::OAuth2BuilderError;
pub use context::OAuth2Context;
pub use handler::{AfterLoginCookies, OAuth2Handler, TokenResponse};
pub(crate) use redirect::{on_redirect, start_login};
pub use router::OAuth2Ext;

use oauth2::{CsrfToken, EndpointNotSet, EndpointSet, PkceCodeVerifier, basic::BasicClient};

pub(crate) type OAuth2ClientTyped =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct OAuthState {
    csrf_token: CsrfToken,
    pkce_verifier: Option<PkceCodeVerifier>,
}

impl Clone for OAuthState {
    fn clone(&self) -> Self {
        Self {
            csrf_token: self.csrf_token.clone(),
            pkce_verifier: self
                .pkce_verifier
                .as_ref()
                .map(|verifier| PkceCodeVerifier::new(verifier.secret().clone())),
        }
    }
}
