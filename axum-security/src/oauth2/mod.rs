mod builder;
mod callback;
mod context;
mod handler;
mod inject;
pub mod providers;

pub(crate) use callback::{callback, start_login};
pub use context::OAuth2Context;
pub use handler::{AfterLoginContext, OAuth2Handler, TokenResponse};

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
