mod builder;
mod callback;
mod context;
mod inject;
pub mod providers;
mod response;

pub(crate) use callback::{callback, start_login};
pub use context::OAuth2Context;

use crate::cookie::SessionId;
pub use response::TokenResponse;

use ::oauth2::{CsrfToken, PkceCodeVerifier};
use axum::response::IntoResponse;

use oauth2::{EndpointNotSet, EndpointSet, basic::BasicClient};
pub(crate) type OAuth2ClientTyped =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

pub struct OAuthSessionState {
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

impl Clone for OAuthSessionState {
    fn clone(&self) -> Self {
        Self {
            csrf_token: self.csrf_token.clone(),
            pkce_verifier: PkceCodeVerifier::new(self.pkce_verifier.secret().clone()),
        }
    }
}

pub trait OAuth2Handler: Send + Sync + 'static {
    fn generate_session_id(&self) -> SessionId {
        SessionId::new_uuid_v7()
    }

    fn after_login(
        &self,
        token_res: TokenResponse,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}
