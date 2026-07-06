use std::time::Duration;

use axum::{http::StatusCode, response::IntoResponse};

pub use crate::after_login::AfterLoginCookies;

/// Tokens received after a successful OAuth 2.0 authorization code exchange.
pub struct TokenResponse {
    /// The access token issued by the provider.
    pub access_token: String,
    /// The refresh token, if the provider issued one.
    pub refresh_token: Option<String>,
    /// The lifetime of the access token, if the provider sent `expires_in`.
    pub expires_in: Option<Duration>,
}

/// An error the provider returned on the callback redirect
/// (RFC 6749 §4.1.2.1) instead of an authorization code — for example when
/// the user denies consent (`access_denied`).
#[derive(Debug, Clone)]
pub struct AuthorizationErrorResponse {
    /// The `error` code, e.g. `access_denied` or `invalid_scope`.
    pub error: String,
    /// The optional human-readable `error_description`.
    pub error_description: Option<String>,
    /// The optional `error_uri` pointing at documentation.
    pub error_uri: Option<String>,
}

/// Implement this trait to handle the outcome of an OAuth 2.0 login.
///
/// After the authorization code exchange succeeds, [`after_login`](OAuth2Handler::after_login)
/// is called with the tokens and an [`AfterLoginCookies`] helper for setting response cookies.
///
/// If the provider redirects back with an error instead (RFC 6749 §4.1.2.1),
/// [`on_error`](OAuth2Handler::on_error) is called; override it to render your
/// own page or redirect. The default returns `401 Unauthorized`.
pub trait OAuth2Handler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: TokenResponse,
        _context: &mut AfterLoginCookies<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;

    /// Called when the provider returns an authorization error on the
    /// callback (e.g. the user cancelled). The state cookie has already been
    /// cleared. The default renders `401 Unauthorized`.
    fn on_error(
        &self,
        error: AuthorizationErrorResponse,
    ) -> impl Future<Output = impl IntoResponse> + Send {
        async move {
            let _ = error;
            StatusCode::UNAUTHORIZED
        }
    }
}
