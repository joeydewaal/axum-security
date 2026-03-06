use axum::response::IntoResponse;

pub use crate::after_login::AfterLoginCookies;

/// Tokens received after a successful OAuth 2.0 authorization code exchange.
pub struct TokenResponse {
    /// The access token issued by the provider.
    pub access_token: String,
    /// The refresh token, if the provider issued one.
    pub refresh_token: Option<String>,
}

/// Implement this trait to handle a successful OAuth 2.0 login.
///
/// After the authorization code exchange succeeds, [`after_login`](OAuth2Handler::after_login)
/// is called with the tokens and an [`AfterLoginCookies`] helper for setting response cookies.
pub trait OAuth2Handler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: TokenResponse,
        _context: &mut AfterLoginCookies<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}
