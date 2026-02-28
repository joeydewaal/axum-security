use axum::response::IntoResponse;

pub use crate::after_login::AfterLoginCookies;

pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub trait OAuth2Handler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: TokenResponse,
        _context: &mut AfterLoginCookies<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}
