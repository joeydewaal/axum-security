use axum::response::IntoResponse;

use crate::after_login::AfterLoginCookies;

use super::OidcTokenResponse;

pub trait OidcHandler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: OidcTokenResponse,
        context: &mut AfterLoginCookies<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}
