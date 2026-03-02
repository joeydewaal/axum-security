use axum::response::IntoResponse;

use crate::after_login::AfterLoginCookies;

use super::{OidcTokenResponse, context::LogoutContext};

pub trait OidcHandler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: OidcTokenResponse,
        context: &mut AfterLoginCookies<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;

    fn logout(&self, context: LogoutContext) -> impl Future<Output = impl IntoResponse> + Send {
        async move { context.default_redirect() }
    }
}
