use axum::response::IntoResponse;

use crate::after_login::AfterLoginCookies;

use super::{OidcTokenResponse, context::LogoutContext};

/// Implement this trait to handle a successful OIDC login.
///
/// After ID token verification succeeds, [`after_login`](OidcHandler::after_login)
/// is called with the tokens/claims and an [`AfterLoginCookies`] helper.
///
/// Override [`logout`](OidcHandler::logout) to customize the logout behavior.
/// The default implementation redirects to the provider's end-session endpoint
/// (if configured) or `/`.
pub trait OidcHandler: Send + Sync + 'static {
    fn after_login(
        &self,
        token_res: OidcTokenResponse<'_>,
        context: &mut AfterLoginCookies<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;

    fn logout(&self, context: LogoutContext) -> impl Future<Output = impl IntoResponse> + Send {
        async move { context.default_redirect() }
    }
}
