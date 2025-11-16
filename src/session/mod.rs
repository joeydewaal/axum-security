use axum::http::request::Parts;

use crate::cookie::CookieSession;

pub trait HttpSession: Send + Sync + 'static {
    type State: Send + Sync + 'static;

    fn load_from_request_parts(
        &self,
        parts: &mut Parts,
    ) -> impl Future<Output = Option<CookieSession<Self::State>>> + Send;
}
