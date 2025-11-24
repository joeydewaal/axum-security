use std::borrow::Cow;

use axum::response::IntoResponse;
use cookie_monster::{CookieBuilder, CookieJar};

use crate::cookie::SessionId;

#[non_exhaustive]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub trait OAuth2Handler: Send + Sync + 'static {
    fn generate_session_id(&self) -> SessionId {
        SessionId::new_uuid_v7()
    }

    fn after_login(
        &self,
        token_res: TokenResponse,
        _context: &mut AfterLoginContext<'_>,
    ) -> impl Future<Output = impl IntoResponse> + Send;
}

pub struct AfterLoginContext<'a> {
    pub cookies: CookieJar,
    pub(crate) cookie_opts: &'a CookieBuilder,
}

impl AfterLoginContext<'_> {
    pub fn cookie(&self, name: impl Into<Cow<'static, str>>) -> CookieBuilder {
        self.cookie_opts.clone().name(name)
    }
}
