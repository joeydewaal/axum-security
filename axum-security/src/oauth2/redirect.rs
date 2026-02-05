use axum::{Extension, extract::Query, response::IntoResponse};
use cookie_monster::CookieJar;
use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use crate::oauth2::OAuth2Context;

#[derive(Deserialize, Debug)]
pub struct OAuth2Params {
    code: AuthorizationCode,
    state: CsrfToken,
}

pub(crate) async fn on_redirect(
    Extension(context): Extension<OAuth2Context>,
    Query(params): Query<OAuth2Params>,
    jar: CookieJar,
) -> impl IntoResponse {
    context.on_redirect(jar, params.code, params.state).await
}

pub async fn start_login(Extension(context): Extension<OAuth2Context>) -> impl IntoResponse {
    context.start_challenge().await
}
