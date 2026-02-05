use axum::{Extension, extract::Query, response::IntoResponse};
use cookie_monster::CookieJar;
use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use crate::{
    cookie::CookieStore,
    oauth2::{OAuth2Context, OAuthState},
};

#[derive(Deserialize, Debug)]
pub struct OAuth2Params {
    code: AuthorizationCode,
    state: CsrfToken,
}

pub(crate) async fn on_redirect<S>(
    Extension(context): Extension<OAuth2Context<S>>,
    Query(params): Query<OAuth2Params>,
    jar: CookieJar,
) -> impl IntoResponse
where
    S: CookieStore<State = OAuthState>,
{
    context.on_redirect(jar, params.code, params.state).await
}

pub async fn start_login<S: CookieStore<State = OAuthState>>(
    Extension(context): Extension<OAuth2Context<S>>,
) -> impl IntoResponse {
    context.start_challenge().await
}
