use axum::{Extension, extract::Query, response::IntoResponse};
use cookie_monster::CookieJar;
use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

use crate::{
    cookie::SessionStore,
    oauth2::{OAuth2Context, OAuth2Handler, OAuthSessionState},
};

#[derive(Deserialize)]
pub struct OAuth2Params {
    code: AuthorizationCode,
    state: CsrfToken,
}

pub(crate) async fn callback<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>>(
    Extension(context): Extension<OAuth2Context<T, S>>,
    Query(params): Query<OAuth2Params>,
    jar: CookieJar,
) -> impl IntoResponse {
    context.callback(jar, params.code, params.state).await
}

pub async fn start_login<T: OAuth2Handler, S: SessionStore<State = OAuthSessionState>>(
    Extension(context): Extension<OAuth2Context<T, S>>,
) -> impl IntoResponse {
    context.start_challenge().await
}
