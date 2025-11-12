use axum::{Extension, extract::Query, response::IntoResponse};
use cookie_monster::CookieJar;
use oauth2::{AuthorizationCode, CsrfToken, TokenResponse as _};
use serde::Deserialize;

use crate::{
    oauth2::{OAuth2Context, OAuth2Handler, OAuthSessionState, TokenResponse},
    session::{SessionId, SessionStore},
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
    // get session cookie
    let Some(cookie) = jar.get(context.0.cookie_opts.get_name()) else {
        return ().into_response();
    };

    // load session
    let session_id = SessionId::from_cookie(cookie);

    // retrieve csrf token from session
    let Some(session) = context.0.session.remove_session(&session_id).await else {
        return ().into_response();
    };

    let OAuthSessionState {
        csrf_token,
        pkce_verifier,
    } = session.into_state();

    // verify that csrf token is equal
    if csrf_token.secret() != params.state.secret() {
        // bad req
        return ().into_response();
    }

    // exchange authorization code
    let response = context
        .0
        .client
        .exchange_code(params.code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(&context.0.http_client)
        .await
        .unwrap();

    let access_token = response.access_token().secret().clone();
    let refresh_token = response.refresh_token().map(|t| t.secret().clone());

    let token_response = TokenResponse {
        access_token,
        refresh_token,
    };

    // tada, access token, maybe refresh token.

    // after login callback
    context
        .0
        .inner
        .after_login(token_response)
        .await
        .into_response()
}
