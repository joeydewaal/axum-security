use std::{borrow::Cow, sync::Arc};

mod builder;
mod client;
mod router;

use ::oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse as _,
};
use axum::{
    Extension,
    extract::{FromRef, FromRequest, FromRequestParts, Request, State},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use cookie_monster::{Cookie, CookieBuilder, CookieJar, SameSite};
use uuid::{Timestamp, Uuid};

use crate::{
    oauth2::{
        builder::{OAuth2ClientTyped, Oauth2ContextBuilder},
        client::{OAuth2Client, OAuth2ClientBuilder, TokenResponse},
    },
    session::{Session, SessionId, SessionStore},
    store::MemoryStore,
};

pub struct OAuth2Context<T>(Arc<OAuth2ContextInner<T>>);

impl<T> Clone for OAuth2Context<T> {
    fn clone(&self) -> Self {
        OAuth2Context(self.0.clone())
    }
}

struct OAuthSessionState {
    csrf_token: CsrfToken,
    pkce_verifier: PkceCodeVerifier,
}

struct OAuth2ContextInner<T> {
    inner: T,
    client: OAuth2ClientTyped,
    store: MemoryStore<OAuthSessionState>,
    cookie_opts: CookieBuilder,
    start_challenge_path: Option<String>,
    scopes: Vec<Scope>,
    http_client: ::oauth2::reqwest::Client,
}
impl OAuth2Context<()> {
    pub fn builder() -> Oauth2ContextBuilder {
        Oauth2ContextBuilder::builder()
    }
}

impl<T: OAuth2Handler> OAuth2Context<T> {
    pub(crate) fn callback_url(&self) -> String {
        let x = self
            .0
            .client
            .redirect_uri()
            .unwrap()
            .split("/")
            .nth(1)
            .unwrap();

        format!("/{x}")
    }

    async fn start_challenge(&self) -> axum::response::Response {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let req = self.0.client.authorize_url(CsrfToken::new_random);

        // Create authorize url, with csrf token
        let (url, csrf_token) = req
            .add_scopes(self.0.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        // Store CSRF token on the server somewhere temp. (session)
        let session_id = self.0.inner.generate_session_id();
        let session = Session::new(
            session_id.clone(),
            OAuthSessionState {
                csrf_token,
                pkce_verifier,
            },
        );
        self.0.store.store_session(session).await;

        // Send session cookie back
        let mut cookie = self.0.cookie_opts.clone().value(session_id).build();

        (cookie, Redirect::to(url.as_str())).into_response()
    }
}
async fn callback<T: OAuth2Handler>(
    Extension(context): Extension<OAuth2Context<T>>,
    req: Request,
) -> impl IntoResponse {
    // get session cookie
    let jar: CookieJar = CookieJar::from_headers(req.headers());
    let Some(cookie) = jar.get(context.0.cookie_opts.get_name()) else {
        return ().into_response();
    };

    // load session
    let session_id = SessionId::from_cookie(cookie);

    // retrieve csrf token from session
    let Some(session) = context.0.store.remove_session(&session_id).await else {
        return ().into_response();
    };

    let OAuthSessionState {
        csrf_token,
        pkce_verifier,
    } = session.into_state();

    let (req_code, req_state): (AuthorizationCode, CsrfToken) = todo!("get from req");

    // verify that csrf token is equal
    if csrf_token.secret() != req_state.secret() {
        // bad req
        return ().into_response();
    }

    // exchange authorization code
    let response = context
        .0
        .client
        .exchange_code(req_code)
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
        .unwrap()
        .into_response()
}

async fn start_challenge<T: OAuth2Handler>(
    Extension(context): Extension<OAuth2Context<T>>,
) -> impl IntoResponse {
    context.start_challenge().await
}

pub trait OAuth2Handler: Send + Sync + 'static {
    fn generate_session_id(&self) -> SessionId {
        SessionId::new_uuid_v7()
    }

    fn after_login(
        &self,
        token_res: TokenResponse,
    ) -> impl Future<Output = crate::Result<impl IntoResponse>> + Send;
}

#[cfg(test)]
mod oauth2 {
    use std::time::Duration;

    use axum::{
        Router,
        extract::{FromRef, State},
        response::{IntoResponse, Redirect},
        routing::get,
        serve,
    };
    use tokio::{
        net::TcpListener,
        sync::mpsc::{self, Sender},
    };

    use crate::{
        oauth2::{OAuth2Context, OAuth2Handler, client::TokenResponse, router::RouterOAuthExt},
        session::{Session, SessionId, SessionStore},
        store::MemoryStore,
    };

    struct Oauth2Backend {
        channel: Sender<()>,
        session: MemoryStore<User>,
    }

    impl Oauth2Backend {
        pub fn new(channel: Sender<()>, session: MemoryStore<User>) -> Self {
            Oauth2Backend { channel, session }
        }
    }

    struct User {
        id: String,
        username: String,
    }

    impl OAuth2Handler for Oauth2Backend {
        async fn after_login(&self, res: TokenResponse) -> crate::Result<impl IntoResponse> {
            println!("user logged in");
            println!("at: {}", res.access_token());
            println!("refresh token:: {:?}", res.refresh_token());

            let id = todo!();
            let username = todo!();

            let user = User { id, username };

            let session = Session::new(SessionId::new_uuid_v7(), user);

            self.session.store_session(session).await;

            self.channel.send(()).await;

            Ok(Redirect::to("/"))
        }
    }

    #[tokio::test]
    async fn test1() -> crate::Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        let session = MemoryStore::new();

        let context = OAuth2Context::builder()
            .redirect_uri("")
            .client_id("")
            .client_secret("")
            .start_challenge_path("/login")
            .cookie_opts(|cookie| cookie.http_only().secure())
            .build(Oauth2Backend::new(tx, session.clone()));

        let router = Router::new()
            .route("/", get(|| async { "hello world" }))
            .route("/authorized", get(authorized))
            .with_oauth2(&context)
            .with_state(session);

        async fn authorized(user: Session<User>) -> String {
            user.into_state().username
        }

        let listener = TcpListener::bind("0.0.0.0:3000").await?;

        serve(listener, router)
            .with_graceful_shutdown(async move {
                rx.recv().await;
            })
            .await;
        Ok(())
    }
}
