use std::{borrow::Cow, sync::Arc};

mod builder;
mod client;
mod router;

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
        builder::Oauth2ContextBuilder,
        client::{OAuth2Client, OAuth2ClientBuilder, TokenResponse},
    },
    store::MemoryStore,
};

pub struct OAuth2Context<T>(Arc<OAuth2ContextInner<T>>);

impl<T> Clone for OAuth2Context<T> {
    fn clone(&self) -> Self {
        OAuth2Context(self.0.clone())
    }
}

struct OAuth2ContextInner<T> {
    inner: T,
    client: OAuth2Client,
    store: MemoryStore,
    cookie_opts: CookieBuilder,
}
impl OAuth2Context<()> {
    pub fn builder() -> Oauth2ContextBuilder {
        Oauth2ContextBuilder::builder()
    }
}

impl<T: OAuth2Handler> OAuth2Context<T> {
    async fn start_challenge(&self) -> axum::response::Response {
        let (state, url) = self.0.client.authorization_url("random csrf token");
        // Create authorize url, with csrf token

        // Store CSRF token on the server somewhere temp. (session)
        let session_id = self.0.inner.generate_session_id();
        self.0.store.write(&session_id, &state).await;

        // Send session cookie back
        let mut cookie = self.0.cookie_opts.clone().value(session_id).build();

        (cookie, Redirect::to(&url)).into_response()
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
    // retrieve csrf token from session
    let Some(state) = context.0.store.remove(cookie.value()).await else {
        return ().into_response();
    };

    let (req_code, req_state): (String, String) = todo!("get from req");

    // verify that csrf token is equal
    if state != req_code {
        // bad req
        return ().into_response();
    }

    // exchange authorization code
    let token_response = context.0.client.exchange_code(&req_code).await;

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

pub trait OAuth2Handler: Send + Sync + 'static {
    fn generate_session_id(&self) -> String {
        Uuid::now_v7().to_string()
    }

    fn after_login(
        &self,
        token_res: TokenResponse,
    ) -> impl Future<Output = crate::Result<impl IntoResponse>> + Send {
        async { Ok(().into_response()) }
    }
}

impl<S: Send + Sync, T> FromRequestParts<S> for OAuth2Context<T>
where
    OAuth2Context<T>: FromRef<S>,
{
    type Rejection = ();
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(OAuth2Context::from_ref(state))
    }
}

#[cfg(test)]
mod oauth2 {
    use std::time::Duration;

    use axum::{
        Router,
        extract::FromRef,
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
        store::MemoryStore,
    };

    struct Oauth2Backend {
        store: MemoryStore,
        channel: Sender<()>,
    }

    impl Oauth2Backend {
        pub fn new(chan: Sender<()>) -> Self {
            Oauth2Backend {
                store: MemoryStore::new(),
                channel: chan,
            }
        }
    }

    impl OAuth2Handler for Oauth2Backend {
        async fn after_login(&self, res: TokenResponse) -> crate::Result<impl IntoResponse> {
            println!("user logged in");
            println!("at: {}", res.access_token());
            println!("refresh token:: {:?}", res.refresh_token());

            self.channel.send(()).await;

            Ok(Redirect::to("/"))
        }
    }

    #[tokio::test]
    async fn test1() -> crate::Result<()> {
        let (tx, mut rx) = mpsc::channel(1);

        let context = OAuth2Context::builder()
            .callback_url("/callback")
            .client_id("client_id")
            .client_secret("secret")
            .cookie_opts(|cookie| {
                if cfg!(debug_assertions) {
                    cookie.http_only()
                } else {
                    cookie.http_only().secure()
                }
            })
            .build(Oauth2Backend::new(tx));

        let router = Router::new()
            .route("/", get(|| async { "hello world" }))
            .route("/login", get(login))
            .with_oauth2(&context)
            .with_state(context);

        async fn login(context: OAuth2Context<Oauth2Backend>) -> impl IntoResponse {
            context.start_challenge().await
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
