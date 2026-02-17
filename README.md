# axum-security
A security toolbox for the Axum library.

todo:
* OpenIDConnect
* Bearer Auth

* Docs
* Auth2 use cookies, cleanup pkce support

* Role based auth
* Policy Based auth

### Features
* `cookie`, adds support for cookie sessions.
* `jwt`, adds support for jwt sessions.
* `oauth2`, adds support for oauth2.
* `jiff`, adds support for the [jiff](https://docs.rs/jiff/latest/jiff/) crate.
* `chrono`, adds support for the [chrono](https://docs.rs/chrono/latest/chrono/) crate.
* `time`, adds support for the [time](https://docs.rs/time/latest/time/index.html) crate.


## Cookie sessions
### Config
```rust
let cookie_service = CookieContext::builder()
    .cookie(|c| {
        c.name("session")
            .max_age(Duration::from_hours(24))
            .secure()
            .http_only()
            .same_site(SameSite::Strict)
    })
    .dev_cookie(|c| c.name("dev-session"))
    .use_dev_cookie(cfg!(debug_assertions)) // use dev cookies in debug mode
    .store(MemStore::new())
    .expires_max_age()
    .build::<User>();

let router = Router::new()
    .route("/", get(maybe_authorized))
    .route("/login", get(login))
    .layer(cookie_service.clone()) // Inject the cookie service into this router.
    .with_state(cookie_service);
```

### Managing sessions
```rust
async fn login(
    session: CookieContext<User>,
    Query(login): Query<LoginAttempt>,
) -> impl IntoResponse {
    if login.username == "admin" && login.password == "admin" {
        let user = User {
            username: login.username,
            email: None,
            created_at: Timestamp::now(),
        };

        let cookie = session.create_session(user).await.unwrap();

        (Some(cookie), "Logged in")
    } else {
        (None, "failed to log in")
    }
}

async fn logout(context: CookieContext<User>, jar: CookieJar) -> impl IntoResponse {
    match context.remove_session_jar(&jar).await.unwrap() {
        Some(e) => format!("Removed: {}", e.state.username),
        None => "No session found".to_string(),
    }
}
```

### Extractors
```rust
async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

async fn maybe_authorized(user: Option<CookieSession<User>>) -> String {
    if let Some(user) = user {
        format!("Hi, {}", user.state.username)
    } else {
        "You are not logged in.".to_string()
    }
}
```

## Jwt sessions
### Config
```rust
static JWT_SECRET: &str = "my-secure-jwt-secret";

let jwt_service = JwtContext::builder()
    .jwt_secret(JWT_SECRET)
    .build::<AccessToken>();

// The jwt service is also used as state to create jwt's.
let state = jwt_service.clone();

let router = Router::new()
    .route("/", get(maybe_authorized))
    .route("/me", get(authorized))
    .route("/login", get(login))
    .layer(jwt_service)
    .with_state(state);
```

### Managing jwt's
```rust
async fn login(
    context: JwtContext<AccessToken>,
    Query(login): Query<LoginAttempt>,
) -> Result<String, StatusCode> {
    if login.username == "admin" && login.password == "admin" {
        let now = Timestamp::now();

        // This token is only valid for 1 day.
        let expires = now + 24.hours();

        let user = AccessToken {
            username: login.username,
            emailadres: None,
            created_at: now,
            exp: expires,
        };

        context
            .encode_token(&user)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}
```

### Extractors
```rust
async fn authorized(Jwt(token): Jwt<AccessToken>) -> Json<AccessToken> {
    Json(token)
}

async fn maybe_authorized(token: Option<Jwt<AccessToken>>) -> String {
    if let Some(Jwt(token)) = token {
        format!("Hi, {}", token.username)
    } else {
        "You are not logged in.".to_string()
    }
}
```

## OAuth2 support
### Config
```rust
struct LoginHandler;

impl OAuth2Handler for LoginHandler {
    async fn after_login(
        &self,
        token_res: TokenResponse,
        context: &mut AfterLoginCookies<'_>,
    ) -> impl IntoResponse {
        self.handle_login(token_res, context).await
    }
}

let oauth2_service = OAuth2Context::builder()
    .auth_url(github::AUTH_URL)
    .token_url(github::TOKEN_URL)
    .client_id_env("CLIENT_ID")
    .client_secret_env("CLIENT_SECRET")
    .redirect_url("http://localhost:3000/redirect")
    .login_path("/login")
    .cookie(|c| c.path("/login"))
    .store(MemStore::new())
    .build(LoginHandler);

let router = Router::new()
    .route("/me", get(authorized))
    .layer(cookie_service)
    .with_oauth2(oauth2_service);
```

## Role-base access control

## Security headers


### License
This project is licensed under the [MIT license].

[MIT license]: https://github.com/joeydewaal/axum-security/blob/main/LICENSE
