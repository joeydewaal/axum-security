# axum-security

A security toolkit for Axum.

## Features

`axum-security` is modular -- enable only what you need.

| Feature | Description |
|---------|-------------|
| `cookie` | Server-side session management with pluggable stores |
| `jwt` | JWT authentication (header or cookie) |
| `basic-auth` | HTTP Basic Authentication |
| `oauth2` | OAuth 2.0 authorization code flow |
| `oidc` | OpenID Connect (auto-discovery, ID token verification) |
| `rbac` | Role-based access control |
| `pbac` | Policy-based access control |
| `headers` | Security response headers (CSP, HSTS, etc.) |
| `csrf` | CSRF protection (double-submit cookie) |
| `rate-limit` | Rate limiting (fixed window / token bucket) |

Additional features: `macros`, `tracing`.

Time crate integration: `jiff`, `chrono`, `time`.

## Installation

```sh
cargo add axum-security --features cookie,jwt
```

Pick the features you need. No features are enabled by default.

## Cookie sessions

The `cookie` feature provides server-side session management. Sessions are stored in a pluggable store (an in-memory store is included for development).

```rust
use axum_security::cookie::{CookieContext, CookieSession, MemStore, SameSite};

// Build the cookie service
let cookie_service = CookieContext::builder()
    .cookie(|c| {
        c.name("session")
            .max_age(Duration::from_hours(24))
            .secure()
            .http_only()
            .same_site(SameSite::Strict)
    })
    .dev_cookie(|c| c.name("dev-session"))
    .use_dev_cookie(cfg!(debug_assertions))
    .store(MemStore::new())
    .expires_max_age()
    .build::<User>();

let router = Router::new()
    .route("/me", get(authorized))
    .route("/login", get(login))
    .layer(cookie_service.clone())
    .with_state(cookie_service);
```

Create sessions via `CookieContext` and extract them with `CookieSession`:

```rust
async fn login(session: CookieContext<User>, /* ... */) -> impl IntoResponse {
    let cookie = session.create_session(user).await.unwrap();
    (Some(cookie), "Logged in")
}

async fn authorized(user: CookieSession<User>) -> Json<User> {
    Json(user.state)
}

// Use Option<CookieSession<User>> for optional authentication.
```

## JWT

The `jwt` feature adds JWT-based authentication. By default, tokens are read from the `Authorization` header.

```rust
use axum_security::jwt::{Jwt, JwtContext};

let jwt_service = JwtContext::builder()
    .jwt_secret("my-secret")
    .build::<AccessToken>();

let router = Router::new()
    .route("/me", get(authorized))
    .route("/login", get(login))
    .layer(jwt_service.clone())
    .with_state(jwt_service);
```

Encode tokens via `JwtContext` and extract them with `Jwt`:

```rust
async fn login(context: JwtContext<AccessToken>, /* ... */) -> Result<String, StatusCode> {
    context
        .encode_token(&token)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn authorized(Jwt(token): Jwt<AccessToken>) -> Json<AccessToken> {
    Json(token)
}
```

## Basic auth

The `basic-auth` feature provides HTTP Basic Authentication via a `BasicAuthenticator` trait.

```rust
use axum_security::basic_auth::{BasicAuth, BasicAuthLayer, BasicAuthenticator};

struct MyAuth;

impl BasicAuthenticator for MyAuth {
    type User = User;
    type Error = StatusCode;

    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<User>, StatusCode> {
        if username == "admin" && password == "secret" {
            Ok(Some(User { username: username.to_owned() }))
        } else {
            Ok(None)
        }
    }
}

let router = Router::new()
    .route("/hello", get(hello))
    .layer(BasicAuthLayer::new(MyAuth));
```

Extract with `BasicAuth<User>` or `Option<BasicAuth<User>>`:

```rust
async fn hello(BasicAuth(user): BasicAuth<User>) -> String {
    format!("Hello, {}!", user.username)
}
```

## OAuth 2.0

The `oauth2` feature handles the authorization code flow. Implement `OAuth2Handler` to process the token response after a successful login.

```rust
use axum_security::oauth2::{
    AfterLoginCookies, OAuth2Context, OAuth2Ext, OAuth2Handler, TokenResponse,
};

impl OAuth2Handler for LoginHandler {
    async fn after_login(
        &self,
        token_res: TokenResponse,
        cookies: &mut AfterLoginCookies<'_>,
    ) -> impl IntoResponse {
        // Fetch user info, create a session, add cookies
        cookies.add(session_cookie);
        Redirect::to("/")
    }
}

let oauth2_service = OAuth2Context::github()
    .client_id_env("CLIENT_ID")
    .client_secret_env("CLIENT_SECRET")
    .redirect_url("http://localhost:3000/redirect")
    .login_path("/login")
    .build(handler);

let router = Router::new()
    .route("/me", get(authorized))
    .layer(cookie_service)
    .with_oauth2(oauth2_service);
```

## OIDC

The `oidc` feature adds OpenID Connect with auto-discovery and ID token verification. PKCE and nonce replay protection are always enabled.

```rust
use axum_security::oidc::{
    AfterLoginCookies, OidcContext, OidcExt, OidcHandler, OidcTokenResponse,
};

impl OidcHandler for LoginHandler {
    async fn after_login(
        &self,
        token_res: OidcTokenResponse,
        cookies: &mut AfterLoginCookies<'_>,
    ) -> impl IntoResponse {
        let user = User {
            subject: token_res.claims.subject,
            email: token_res.claims.email,
            name: token_res.claims.name,
        };
        cookies.add(self.cookie_service.create_session(user).await.unwrap());
        Redirect::to("/")
    }
}

let oidc_context = OidcContext::google()
    .await?
    .client_id_env("GOOGLE_CLIENT_ID")
    .client_secret_env("GOOGLE_CLIENT_SECRET")
    .redirect_url("http://localhost:3000/auth/oidc/callback")
    .login_path("/login")
    .logout_path("/logout")
    .scopes(&["openid", "email", "profile"])
    .build(handler);

let router = Router::new()
    .route("/me", get(me))
    .layer(cookie_service)
    .with_oidc(oidc_context);
```

## RBAC

The `rbac` feature provides role-based access control. Implement the `RBAC` trait to tell the library how to extract roles from your user type.

```rust
use axum_security::rbac::RBAC;

impl RBAC for Role {
    type Resource = User;

    fn extract_roles(resource: &Self::Resource) -> impl IntoIterator<Item = &Self> {
        Some(&resource.role)
    }
}
```

Protect routes with the `#[requires]` macro (needs the `macros` feature):

```rust
#[axum_security::rbac::requires(Role::Admin)]
async fn admin_only(cookie: CookieSession<User>) -> String {
    format!("hi admin: {}", cookie.state.name)
}
```

Or use the `RBACExt` methods on routes: `.requires()`, `.requires_all()`, `.requires_any()`.

## PBAC

The `pbac` feature adds policy-based access control. Policies are composable -- combine them with `.and()`, `.or()`, and `.not()`.

```rust
use axum_security::pbac::{HasRole, PolicyRouterExt};

fn is_not_banned(u: &User) -> bool {
    !u.banned
}

let admin_policy = HasRole::new(Role::Admin).and(is_not_banned);

let mod_policy = HasRole::new(Role::Admin)
    .or(HasRole::new(Role::Mod))
    .and(is_not_banned);

let router = Router::new()
    .route("/admin", get(handler).with_policy(admin_policy))
    .route("/mod-area", get(handler).with_policy(mod_policy))
    .layer(cookie_service);
```

Any `Fn(&User) -> bool` works as a policy. Use `AsyncPolicy` or `AsyncFalliblePolicy` for async checks.

## Security headers

The `headers` feature adds a Tower layer that sets security response headers. Use `SecurityHeaders::recommended()` for sensible defaults, or apply individual headers.

```rust
use axum_security::headers::{CrossOriginOpenerPolicy, SecurityHeaders, XssProtection};

let security_layer = SecurityHeaders::recommended()
    .use_dev_headers(cfg!(debug_assertions))
    .add(XssProtection::ZERO);

let coop_layer = CrossOriginOpenerPolicy::SAME_ORIGIN;

let router = Router::new()
    .route("/", get(index))
    .layer(security_layer)
    .layer(coop_layer);
```

## CSRF protection

The `csrf` feature provides double-submit cookie CSRF protection. Extract a `CsrfToken` in your handler and include it as a hidden form field or request header.

```rust
use axum_security::csrf::{Csrf, CsrfToken};

let csrf = Csrf::builder()
    .secret("my-csrf-secret")
    .use_dev_cookie(cfg!(debug_assertions))
    .build();

let router = Router::new()
    .route("/", get(form))
    .route("/submit", post(submit))
    .layer(csrf);
```

```rust
async fn form(csrf: CsrfToken) -> Html<String> {
    Html(format!(
        r#"<form method="POST" action="/submit">
            <input type="hidden" name="_csrf" value="{csrf}" />
            <button type="submit">Submit</button>
        </form>"#,
    ))
}
```

Tokens are validated automatically on non-safe HTTP methods (POST, PUT, DELETE, PATCH). Submit via the `_csrf` form field or the `x-csrf-token` header.

## Rate limiting

The `rate-limit` feature adds rate limiting with two algorithms: fixed window (default) and token bucket. Keys are extracted per-request (by IP, session, or a custom extractor).

```rust
use axum_security::rate_limit::RateLimitLayer;

// Fixed window: 100 requests per 60 seconds
let global_limiter = RateLimitLayer::builder()
    .max_requests(100)
    .window_secs(60)
    .for_smart_ip()
    .build();

// Token bucket: burst of 10, refill 2 tokens/sec
let api_limiter = RateLimitLayer::builder()
    .token_bucket(10, 2.0)
    .for_smart_ip()
    .build();

let router = Router::new()
    .route("/", get(index))
    .route("/api", get(api).layer(api_limiter))
    .layer(global_limiter);
```

Returns 429 Too Many Requests with `Retry-After` when the limit is exceeded. Allowed responses include standard `RateLimit` headers.

## Examples

See the [`examples/`](examples/) directory for complete, runnable examples of each feature.

## Roadmap

- CSP nonce support
- OIDC logout support
- Eager/lazy session loading

## License

This project is licensed under the [MIT license](https://github.com/joeydewaal/axum-security/blob/main/LICENSE).
