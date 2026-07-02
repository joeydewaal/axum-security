# Design: `axum-security-oauth2`

An independent OAuth2 client crate owned by the axum-security workspace,
**inspired by** — not forked from — the
[`oauth2`](https://crates.io/crates/oauth2) crate (v5.x). We take upstream as
the reference for *which protocol capabilities to support* and implement from
the RFCs ourselves: no code is copied, so there are no fork licensing or
attribution obligations. The crate ships under the workspace's own license.
Eventually every protocol capability upstream supports is also supported here
(except deliberate, documented omissions), but implementation starts with
only what axum-security actually uses.

## Design constraints (non-negotiable)

1. **Feature parity, not API parity — and not a fork.** The same set of
   protocol features as `oauth2` 5.x is the end goal (inventory below), but
   the API and code are ours, written from the RFCs. **The API is designed
   fresh and deliberately does not mimic upstream's** — not its method names
   (`exchange_code`, `authorize_url`, `request_async`), not its shapes. It
   is not a drop-in replacement and doesn't try to be. Phase 1 implements
   only the subset axum-security uses today; parity arrives incrementally.
2. **No typestate.** Configuration is validated once at `build()`; missing
   endpoints are runtime errors at call time. Zero type parameters on the
   client.
3. **No unnecessary wrapper types.** A newtype must earn its place by being
   security-load-bearing (Debug redaction, constant-time comparison,
   preventing secret-argument mixups). Everything else is `String`, `&str`,
   `url::Url`, `std::time::Duration`, or `i64`. Upstream's `Scope`,
   `ClientId`, `AuthUrl`, `TokenUrl`, `RedirectUrl`, etc. do not survive.
4. **Datetime-library agnostic.** Core API uses std types (`Duration`) and
   raw unix seconds (`i64`). Optional `jiff` / `chrono` / `time` features add
   conversion accessors — the cookie-monster `Expires` pattern
   (`expires/dep_jiff.rs`, `dep_chrono.rs`, `dep_time.rs`). Upstream's
   unconditional `chrono` dependency is dropped entirely.
5. **HTTP-client agnostic — without `Box<dyn>`.** Either a feature-gated
   enum of backends (the `Session<U>` pattern: variants behind `cfg` gates)
   or an async trait in RPITIT style (`fn send(...) -> impl Future<...> +
   Send`, like `pbac::Policy`). Never a trait object, never boxed futures.
   Chosen: the enum — see "HTTP backend" below.
6. **Minimal dependencies.** Every direct dependency needs a justification;
   see the dependency table. Target: 7 direct deps vs upstream's 10.
7. **House API style** — follow axum-security and cookie-monster
   conventions (detailed below).

## Motivation

Upstream's `Client` carries ten type parameters — five trait-generic
response types, five `EndpointSet`/`EndpointNotSet`/`EndpointMaybeSet`
typestates. The cost lands wherever a client is *stored*:
`axum-security/src/oauth2/mod.rs` needs a private alias just to name
`BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet,
EndpointSet>`, and adding one endpoint later changes the stored type
everywhere. `openidconnect` inherits and worsens this, then degrades to
`EndpointMaybeSet` + runtime `Result` anyway — ceremony without the
guarantee. Meanwhile the typestate's actual payoff ("can't call
`exchange_code` without a token URL") is a one-time configuration error that
`OAuth2ContextBuilder::try_build` already catches at runtime today.

## Upstream feature inventory and what we need

Verified against vendored `oauth2-5.0.0` source. "axs" = what
`axum-security`'s oauth2 module uses today; "oidc" = what the committed
`axum-security-oidc` crate will require from this crate.

### Protocol features

| Upstream capability | Spec | axs today | oidc needs | Our plan |
|---|---|---|---|---|
| Authorization code grant (`exchange_code`) | RFC 6749 §4.1 | ✅ | ✅ | **Phase 1** |
| CSRF `state` generation + authorize-URL building | §10.12 | ✅ | ✅ | **Phase 1** |
| Scopes on auth + token requests | §3.3 | ✅ | ✅ | **Phase 1** |
| PKCE, S256 | RFC 7636 | ✅ | ✅ | **Phase 1** |
| PKCE, `plain` | RFC 7636 | ❌ | ❌ | Parity: `pkce-plain` feature (off) |
| Extra params on auth URL / token requests | — | ❌ | ✅ (`nonce`, `prompt`, `hd`, …) | Phase 3 (oidc prereq) |
| Refresh token grant | §6 | exposed to users, not called | ✅ | Phase 3 (oidc prereq) |
| Client auth: HTTP Basic (default) / request body (`AuthType`) | §2.3.1 | default only | ✅ (some IdPs body-only) | Basic: **Phase 1**; `RequestBody`: Phase 3 |
| Per-request redirect-URI override | §4.1.3 | ❌ | maybe | Phase 3 |
| Extra/nonstandard token-response fields (`ExtraTokenFields`) | — | ❌ | ✅ (`id_token`) | **Phase 1** — free, the parser retains unknown fields in the `extra` map; no generic |
| Client credentials grant | §4.4 | ❌ | ❌ | Phase 4 |
| Device authorization grant | RFC 8628 | ❌ | ❌ | Phase 4 |
| Token introspection | RFC 7662 | ❌ | ❌ | Phase 4 |
| Token revocation | RFC 7009 | ❌ | ❌ | Phase 4 (logout could revoke on the way out) |
| Resource-owner password grant | §4.3 | ❌ | ❌ | Parity: `legacy-grants` feature (off); deprecated in OAuth 2.1 |
| Implicit grant (`use_implicit_flow`) | §4.2 | ❌ | ❌ | **Dropped.** Removed in OAuth 2.1; tokens leak via fragments. Documented omission |
| Custom token types (non-`bearer`) | §7.1 | ❌ | ❌ | `token_type` is a plain `String` + `is_bearer()`; covered without the trait hierarchy |
| Custom error-response types (`ErrorResponse` trait) | §5.2 | ❌ | ❌ | One concrete `ServerError` with std fields + `extra` map |
| Custom revocable-token hints (`StandardRevocableToken`) | RFC 7009 §2.1 | ❌ | ❌ | Small enum: `AccessToken`/`RefreshToken` hint |

### Infrastructure features

| Upstream capability | axs today | Our plan |
|---|---|---|
| Async HTTP via `AsyncHttpClient` trait | ✅ (reqwest) | `HttpClient` trait (ours, simpler), `Arc<dyn>` — **Phase 1** |
| reqwest backend (`reqwest`, default) | ✅ | Default feature, no-redirect + 10s-timeout default client |
| `rustls-tls` (default) / `native-tls` | ✅ rustls | Same two features |
| Sync HTTP: `reqwest-blocking`, `curl`, `ureq` | ❌ | **Dropped.** Async-only |
| wasm support (getrandom/js) | ❌ | Kept cheaply — we use `getrandom` anyway; not a promise, just not broken |
| `timing-resistant-secret-traits` (opt-in CT eq) | ❌ (axs uses `subtle` itself) | **Always on** via `subtle` — no feature |
| Deserialize diagnostics via `serde_path_to_error` | n/a | Dropped (dep budget); errors still carry endpoint + body context |
| Devicecode injectable clock/sleep (`chrono` + sleep_fn) | n/a | `Instant`-based deadline + caller-supplied async sleep fn → **no runtime dep, no chrono** |

## Dependencies

| Upstream (5.0.0, direct) | Ours | Why |
|---|---|---|
| `serde`, `serde_json` | keep | wire format |
| `sha2` | keep | PKCE S256 |
| `base64` | keep | PKCE challenge (base64url-nopad), Basic auth |
| `url` | keep | endpoint validation at `build()`, query building. The one debatable keep — `form_urlencoded` + raw strings would be smaller; not worth losing build-time URL errors (`OAuth2BuilderError::Invalid*Url` depends on them) |
| `rand` | → `getrandom` | we need exactly "32 random bytes from the OS CSPRNG"; `getrandom` is the bottom of that stack |
| `chrono` (non-optional!) | **dropped** | datetime-agnostic core: `Duration` + unix `i64`; optional `jiff`/`chrono`/`time` conversion features |
| `http` | **dropped** | our `HttpClient` trait uses two tiny domain structs instead of `http::Request`/`Response` |
| `thiserror` | **dropped** | hand-rolled `Display`/`Error` impls (house style; axum-security and cookie-monster both do this) |
| `serde_path_to_error` | **dropped** | dep budget |
| — | + `subtle` | constant-time secret comparison, always on; zero-dep crate already used by axum-security |
| `reqwest` (optional, default) | same | plus: crate compiles and builds authorize URLs with **no** HTTP feature at all |
| `curl`, `ureq` (optional) | **dropped** | async-only |

Direct deps: **7** (`serde`, `serde_json`, `sha2`, `base64`, `getrandom`,
`subtle`, `url`) + optional `reqwest`, `jiff`, `chrono`, `time`.

### Feature flags

| Feature | Default | Contents |
|---|---|---|
| `reqwest` | yes | `HttpClient` impl for `reqwest::Client` |
| `rustls-tls` | yes | reqwest rustls backend |
| `native-tls` | no | reqwest native-tls backend |
| `jiff` / `chrono` / `time` | no | timestamp conversion accessors (cookie-monster pattern) |
| `pkce-plain` | no | `plain` code-challenge method |
| `legacy-grants` | no | resource-owner password grant |

## API conventions (from axum-security & cookie-monster)

These are the house rules, extracted from `cookie_monster::Cookie` /
`CookieBuilder` and axum-security's builders. They govern every public type
in this crate.

### Parameters

- String-ish params take `impl Into<Cow<'static, str>>` (cookie-monster's
  `name`/`value`/`domain`/`path`; axum-security's `login_path`,
  `provider_name`). Use `impl Into<String>` only where the value is always
  owned anyway (axum-security's `client_id`, URLs).
- Byte-ish secrets take `impl AsRef<[u8]>` (axum-security's
  `cookie_secret`).
- Lists take slices of borrows: `scopes(&[&str])`, not
  `Vec<Scope>`/iterator gymnastics.
- Polymorphic params go through a conversion enum + `impl Into<...>`
  (cookie-monster's `expires(impl Into<Expires>)`,
  `same_site(impl Into<Option<SameSite>>)`) — not through generics on the
  type or trait objects.
- Convenience unit variants where a plain number is friendlier:
  `max_age(Duration)` + `max_age_secs(u64)`,
  `max_login_duration(Duration)` + `max_login_duration_minutes(u64)`.

### Getters and setters

- **Built types** (`Cookie`, here: `OAuth2Client`, `TokenResponse`, …):
  bare-name getters — `name() -> &str`, `max_age() -> Option<Duration>`;
  booleans read as `is_x()` (`is_secure()`, here `is_bearer()`). Mutators,
  where a built type is mutable at all, are `set_x(&mut self, ...)` and
  `unset_x(&mut self)`. Response types here are read-only: getters only.
- **Builders**: the bare name is the chainable *setter* —
  `fn x(mut self, val) -> Self`. Flags get a no-arg true-setter plus a
  chainable explicit variant: `secure()` / `set_secure(bool) -> Self`
  (here: `pkce()` on by default / `set_pkce(bool)`). When a builder needs a
  getter, it takes the `get_` prefix (`CookieBuilder::get_name`,
  axum-security's `get_start_challenge_path`) since the bare name is taken.
- Terminal `build()`; where construction can fail, `try_build() -> Result`
  with `build()` as the panicking convenience (axum-security's
  `build`/`try_build` split) — for this crate `build()? -> Result` only;
  the panicking convenience stays in axum-security's own builders.

### Lifetimes

- **No lifetime parameters on public types.** `Cookie`, `CookieJar`,
  `CookieBuilder` all own their data via `Cow<'static, str>` — deliberately
  unlike the `cookie` crate's `Cookie<'c>`. Apply the same here: request
  builders **own** their inputs (small strings; clone at the boundary),
  unlike upstream's `RefreshTokenRequest<'a>` / `IntrospectionRequest<'a>`
  which thread `&'a` through every stored request.
- `Cow<'static, str>` is the tool for borrowed-or-owned; a lifetime param
  is never the answer in this crate's public API.

### Errors, features, docs

- One error enum per concern, hand-rolled `Display` + `Error` impls, no
  `thiserror` (matches `OAuth2BuilderError`, cookie-monster's `Error`).
- Feature-gated dep integration lives in dedicated files: `dep_jiff.rs` /
  `dep_chrono.rs` / `dep_time.rs` under the module that needs them
  (cookie-monster's `cookie/expires/`).
- Crate docs: overview → feature list with one-paragraph explanations →
  runnable example (cookie-monster's `lib.rs`).
- Env-var helpers (`client_id_env` etc.) stay in **axum-security's**
  builders, not here — this crate is the protocol layer.

## Core API

Designed from the consumer's point of view (axum-security's login flow), not
from the protocol's. The two legs of the code flow are a symmetric pair:
`start_login()` / `finish_login()` — matching axum-security's own mental
model (`start_challenge` / `on_redirect`), not upstream's
`authorize_url` / `exchange_code`.

### Client

One concrete struct, zero type parameters:

```rust
pub struct OAuth2Client {
    client_id: String,
    client_secret: Option<ClientSecret>,
    auth_url: Option<Url>,
    token_url: Option<Url>,
    device_auth_url: Option<Url>,
    introspection_url: Option<Url>,
    revocation_url: Option<Url>,
    redirect_url: Option<Url>,
    scopes: Vec<String>,
    pkce: bool,                   // default true
    auth_type: AuthType,          // BasicAuth (default) | RequestBody
    http: Option<HttpClient>,     // enum, see "HTTP backend"
}
```

Scopes and the PKCE switch are client configuration, not per-request
builder calls — that's where axum-security's own builder puts them
(`scopes(&[&str])`, `authorization_code_flow()` vs `..._with_pkce()`), and
per-login variation is not a real use case for a login flow.

```rust
let client = OAuth2Client::builder()
    .client_id("...")
    .client_secret("...")
    .auth_url("https://github.com/login/oauth/authorize")
    .token_url("https://github.com/login/oauth/access_token")
    .redirect_url("https://example.com/callback")
    .scopes(&["read:user"])
    .build()?;   // ConfigError: URL parse failures + missing client_id here
```

`build()` requires only `client_id`. Endpoints are optional; a call whose
endpoint is missing returns `Error::MissingEndpoint(Endpoint::Token)` — the
same failure mode `EndpointMaybeSet` has anyway, minus ten type parameters.
Under the default `reqwest` feature the builder provides a default backend
(no redirects, 10s timeout — replaces the `default_reqwest_client()`
helpers duplicated in axum-security's oauth2 and oidc modules);
`.http_client(...)` overrides it.

### The login flow (phase 1)

```rust
// Leg 1 — pure, no I/O, works with zero features enabled
let login: Login = client.start_login()?;   // Err if auth_url unset

login.url()            // &Url — redirect the user here
login.csrf_token()     // &CsrfToken — persist (axum-security: HMAC cookie)
login.pkce_verifier()  // Option<&PkceVerifier> — persist alongside

// Leg 2 — plain async method; the only option is a plain argument
let tokens: Tokens = client.finish_login(code, login.pkce_verifier()).await?;
```

No request-builder object, no `.send()`, no `.request_async(&http)` — leg 2
is an ordinary `async fn`. Builders exist where there is real optional
surface (the *client* builder); a call with one optional argument doesn't
earn one. When phase 3 adds per-login extras (nonce et al.), the shape is a
closure-configured variant in axum-security style
(`.cookie(|c| c...)`): `client.start_login_with(|o| o.param("nonce", n))?`.

CSRF comparison stays the consumer's job (cookie vs. query param — that's
axum-security's `verify_cookies` + `subtle` comparison), as does verifier
storage. The crate generates the secrets; it doesn't pretend to own state
it can't see.

### Later-phase calls (target shapes, not phase 1)

```rust
client.refresh_tokens(&refresh_token).await?;          // phase 3
client.fetch_client_tokens().await?;                   // phase 4: client credentials
let device = client.start_device_login().await?;       // phase 4: RFC 8628
client.finish_device_login(&device, tokio::time::sleep).await?;
client.introspect(&access_token).await?;               // phase 4
client.revoke(RevocableToken::Refresh(rt)).await?;     // phase 4
```

`start_/finish_` symmetry carries over to the device flow. Polling takes a
caller-supplied async sleep fn so the crate needs **no async runtime
dependency**; deadlines use `std::time::Instant`, not wall-clock time.

### Token response: concrete, extras retained

```rust
pub struct Tokens {
    access_token: AccessToken,
    token_type: String,
    expires_in: Option<Duration>,          // std::time::Duration
    refresh_token: Option<RefreshToken>,
    scopes: Option<Vec<String>>,
    extra: serde_json::Map<String, Value>, // every unrecognized field
}

impl Tokens {
    // bare-name getters per the conventions; plus:
    pub fn is_bearer(&self) -> bool;
    pub fn extra_field<T: DeserializeOwned>(&self, key: &str) -> Option<T>;
    pub fn extra_fields<T: DeserializeOwned>(&self) -> Result<T, serde_json::Error>;
}
```

This replaces upstream's `TR`/`EF` generics. It covers GitHub's `scope`
string, Google's `id_token` (which is exactly how `axum-security-oidc` will
pull the ID token out), Slack's nested objects — without a type parameter.
The device and introspection responses and `ServerError` get the same
concrete-plus-`extra` treatment. (`Tokens`, not `TokenResponse`: short noun
per house style, and it avoids colliding with axum-security's existing
`handler::TokenResponse`.)

## Type policy: which wrappers survive

**Rule:** a wrapper exists only if it (a) redacts `Debug`, (b) compares in
constant time, or (c) prevents mixing up two secrets in an argument list.
Everything else is a std/url type.

Survivors — the secret set, one shared implementation (macro or generic
`Secret<Marker>` internally, distinct public names): `ClientSecret`,
`AccessToken`, `RefreshToken`, `AuthorizationCode`, `CsrfToken`,
`PkceCodeVerifier`, `DeviceCode`. All: `Debug` prints `[redacted]`, no
`Display`, `PartialEq` via `subtle`, access via `.secret() -> &str`,
`Serialize` only where the wire format requires it.

Dropped (plain `String`/`&str`/`Url`): `Scope`, `ClientId`, `AuthUrl`,
`TokenUrl`, `RedirectUrl`, `DeviceAuthUrl`, `IntrospectionUrl`,
`RevocationUrl`, `UserCode` (shown to the user, not secret),
`EndUserVerificationUrl`, the `*TokenType` trait hierarchy, the
`ErrorResponseType` trait.

## Datetime handling (agnostic core)

OAuth2 touches time in three places; none justifies a datetime dependency:

- **`expires_in`** (token + device responses): relative seconds →
  `std::time::Duration`.
- **Introspection `exp` / `iat` / `nbf`**: absolute unix timestamps → stored
  and exposed as `i64` (`fn exp(&self) -> Option<i64>`). Feature-gated
  accessors add typed views, one file per dep like cookie-monster's
  `expires/`: `exp_jiff() -> Option<jiff::Timestamp>`, `exp_chrono() ->
  Option<chrono::DateTime<Utc>>`, `exp_time() -> Option<time::OffsetDateTime>`.
- **Device-flow deadline**: monotonic `std::time::Instant` internally
  (upstream used `chrono::Utc::now` + an injectable `time_fn`; an injectable
  clock for tests keeps that testability without the dep).

## HTTP abstraction (agnostic from day one)

```rust
pub struct HttpRequest {           // domain-level, not generic HTTP
    pub url: Url,                  // always POST, form-urlencoded
    pub headers: Vec<(&'static str, String)>,  // Accept, Content-Type, Authorization
    pub body: Vec<u8>,
}

pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

pub trait HttpClient: Send + Sync + 'static {
    fn send(&self, req: HttpRequest)
        -> Pin<Box<dyn Future<Output = Result<HttpResponse, BoxError>> + Send + '_>>;
}
```

The protocol only ever needs "POST a form, read status + JSON" — so the
trait is two tiny structs instead of the `http` crate's full generality
(one less dep). Stored as `Arc<dyn HttpClient>`: swappable per the
agnosticism requirement, and dyn dispatch keeps `OAuth2Client` free of type
parameters. One boxed future per token exchange is nothing on a login flow.
The reqwest impl ships behind the default `reqwest` feature; hyper/wasm/test
impls are a page of user code. Implementations must not follow redirects
(documented; the default client enforces it).

## Security invariants

- CSRF tokens, PKCE verifiers: 32 bytes via `getrandom` (OS CSPRNG),
  base64url-nopad.
- PKCE S256 only by default; `plain` behind `pkce-plain`.
- Token-endpoint auth: HTTP Basic with form-urlencoded credentials per
  RFC 6749 §2.3.1 by default; `AuthType::RequestBody` for providers that
  demand it.
- Token requests: POST, `Accept: application/json`, redirects never followed.
- Device-flow polling honors `interval` and `slow_down` (RFC 8628 §3.5).
- Secret types: redacted `Debug`, no `Display`, constant-time `PartialEq` —
  always, not feature-gated.
- TLS: `rustls-tls` default.
- Redaction test: `format!("{:?}", ...)` of client + every response type
  contains no secret bytes.

## `axum-security-oidc` (committed follow-up, separate design doc)

The `oidc` feature **will** move off `openidconnect` onto a new
`axum-security-oidc` crate layered on this one. That design is written
separately (ID-token JWS verification, JWKS caching — the lazy-JWKS work —
and discovery are their own security surface). What it requires from *this*
crate — phase-3 scope here, landing before the oidc crate starts:

- `add_extra_param` on the authorize URL (nonce, prompt, login_hint, hd).
- `id_token` retrieval via `TokenResponse::extra_field("id_token")` (the
  retained-extras map itself exists from phase 1).
- Refresh grant, `AuthType::RequestBody` (some IdPs), and the `HttpClient`
  trait shared so both crates ride one connection pool.

Until it lands, `openidconnect` (and transitively upstream `oauth2`) stays
in the tree when the `oidc` feature is on — compile-time cost only; the oidc
module doesn't leak upstream types.

## Migration of `axum-security`'s `oauth2` feature

Mechanical — the module touches a narrow upstream slice:

1. `Cargo.toml`: `oauth2 = { workspace = true, ... }` →
   `axum-security-oauth2 = { path = "../axum-security-oauth2" }`.
2. Delete the `OAuth2ClientTyped` alias (`oauth2/mod.rs:28`); the field
   becomes `client: OAuth2Client`.
3. `builder.rs`: `Client::new(...).set_auth_uri(...)` chain → new builder;
   `default_reqwest_client()` deleted; existing `OAuth2BuilderError`
   variants map 1:1 onto the new `ConfigError`.
4. `context.rs`: drop the `TokenResponse as _` trait import (accessors are
   inherent); `Scope` vec becomes `Vec<String>`; flow calls near-identical.
5. `cookie.rs`/`redirect.rs`: import-path changes for `CsrfToken`,
   `PkceCodeVerifier`, `AuthorizationCode`.

No intended change to axum-security's public API — upstream types never
leaked (`handler::TokenResponse` is already our own struct).

## Testing

All tests written from scratch against the RFCs — nothing ported from
upstream (not-a-fork applies to tests too).

- Token/error deserialization cases built from RFC 6749 §5.1/§5.2 examples
  plus real-provider quirks (GitHub's `scope` string, Google's `id_token`).
- PKCE: RFC 7636 Appendix B test vector.
- Mock-server integration tests (`wiremock`): every grant against a fake
  endpoint — success, §5.2 error bodies, non-JSON bodies, wrong
  content-type, device-flow `authorization_pending`/`slow_down` sequences.
- Redaction tests (above).
- Acceptance gate: axum-security's existing oauth2 tests (builder unit
  tests, redirect tests) pass unchanged after migration.

## Phases

1. **Core — exactly axum-security's current footprint.** Crate skeleton,
   secret types, errors, builder, `HttpClient` trait + reqwest impl,
   authorize URL + CSRF + scopes, PKCE S256, code exchange, Basic client
   auth. Nothing more. *Exit: axum-security's `oauth2` feature compiles and
   passes its tests on this crate.*
2. **Migration** — swap the dependency in axum-security, delete glue
   (`OAuth2ClientTyped`, `default_reqwest_client()`).
3. **oidc prerequisites** — extra auth params, refresh grant,
   `AuthType::RequestBody`, per-request redirect override.
4. **Parity + publish** — client credentials, device flow, introspection,
   revocation, `pkce-plain`, `legacy-grants`, datetime conversion features;
   docs.rs pass, README with upstream-divergence table, `0.1.0`.
5. **`axum-security-oidc`** — separate design doc, layered on this crate;
   retires the `openidconnect` dependency.

## Open decisions

| Decision | Recommendation | Alternative |
|---|---|---|
| `url` dependency | Keep — build-time URL validation feeds existing error variants | `form_urlencoded` + opaque strings; smaller tree, worse errors |
| Distinct secret types vs one `Secret` | Distinct names over one shared impl — prevents access/refresh mixups at zero cost | Single `Secret` type everywhere |
| `HttpRequest`/`HttpResponse` own structs vs `http` crate types | Own structs (drops a dep; trait is domain-level) | `http` types interop better with tower/hyper middleware users |
| Device-flow convenience polling | Ship `sleep_fn`-based `send()` + expose single-poll for manual loops | Only manual polling; smaller API, worse ergonomics |
| Crate name | `axum-security-oauth2` (family branding; note: no axum dependency) | Neutral name if it should stand alone |
