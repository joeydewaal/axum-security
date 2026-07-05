# Phase 1 API plan: `axum-security-oauth2`

Companion to [`axum-security-oauth2.md`](./axum-security-oauth2.md) (the
overall design: constraints, dependency budget, phases). This doc pins down
the **phase 1 public API** — exactly the footprint axum-security's `oauth2`
module needs — in three parts: what axum-security actually calls today, the
upstream `oauth2` 5.0.0 API surface for that area (every option each call
accepts), and our surface item by item with the design options considered.

## 1. What axum-security calls today

The complete upstream footprint, from `oauth2/builder.rs` and
`oauth2/context.rs` — this is everything phase 1 must be able to express:

```rust
// builder.rs — construction
Client::new(ClientId::new(id))
    .set_client_secret(ClientSecret::new(secret))
    .set_auth_uri(AuthUrl::new(url)?)        // parse error → OAuth2BuilderError
    .set_token_uri(TokenUrl::new(url)?)
    .set_redirect_uri(RedirectUrl::new(url)?);
// + default_reqwest_client(): redirect::Policy::none()

// context.rs — leg 1 (start_challenge)
let mut req = client.authorize_url(CsrfToken::new_random);
req = req.add_scopes(scopes.clone());                     // Vec<Scope>, cloned every login
let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();  // if PKCE flow
req = req.set_pkce_challenge(challenge);
let (redirect_url, csrf_token) = req.url();
csrf_token.secret(); verifier.secret();                   // → HMAC cookie

// context.rs — leg 2 (exchange_code)
client.exchange_code(AuthorizationCode::new(code))
    .set_pkce_verifier(pkce_verifier)                     // if PKCE flow
    .request_async(&http_client).await
    .map_err(|e| e.to_string())?;                         // error → String, that's all
response.access_token().secret();                          // TokenResponse trait import
response.refresh_token().map(|t| t.secret());

// misc
client.redirect_uri().unwrap().url().path();               // callback route path
```

Notable: axum-security never touches `expires_in`, `scopes` on the
response, `token_type`, `AuthType`, extra params, or refresh — and it
flattens all token-request errors to `String`.

## 2. Upstream API inventory (phase-1 area)

What `oauth2` 5.0.0 exposes for this part of the protocol. ✓ = axum-security
uses it today. This is the checklist our API must cover (✓ rows) or
consciously defer/drop (the rest).

### Client construction

| Upstream | axs | Our phase 1 |
|---|---|---|
| `Client::new(ClientId)` | ✓ | builder `client_id(...)` |
| `set_client_secret(ClientSecret)` | ✓ | builder `client_secret(...)` |
| `set_auth_uri(AuthUrl)` / `_option(Option<_>)` | ✓ | builder `auth_url(...)`; required at `try_build()`, no `_option` twins (those exist only to feed `EndpointMaybeSet` — see decision 11) |
| `set_token_uri(TokenUrl)` / `_option` | ✓ | builder `token_url(...)` |
| `set_redirect_uri(RedirectUrl)` | ✓ | builder `redirect_url(...)` |
| `set_auth_type(AuthType)` (§2.3.1 Basic vs body) | ❌ | deferred to phase 3 — Basic hardcoded (see decision 2) |
| `set_device_authorization_url`, `set_introspection_url`, `set_revocation_url` (+`_option`) | ❌ | phase 4 |
| Getters: `client_id()`, `auth_uri()`, `token_uri()`, `redirect_uri()`, `auth_type()` | ✓ (`redirect_uri`) | bare-name getters on `OAuth2Client` |

### Authorize URL — `authorize_url(state_fn) -> AuthorizationRequest<'a>`

| Upstream option | axs | Our phase 1 |
|---|---|---|
| `state_fn: FnOnce() -> CsrfToken` (injectable CSRF source) | ✓ (`new_random` only) | not injectable — `start_login()` always generates via `getrandom`; tests mock at the HTTP seam, not the RNG (see decision 3) |
| `add_scope(Scope)` / `add_scopes(iter)` | ✓ | client-level `scopes(&[&str])` config — set once, not re-added per login (see decision 9) |
| `set_pkce_challenge(PkceCodeChallenge)` | ✓ | no flag — challenge generated inside `start_login()`; a parallel `start_login_non_pkce()` pair covers providers that reject the params (see decision 4) |
| `add_extra_param(name, value)` | ❌ | phase 3 (`start_login_with(\|o\| o.param(...))`) — oidc prereq |
| `set_redirect_uri(Cow<RedirectUrl>)` (per-request override) | ❌ | phase 3 |
| `set_response_type(&ResponseType)` | ❌ | dropped with the implicit grant; revisit only if oidc needs a non-`code` response type |
| `use_implicit_flow()` | ❌ | **dropped** (OAuth 2.1) |
| terminal `url() -> (Url, CsrfToken)` | ✓ | `start_login() -> Login` (infallible — config validated at build) — one struct, PKCE verifier included instead of a separate variable to carry |

### PKCE and random types

| Upstream | axs | Our phase 1 |
|---|---|---|
| `PkceCodeChallenge::new_random_sha256() -> (challenge, verifier)` | ✓ | internal to `start_login()`; S256 always |
| `new_random_sha256_len(n)` / `CsrfToken::new_random_len(n)` | ❌ | dropped — 32-byte `getrandom` fixed; length knobs invite weak configs |
| `from_code_verifier_sha256(&verifier)` (recompute challenge) | ❌ | not public; used internally |
| `new_random_plain()` / `from_code_verifier_plain()` | ❌ | phase 4, `pkce-plain` feature |
| `PkceCodeChallenge::as_str()`, `.method()` | ❌ | not public in phase 1 (challenge never leaves `start_login`) |
| newtype pattern: `T::new(String)`, `.secret()`, `.into_secret()` | ✓ (`new`, `secret`) | **dropped** — secrets are plain strings; holding types redact in `Debug` (see §3, decision 12) |

### Code exchange — `exchange_code(code) -> CodeTokenRequest<'a>`

| Upstream option | axs | Our phase 1 |
|---|---|---|
| `exchange_code(AuthorizationCode)` | ✓ | `finish_login(code, verifier)` |
| `set_pkce_verifier(PkceCodeVerifier)` (owned) | ✓ | second arg: `&str`, required (see decisions 4, 12) |
| `add_extra_param(name, value)` | ❌ | phase 3 |
| `set_redirect_uri(Cow<RedirectUrl>)` | ❌ | phase 3 (client-level `redirect_url` is sent automatically, as upstream does) |
| `request(sync)` / `request_async(&http)` | ✓ (async) | gone — `finish_login` is the async call itself; the backend lives on the client |

### Token response

Upstream: `TokenResponse` trait (`access_token()`, `token_type()`,
`expires_in()`, `refresh_token()`, `scopes()`), implemented by
`StandardTokenResponse<EF: ExtraTokenFields, TT: TokenType>`, plus mutating
setters (`set_access_token`, …) and `extra_fields() -> &EF`.
`BasicTokenType`: `Bearer | Mac | Extension(String)`.

Ours: one concrete read-only `Tokens` struct (parent doc §Core API) — no
trait, no `EF`/`TT` generics, no setters. `token_type` is `String` +
`is_bearer()`; unknown fields land in the `extra` map with
`extra_field::<T>(key)` / `extra_fields::<T>()`. axs uses only
`access_token` + `refresh_token`; everything else on `Tokens` is free.

### Errors

Upstream: `RequestTokenError<RE, T>` — `ServerResponse(T)`, `Request(RE)`,
`Parse(serde_path_to_error::Error, Vec<u8>)`, `Other(String)`;
`StandardErrorResponse<T>` with `error: T`, `error_description`,
`error_uri`; `BasicErrorResponseType` enum of the six RFC 6749 §5.2 codes +
`Extension(String)`. Construction: `ConfigurationError::MissingUrl` for
`EndpointMaybeSet` calls, `url::ParseError` from `AuthUrl::new` etc.

Ours: two enums, no generics — `ConfigError` (build time) and `Error` (call
time), detailed in §3. axs only ever `.to_string()`s the error today, so
anything with a good `Display` clears the migration bar; the structure is
for the crate's own users (and phase 5's oidc crate).

### HTTP

Upstream: `AsyncHttpClient` trait over `http::Request/Response` +
`SyncHttpClient`; impls for reqwest/curl/ureq. Ours: the feature-gated
`HttpClient` enum with a crate-private seam (parent doc §HTTP backend);
sync dropped.

## 3. Phase 1 public surface

Everything `pub` in phase 1 — if it's not listed here, it doesn't exist yet.

### Module layout

```
src/
  lib.rs          // docs, re-exports
  client.rs       // OAuth2Client + start_login/finish_login
  builder.rs      // OAuth2ClientBuilder + ConfigError
  login.rs        // Login, LoginNonPkce
  tokens.rs       // Tokens
  rand.rs         // random_b64 (crate-private CSPRNG helper)
  pkce.rs         // challenge derivation (crate-private)
  error.rs        // Error, ServerError, ErrorCode
  http/
    mod.rs        // HttpClient enum + crate-private post_form seam
    dep_reqwest.rs// cfg(feature = "reqwest") variant impl + default client
```

`dep_reqwest.rs` follows cookie-monster's `dep_*.rs` convention; phase 4's
`jiff`/`chrono`/`time` accessors will do the same.

### Secrets (revised — the newtypes are gone)

Phase 1 originally shipped six secret newtypes (`ClientSecret`,
`AccessToken`, `RefreshToken`, `AuthorizationCode`, `CsrfToken`,
`PkceVerifier`); they were removed in favor of plain `String`/`&str`
(see decision 12). Redaction moved into the hand-written `Debug` impls
of every type that holds a secret (`OAuth2Client`, `Login`,
`LoginNonPkce`, `Tokens`), none of which implements `Display`; the
crate-wide redaction test pins it. `start_login()` is still the only
generator of CSRF tokens and verifiers — there's just no wrapper around
what it hands back, so it round-trips through axum-security's HMAC
cookie without `::new()`/`.secret()` ceremony.

### Builder

```rust
let client = OAuth2Client::builder()
    .client_id("...")                       // impl Into<String>, required
    .client_secret("...")                   // impl Into<String>, optional
    .auth_url("https://.../authorize")      // impl Into<String>, parsed in build()
    .token_url("https://.../token")
    .redirect_url("https://app/callback")
    .scopes(&["read:user", "user:email"])   // &[&str], replaces; default empty
    .http_client(reqwest_client)            // impl Into<HttpClient>; default under `reqwest` feature
    .try_build()?;                          // -> Result<OAuth2Client, ConfigError>; build() = try_build().unwrap()

#[non_exhaustive]
pub enum ConfigError {
    MissingClientId,
    MissingAuthUrl,
    MissingTokenUrl,
    InvalidAuthUrl(url::ParseError),
    InvalidTokenUrl(url::ParseError),
    InvalidRedirectUrl(url::ParseError),
    NoHttpClient,   // no backend feature and no http_client(...) set
}
```

House rules applied: bare-name chainable setters, `build()`/`try_build()`
terminal pair (axum-security's split: `try_build()` returns `Result`,
`build()` is the panicking convenience). `client_id`, `auth_url` and
`token_url` are required, and an HTTP backend must exist (the `reqwest`
default or an explicit `http_client(...)`) — `try_build()` validates all of
it, so the client's methods never fail on configuration (see decision 11).
No `get_` builder getters until something needs one. Env-var variants
(`client_id_env`) stay in axum-security's builder.

The default HTTP client (behind `reqwest`): no redirects, 10s timeout —
replaces axum-security's `default_reqwest_client()`.

### Client getters

```rust
impl OAuth2Client {
    pub fn client_id(&self) -> &str;
    pub fn auth_url(&self) -> &Url;
    pub fn token_url(&self) -> &Url;
    pub fn redirect_url(&self) -> Option<&Url>;   // axs: .path() → callback route
    pub fn scopes(&self) -> &[String];
}
```

No `client_secret()` getter — nothing reads it back, and not exposing it is
the cheapest redaction of all.

### Leg 1: `start_login`

```rust
pub fn start_login(&self) -> Login                 // pure, infallible; PKCE
pub fn start_login_non_pkce(&self) -> LoginNonPkce // ditto, no PKCE params

pub struct Login { /* owns url, csrf_token, pkce_verifier */ }

impl Login {
    pub fn url(&self) -> &Url;
    pub fn csrf_token(&self) -> &str;
    pub fn pkce_verifier(&self) -> &str;
    pub fn into_parts(self) -> (Url, String, String); // url, csrf, verifier
}

pub struct LoginNonPkce { /* owns url, csrf_token — no verifier field */ }
// url(), csrf_token(), into_parts() -> (Url, String)
```

Pure — no I/O, no async, infallible (configuration was validated at
build). Generates the CSRF token (32 bytes, base64url-nopad) and, in
`start_login`, the S256 challenge/verifier pair; builds the URL with
`response_type=code`, `client_id`, `redirect_uri` (if set), joined scopes,
`state`, and (PKCE leg) the challenge params. `into_parts` is for
consumers like axum-security that immediately scatter the pieces (cookie
one way, redirect the other) — avoids cloning out of the struct. The two
flows are separate method pairs with separate `Login` types instead of a
flag or an `Option` (see decision 4); each leg's docs point at its
matching counterpart, since the type system can't link legs that meet
across a cookie.

### Leg 2: `finish_login`

```rust
pub async fn finish_login(
    &self,
    code: &str,
    pkce_verifier: &str,
) -> Result<Tokens, Error>

pub async fn finish_login_non_pkce(&self, code: &str) -> Result<Tokens, Error>
```

POSTs the token endpoint: `grant_type=authorization_code`, the code, the
verifier (PKCE pair only), `redirect_uri` if configured; client auth via HTTP Basic
(form-urlencoded credentials, §2.3.1) when a secret is set, `client_id` in
the body otherwise; `Accept: application/json`; redirects never followed.
No fail-fast configuration checks — everything configuration-shaped was
already validated by `try_build()`.

### `Tokens`

As specified in the parent doc (§Core API): concrete read-only struct,
bare-name getters, `is_bearer()`, `extra` map with typed accessors.

### Errors (call time)

```rust
#[non_exhaustive]
pub enum Error {
    Http(HttpError),                // transport failure; source() → backend error
    Server(ServerError),            // well-formed §5.2 error body
    Parse(ParseError),              // non-JSON / wrong-shape body
}
```

Only things that can actually happen at request time — configuration
problems (missing/invalid endpoints, no HTTP backend) are `ConfigError`
at `try_build()` and cannot reach a built client (see decision 11).

```rust

pub struct ServerError {            // RFC 6749 §5.2 body + context
    // code() -> &ErrorCode, description() -> Option<&str>, uri() -> Option<&str>,
    // status() -> u16, extra_field::<T>(key) like Tokens
}

#[non_exhaustive]
pub enum ErrorCode {
    InvalidRequest, InvalidClient, InvalidGrant,
    UnauthorizedClient, UnsupportedGrantType, InvalidScope,
    Other(String),                  // extension / nonstandard codes
}
```

`ParseError` keeps the offending body for diagnostics but its `Debug`/
`Display` print only length and content-type — a failed *success* parse can
contain live tokens, so the raw body is only available through an explicit
`body()` accessor. (Upstream's `Parse` variant `Debug`s the raw bytes.)
`serde_path_to_error` is dropped; the endpoint URL + status carried on the
error replace most of its diagnostic value.

Hand-rolled `Display`/`Error` impls throughout (no `thiserror`), one line
per variant, good enough that axum-security's `map_err(|e| e.to_string())`
keeps producing useful log lines.

### HTTP backend

Exactly the parent doc's design; phase 1 pub surface is just:

```rust
#[non_exhaustive]
pub enum HttpClient {
    #[cfg(feature = "reqwest")]
    Reqwest(reqwest::Client),
}
impl From<reqwest::Client> for HttpClient {}   // cfg(feature = "reqwest")
```

### Full re-export list (`lib.rs`)

`OAuth2Client`, `OAuth2ClientBuilder`, `ConfigError`, `Login`,
`LoginNonPkce`, `Tokens`, `Error`, `HttpError`, `ParseError`,
`ServerError`, `ErrorCode`, `HttpClient`. Twelve items, flat — no module
paths in the public API.

## 4. Decision points

Options considered per design point; recommendation first.

1. **Endpoint URL parameters: `impl Into<String>` parsed at `build()`**
   (chosen) vs taking `url::Url` vs `impl TryInto<Url>`. Parsing at build
   keeps one fallible point, matches axum-security's `try_build` behavior
   and its `Invalid*Url` error variants 1:1, and keeps call sites
   string-literal clean. Taking `Url` would push `?` onto every setter
   line; `TryInto<Url>` hides which setter can fail.
2. **`AuthType`: defer to phase 3** (chosen) vs shipping the enum now with
   only `BasicAuth`. Nothing in phase 1 reads it, a one-variant enum is
   dead surface, and adding a defaulted builder method later is
   non-breaking. Cost of deferring: none.
3. **CSRF/PKCE randomness: not injectable** (chosen) vs upstream's
   `state_fn` closure parameter. The closure exists for deterministic
   tests; we test by asserting URL structure and round-tripping
   `state`/`verifier` through the mock server instead. Removing it deletes
   a generic from the hot path and an entire class of "caller supplied weak
   randomness" misuse.
4. **PKCE: two method pairs, no flag, no `Option`** (chosen; revised
   twice — from a client-level `pkce` flag with `Option<&PkceVerifier>`,
   then from PKCE-only) vs the opt-out flag vs splitting the *client* per
   flow (`PkceClient`, ...). The default pair `start_login()` /
   `finish_login(code, &verifier)` is PKCE with a required verifier;
   `start_login_non_pkce() -> LoginNonPkce` / `finish_login_non_pkce(code)`
   exist for providers that reject requests carrying `code_challenge`
   (compliant ones ignore it per RFC 6749 §3.1, so PKCE is the right
   default and carries no suffix). Method pairs keep every signature
   `Option`-free — the earlier flag design forced `Option` into `Login`
   and `finish_login`, plus `Error::MissingPkceVerifier`. The flow-split
   *client* was rejected: it doubles the client/builder surface,
   multiplies with every phase-3/4 grant, and forces multi-provider
   consumers to wrap the pair in an enum. Known limit, documented on the
   methods: the legs can't be type-linked (leg 2's verifier arrives from
   a cookie in a different request), so a mismatched
   `start_login` + `finish_login_non_pkce` fails at the provider, not at
   compile time. A consumer whose cookie is missing the verifier fails
   its own cookie validation before ever reaching the crate.
5. **`ServerError` code: enum with `Other(String)`** (chosen) vs plain
   `String`. The six §5.2 codes are closed by the RFC; matching
   `ErrorCode::InvalidGrant` (expired code — the retryable case) beats
   string comparison. `Other` absorbs extensions; `#[non_exhaustive]` lets
   us promote common ones later.
6. **Parse-error body: retained but redacted in `Debug`/`Display`**
   (chosen) vs upstream's raw `Vec<u8>` in the variant vs not keeping it.
   Failed success-parses can contain tokens; logging `{:?}` of an error
   must stay safe (same invariant as the secret types). Explicit `.body()`
   opts into the risk.
7. **Scopes: client-level `scopes(&[&str])`, replace semantics, no
   `add_scope`** (chosen) vs per-login scopes vs both. axum-security sets
   scopes once at build and clones them into every request; per-login
   scope variation returns with `start_login_with` in phase 3 if oidc
   needs it. One way to do it.
8. **`Login`: named struct + `into_parts()`** (chosen) vs bare tuple
   (upstream's `(Url, CsrfToken)` + a floating verifier variable) vs
   getters only. Struct per house style; `into_parts` because the one real
   consumer immediately splits ownership of the three pieces.
9. **Naming: `pkce_verifier`** (chosen) vs upstream's
   `pkce_code_verifier`. Short noun per house style; "code" adds nothing
   next to the authorization code. (Originally about the `PkceVerifier`
   type; the type is gone — decision 12 — but the method/argument name
   keeps the convention.)
10. **`AuthorizationCode` argument: explicit newtype** — superseded by
    decision 12; `finish_login` takes the code as a plain `&str` straight
    from the query string.
11. **Endpoints + HTTP backend validated at `try_build()`** (chosen;
    revised from optional endpoints failing at call time) vs
    `Error::MissingEndpoint(Endpoint)`/`Error::NoHttpClient` surfacing on
    the first login. The call-time design was the runtime translation of
    upstream's `EndpointMaybeSet`, kept for phase-4 grants that don't use
    `auth_url` (client credentials, device flow) — but every phase-1–3
    flow needs both endpoints, so a missing one is a configuration bug
    that should fail at startup, not on the first login attempt. Moving
    the checks makes `start_login` infallible and shrinks `Error` to
    `Http`/`Server`/`Parse`. Cost, accepted at 0.0.x: without a backend
    feature `try_build()` now always fails (`ConfigError::NoHttpClient`),
    and phase 4 revisits `auth_url` being required when grants that never
    authorize land.
12. **No secret newtypes** (chosen; revised — six shipped originally) vs
    the wrapper set with redacted `Debug` + `subtle` `PartialEq`.
    Secrets are plain `String`/`&str`; every crate type that holds one
    (`OAuth2Client`, `Login`, `LoginNonPkce`, `Tokens`) hand-writes
    `Debug` to redact it, pinned by the redaction tests. This deletes
    the `.secret()`/`::new()` ceremony at every call site, the six-type
    macro, and the `subtle` dep (constant-time `state` comparison is the
    consumer's job — axum-security already does its own; standalone
    users are pointed at it in the `csrf_token()` docs). Accepted
    trade-offs, stated honestly: a secret past a getter is an ordinary
    string, so consumer-side `Debug` leak-safety is the consumer's
    responsibility, and `finish_login(code, verifier)`'s two `&str`
    arguments are order-documented, not type-checked.

## 5. Explicitly not in phase 1

Deferred, with the phase that adds them: extra auth/token params,
refresh grant, `AuthType::RequestBody`, per-request redirect override
(phase 3); client credentials, device flow, introspection, revocation,
`pkce-plain`, `legacy-grants`, datetime accessor features (phase 4).
Dropped forever: implicit grant, sync HTTP, injectable RNG, length-
configurable secrets, the `Scope`/`ClientId`/`*Url` wrapper zoo, the
`TokenResponse`/`ErrorResponse` trait hierarchies.

## 6. Exit criteria

- axum-security's `oauth2` feature compiles on this crate with the
  migration steps from the parent doc; its existing builder + redirect
  tests pass unchanged.
- PKCE S256 verified against the RFC 7636 Appendix B vector.
- `wiremock` integration: `finish_login` success, §5.2 error body →
  `Error::Server` with the right `ErrorCode`, non-JSON body →
  `Error::Parse`, Basic-auth header correctness, redirects-not-followed.
- Redaction: `format!("{:?}", ...)` over the client, `Login`, `Tokens`,
  and every `Error` variant contains no secret bytes.
