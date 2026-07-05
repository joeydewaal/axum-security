# Design: `axum-security-oidc`

The committed follow-up to
[`axum-security-oauth2`](./axum-security-oauth2.md): an independent OpenID
Connect client crate owned by the axum-security workspace, **inspired by** —
not forked from — the [`openidconnect`](https://crates.io/crates/openidconnect)
crate (v4.0.1). It layers on `axum-security-oauth2` for the OAuth2 half of the
flow and adds the OIDC half: ID-token JWS verification, JWKS fetch/cache,
provider discovery, and RP-initiated logout. We take upstream as the reference
for *which OIDC capabilities to support* and implement from the specs (OIDC
Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0, RFC 7517/7519) ourselves: no
code is copied. Landing it retires the `openidconnect` dependency — and,
transitively, the last copy of the upstream `oauth2` crate — from the tree.

This mirrors the oauth2 crate's split: **`axum-security-oidc` is a pure
protocol crate with no axum dependency**; axum-security's `oidc` module keeps
the axum wiring (routes, signed cookie, `OidcHandler`, `LogoutContext`), same
as its `oauth2` module wraps `axum-security-oauth2` today.

## Design constraints (non-negotiable)

Inherit the oauth2 crate's constraints verbatim, plus OIDC-specific ones:

1. **Feature parity, not API parity — and not a fork.** Match the OIDC
   protocol surface `openidconnect` exposes (inventory below), API and code
   ours, written from the specs. Not a drop-in replacement.
2. **No typestate.** `openidconnect`'s `Client` carries **eight-plus** type
   parameters (additional claims, gender enum, JWE enc/alg, token type, token
   response, introspection response, error type) *on top of* oauth2 5.0's
   `EndpointSet`/`EndpointMaybeSet`/`EndpointNotSet` endpoint markers — the
   exact `CoreClient<EndpointSet, ..., EndpointMaybeSet, EndpointMaybeSet>`
   shape the current module is stuck naming. One concrete `OidcClient`, zero
   type parameters. Configuration validated once at `try_build()`.
3. **No wrapper types.** `Nonce`, `CsrfToken`, `IssuerUrl`, `ClientId`,
   `ClientSecret`, `Scope`, `AccessTokenHash`, the whole `Core*` alias family —
   gone. Plain `String`/`&str`/`url::Url`/`Duration`/`i64`; redaction lives in
   hand-written `Debug` impls; constant-time compares are the consumer's job
   (axum-security already does this via `subtle` in `verify_cookies`).
4. **Datetime-library agnostic.** `OidcClaims` already does this — datetime
   claims are private `UtcTimestamp` (unix `i64`) with feature-gated
   `jiff`/`chrono`/`time` accessors. Keep it; move the type into the crate.
   Drop `openidconnect`'s unconditional `chrono` dependency.
5. **One connection pool.** Discovery and JWKS fetches ride the *same*
   `axum-security-oauth2::HttpClient` backend the login flow uses — no second
   reqwest client, no second TLS stack. (Prerequisite: extend that enum with a
   JSON `GET`; see "Shared HTTP backend".)
6. **Minimal dependencies.** One substantial new dep — `jsonwebtoken` — and it
   is already in the tree (the `jwt` feature). Everything else is shared with
   the oauth2 crate. Justification per dep below.
7. **House API style** — `try_build()`/`build()`, bare-name getters,
   `set_x`/`get_x`, `Cow<'static, str>` params, one error enum per concern with
   hand-rolled `Display`/`Error`.

## Motivation

The current `oidc` module already decodes and deserializes the ID token itself
(`claims.rs` → `OidcClaims`), so `openidconnect`'s claims model is *already
bypassed*. What the crate is still pulled in for is a narrow slice:

- `CoreIdTokenVerifier` + `CoreJsonWebKeySet` — ID-token signature +
  iss/aud/exp/nonce verification (`context.rs`, `jwks.rs`).
- `ProviderMetadataWithLogout::discover_async` — discovery (`builder.rs`).
- `CoreJsonWebKeySet::fetch_async` — JWKS retrieval (`jwks.rs`).
- `LogoutRequest`/`EndSessionUrl`/… — logout URL assembly (`context.rs`).
- Newtype ceremony (`Nonce`, `CsrfToken`, `PkceCodeVerifier`, …) threaded
  through `cookie.rs`, `redirect.rs`, `context.rs`.

For that slice we pay: the eight-parameter generic client, a **second crypto
stack** (`openidconnect` is pure-RustCrypto — `rsa`, `p256`, `p384`,
`ed25519-dalek`, `sha2 0.10`, `hmac 0.12` — while the rest of axum-security
verifies JWTs with `jsonwebtoken` on `aws-lc-rs`), an unconditional `chrono`, a
whole transitive copy of `oauth2 5.0`, and `thiserror`. Reimplementing on
`jsonwebtoken` collapses the tree onto **one** JWT/crypto backend and removes
the last typestate client from axum-security's storage types.

## Upstream feature inventory and what we need

`openidconnect 4.0.1` verified against the survey below. "oidc today" = what
the current module actually exercises; "we need" = what the reimplementation
must ship; the rest is parity backlog or documented omission.

### Protocol features

| `openidconnect` capability | Spec | oidc today | We need | Our plan |
|---|---|---|---|---|
| Provider discovery (`.well-known/openid-configuration`) | Discovery 1.0 | ✅ | ✅ | **Phase 2** — fetch + deserialize + issuer-match check |
| Manual endpoint configuration | — | ✅ | ✅ | **Phase 2** — the builder's `issuer_url`/`auth_url`/`token_url`/`jwks_url` path |
| JWKS model + `jwks_uri` fetch | RFC 7517 | ✅ | ✅ | **Phase 1/2** — `jsonwebtoken::jwk::JwkSet` + our fetch |
| JWKS caching + key rotation refetch | — | ✅ (`LazyVerifier`) | ✅ | **Phase 2** — port `LazyVerifier` (rate-limited refetch on unknown `kid`) |
| ID-token signature verification | OIDC Core §3.1.3.7 | ✅ | ✅ | **Phase 1** — `jsonwebtoken::decode` + `DecodingKey::from_jwk`, `alg` allow-list |
| `iss` / `aud` / `exp` / `iat` checks | §3.1.3.7 | ✅ | ✅ | **Phase 1** — `jsonwebtoken::Validation` (`iss`,`aud`,`validate_exp`,`leeway`) |
| `nonce` replay check | §3.1.3.7 (11) | ✅ | ✅ | **Phase 1** — manual constant-time compare (jsonwebtoken has no nonce concept) |
| JWS algs RS256/384/512, PS256/384/512, ES256/384, EdDSA, HS256/384/512 | RFC 7518 | ✅ (via Core) | ✅ | **Phase 1** — `jsonwebtoken` covers this set exactly |
| `ES512` / P-521 | RFC 7518 | ❌ (upstream unimpl) | ❌ | **Dropped** — `jsonwebtoken` lacks it too; no provider parity loss |
| RP-Initiated Logout (`end_session_endpoint`, `id_token_hint`, `post_logout_redirect_uri`, `state`, `logout_hint`) | RP-Initiated Logout 1.0 | ✅ | ✅ | **Phase 3** — plain query-string builder (our `LogoutUrl`) |
| Standard claims model (profile/email/phone/address/…) | §5.1 | ✅ (`OidcClaims`) | ✅ | **Phase 1** — already ours; move into the crate |
| `azp` claim verification | §3.1.3.7 (4) | ❌ (upstream **does not** verify) | optional | **Phase 5** — opt-in `expected_azp`; an *improvement* over upstream |
| `at_hash` / `c_hash` verification | §3.1.3.6 | ❌ (not exercised) | optional | **Phase 5** — needs SHA-2 halves; `sha2` already present |
| `auth_time` / `acr` / `amr` exposure | §2 | ✅ (fields on `OidcClaims`) | ✅ | **Phase 1** — plain claim fields; policy is the caller's |
| UserInfo endpoint | §5.3 | ❌ | ❌ | **Phase 5** — `client.user_info()`; not used today |
| Refresh-token grant | RFC 6749 §6 | ✅ (returned to handler) | ✅ | **From oauth2** — `OAuth2Client::refresh_tokens` |
| PKCE (S256) + CSRF `state` + scopes + code exchange | RFC 7636 / 6749 | ✅ | ✅ | **From oauth2** — `start_login_with` / `finish_login` |
| `nonce` / `prompt` / `login_hint` / `hd` on authorize URL | §3.1.2.1 | ✅ | ✅ | **From oauth2** — `LoginOptions::param(...)` (phase-3 of oauth2, shipped) |
| JWE / encrypted ID tokens | §3.1.3.7 | ❌ (upstream **unsupported**) | ❌ | **Dropped** — documented omission, matches upstream |
| Dynamic client registration | Registration 1.0 | ❌ | ❌ | **Dropped** — documented omission |
| Token introspection / revocation | RFC 7662 / 7009 | ❌ | ❌ | Deferred to oauth2 crate's phase 4 if ever needed |
| Implicit / hybrid flows | §3.2 / §3.3 | ❌ | ❌ | **Dropped** — code flow only (2.1 direction) |
| `private_key_jwt` / `client_secret_jwt` client auth | §9 | ❌ (upstream parses but **doesn't sign**) | ❌ | **Dropped** unless a consumer needs it |

### Infrastructure features

| `openidconnect` capability | oidc today | Our plan |
|---|---|---|
| Crypto: `rsa`/`p256`/`p384`/`ed25519-dalek` (RustCrypto) | via crate | **Replaced** by `jsonwebtoken` on `aws-lc-rs` — one backend for the whole workspace |
| `chrono` (non-optional) | via crate | **Dropped** — `UtcTimestamp` (`i64`) + optional `jiff`/`chrono`/`time` accessors |
| `thiserror` | via crate | **Dropped** — hand-rolled `Display`/`Error` (house style) |
| transitive `oauth2 5.0` | via crate | **Dropped** — replaced by `axum-security-oauth2` |
| Async HTTP (reqwest, rustls default) | ✅ | **Shared** `axum-security-oauth2::HttpClient` enum — one pool, one TLS stack |
| Lenient parsing flags (`accept-rfc3339-timestamps`, `accept-string-booleans`) | off | Reconsider per-provider need; likely dropped |

## Dependencies

| Dep | Why | Shared with oauth2 crate? |
|---|---|---|
| `axum-security-oauth2` | the OAuth2 half of every flow + the `HttpClient` backend | — |
| `jsonwebtoken` (10.x, `aws-lc-rs`) | JWS verify (`decode`), `jwk::JwkSet`, `DecodingKey::from_jwk`, `Validation` (iss/aud/exp/nbf/alg-allowlist/leeway). **The one substantial new dep** — but already in the tree via the `jwt` feature; reimplementing JWS/JWK from `aws-lc-rs` primitives is exactly the error-prone crypto we refuse to own | already in tree |
| `serde`, `serde_json` | discovery metadata, JWKS, claims | ✅ |
| `base64` | JWT payload decode (for our own `OidcClaims`), `at_hash` (phase 5) | ✅ |
| `sha2` | `at_hash`/`c_hash` halves (phase 5) | ✅ |
| `subtle` | constant-time `nonce`/`state` compare | ✅ |
| `url` | endpoint validation at build, logout URL building | ✅ |
| optional `jiff` / `chrono` / `time` | `OidcClaims` timestamp accessors (cookie-monster pattern) | ✅ |

No `getrandom` here (nonce/CSRF/PKCE randomness is generated in the oauth2
crate). Direct new dep vs the tree today: **+`jsonwebtoken`, −`openidconnect`,
−`oauth2`, −`chrono`(forced), −`thiserror`, −`rsa`/`p256`/`p384`/`ed25519-dalek`**.

### Feature flags

| Feature | Default | Contents |
|---|---|---|
| `reqwest` / `rustls-tls` / `native-tls` | reqwest+rustls | forwarded to `axum-security-oauth2` (the shared backend) |
| `jiff` / `chrono` / `time` | no | `OidcClaims` timestamp accessors |
| `userinfo` | no | UserInfo endpoint client (phase 5) |

## Shared HTTP backend (prerequisite)

The oauth2 crate's `HttpClient` enum currently exposes only a crate-private
`post_form` (token endpoint). Discovery and JWKS are `GET`s returning JSON, so
`axum-security-oauth2` must grow **one** public method:

```rust
impl HttpClient {
    /// GET a URL, return status + body bytes. No redirects (same policy as post_form).
    pub async fn get(&self, url: &Url) -> Result<HttpResponse, HttpError>;
}
```

That is the only change to the oauth2 crate this design requires (call it an
addendum to its phase 3). `axum-security-oidc` then reuses the *same*
`HttpClient` value the `OAuth2Client` holds, so both crates share one
connection pool and TLS stack — constraint 5. Alternative rejected: a private
reqwest client in the oidc crate (a second pool, a second `default_reqwest_client`
to keep in sync — the exact duplication the oauth2 doc set out to delete).

## Core API

Designed from the consumer's view (axum-security's `start_challenge` /
`on_redirect`), not the protocol's.

### Client

One concrete struct, zero type parameters — contrast the current
`OidcClient = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>`:

```rust
pub struct OidcClient {
    oauth2: OAuth2Client,          // the login half — from axum-security-oauth2
    issuer: String,                // for the iss check
    client_id: String,             // for the aud check (redacts nothing; public)
    verifier: IdTokenVerifier,     // JWKS-backed, see below
    scopes: Vec<String>,           // "openid" always forced in
    end_session_endpoint: Option<Url>,
}
```

Two build paths, matching today (the surface the module already exposes stays
identical to consumers):

```rust
// Discovery — fetches metadata + JWKS up front
let client = OidcClient::discover("google", "https://accounts.google.com", &http).await?
    .client_id("…").client_secret("…").redirect_url("…").scopes(&["email"])
    .try_build()?;

// Manual — every endpoint given; JWKS fetched lazily on first verify
let client = OidcClient::builder("keycloak")
    .issuer_url("…").auth_url("…").token_url("…").jwks_url("…")
    .client_id("…").redirect_url("…")
    .try_build()?;
```

### The login flow

Leg 1 generates the nonce alongside CSRF+PKCE and threads it onto the authorize
URL via the oauth2 crate's `LoginOptions`; leg 2 exchanges the code, pulls the
`id_token` out of the token response's extras, and verifies it:

```rust
// Leg 1 — pure, infallible
let login: OidcLogin = client.start_login();
login.url();            // redirect here
login.csrf_token();     // persist (HMAC cookie)
login.pkce_verifier();  // persist
login.nonce();          // persist — the new field vs oauth2's Login

// Leg 2 — exchange + verify in one call
let verified: VerifiedIdToken = client.finish_login(code, login.pkce_verifier(), login.nonce()).await?;
verified.claims();       // &OidcClaims
verified.id_token();     // &str (raw JWT, for id_token_hint on logout)
verified.access_token(); // &str
verified.refresh_token();// Option<&str>
```

`finish_login` = `oauth2.finish_login(code, verifier)` → `tokens.extra_field::<String>("id_token")`
→ `verifier.verify(&id_token, nonce)`. One error type (`OidcError`) covers
`token exchange failed / no id_token / signature / iss / aud / exp / nonce
mismatch / jwks fetch`. CSRF/`state` comparison and cookie storage stay the
consumer's job — the crate generates the secrets, it doesn't own the session.

### ID-token verification (the security core)

`jsonwebtoken` does the crypto and the standard-claim checks; we add nonce (and
later `at_hash`/`azp`):

```rust
struct IdTokenVerifier {
    jwks: JwksCache,               // ported LazyVerifier — see below
    validation: Validation,        // iss = {issuer}, aud = {client_id},
                                   // validate_exp = true, leeway, algorithms = allow-list
}

impl IdTokenVerifier {
    async fn verify(&self, id_token: &str, nonce: &str) -> Result<OidcClaims<'_>, OidcError> {
        let header = jsonwebtoken::decode_header(id_token)?;         // read kid + alg
        let key = self.jwks.decoding_key(header.kid.as_deref()).await?;  // fetch/cache/rotate
        let data = jsonwebtoken::decode::<RawClaims>(id_token, &key, &self.validation)?; // sig + iss/aud/exp
        if !bool::from(nonce.as_bytes().ct_eq(data.claims.nonce.as_bytes())) {  // subtle
            return Err(OidcError::NonceMismatch);
        }
        // then hand back our borrow-based OidcClaims (decode payload once, as today)
        …
    }
}
```

**Algorithm allow-listing is mandatory** (`Validation::algorithms`) — it is the
defense against `alg`-confusion / key-substitution. Default to the discovered
`id_token_signing_alg_values_supported`, else the RSA set (RS256 baseline) plus
whatever the JWKS advertises. `jsonwebtoken` verifies signature + iss + aud +
exp + nbf + leeway in the single `decode` call; nonce is the one OIDC-specific
check we bolt on (upstream's `IdToken::claims` does the same internally).

### JWKS cache (ported `LazyVerifier`)

The existing `jwks.rs` design carries over almost unchanged — only the key type
and fetch differ (`jsonwebtoken::jwk::JwkSet` deserialized from our
`HttpClient::get`, instead of `CoreJsonWebKeySet::fetch_async`):

- **Discovery path** — JWKS baked at build time (keys fetched during
  `discover`).
- **Manual path** — JWKS fetched on first `verify`, cached, and refetched
  (rate-limited: at most one attempt per `min_refetch_interval`, default 60s)
  when a token presents an unknown `kid` — key rotation. The mutex-coalesced,
  last-attempt-rate-limited logic in `jwks.rs` is sound and ports directly;
  swap `CoreIdTokenVerifier` for our `IdTokenVerifier`, `CoreJsonWebKeySet` for
  `JwkSet`, and select the key by `kid` ourselves (`JwkSet::find`).

### Logout URL builder

`openidconnect`'s `LogoutRequest`/`EndSessionUrl`/`LogoutHint`/`ClientId`
newtypes reduce to plain query-string assembly on the discovered/configured
`end_session_endpoint`:

```rust
pub struct LogoutUrl { /* end_session_endpoint + optional params */ }
impl LogoutUrl {
    pub fn id_token_hint(self, jwt: impl Into<String>) -> Self;
    pub fn post_logout_redirect_uri(self, url: impl Into<String>) -> Self;
    pub fn logout_hint(self, hint: impl Into<String>) -> Self;
    pub fn client_id(self, id: impl Into<String>) -> Self;
    pub fn state(self, state: impl Into<String>) -> Self;
    pub fn build(self) -> Url;   // or None → caller falls back to "/" / post_logout url
}
```

axum-security's `LogoutContext` (its axum `Redirect`, extension access,
`cookie_session`) stays in the module and calls this to assemble the redirect —
the module keeps every public method it has today; only the `openidconnect`
imports inside it change.

## Security invariants

- **`alg` allow-list on every verify** — never trust the token header's `alg`;
  `Validation::algorithms` is set from provider metadata / JWKS, and `none` is
  categorically rejected (`jsonwebtoken` has no `Algorithm::None`).
- **iss / aud / exp / iat** — `jsonwebtoken::Validation` (exact `iss`, `aud`
  contains `client_id`, `validate_exp`, `leeway` default 60s).
- **nonce** — constant-time compare via `subtle`; a token with no/mismatched
  nonce is rejected. Nonce is 32 bytes from the oauth2 crate's CSPRNG,
  base64url-nopad, stored HMAC-signed in the same session cookie as CSRF+PKCE.
- **JWKS refetch is rate-limited** — a stream of bogus-`kid` tokens can force at
  most one JWKS fetch per `min_refetch_interval`.
- **No redirects on discovery/JWKS/token fetches** — the shared `HttpClient`
  enforces it.
- **Secrets never in the crate's own output** — `OidcClient`, `OidcLogin`,
  `VerifiedIdToken` hand-write `Debug` to redact tokens/verifier/nonce; nothing
  secret-bearing implements `Display`. Redaction test pins it.
- **`azp` / `at_hash` (phase 5)** — opt-in enforcement; documented that, like
  `openidconnect`, they are *not* checked by default.
- TLS: `rustls-tls` default (inherited from the shared backend).

## What `axum-security-oidc` consumes from `axum-security-oauth2`

All shipped except the HTTP `get` addendum:

- `OAuth2Client` + `start_login_with` / `finish_login` / `refresh_tokens`
  (authorize URL, CSRF, PKCE S256, code exchange, refresh).
- `LoginOptions::param(...)` for `nonce` (+ `prompt`/`login_hint`/`hd`).
- `Tokens::extra_field::<String>("id_token")` — how the ID token comes out.
- `AuthType::RequestBody` for IdPs that only take credentials in the body.
- The `HttpClient` backend enum — **plus a new public `get()`** for discovery +
  JWKS, so both crates share one pool (the only oauth2-crate change required).

## Migration of axum-security's `oidc` feature

Same shape as the oauth2 migration — the module touches a narrow slice, so the
rewrite is contained and its public API is unchanged (upstream types never
leaked; `OidcTokenResponse`/`OidcClaims`/`OidcHandler`/`LogoutContext` are all
ours already):

1. `Cargo.toml`: drop `openidconnect`; the `oidc` feature depends on
   `axum-security-oidc` (which pulls `axum-security-oauth2`). Drop `serde_json`
   as a direct oidc dep if the crate owns claim parsing.
2. `context.rs`: delete the `OidcClient = CoreClient<…6 params…>` alias; the
   field becomes `client: axum_security_oidc::OidcClient`. `start_challenge`'s
   `authorize_url + set_pkce_challenge + add_scopes` collapses to
   `client.start_login()`; `on_redirect`'s `exchange_code + set_pkce_verifier +
   request_async + id_token() + verify_id_token` collapses to
   `client.finish_login(code, verifier, nonce).await?`. `LogoutContext` keeps
   its methods; its body calls `LogoutUrl`. Drop every `openidconnect::` import.
3. `jwks.rs`: the module's copy goes away — the `LazyVerifier` logic now lives
   in `axum-security-oidc` (`JwksCache`). If any rate-limit config
   (`jwks_min_refetch_interval`) is user-facing, forward it through the builder.
4. `claims.rs`: **move `OidcClaims`/`OidcAddress`/`UtcTimestamp` into the
   crate** and re-export from the module (they are already datetime-agnostic and
   dependency-free — a clean fit). `decode_token`/`from_decoded_payload` become
   the crate's verify path.
5. `cookie.rs`/`redirect.rs`: `CsrfToken`/`Nonce`/`PkceCodeVerifier`/
   `AuthorizationCode` imports disappear — the signed cookie already stores
   plain `&str`; `OidcParams { code, state }` become `String`s (constant-time
   `state` compare stays, via `subtle`).
6. `builder.rs`: `ProviderMetadataWithLogout::discover_async` →
   `OidcClient::discover`; the manual `CoreProviderMetadata::new(...)` scaffold
   (built today just to satisfy the typestate) is deleted — the manual path is
   now plain fields. `OidcBuilderError` variants map ~1:1 onto the crate's
   `OidcBuilderError`; `openidconnect::url::ParseError` becomes `url::ParseError`.

Acceptance gate: the module's existing tests (`builder.rs`, `redirect.rs`,
`cookie.rs`, `context.rs` logout tests) pass unchanged — they already assert
behavior (redirect targets, cookie round-trips, state rejection), not upstream
types.

## Testing

Written from scratch against the specs (not-a-fork applies to tests too):

- **ID-token verification** — a test RSA/EC keypair signs tokens; assert accept
  on valid, reject on: bad signature, wrong `iss`, `aud` without `client_id`,
  expired `exp`, `alg` not in the allow-list (RS256-signed token verified under
  an ES256-only list), missing/mismatched `nonce`, unknown `kid`.
- **JWKS** — parse real provider JWKS JSON (Google, Microsoft, a Keycloak
  realm) into `JwkSet`; key selection by `kid`; rotation test (unknown `kid`
  → one rate-limited refetch → success).
- **Discovery** — `wiremock` serving a `.well-known/openid-configuration`;
  issuer-match check; `end_session_endpoint` extraction; the manual path with
  no discovery.
- **Claims** — the deserialization cases already in `claims.rs`, plus `aud` as
  string vs array, `#[serde(flatten)]` extras, datetime-accessor features.
- **Redaction** — `format!("{:?}", …)` of client/login/verified contains no
  token, nonce, or key bytes.
- Full-flow `wiremock` integration: authorize → callback → token (with
  `id_token`) → verify → claims.

## Phases

1. **Verification core** — crate skeleton; move `OidcClaims`; `IdTokenVerifier`
   over `jsonwebtoken` (`decode` + `Validation` + nonce); `JwkSet` key
   selection; errors; redaction. *Exit: given a JWKS and a token, verify it.*
2. **Discovery + JWKS fetch/cache** — `OidcClient::discover` + manual builder;
   port `LazyVerifier` as `JwksCache` on the shared `HttpClient::get` (the
   oauth2-crate addendum lands here). *Exit: verify a live provider's token.*
3. **Client + login flow + logout** — `start_login` (nonce via `LoginOptions`)
   / `finish_login` (exchange + verify); `LogoutUrl` builder; provider
   shortcuts (`google`/`microsoft`/`apple`/`keycloak`).
4. **Migration** — swap the dependency in axum-security's `oidc` module; delete
   the `CoreClient` alias, `jwks.rs`, the `openidconnect` imports; module tests
   green; `openidconnect` + `oauth2` + `chrono` leave the tree.
5. **Parity + publish** — opt-in `azp`/`at_hash`/`c_hash`, UserInfo
   (`userinfo` feature), datetime accessors, docs.rs pass, README with an
   upstream-divergence table, `0.1.0`.

## Open decisions

| Decision | Recommendation | Alternative |
|---|---|---|
| Crypto backend | `jsonwebtoken`+`aws-lc-rs` — consolidates the workspace onto one JWT stack, already vetted in-tree | Hand-roll JWS on `aws-lc-rs` primitives (more surface we own) or keep RustCrypto (second stack) |
| Shared vs private HTTP client | Extend oauth2's `HttpClient` with `get()` — one pool | Private reqwest client in the oidc crate (duplicate default-client logic) |
| `azp` enforcement | Opt-in `expected_azp`, default off (matches upstream) — but *offer* it, since upstream can't | Never check (strict parity) |
| `at_hash`/`c_hash` | Phase 5, opt-in; not exercised today so not a launch blocker | Always verify when an access token/code is present (upstream's behavior) |
| `OidcClaims` home | Move into the crate, re-export from the module — it's already self-contained | Leave in axum-security, have the crate return raw bytes |
| Crate name | `axum-security-oidc` (family branding; no axum dependency, like the oauth2 crate) | Neutral standalone name |
