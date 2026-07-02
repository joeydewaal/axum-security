# Lazy JWKS for the hard-coded OIDC path

**Status:** implemented on `feat/oidc-lazy-jwks`
**Date:** 2026-07-02

## Implementation notes (what shipped vs. this design)

- **Prefetch (§3) was dropped for v1.** The manual path is pure lazy-on-verify:
  the callback self-fetches (§4), which works on every deployment model. No
  `tokio::spawn`, so only the `sync` tokio feature was added, not `rt`.
- **The refetch interval is configurable** via
  `OidcContextBuilder::jwks_min_refetch_interval(Duration)`, defaulting to 60s
  (resolves open question #1). This also lets tests drive the rotation path with a
  zero interval instead of waiting 60s.
- Verification lives in `OidcContext::verify_id_token`; the mode is an
  `IdTokenVerification` enum (`Baked` for discovery, boxed `Lazy` for manual).
  The JWKS cache is `oidc/jwks.rs` (`tokio::sync::Mutex`, single-flight).
- Tests (`tests/tests/oidc.rs`): full manual-path login, refetch-on-unknown-key,
  and no-fetch-at-build.

## Problem

Using OIDC currently requires `OidcContext::discover(...)` (or a provider shortcut
like `google()`), which is `async` and performs network I/O at startup. Web apps
would rather hard-code their endpoints and avoid startup network calls, fetching
the JWKS lazily instead.

The manual builder path (`OidcContext::builder(...)` with `.issuer_url` /
`.auth_url` / `.token_url` / `.jwks_url`) *looks* like it already supports this,
but it is **broken for signature verification**:

- `id_token.claims(&verifier, &nonce)` (`context.rs:180`) is **synchronous** and
  verifies the signature against an **in-memory** `JsonWebKeySet`. It never
  fetches keys.
- `discover_async` fetches the discovery doc **and** the JWKS, baking the keys
  into the metadata → client (`openidconnect discovery/mod.rs:333`).
- The manual path builds `CoreProviderMetadata::new(...)`, which starts with
  `jwks: JsonWebKeySet::new(Vec::new())` — **empty** — and nothing ever fetches
  `jwks_url`. The `.jwks_url(...)` setter is stored and silently ignored.

So today a hard-coded config fails RS256 verification against any real provider.
Discovery is effectively mandatory because it is the only path that populates the
signing keys.

## Goal

Let apps hard-code all OIDC endpoints (issuer, auth, token, `jwks_uri`) with a
**synchronous `build()`** and **zero startup network**. Fetch the JWKS lazily on
the first callback, cache it, and refetch when a token presents an unknown `kid`
(key rotation).

Non-goals: changing the discovery path (it keeps eagerly baking keys as today);
hard-coded provider endpoint constants (tracked as a follow-up, see below).

## What makes this feasible

Instead of `client.id_token_verifier()` (which bakes keys in at construction), a
verifier can be built on demand from a dynamically fetched key set:

- `IdTokenVerifier::new_public_client(client_id, issuer, jwks)` and
  `new_confidential_client(client_id, secret, issuer, jwks)`
  (`openidconnect verification/mod.rs:558,586`).
- `JsonWebKeySet::fetch_async(&jwks_url, &http_client)`
  (`openidconnect types/jwks.rs:112`).

The `CoreClient` still handles `authorize_url` and the code exchange. Only the
ID-token verification step changes.

## Design

### 1. API surface — fix the manual path in place

The existing manual builder becomes *the* lazy path. No new required API;
`build()` stays synchronous. `.jwks_url(...)` finally takes effect.

`OidcContextInner` gains the fields verification needs at runtime:

- `client_id: ClientId`
- `client_secret: Option<ClientSecret>`
- `issuer_url: IssuerUrl`
- `jwks_url: JsonWebKeySetUrl`

(These are stored only for the lazy path. The discovery path continues to use the
client's baked-in verifier.)

### 2. JWKS cache + single-flight

New field on `OidcContextInner`, present only for the lazy path:

```rust
struct JwksCache {
    keys: Option<Arc<JsonWebKeySet>>,
    last_fetch: Option<Instant>,
}
// tokio::sync::Mutex<JwksCache>
```

`tokio::sync::Mutex` held **across** the fetch gives single-flight for free: there
are two trigger points that can race — the prefetch at flow start (§3) and the
verify at callback (§4). Whichever fires first acquires the lock and fetches; the
other blocks briefly, then finds the keys already populated. Login flows are
low-frequency, so serializing them behind one lock costs nothing, and callers that
block were going to wait for the same fetch anyway.

Two operations:

```rust
// cold path: fetch only if empty; no rate-limit (we have no keys yet)
async fn ensure_keys(&self) -> Result<Arc<JsonWebKeySet>, FetchError>;

// rotation path: force a refetch, subject to the min-interval rate-limit (§5)
async fn refresh_keys(&self) -> Result<Arc<JsonWebKeySet>, FetchError>;
```

Both lock the mutex, and `ensure_keys` returns the cached `Arc` immediately when
present. The reqwest client used for the fetch should carry a request timeout so a
hung JWKS endpoint can't pin the lock indefinitely.

### 3. Prefetch at flow start — optional, long-lived-server only

`start_challenge()` (`context.rs:106`) *may* kick off the fetch as it hands back
the redirect, so keys warm while the user authenticates at the provider (password
+ MFA + consent — seconds to minutes). It is **fire-and-forget** (`tokio::spawn`):
awaiting inline would just move the latency onto the redirect instead of
overlapping it, and the callback is a *separate* request so the fetch has to
outlive `start_challenge`.

```rust
let inner = self.0.clone();
tokio::spawn(async move {
    // best-effort warm; errors ignored — the callback (§4) always self-fetches
    let _ = inner.ensure_keys().await;
});
```

**This is a pure optimization and is never relied upon.** It only helps when a
single long-lived process handles both the login and the callback, and only for
the first login after boot (later logins find warm keys; rotation is unaffected
because the cache still holds the old keys at flow start).

On serverless / multi-instance it does **nothing useful, and can be dead work**:

- Login and callback can land on *different* instances (Lambda env B, a new pod),
  whose in-memory cache is empty regardless of what instance A prefetched.
- After the handler returns the redirect, Lambda **freezes** the execution
  environment — the spawned fetch is suspended and likely never completes.

So it degrades cleanly to pure lazy-on-verify. Because the benefit is this narrow,
it is a candidate to gate behind a builder flag (default off) or drop entirely —
see open questions.

### 4. Verification flow

Replaces the `client.id_token_verifier()` call at `context.rs:180`.

```
verifier(keys) =
    match client_secret {
        Some(secret) => IdTokenVerifier::new_confidential_client(id, secret, issuer, keys),
        None         => IdTokenVerifier::new_public_client(id, issuer, keys),
    }

1. keys = ensure_keys().await        // warm keys if present, else fetch now
2. try id_token.claims(verifier(keys), nonce)
3. on signature / unknown-kid failure:
       keys = refresh_keys().await    // rotation; rate-limited (§5)
       retry id_token.claims(verifier(keys), nonce) once
4. -> claims, or 401
```

**Step 1 is the load-bearing correctness path.** `ensure_keys()` fetches whenever
the cache is cold, so the callback is fully self-sufficient — it never assumes the
prefetch (§3) ran. This is what makes the design correct on a fresh Lambda
environment, a newly-scheduled pod, or any instance that did not handle the
matching login: the callback simply fetches the JWKS itself, once, on first use.

Note the rate-limit (§5) interaction on a cold instance: if step 1 just fetched
the freshest JWKS and the token's `kid` still isn't in it, `refresh_keys()` is
correctly suppressed (we already hold the newest keys), so verification returns
`401` rather than hammering the endpoint — the desired outcome for a genuinely
unknown key.

`new_confidential_client` is required to verify tokens signed with a shared-secret
algorithm (HS256/384/512); `new_public_client` covers the asymmetric case
(RS256, etc.). Selecting on `client_secret` presence matches the crate's own
convention.

### 5. Security — rate-limit refetches

A token with a bogus `kid` would otherwise force a JWKS refetch on every request —
egress/DoS amplification against the provider's JWKS endpoint. `refresh_keys`
skips the network call if `last_fetch` is within a minimum interval
(default ~60s, configurable via the builder). The cold path (`ensure_keys`, no
keys cached yet) always fetches.

### 6. Dependencies

`tokio` is currently `default-features = false` with no features on this crate.

- `sync` (for `tokio::sync::Mutex`) is **always** required — it backs the
  single-flight cache (§2), which the callback-self-fetch path depends on.
- `rt` (for `tokio::spawn`) is required **only if the §3 prefetch is kept**. If
  prefetch is dropped or made a no-op on unsupported runtimes, `rt` is not needed.

Both are gated behind the `oidc` feature. `rt` only makes `tokio::spawn` nameable —
it doesn't force a runtime flavor; the app already runs on tokio via axum.

### 7. Error handling

- **Cold-path fetch failure** (no keys yet): respond `500`, log via
  `crate::debug!`, leave the cache empty so the next login retries. This mirrors
  how the existing token-exchange failures are handled in `on_redirect`.
- **Rotation-refetch failure**: keep the existing cached keys; the current
  verification returns `401`.
- Fetch is a runtime concern, logged like the existing errors — no new
  `OidcBuilderError` variant.

### 8. Testing

- **Unit:** verifier construction (public vs confidential) from a static
  `JsonWebKeySet`; the refetch-eligibility (rate-limit) predicate.
- **Integration** (mock JWKS endpoint): (a) cold fetch happens exactly once across
  concurrent first-logins (single-flight), (b) a prefetch at flow start warms the
  cache so the callback does no fetch, (c) an unknown `kid` triggers exactly one
  refetch, (d) the rate-limit blocks rapid bogus-`kid` refetches.

## Follow-up (out of scope)

Optional sync provider constructors — hard-coded endpoint constants plus
`OidcContext::builder("google").google_endpoints()` in `providers.rs` — so common
providers can skip discovery entirely. Deferred because hard-coded endpoints can
change upstream and add maintenance burden. The `providers` module currently holds
only issuer URLs.

## Open questions

- Should the refetch min-interval be exposed as a builder knob now, or hard-coded
  at ~60s until there's a reason to configure it?
- Keep the §3 prefetch at all? Its benefit is limited to the first login on a
  long-lived single process, and it's dead work on serverless (different instance
  handles the callback; Lambda freezes the spawned task). Options: (a) drop it and
  ship pure lazy-on-verify, (b) keep it behind a builder flag defaulting off. Only
  `sync` is needed regardless; `rt` rides along only if we keep it.
