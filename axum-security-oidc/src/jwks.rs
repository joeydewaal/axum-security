use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum_security_oauth2::HttpClient;
use jsonwebtoken::{Algorithm, jwk::JwkSet};
use url::Url;

use crate::{
    error::VerifyError,
    verifier::{IdTokenVerifier, VerifiedIdToken},
};

/// Default minimum time between JWKS refetch attempts triggered by an unknown
/// signing key; bounds the JWKS load a stream of bogus-`kid` tokens can cause.
pub const DEFAULT_MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// A JWKS-backed ID-token verifier that fetches (and caches) the provider's
/// signing keys.
///
/// The keys are turned into an [`IdTokenVerifier`] on first use and cached. A
/// token whose `kid` is absent from the cache — a sign the provider rotated
/// keys — triggers a single refetch, rate-limited to at most one attempt per
/// [`min_refetch_interval`](Self::min_refetch_interval) (default 60s) so a
/// stream of bogus-`kid` tokens can't hammer the JWKS endpoint.
///
/// Build with [`new`](Self::new) (keys fetched lazily) or
/// [`with_keys`](Self::with_keys) (keys already in hand, e.g. from discovery);
/// either way a rotation still refetches. Owns its [`HttpClient`] — clone the
/// login flow's backend in so both share one connection pool.
pub struct JwksCache {
    issuer: String,
    audience: String,
    algorithms: Option<Vec<Algorithm>>,
    leeway_secs: Option<u64>,
    jwks_url: Url,
    http: HttpClient,
    min_refetch_interval: Duration,
    state: Mutex<State>,
}

struct State {
    /// The verifier built from the current key set, once one exists.
    verifier: Option<Arc<IdTokenVerifier>>,
    /// Keys supplied up front (discovery) but not yet turned into a verifier —
    /// so the config setters still apply. Taken on first use.
    seed: Option<JwkSet>,
    /// Last fetch *attempt*, successful or not — failures count against the
    /// rate limit too.
    last_attempt: Option<Instant>,
}

impl JwksCache {
    /// A cache that fetches the JWK set from `jwks_url` on first verification.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: Url,
        http: HttpClient,
    ) -> Self {
        Self::build(issuer, audience, jwks_url, http, None)
    }

    /// A cache pre-seeded with `jwks` (e.g. keys baked in during discovery). A
    /// later rotation still refetches from `jwks_url`.
    pub fn with_keys(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: Url,
        http: HttpClient,
        jwks: JwkSet,
    ) -> Self {
        Self::build(issuer, audience, jwks_url, http, Some(jwks))
    }

    fn build(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: Url,
        http: HttpClient,
        seed: Option<JwkSet>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: None,
            leeway_secs: None,
            jwks_url,
            http,
            min_refetch_interval: DEFAULT_MIN_REFETCH_INTERVAL,
            state: Mutex::new(State {
                verifier: None,
                seed,
                last_attempt: None,
            }),
        }
    }

    /// Restrict the accepted signing algorithms (see
    /// [`IdTokenVerifier::algorithms`]). Defaults to the asymmetric allow-list.
    pub fn algorithms(mut self, algorithms: &[Algorithm]) -> Self {
        self.algorithms = Some(algorithms.to_vec());
        self
    }

    /// Set the clock-skew leeway (seconds) applied to `exp`/`nbf`.
    pub fn leeway_secs(mut self, leeway_secs: u64) -> Self {
        self.leeway_secs = Some(leeway_secs);
        self
    }

    /// Set the minimum interval between rotation-triggered JWKS refetches.
    pub fn min_refetch_interval(mut self, interval: Duration) -> Self {
        self.min_refetch_interval = interval;
        self
    }

    /// Verify `id_token` and check its `nonce`, fetching the JWK set if needed.
    ///
    /// On an unknown signing key the JWK set is refetched once (rate-limited)
    /// and verification retried, to ride out a provider key rotation.
    pub async fn verify(
        &self,
        id_token: &str,
        nonce: &str,
    ) -> Result<VerifiedIdToken, VerifyError> {
        let verifier = self.ensure_verifier().await?;

        match verifier.verify(id_token, nonce) {
            // An unknown `kid` may just mean the keys rotated: refetch and retry.
            Err(VerifyError::UnknownKey) => match self.refresh_verifier(&verifier).await? {
                Some(fresh) => fresh.verify(id_token, nonce),
                None => Err(VerifyError::UnknownKey),
            },
            result => result,
        }
    }

    /// The cached verifier, building it from the seed or a fresh fetch.
    async fn ensure_verifier(&self) -> Result<Arc<IdTokenVerifier>, VerifyError> {
        {
            let mut state = self.state.lock().unwrap();
            if let Some(verifier) = &state.verifier {
                return Ok(verifier.clone());
            }
            // Seeded keys (discovery) — build without any I/O.
            if let Some(seed) = state.seed.take() {
                let verifier = Arc::new(self.build_verifier(seed));
                state.verifier = Some(verifier.clone());
                return Ok(verifier);
            }
        }
        self.fetch_and_store().await
    }

    /// Force a refetch, at most one attempt per `min_refetch_interval`. When
    /// rate-limited, returns a verifier built since `tried`, or `None` if
    /// `tried` is already the freshest available.
    async fn refresh_verifier(
        &self,
        tried: &Arc<IdTokenVerifier>,
    ) -> Result<Option<Arc<IdTokenVerifier>>, VerifyError> {
        {
            let mut state = self.state.lock().unwrap();
            if let Some(last_attempt) = state.last_attempt
                && last_attempt.elapsed() < self.min_refetch_interval
            {
                return Ok(state.verifier.clone().filter(|v| !Arc::ptr_eq(v, tried)));
            }
            // Claim the slot before releasing the lock so concurrent callers
            // coalesce onto this one fetch instead of stampeding the endpoint.
            state.last_attempt = Some(Instant::now());
        }

        let verifier = Arc::new(self.build_verifier(self.fetch_jwks().await?));
        self.state.lock().unwrap().verifier = Some(verifier.clone());
        Ok(Some(verifier))
    }

    async fn fetch_and_store(&self) -> Result<Arc<IdTokenVerifier>, VerifyError> {
        self.state.lock().unwrap().last_attempt = Some(Instant::now());
        let verifier = Arc::new(self.build_verifier(self.fetch_jwks().await?));
        self.state.lock().unwrap().verifier = Some(verifier.clone());
        Ok(verifier)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, VerifyError> {
        let response = self
            .http
            .get(&self.jwks_url)
            .await
            .map_err(|_| VerifyError::JwksUnavailable)?;

        if !response.is_success() {
            return Err(VerifyError::JwksUnavailable);
        }

        serde_json::from_slice(response.body()).map_err(|_| VerifyError::JwksUnavailable)
    }

    fn build_verifier(&self, jwks: JwkSet) -> IdTokenVerifier {
        let mut verifier = IdTokenVerifier::new(self.issuer.clone(), self.audience.clone(), jwks);
        if let Some(algorithms) = &self.algorithms {
            verifier = verifier.algorithms(algorithms);
        }
        if let Some(leeway_secs) = self.leeway_secs {
            verifier = verifier.leeway_secs(leeway_secs);
        }
        verifier
    }
}
