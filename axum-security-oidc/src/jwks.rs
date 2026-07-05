use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum_security_oauth2::HttpClient;
use jsonwebtoken::{Algorithm, jwk::JwkSet};
use tokio::sync::Mutex;
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
/// The keys are fetched on first use, turned into an [`IdTokenVerifier`], and
/// cached. A token whose `kid` is absent from the cache — a sign the provider
/// rotated keys — triggers a single refetch, rate-limited to at most one
/// attempt per [`min_refetch_interval`](Self::min_refetch_interval) (default
/// 60s) so a stream of bogus-`kid` tokens can't hammer the JWKS endpoint.
///
/// A [`Mutex`] guards the cache and is held across the fetch, so concurrent
/// callers coalesce onto a single request instead of stampeding the endpoint.
/// Owns its [`HttpClient`] — clone the login flow's backend in so both share
/// one connection pool.
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

#[derive(Default)]
struct State {
    /// The verifier built from the current key set, once one has been fetched.
    verifier: Option<Arc<IdTokenVerifier>>,
    /// Last fetch *attempt* for a rotation refetch — failures count too, so a
    /// down endpoint can't be retried faster than the rate limit.
    last_refetch: Option<Instant>,
}

impl JwksCache {
    /// A cache that fetches the JWK set from `jwks_url` on first verification.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_url: Url,
        http: HttpClient,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algorithms: None,
            leeway_secs: None,
            jwks_url,
            http,
            min_refetch_interval: DEFAULT_MIN_REFETCH_INTERVAL,
            state: Mutex::new(State::default()),
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
        let verifier = self.current_verifier().await?;

        match verifier.verify(id_token, nonce) {
            // An unknown `kid` may just mean the keys rotated: refetch and retry
            // (once — `refetch` gives back the same verifier if rate-limited, so
            // this can't loop).
            Err(VerifyError::UnknownKey) => self.refetch(&verifier).await?.verify(id_token, nonce),
            result => result,
        }
    }

    /// The cached verifier, fetching the JWK set on first use. The lock is held
    /// across the fetch so concurrent first-callers coalesce onto one request.
    async fn current_verifier(&self) -> Result<Arc<IdTokenVerifier>, VerifyError> {
        let mut state = self.state.lock().await;
        if let Some(verifier) = &state.verifier {
            return Ok(verifier.clone());
        }
        let verifier = Arc::new(self.build_verifier(self.fetch_jwks().await?));
        state.verifier = Some(verifier.clone());
        state.last_refetch = Some(Instant::now());
        Ok(verifier)
    }

    /// Refetch after an unknown key, returning the freshest verifier available.
    ///
    /// Returns `tried` unchanged when rate-limited (so the retry fails cleanly),
    /// or a newer verifier a concurrent caller already fetched.
    async fn refetch(
        &self,
        tried: &Arc<IdTokenVerifier>,
    ) -> Result<Arc<IdTokenVerifier>, VerifyError> {
        let mut state = self.state.lock().await;

        // A concurrent caller may have refetched while we waited for the lock.
        if let Some(current) = &state.verifier
            && !Arc::ptr_eq(current, tried)
        {
            return Ok(current.clone());
        }

        // Rate-limit; claim the slot before fetching so failures count too.
        if let Some(last) = state.last_refetch
            && last.elapsed() < self.min_refetch_interval
        {
            return Ok(tried.clone());
        }
        state.last_refetch = Some(Instant::now());

        let verifier = Arc::new(self.build_verifier(self.fetch_jwks().await?));
        state.verifier = Some(verifier.clone());
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

        serde_json::from_slice(&response.body).map_err(|_| VerifyError::JwksUnavailable)
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
