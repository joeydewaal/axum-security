use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use openidconnect::{JsonWebKeySetUrl, core::CoreJsonWebKeySet, reqwest::Client as HttpClient};
use tokio::sync::Mutex;

/// Default minimum time between JWKS refetch attempts triggered by an unknown
/// signing key. Bounds the damage from tokens carrying bogus `kid`s, which
/// would otherwise force a refetch on every request (a DoS amplification
/// against the provider's JWKS endpoint).
pub(super) const DEFAULT_MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Lazily-fetched, cached JWKS for the manual (hard-coded endpoint) OIDC path.
///
/// Keys are fetched on first use and cached. When a token presents a signing
/// key that isn't in the cache (key rotation), the cache is refetched — at most
/// one attempt (successful or not) per `min_refetch_interval`.
///
/// The mutex is held across the fetch, so concurrent callers coalesce onto a
/// single request (single-flight): whichever caller arrives first fetches, the
/// rest block briefly and then find the keys already populated.
pub(super) struct JwksCache {
    jwks_url: JsonWebKeySetUrl,
    min_refetch_interval: Duration,
    state: Mutex<JwksState>,
}

struct JwksState {
    keys: Option<Arc<CoreJsonWebKeySet>>,
    /// When a fetch was last *attempted*, successful or not. Failed attempts
    /// count against the refetch rate limit too, so a broken JWKS endpoint
    /// isn't hammered once per bad token.
    last_attempt: Option<Instant>,
}

impl JwksCache {
    pub(super) fn new(jwks_url: JsonWebKeySetUrl, min_refetch_interval: Duration) -> Self {
        Self {
            jwks_url,
            min_refetch_interval,
            state: Mutex::new(JwksState {
                keys: None,
                last_attempt: None,
            }),
        }
    }

    /// Return the cached keys, fetching them once if the cache is cold.
    ///
    /// This is the load-bearing correctness path: it works identically whether or
    /// not any prior request warmed the cache, so a fresh process (new Lambda
    /// environment, new pod) fetches the keys itself on first use.
    pub(super) async fn ensure_keys(
        &self,
        http_client: &HttpClient,
    ) -> Result<Arc<CoreJsonWebKeySet>, JwksError> {
        let mut state = self.state.lock().await;
        if let Some(keys) = &state.keys {
            return Ok(keys.clone());
        }
        self.fetch_into(&mut state, http_client).await
    }

    /// Force a refetch after an unknown signing key (rotation), at most one
    /// attempt per `min_refetch_interval`.
    ///
    /// When rate-limited, returns keys a concurrent caller fetched since `tried`
    /// — or `None`, meaning `tried` is the freshest available and the caller's
    /// verification failure stands.
    pub(super) async fn refresh_keys(
        &self,
        http_client: &HttpClient,
        tried: &Arc<CoreJsonWebKeySet>,
    ) -> Result<Option<Arc<CoreJsonWebKeySet>>, JwksError> {
        let mut state = self.state.lock().await;
        if let Some(last_attempt) = state.last_attempt
            && last_attempt.elapsed() < self.min_refetch_interval
        {
            return Ok(state.keys.clone().filter(|keys| !Arc::ptr_eq(keys, tried)));
        }
        self.fetch_into(&mut state, http_client).await.map(Some)
    }

    async fn fetch_into(
        &self,
        state: &mut JwksState,
        http_client: &HttpClient,
    ) -> Result<Arc<CoreJsonWebKeySet>, JwksError> {
        state.last_attempt = Some(Instant::now());
        let keys = CoreJsonWebKeySet::fetch_async(&self.jwks_url, http_client)
            .await
            .map_err(|e| JwksError(e.to_string()))?;
        let keys = Arc::new(keys);
        state.keys = Some(keys.clone());
        Ok(keys)
    }
}

/// Error fetching the JWKS from the provider.
pub(super) struct JwksError(String);

impl std::fmt::Display for JwksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
