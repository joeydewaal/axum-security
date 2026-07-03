use std::{
    error::Error,
    sync::Arc,
    time::{Duration, Instant},
};

use openidconnect::{
    ClaimsVerificationError, ClientId, ClientSecret, IssuerUrl, JsonWebKeySetUrl, Nonce,
    core::{CoreIdToken, CoreIdTokenVerifier, CoreJsonWebKeySet},
    reqwest::Client as HttpClient,
};
use tokio::sync::Mutex;

/// Default minimum time between JWKS refetch attempts triggered by an unknown
/// signing key; bounds the JWKS load a stream of bogus-`kid` tokens can cause.
pub(super) const DEFAULT_MIN_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

type SharedVerifier = Arc<CoreIdTokenVerifier<'static>>;

/// ID-token verification for the manual (hard-coded endpoint) OIDC path: the
/// JWKS is fetched on first use, cached as a ready-made verifier, and
/// refetched (rate-limited) when a token presents an unknown signing key.
///
/// The mutex is held across the fetch so concurrent callers coalesce onto a
/// single request.
pub(super) struct LazyVerifier {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    issuer_url: IssuerUrl,
    jwks_url: JsonWebKeySetUrl,
    min_refetch_interval: Duration,
    state: Mutex<State>,
}

struct State {
    verifier: Option<SharedVerifier>,
    /// Last fetch *attempt*, successful or not — failures count against the
    /// rate limit too.
    last_attempt: Option<Instant>,
}

impl LazyVerifier {
    pub(super) fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        issuer_url: IssuerUrl,
        jwks_url: JsonWebKeySetUrl,
        min_refetch_interval: Duration,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            issuer_url,
            jwks_url,
            min_refetch_interval,
            state: Mutex::new(State {
                verifier: None,
                last_attempt: None,
            }),
        }
    }

    /// Verify an ID token's signature, nonce, audience, and expiration.
    pub(super) async fn verify(
        &self,
        id_token: &CoreIdToken,
        nonce: &Nonce,
        http_client: &HttpClient,
    ) -> bool {
        match self.try_verify(id_token, nonce, http_client).await {
            Ok(()) => true,
            Err(_e) => {
                crate::debug!("id_token verification failed: {_e}");
                false
            }
        }
    }

    async fn try_verify(
        &self,
        id_token: &CoreIdToken,
        nonce: &Nonce,
        http_client: &HttpClient,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let verifier = self.ensure_verifier(http_client).await?;
        let sig_err = match id_token.claims(&verifier, nonce) {
            Ok(_) => return Ok(()),
            // May be a key rotation: refetch once (rate-limited) and retry.
            Err(err @ ClaimsVerificationError::SignatureVerification(_)) => err,
            Err(err) => return Err(err.into()),
        };
        crate::debug!("id_token signature check failed, refetching JWKS: {sig_err}");

        match self.refresh_verifier(http_client, &verifier).await? {
            Some(fresh) => {
                id_token.claims(&fresh, nonce)?;
                Ok(())
            }
            None => Err(sig_err.into()),
        }
    }

    async fn ensure_verifier(&self, http_client: &HttpClient) -> Result<SharedVerifier, JwksError> {
        let mut state = self.state.lock().await;
        if let Some(verifier) = &state.verifier {
            return Ok(verifier.clone());
        }
        self.fetch_into(&mut state, http_client).await
    }

    /// Force a refetch, at most one attempt per `min_refetch_interval`. When
    /// rate-limited, returns a verifier built since `tried`, or `None` if
    /// `tried` is already the freshest available.
    async fn refresh_verifier(
        &self,
        http_client: &HttpClient,
        tried: &SharedVerifier,
    ) -> Result<Option<SharedVerifier>, JwksError> {
        let mut state = self.state.lock().await;
        if let Some(last_attempt) = state.last_attempt
            && last_attempt.elapsed() < self.min_refetch_interval
        {
            return Ok(state.verifier.clone().filter(|v| !Arc::ptr_eq(v, tried)));
        }
        self.fetch_into(&mut state, http_client).await.map(Some)
    }

    async fn fetch_into(
        &self,
        state: &mut State,
        http_client: &HttpClient,
    ) -> Result<SharedVerifier, JwksError> {
        state.last_attempt = Some(Instant::now());
        let keys = CoreJsonWebKeySet::fetch_async(&self.jwks_url, http_client)
            .await
            .map_err(|e| JwksError(e.to_string()))?;
        let verifier = Arc::new(self.build_verifier(keys));
        state.verifier = Some(verifier.clone());
        Ok(verifier)
    }

    /// Mirrors the public/confidential selection of `CoreClient::id_token_verifier`.
    fn build_verifier(&self, keys: CoreJsonWebKeySet) -> CoreIdTokenVerifier<'static> {
        match &self.client_secret {
            Some(secret) => CoreIdTokenVerifier::new_confidential_client(
                self.client_id.clone(),
                secret.clone(),
                self.issuer_url.clone(),
                keys,
            ),
            None => CoreIdTokenVerifier::new_public_client(
                self.client_id.clone(),
                self.issuer_url.clone(),
                keys,
            ),
        }
    }
}

#[derive(Debug)]
struct JwksError(String);

impl std::fmt::Display for JwksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for JwksError {}
