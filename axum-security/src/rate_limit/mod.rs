//! Rate limiting middleware.
//!
//! This module provides [`RateLimitLayer`], a Tower middleware that limits
//! requests per client using either a fixed window or token bucket algorithm.
//!
//! Clients are identified by a [`KeyExtractor`]. Built-in extractors:
//! - [`PeerIpKeyExtractor`] — peer socket address (default)
//! - [`SmartIpKeyExtractor`] — `X-Forwarded-For` / `X-Real-Ip` with peer IP fallback
//! - [`SessionKeyExtractor`] — keyed by the authenticated user (requires a session feature)
//!
//! Rate-limited responses get a `429 Too Many Requests` status with `RateLimit` and
//! `Retry-After` headers. Allowed responses include a `RateLimit` header.
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::Router;
//! use axum_security::rate_limit::RateLimitLayer;
//!
//! let app = Router::new()
//!     .layer(
//!         RateLimitLayer::builder()
//!             .max_requests(100)
//!             .window_secs(60)
//!             .build(),
//!     );
//! ```

mod algorithm;
pub mod service;
pub(crate) mod store;

use std::{hash::Hash, net::SocketAddr, sync::Arc};

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
use std::marker::PhantomData;

use axum::extract::Request;
use tower::Layer;

use algorithm::Algorithm;
pub use service::RateLimitService;
use store::Store;

#[cfg(feature = "rate-limit-macros")]
pub use axum_security_macros::RateLimitKey;

/// Trait for user types that can produce a rate-limit key.
///
/// Used by [`SessionKeyExtractor`] to key rate limits per user. Derive with
/// `#[derive(RateLimitKey)]` (requires the `rate-limit-macros` feature) and
/// mark the key field with `#[key]`.
pub trait RateLimitKey {
    /// The key type used to identify this client in the rate-limit store.
    type Key: Hash + Eq + Clone + Send + Sync + 'static;

    /// Return the rate-limit key for this user.
    fn rate_limit_key(&self) -> Self::Key;
}

/// Extracts a rate-limit key from a request.
///
/// Return `None` to skip rate limiting for this request.
/// Closures `Fn(&mut Request) -> Option<K>` implement this trait automatically.
pub trait KeyExtractor: Clone + Send + Sync + 'static {
    /// The key type used to identify a client.
    type Key: Hash + Eq + Clone + Send + Sync + 'static;

    /// Extract a key from the request. Return `None` to bypass rate limiting.
    fn extract(&self, req: &mut Request) -> Option<Self::Key>;
}

impl<F, K> KeyExtractor for F
where
    F: Fn(&mut Request) -> Option<K> + Clone + Send + Sync + 'static,
    K: Hash + Eq + Clone + Send + Sync + 'static,
{
    type Key = K;

    fn extract(&self, req: &mut Request) -> Option<K> {
        (self)(req)
    }
}

/// Key extractor that uses the peer socket address from `ConnectInfo`.
#[derive(Clone)]
pub struct PeerIpKeyExtractor;

impl KeyExtractor for PeerIpKeyExtractor {
    type Key = SocketAddr;

    fn extract(&self, req: &mut Request) -> Option<Self::Key> {
        req.extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0)
    }
}

/// Key extractor that checks `X-Forwarded-For`, then `X-Real-Ip`, then peer IP.
///
/// Use this behind a reverse proxy that sets these headers.
#[derive(Clone)]
pub struct SmartIpKeyExtractor;

impl KeyExtractor for SmartIpKeyExtractor {
    type Key = SocketAddr;

    fn extract(&self, req: &mut Request) -> Option<Self::Key> {
        // Check X-Forwarded-For first
        if let Some(val) = req.headers().get("x-forwarded-for")
            && let Ok(s) = val.to_str()
            && let Some(first) = s.split(',').next()
            && let Ok(addr) = first.trim().parse()
        {
            return Some(addr);
        }

        // Check X-Real-Ip
        if let Some(val) = req.headers().get("x-real-ip")
            && let Ok(s) = val.to_str()
            && let Ok(addr) = s.trim().parse()
        {
            return Some(addr);
        }

        // Fall back to peer IP
        req.extensions()
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0)
    }
}

/// Key extractor that uses the authenticated user's [`RateLimitKey`].
///
/// Requires a session feature (`jwt`, `cookie`, or `basic-auth`).
#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
#[derive(Clone)]
pub struct SessionKeyExtractor<U: RateLimitKey>(PhantomData<fn() -> U>);

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
impl<U: RateLimitKey> SessionKeyExtractor<U> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
impl<U: RateLimitKey> Default for SessionKeyExtractor<U> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
impl<U> KeyExtractor for SessionKeyExtractor<U>
where
    U: RateLimitKey + Clone + Send + Sync + 'static,
{
    type Key = U::Key;

    fn extract(&self, req: &mut Request) -> Option<Self::Key> {
        let session = crate::session::Session::<U>::from_extensions(req.extensions_mut())?;
        let key = session.rate_limit_key();
        session.insert_into(req.extensions_mut());
        Some(key)
    }
}

/// Tower [`Layer`] that enforces rate limits.
///
/// Construct with [`RateLimitLayer::builder`]. Uses the fixed window algorithm
/// by default; call [`token_bucket`](RateLimitLayerBuilder::token_bucket) on the
/// builder for the token bucket algorithm.
#[derive(Clone)]
pub struct RateLimitLayer<K: KeyExtractor> {
    store: Arc<Store<K::Key>>,
    extractor: K,
}

impl<S, K> Layer<S> for RateLimitLayer<K>
where
    K: KeyExtractor,
    K::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    type Service = RateLimitService<K, S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            store: self.store.clone(),
            extractor: self.extractor.clone(),
        }
    }
}

impl RateLimitLayer<PeerIpKeyExtractor> {
    pub fn builder() -> RateLimitLayerBuilder<PeerIpKeyExtractor> {
        RateLimitLayerBuilder {
            algorithm: None,
            max_requests: 60,
            window_secs: 60,
            cleanup_interval_secs: 300,
            extractor: PeerIpKeyExtractor,
        }
    }
}

/// Builder for [`RateLimitLayer`].
pub struct RateLimitLayerBuilder<K: KeyExtractor> {
    algorithm: Option<Algorithm>,
    max_requests: u64,
    window_secs: u64,
    cleanup_interval_secs: u64,
    extractor: K,
}

impl<K: KeyExtractor> RateLimitLayerBuilder<K>
where
    K::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    /// Maximum requests allowed per window. Defaults to 60.
    pub fn max_requests(mut self, n: u64) -> Self {
        self.max_requests = n;
        self
    }

    /// Window duration in seconds (fixed window algorithm). Defaults to 60.
    pub fn window_secs(mut self, secs: u64) -> Self {
        self.window_secs = secs;
        self
    }

    /// Switch to the token bucket algorithm with the given burst size and refill rate.
    pub fn token_bucket(mut self, burst_size: u64, refill_rate_per_sec: f64) -> Self {
        self.algorithm = Some(Algorithm::TokenBucket {
            burst_size,
            refill_rate_per_sec,
        });
        self
    }

    /// How often expired entries are cleaned up (seconds). Defaults to 300.
    pub fn cleanup_interval_secs(mut self, secs: u64) -> Self {
        self.cleanup_interval_secs = secs;
        self
    }

    /// Use a custom [`KeyExtractor`].
    pub fn key_extractor<K2: KeyExtractor>(self, extractor: K2) -> RateLimitLayerBuilder<K2> {
        RateLimitLayerBuilder {
            algorithm: self.algorithm,
            max_requests: self.max_requests,
            window_secs: self.window_secs,
            cleanup_interval_secs: self.cleanup_interval_secs,
            extractor,
        }
    }

    /// Use [`SmartIpKeyExtractor`] (proxy-aware IP extraction).
    pub fn for_smart_ip(self) -> RateLimitLayerBuilder<SmartIpKeyExtractor> {
        self.key_extractor(SmartIpKeyExtractor)
    }

    #[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
    /// Use [`SessionKeyExtractor`] to key rate limits per authenticated user.
    pub fn for_session<U: RateLimitKey + Clone + Send + Sync + 'static>(
        self,
    ) -> RateLimitLayerBuilder<SessionKeyExtractor<U>> {
        self.key_extractor(SessionKeyExtractor::<U>::new())
    }

    /// Build the [`RateLimitLayer`].
    pub fn build(self) -> RateLimitLayer<K> {
        let algorithm = self.algorithm.unwrap_or(Algorithm::FixedWindow {
            max_requests: self.max_requests,
            window_secs: self.window_secs,
        });

        let store = Arc::new(Store::new(algorithm, self.cleanup_interval_secs));

        RateLimitLayer {
            store,
            extractor: self.extractor,
        }
    }
}

#[cfg(any(feature = "jwt", feature = "cookie", feature = "basic-auth"))]
impl<U: RateLimitKey> RateLimitKey for crate::session::Session<U> {
    type Key = U::Key;

    fn rate_limit_key(&self) -> Self::Key {
        use std::ops::Deref;
        self.deref().rate_limit_key()
    }
}
