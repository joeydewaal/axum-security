use std::{
    hash::Hash,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use dashmap::DashMap;

use super::algorithm::{Algorithm, BucketState, RateLimitResult};

pub(crate) struct Store<K> {
    map: DashMap<K, BucketState>,
    algorithm: Algorithm,
    last_cleanup: AtomicU64,
    cleanup_interval_secs: u64,
    max_entry_age_secs: u64,
    start: Instant,
}

impl<K: Hash + Eq + Clone + Send + Sync + 'static> Store<K> {
    pub(crate) fn new(algorithm: Algorithm, cleanup_interval_secs: u64) -> Self {
        let window = algorithm.window_secs();
        Self {
            map: DashMap::new(),
            algorithm,
            last_cleanup: AtomicU64::new(0),
            cleanup_interval_secs,
            max_entry_age_secs: window * 2,
            start: Instant::now(),
        }
    }

    pub(crate) fn check(&self, key: K) -> RateLimitResult {
        let now = Instant::now();
        self.maybe_cleanup(now);

        let mut entry = self
            .map
            .entry(key)
            .or_insert_with(|| self.algorithm.initial_state());

        self.algorithm.check(entry.value_mut(), now)
    }

    fn maybe_cleanup(&self, now: Instant) {
        let elapsed = now.duration_since(self.start).as_secs();
        let last = self.last_cleanup.load(Ordering::Relaxed);

        if elapsed.saturating_sub(last) < self.cleanup_interval_secs {
            return;
        }

        // CAS to avoid redundant sweeps
        if self
            .last_cleanup
            .compare_exchange(last, elapsed, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let max_age = std::time::Duration::from_secs(self.max_entry_age_secs);
        self.map.retain(|_, state| {
            let age = match state {
                BucketState::FixedWindow { window_start, .. } => now.duration_since(*window_start),
                BucketState::TokenBucket { last_refill, .. } => now.duration_since(*last_refill),
            };
            age < max_age
        });
    }
}
