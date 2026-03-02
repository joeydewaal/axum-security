use std::time::Instant;

#[derive(Clone)]
pub(crate) enum Algorithm {
    FixedWindow {
        max_requests: u64,
        window_secs: u64,
    },
    TokenBucket {
        burst_size: u64,
        refill_rate_per_sec: f64,
    },
}

pub(crate) enum BucketState {
    FixedWindow { count: u64, window_start: Instant },
    TokenBucket { tokens: f64, last_refill: Instant },
}

pub(crate) struct RateLimitResult {
    pub(crate) allowed: bool,
    pub(crate) remaining: u64,
    pub(crate) reset_after_secs: u64,
    pub(crate) limit: u64,
}

impl Algorithm {
    pub(crate) fn check(&self, state: &mut BucketState, now: Instant) -> RateLimitResult {
        match (self, state) {
            (
                Algorithm::FixedWindow {
                    max_requests,
                    window_secs,
                },
                BucketState::FixedWindow {
                    count,
                    window_start,
                },
            ) => {
                let window = std::time::Duration::from_secs(*window_secs);
                let elapsed = now.duration_since(*window_start);

                if elapsed >= window {
                    *window_start = now;
                    *count = 1;
                    return RateLimitResult {
                        allowed: true,
                        remaining: max_requests.saturating_sub(1),
                        reset_after_secs: *window_secs,
                        limit: *max_requests,
                    };
                }

                if *count < *max_requests {
                    *count += 1;
                    RateLimitResult {
                        allowed: true,
                        remaining: max_requests - *count,
                        reset_after_secs: (*window_secs).saturating_sub(elapsed.as_secs()),
                        limit: *max_requests,
                    }
                } else {
                    RateLimitResult {
                        allowed: false,
                        remaining: 0,
                        reset_after_secs: (*window_secs).saturating_sub(elapsed.as_secs()),
                        limit: *max_requests,
                    }
                }
            }
            (
                Algorithm::TokenBucket {
                    burst_size,
                    refill_rate_per_sec,
                },
                BucketState::TokenBucket {
                    tokens,
                    last_refill,
                },
            ) => {
                let elapsed = now.duration_since(*last_refill).as_secs_f64();
                let refilled = *tokens + elapsed * refill_rate_per_sec;
                let capped = refilled.min(*burst_size as f64);
                *last_refill = now;

                if capped >= 1.0 {
                    *tokens = capped - 1.0;
                    let remaining = *tokens as u64;
                    let reset_after = if remaining == 0 {
                        (1.0 / refill_rate_per_sec).ceil() as u64
                    } else {
                        0
                    };
                    RateLimitResult {
                        allowed: true,
                        remaining,
                        reset_after_secs: reset_after,
                        limit: *burst_size,
                    }
                } else {
                    *tokens = capped;
                    let deficit = 1.0 - capped;
                    let wait = (deficit / refill_rate_per_sec).ceil() as u64;
                    RateLimitResult {
                        allowed: false,
                        remaining: 0,
                        reset_after_secs: wait,
                        limit: *burst_size,
                    }
                }
            }
            _ => unreachable!("algorithm and state variant mismatch"),
        }
    }

    pub(crate) fn initial_state(&self) -> BucketState {
        let now = Instant::now();
        match self {
            Algorithm::FixedWindow { .. } => BucketState::FixedWindow {
                count: 0,
                window_start: now,
            },
            Algorithm::TokenBucket { burst_size, .. } => BucketState::TokenBucket {
                tokens: *burst_size as f64,
                last_refill: now,
            },
        }
    }

    pub(crate) fn window_secs(&self) -> u64 {
        match self {
            Algorithm::FixedWindow { window_secs, .. } => *window_secs,
            Algorithm::TokenBucket {
                burst_size,
                refill_rate_per_sec,
            } => (*burst_size as f64 / refill_rate_per_sec).ceil() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_allows_up_to_max() {
        let algo = Algorithm::FixedWindow {
            max_requests: 3,
            window_secs: 60,
        };
        let mut state = algo.initial_state();
        let now = Instant::now();

        for i in 0..3 {
            let result = algo.check(&mut state, now);
            assert!(result.allowed, "request {i} should be allowed");
            assert_eq!(result.remaining, 2 - i as u64);
        }

        let result = algo.check(&mut state, now);
        assert!(!result.allowed, "4th request should be denied");
        assert_eq!(result.remaining, 0);
    }

    #[test]
    fn fixed_window_resets_after_window() {
        let algo = Algorithm::FixedWindow {
            max_requests: 1,
            window_secs: 1,
        };
        let mut state = algo.initial_state();
        let now = Instant::now();

        let result = algo.check(&mut state, now);
        assert!(result.allowed);

        let result = algo.check(&mut state, now);
        assert!(!result.allowed);

        // Advance past window
        let later = now + std::time::Duration::from_secs(2);
        let result = algo.check(&mut state, later);
        assert!(result.allowed);
    }

    #[test]
    fn token_bucket_allows_burst() {
        let algo = Algorithm::TokenBucket {
            burst_size: 5,
            refill_rate_per_sec: 1.0,
        };
        let mut state = algo.initial_state();
        let now = Instant::now();

        for i in 0..5 {
            let result = algo.check(&mut state, now);
            assert!(result.allowed, "burst request {i} should be allowed");
        }

        let result = algo.check(&mut state, now);
        assert!(!result.allowed, "6th request should be denied");
    }

    #[test]
    fn token_bucket_refills() {
        let algo = Algorithm::TokenBucket {
            burst_size: 2,
            refill_rate_per_sec: 1.0,
        };
        let mut state = algo.initial_state();
        let now = Instant::now();

        // Drain all tokens
        algo.check(&mut state, now);
        algo.check(&mut state, now);
        let result = algo.check(&mut state, now);
        assert!(!result.allowed);

        // Advance 1 second — should refill 1 token
        let later = now + std::time::Duration::from_secs(1);
        let result = algo.check(&mut state, later);
        assert!(result.allowed);

        let result = algo.check(&mut state, later);
        assert!(!result.allowed);
    }
}
