//! Middleware: tenant context injection, rate limiting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rate limiter using a token bucket algorithm.
pub struct RateLimiter {
    buckets: HashMap<String, TokenBucket>,
    max_requests_per_minute: u32,
}

struct TokenBucket {
    tokens: u32,
    last_refill: DateTime<Utc>,
    max_tokens: u32,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            max_requests_per_minute,
        }
    }

    /// Check if a request is allowed for a given key (e.g., tenant_id or IP).
    pub fn check(&mut self, key: &str) -> RateLimitResult {
        let now = Utc::now();
        let bucket = self.buckets.entry(key.to_string()).or_insert(TokenBucket {
            tokens: self.max_requests_per_minute,
            last_refill: now,
            max_tokens: self.max_requests_per_minute,
        });

        // Refill tokens based on elapsed time
        let elapsed = (now - bucket.last_refill).num_seconds().max(0) as u32;
        if elapsed >= 60 {
            bucket.tokens = bucket.max_tokens;
            bucket.last_refill = now;
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            RateLimitResult {
                allowed: true,
                remaining: bucket.tokens,
                retry_after_seconds: None,
            }
        } else {
            let seconds_until_refill = 60u32.saturating_sub(elapsed);
            RateLimitResult {
                allowed: false,
                remaining: 0,
                retry_after_seconds: Some(seconds_until_refill),
            }
        }
    }
}

/// Result of a rate limit check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after_seconds: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new(10);
        let result = limiter.check("tenant-1");
        assert!(result.allowed);
        assert_eq!(result.remaining, 9);
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.check("tenant-1").allowed);
        assert!(limiter.check("tenant-1").allowed);
        let result = limiter.check("tenant-1");
        assert!(!result.allowed);
        assert!(result.retry_after_seconds.is_some());
    }

    #[test]
    fn test_rate_limiter_per_key_isolation() {
        let mut limiter = RateLimiter::new(1);
        assert!(limiter.check("tenant-a").allowed);
        assert!(limiter.check("tenant-b").allowed);
        assert!(!limiter.check("tenant-a").allowed);
    }
}
