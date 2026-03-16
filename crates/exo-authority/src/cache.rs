//! LRU Cache for authority chain verification results.
//!
//! Provides P99 < 200ms by caching recently verified chains.

use exo_core::crypto::Blake3Hash;
use exo_governance::types::{AuthorizedAction, DecisionClass, Did};
use std::collections::HashMap;

/// Key for caching authority chain verification results.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ChainCacheKey {
    pub actor: Did,
    pub action: AuthorizedAction,
    pub decision_class: DecisionClass,
    /// Hash of the delegation set — invalidates cache when delegations change.
    pub delegation_set_hash: Blake3Hash,
}

/// Cached chain verification result.
#[derive(Clone, Debug)]
pub struct CachedChainResult {
    pub chain: Vec<Blake3Hash>,
    pub depth: usize,
    pub has_human_signer: bool,
    pub verified_at_ms: u64,
    /// TTL in milliseconds.
    pub ttl_ms: u64,
}

impl CachedChainResult {
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        current_time_ms > self.verified_at_ms + self.ttl_ms
    }
}

/// Simple LRU-ish cache for chain verification.
/// Production would use a proper LRU with bounded size.
pub struct ChainCache {
    entries: HashMap<ChainCacheKey, CachedChainResult>,
    max_entries: usize,
    default_ttl_ms: u64,
}

impl ChainCache {
    pub fn new(max_entries: usize, default_ttl_ms: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            default_ttl_ms,
        }
    }

    /// Look up a cached chain verification result.
    pub fn get(&self, key: &ChainCacheKey, current_time_ms: u64) -> Option<&CachedChainResult> {
        self.entries.get(key).and_then(|entry| {
            if entry.is_expired(current_time_ms) {
                None
            } else {
                Some(entry)
            }
        })
    }

    /// Store a chain verification result.
    pub fn put(
        &mut self,
        key: ChainCacheKey,
        chain: Vec<Blake3Hash>,
        depth: usize,
        has_human_signer: bool,
        current_time_ms: u64,
    ) {
        // Evict expired entries if at capacity
        if self.entries.len() >= self.max_entries {
            self.evict_expired(current_time_ms);
        }

        // If still at capacity, evict oldest
        if self.entries.len() >= self.max_entries {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.verified_at_ms)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(
            key,
            CachedChainResult {
                chain,
                depth,
                has_human_signer,
                verified_at_ms: current_time_ms,
                ttl_ms: self.default_ttl_ms,
            },
        );
    }

    /// Remove all expired entries.
    pub fn evict_expired(&mut self, current_time_ms: u64) {
        self.entries.retain(|_, v| !v.is_expired(current_time_ms));
    }

    /// Invalidate all entries (e.g., when delegations change).
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
    }

    /// Get cache hit rate statistics.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(actor: &str) -> ChainCacheKey {
        ChainCacheKey {
            actor: actor.to_string(),
            action: AuthorizedAction::CreateDecision,
            decision_class: DecisionClass::Operational,
            delegation_set_hash: Blake3Hash([0u8; 32]),
        }
    }

    #[test]
    fn test_cache_put_and_get() {
        let mut cache = ChainCache::new(100, 60_000); // 60s TTL
        let key = test_key("did:exo:alice");

        cache.put(key.clone(), vec![Blake3Hash([1u8; 32])], 1, true, 1000);

        let result = cache.get(&key, 2000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().depth, 1);
    }

    #[test]
    fn test_cache_expiry() {
        let mut cache = ChainCache::new(100, 1000); // 1s TTL
        let key = test_key("did:exo:alice");

        cache.put(key.clone(), vec![], 0, true, 1000);

        // Within TTL
        assert!(cache.get(&key, 1500).is_some());

        // After TTL
        assert!(cache.get(&key, 2500).is_none());
    }

    #[test]
    fn test_cache_eviction_at_capacity() {
        let mut cache = ChainCache::new(2, 60_000);

        cache.put(test_key("a"), vec![], 0, true, 1000);
        cache.put(test_key("b"), vec![], 0, true, 2000);
        assert_eq!(cache.len(), 2);

        // Adding third should evict oldest
        cache.put(test_key("c"), vec![], 0, true, 3000);
        assert_eq!(cache.len(), 2);

        // "a" should be evicted
        assert!(cache.get(&test_key("a"), 3000).is_none());
        assert!(cache.get(&test_key("c"), 3000).is_some());
    }

    #[test]
    fn test_invalidate_all() {
        let mut cache = ChainCache::new(100, 60_000);
        cache.put(test_key("a"), vec![], 0, true, 1000);
        cache.put(test_key("b"), vec![], 0, true, 1000);
        assert_eq!(cache.len(), 2);

        cache.invalidate_all();
        assert!(cache.is_empty());
    }
}
