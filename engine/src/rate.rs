//! Sliding-window identity & IP rate limiter with cluster sync (RV-R-04 & P-01 §3).
//!
//! Tier 1: Local node memory, sub-microsecond evaluation, zero lock contention
//! (sharded locks), strictly bounded memory (bounded capacity with LRU eviction).
//! Tier 2: Cluster-wide counter synchronization primitives to aggregate rates across nodes.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

const NUM_SHARDS: usize = 16;
const SHARD_CAPACITY: usize = 1024; // 16 * 1024 = 16,384 total max tracked keys

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RateResult {
    Allowed { count: u32, limit: u32 },
    Limited { count: u32, limit: u32, retry_after: u64 },
}

#[derive(Clone, Debug)]
struct RateEntry {
    window_start: u64,
    count: u32,
    last_seen: u64,
}

struct Shard {
    entries: HashMap<Vec<u8>, RateEntry>,
}

impl Shard {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

/// Global or engine-scoped rate limiter.
pub struct RateLimiter {
    shards: Vec<RwLock<Shard>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(RwLock::new(Shard::new()));
        }
        Self { shards }
    }

    /// Evaluates rate limit for `key` and increments the counter.
    pub fn check_and_inc(
        &self,
        key: &[u8],
        now_secs: u64,
        limit: u32,
        window_secs: u32,
    ) -> RateResult {
        if limit == 0 {
            return RateResult::Limited {
                count: 1,
                limit: 0,
                retry_after: window_secs as u64,
            };
        }

        let idx = shard_index(key);
        let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());

        let window_secs = window_secs.max(1) as u64;

        if let Some(entry) = shard.entries.get_mut(key) {
            entry.last_seen = now_secs;
            if now_secs >= entry.window_start.saturating_add(window_secs) {
                // Window expired: start fresh window
                entry.window_start = now_secs;
                entry.count = 1;
                RateResult::Allowed { count: 1, limit }
            } else {
                // In current window
                entry.count = entry.count.saturating_add(1);
                if entry.count > limit {
                    let retry_after = entry
                        .window_start
                        .saturating_add(window_secs)
                        .saturating_sub(now_secs)
                        .max(1);
                    RateResult::Limited {
                        count: entry.count,
                        limit,
                        retry_after,
                    }
                } else {
                    RateResult::Allowed {
                        count: entry.count,
                        limit,
                    }
                }
            }
        } else {
            // New entry: check capacity and evict if full
            if shard.entries.len() >= SHARD_CAPACITY {
                evict_one_entry(&mut shard.entries, now_secs, window_secs);
            }
            shard.entries.insert(
                key.to_vec(),
                RateEntry {
                    window_start: now_secs,
                    count: 1,
                    last_seen: now_secs,
                },
            );
            if 1 > limit {
                RateResult::Limited {
                    count: 1,
                    limit,
                    retry_after: window_secs,
                }
            } else {
                RateResult::Allowed { count: 1, limit }
            }
        }
    }

    /// Read-only inspection of current counter without incrementing.
    pub fn get_count(&self, key: &[u8], now_secs: u64, window_secs: u32) -> u32 {
        let idx = shard_index(key);
        let shard = self.shards[idx].read().unwrap_or_else(|e| e.into_inner());
        let window_secs = window_secs.max(1) as u64;

        match shard.entries.get(key) {
            Some(entry) if now_secs < entry.window_start.saturating_add(window_secs) => {
                entry.count
            }
            _ => 0,
        }
    }

    /// Resets all counters (for testing and bundle reload).
    pub fn reset(&self) {
        for shard_lock in &self.shards {
            let mut shard = shard_lock.write().unwrap_or_else(|e| e.into_inner());
            shard.entries.clear();
        }
    }

    /// Tier 2: Exports current active counters for cluster-wide synchronization.
    pub fn export_sync(&self, now_secs: u64, window_secs: u32) -> Vec<RateCounterSync> {
        let mut out = Vec::new();
        let window_secs = window_secs.max(1) as u64;

        for shard_lock in &self.shards {
            let shard = shard_lock.read().unwrap_or_else(|e| e.into_inner());
            for (key, entry) in &shard.entries {
                if now_secs < entry.window_start.saturating_add(window_secs) {
                    out.push(RateCounterSync {
                        key: key.clone(),
                        count: entry.count,
                        window_start: entry.window_start,
                    });
                }
            }
        }
        out
    }

    /// Tier 2: Merges incoming counters from peer cluster nodes into local rate tracking.
    pub fn import_cluster_sync(
        &self,
        batch: &[RateCounterSync],
        now_secs: u64,
        window_secs: u32,
    ) {
        let window_secs = window_secs.max(1) as u64;

        for sync_item in batch {
            // Only merge if the sync item window is still current
            if now_secs < sync_item.window_start.saturating_add(window_secs) {
                let idx = shard_index(&sync_item.key);
                let mut shard = self.shards[idx].write().unwrap_or_else(|e| e.into_inner());

                if let Some(entry) = shard.entries.get_mut(&sync_item.key) {
                    if entry.window_start == sync_item.window_start {
                        entry.count = entry.count.saturating_add(sync_item.count);
                    } else if sync_item.window_start > entry.window_start {
                        entry.window_start = sync_item.window_start;
                        entry.count = sync_item.count;
                    }
                    entry.last_seen = now_secs;
                } else {
                    if shard.entries.len() >= SHARD_CAPACITY {
                        evict_one_entry(&mut shard.entries, now_secs, window_secs);
                    }
                    shard.entries.insert(
                        sync_item.key.clone(),
                        RateEntry {
                            window_start: sync_item.window_start,
                            count: sync_item.count,
                            last_seen: now_secs,
                        },
                    );
                }
            }
        }
    }
}

/// Counter snapshot representation for P-01 §3 cluster synchronization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateCounterSync {
    pub key: Vec<u8>,
    pub count: u32,
    pub window_start: u64,
}

fn shard_index(key: &[u8]) -> usize {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in key {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h as usize) % NUM_SHARDS
}

fn evict_one_entry(entries: &mut HashMap<Vec<u8>, RateEntry>, now_secs: u64, window_secs: u64) {
    // 1. Try finding an expired entry first
    let expired_key = entries.iter().find_map(|(k, v)| {
        if now_secs >= v.window_start.saturating_add(window_secs) {
            Some(k.clone())
        } else {
            None
        }
    });

    if let Some(k) = expired_key {
        entries.remove(&k);
        return;
    }

    // 2. Otherwise find entry with oldest last_seen (LRU)
    let oldest_key = entries
        .iter()
        .min_by_key(|(_, v)| v.last_seen)
        .map(|(k, _)| k.clone());

    if let Some(k) = oldest_key {
        entries.remove(&k);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic_window() {
        let rl = RateLimiter::new();
        let key = b"user:alice";
        let now = 1000;

        // 3 requests allowed, limit = 3, window = 60s
        assert_eq!(
            rl.check_and_inc(key, now, 3, 60),
            RateResult::Allowed { count: 1, limit: 3 }
        );
        assert_eq!(
            rl.check_and_inc(key, now + 1, 3, 60),
            RateResult::Allowed { count: 2, limit: 3 }
        );
        assert_eq!(
            rl.check_and_inc(key, now + 2, 3, 60),
            RateResult::Allowed { count: 3, limit: 3 }
        );

        // 4th request exceeds limit
        assert_eq!(
            rl.check_and_inc(key, now + 3, 3, 60),
            RateResult::Limited {
                count: 4,
                limit: 3,
                retry_after: 57
            }
        );

        // Window rolls over at now + 60
        assert_eq!(
            rl.check_and_inc(key, now + 61, 3, 60),
            RateResult::Allowed { count: 1, limit: 3 }
        );
    }

    #[test]
    fn test_rate_limiter_identity_separation() {
        let rl = RateLimiter::new();
        let alice = b"user:alice";
        let bob = b"user:bob";
        let now = 1000;

        for _ in 0..3 {
            assert!(matches!(
                rl.check_and_inc(alice, now, 3, 60),
                RateResult::Allowed { .. }
            ));
        }
        // Alice limited
        assert!(matches!(
            rl.check_and_inc(alice, now, 3, 60),
            RateResult::Limited { .. }
        ));

        // Bob still has fresh quota
        assert_eq!(
            rl.check_and_inc(bob, now, 3, 60),
            RateResult::Allowed { count: 1, limit: 3 }
        );
    }

    #[test]
    fn test_cluster_sync_aggregates_across_nodes() {
        let node_a = RateLimiter::new();
        let node_b = RateLimiter::new();
        let now = 2000;
        let key = b"login:bad_actor";

        // Node A sees 2 requests
        node_a.check_and_inc(key, now, 5, 60);
        node_a.check_and_inc(key, now, 5, 60);

        // Node B sees 2 requests
        node_b.check_and_inc(key, now, 5, 60);
        node_b.check_and_inc(key, now, 5, 60);

        // Export from Node A and import to Node B
        let sync_data = node_a.export_sync(now, 60);
        assert_eq!(sync_data.len(), 1);
        assert_eq!(sync_data[0].count, 2);

        node_b.import_cluster_sync(&sync_data, now, 60);

        // Node B count is now 4 (2 local + 2 from Node A)
        assert_eq!(node_b.get_count(key, now, 60), 4);

        // Another request on Node B reaches 5 (limit)
        assert_eq!(
            node_b.check_and_inc(key, now, 5, 60),
            RateResult::Allowed { count: 5, limit: 5 }
        );

        // Exceeds limit cluster-wide
        assert!(matches!(
            node_b.check_and_inc(key, now, 5, 60),
            RateResult::Limited { count: 6, limit: 5, .. }
        ));
    }
}
