use bytes::Bytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;
use std::num::NonZeroUsize;

/// Cache key: (name, record type)
type CacheKey = (String, String);

/// A single cached DNS response with expiry metadata.
struct CacheEntry {
    /// Raw wire-format DNS response bytes
    data: Bytes,
    /// When this entry expires
    expires_at: Instant,
}

/// Thread-safe LRU DNS cache with TTL expiry.
pub struct DnsCache {
    inner: Mutex<LruCache<CacheKey, CacheEntry>>,
    min_ttl: u32,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DnsCache {
    /// Create a new cache with the given maximum entry count and minimum TTL.
    pub fn new(max_entries: usize, min_ttl: u32) -> Self {
        let cap = NonZeroUsize::new(max_entries.max(1)).expect("max_entries must be > 0");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            min_ttl,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached DNS response. Returns None on miss or if TTL has expired.
    pub fn get(&self, name: &str, qtype: &str) -> Option<Bytes> {
        let key = (name.to_string(), qtype.to_string());
        let mut cache = self.inner.lock().unwrap();

        match cache.get(&key) {
            Some(entry) => {
                if entry.expires_at <= Instant::now() {
                    // Expired — treat as miss, remove entry
                    drop(cache); // release lock before peek_mut
                    let mut cache2 = self.inner.lock().unwrap();
                    cache2.pop(&key);
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    None
                } else {
                    let data = entry.data.clone();
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    Some(data)
                }
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Insert a DNS response into the cache.
    ///
    /// `ttl` is the TTL from the DNS response (seconds). If None (no answer records),
    /// uses `min_ttl`. The effective TTL is clamped to at least `min_ttl`.
    pub fn insert(&self, name: String, qtype: String, data: Bytes, ttl: Option<u32>) {
        let effective_ttl = ttl
            .map(|t| t.max(self.min_ttl))
            .unwrap_or(self.min_ttl);

        let expires_at = Instant::now() + Duration::from_secs(effective_ttl as u64);
        let entry = CacheEntry { data, expires_at };

        let key = (name, qtype);
        let mut cache = self.inner.lock().unwrap();
        cache.put(key, entry);
    }

    /// Return the number of cache hits since startup.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Return the number of cache misses since startup.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Return the current number of entries in the cache.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Return true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
