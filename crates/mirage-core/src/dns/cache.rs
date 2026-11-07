use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::collections::HashMap;
use std::sync::Mutex;

/// Default TTL for cache entries when no explicit TTL is specified.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Maximum entries per chain cache bucket.
pub const DEFAULT_CAPACITY: usize = 1024;

struct CacheEntry {
    addrs: Arc<[IpAddr]>,
    expires_at: Instant,
}

struct Bucket {
    entries: HashMap<String, CacheEntry>,
    capacity: usize,
}

impl Bucket {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity.min(128)),
            capacity,
        }
    }

    fn get(&mut self, name: &str) -> Option<Arc<[IpAddr]>> {
        let now = Instant::now();
        if let Some(entry) = self.entries.get(name) {
            if entry.expires_at > now {
                return Some(Arc::clone(&entry.addrs));
            }
            // Expired — remove below.
        } else {
            return None;
        }
        self.entries.remove(name);
        None
    }

    fn insert(&mut self, name: String, addrs: Arc<[IpAddr]>, ttl: Duration) {
        // Evict expired entries when we are at capacity.
        if self.entries.len() >= self.capacity {
            let now = Instant::now();
            self.entries.retain(|_, v| v.expires_at > now);
            // If still full, drop the whole bucket rather than OOM.
            if self.entries.len() >= self.capacity {
                self.entries.clear();
            }
        }
        self.entries.insert(name, CacheEntry {
            addrs,
            expires_at: Instant::now() + ttl,
        });
    }
}

/// Isolated per-chain + bypass DNS cache.
///
/// Each chain gets its own `Bucket` keyed by chain_id. The bypass tier has a
/// separate dedicated bucket. Buckets are NOT shared across chains — a TTL
/// stale in chain A cannot affect chain B.
pub struct DnsCache {
    per_chain: Mutex<HashMap<String, Bucket>>,
    bypass: Mutex<Bucket>,
    capacity_per_chain: usize,
    default_ttl: Duration,
}

impl DnsCache {
    /// Create a cache with explicit capacity per chain and TTL.
    pub fn new(capacity_per_chain: usize, default_ttl: Duration) -> Self {
        Self {
            per_chain: Mutex::new(HashMap::new()),
            bypass: Mutex::new(Bucket::new(capacity_per_chain)),
            capacity_per_chain,
            default_ttl,
        }
    }

    /// Look up a name.
    ///
    /// `chain_id = None` → bypass bucket.
    /// `chain_id = Some(id)` → per-chain bucket for `id`.
    ///
    /// Returns `None` on miss or expiry.
    pub fn get(&self, chain_id: Option<&str>, name: &str) -> Option<Arc<[IpAddr]>> {
        match chain_id {
            None => {
                let mut bypass = self.bypass.lock().unwrap_or_else(|p| p.into_inner());
                bypass.get(name)
            }
            Some(id) => {
                let mut map = self.per_chain.lock().unwrap_or_else(|p| p.into_inner());
                map.get_mut(id)?.get(name)
            }
        }
    }

    /// Insert a name → addresses mapping.
    ///
    /// `ttl = None` uses [`DEFAULT_TTL`].
    pub fn insert(
        &self,
        chain_id: Option<&str>,
        name: String,
        addrs: Arc<[IpAddr]>,
        ttl: Option<Duration>,
    ) {
        let ttl = ttl.unwrap_or(self.default_ttl);
        match chain_id {
            None => {
                let mut bypass = self.bypass.lock().unwrap_or_else(|p| p.into_inner());
                bypass.insert(name, addrs, ttl);
            }
            Some(id) => {
                let cap = self.capacity_per_chain;
                let mut map = self.per_chain.lock().unwrap_or_else(|p| p.into_inner());
                map.entry(id.to_owned())
                    .or_insert_with(|| Bucket::new(cap))
                    .insert(name, addrs, ttl);
            }
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_TTL)
    }
}
