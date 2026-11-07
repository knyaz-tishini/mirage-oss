//! Per-source-IP accept budget for the faces.
//!
//! ## Why this lives here and not behind the front door
//!
//! The monitor's mesh-receiver has carried a per-source-IP token bucket
//! (50/s sustained, 200 burst) since anonymous accept landed. That gate reads
//! the accepted socket's peer address — which stops being the client's address
//! the moment this perimeter fronts the listener, because every routed
//! connection then arrives spliced from `127.0.0.1`. One bucket, whole fleet:
//! it would stop isolating any single source and start throttling all of them
//! at once. So the monitor exempts loopback, and the budget moves here, to the
//! only process that still holds the real address.
//!
//! ## One budget per source, not per face
//!
//! The in-flight cap in `crate::face` is deliberately per face, so a flood on
//! one port cannot eat another port's capacity. This is the opposite: a source
//! address gets ONE budget for the whole box. An attacker choosing to spread
//! across four faces is not four different callers, and a per-face bucket would
//! hand them four times the budget for doing so.
//!
//! ## Where it sits in the connection's life
//!
//! Before the camouflage strip, which is the expensive part (a TLS handshake on
//! the `tls_real` face). Rejection closes the socket with no bytes written —
//! the same silence every other non-wire verdict gets today, and the same
//! fingerprint problem, tracked with them at the decoy seam.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Sustained accepts per second allowed from one source address.
///
/// Matches the monitor-side default this replaces, because moving a budget and
/// changing it at the same time makes any resulting behaviour change
/// unattributable.
pub const DEFAULT_ACCEPT_PER_IP_PER_SEC: f64 = 50.0;
/// Burst capacity in tokens. The bucket starts full.
pub const DEFAULT_ACCEPT_BURST: f64 = 200.0;

/// How many entries the map may hold before idle ones are swept. Bounds memory
/// under an address-spray flood, where every packet mints a new key.
const MAX_TRACKED_SOURCES: usize = 8192;
/// A source untouched for this long is dropped by the sweep.
const IDLE_EVICT_SECS: u64 = 120;

/// Process-wide token buckets keyed by source address.
#[derive(Debug)]
pub struct SourceRateLimit {
    per_sec: f64,
    burst: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl SourceRateLimit {
    #[must_use]
    pub fn new(per_sec: f64, burst: f64) -> Self {
        Self {
            per_sec,
            burst,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// `true` = this accept is within `ip`'s budget and may proceed.
    pub fn allow(&self, ip: IpAddr) -> bool {
        self.allow_at(ip, Instant::now())
    }

    /// Testable core: same decision, with the clock supplied.
    pub fn allow_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut map = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() > MAX_TRACKED_SOURCES {
            map.retain(|_, (_, last)| now.duration_since(*last).as_secs() < IDLE_EVICT_SECS);
        }
        let entry = map.entry(ip).or_insert((self.burst, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.per_sec).min(self.burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("static addr parses")
    }

    #[test]
    fn a_full_bucket_allows_exactly_its_burst_then_refuses() {
        let rl = SourceRateLimit::new(10.0, 3.0);
        let now = Instant::now();
        let src = ip("1.2.3.4");
        for i in 0..3 {
            assert!(rl.allow_at(src, now), "accept {i} should be within burst");
        }
        assert!(!rl.allow_at(src, now), "burst is spent");
    }

    #[test]
    fn tokens_refill_with_elapsed_time() {
        let rl = SourceRateLimit::new(10.0, 2.0);
        let now = Instant::now();
        let src = ip("1.2.3.4");
        assert!(rl.allow_at(src, now));
        assert!(rl.allow_at(src, now));
        assert!(!rl.allow_at(src, now));
        assert!(rl.allow_at(src, now + Duration::from_millis(200)));
    }

    #[test]
    fn one_source_cannot_spend_anothers_budget() {
        let rl = SourceRateLimit::new(10.0, 1.0);
        let now = Instant::now();
        assert!(rl.allow_at(ip("1.2.3.4"), now));
        assert!(!rl.allow_at(ip("1.2.3.4"), now));
        assert!(
            rl.allow_at(ip("5.6.7.8"), now),
            "a different source has its own bucket"
        );
    }

    #[test]
    fn the_same_source_shares_one_budget_across_faces() {
        // There is no face dimension in the key, and that is the point: the
        // limiter is constructed once and shared by every face's accept loop,
        // so hitting four ports does not buy four budgets.
        let rl = SourceRateLimit::new(10.0, 2.0);
        let now = Instant::now();
        let src = ip("1.2.3.4");
        assert!(rl.allow_at(src, now)); // as if on :443
        assert!(rl.allow_at(src, now)); // as if on :80
        assert!(!rl.allow_at(src, now), "third accept on any face is refused");
    }
}
