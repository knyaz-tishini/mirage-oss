//! Byte-rate bandwidth cap for the subscriber entrance
//! (`crate::entrance_dispatch::resolve_subscriber_cap`, applied by the
//! caller's own `Tunnel`-to-`Tunnel` pump — see that module).
//!
//! ## Why this exists
//!
//! Hundreds of concurrent connections from a paying customer are normal —
//! browsers and scanners do that, and connection count is not what this
//! module limits. What it limits is SPEED, so a customer cannot latch onto
//! some unlimited heavy source and burn the wire by proxying load onto us.
//! See `docs/mirage/plans/commercial-client-on-the-box-2026-09-17.md` §
//! "bandwidth cap".
//!
//! ## Shape
//!
//! - [`ByteBucket`] is the lock-free primitive: one atomic byte-rate token
//!   bucket, GCRA-based (the generic cell-rate algorithm — see its own doc
//!   for why a single atomic works where a naive `(tokens, timestamp)` pair
//!   would not). It never rejects; it only ever reports how long the caller
//!   must wait, so the caller's own backpressure (not reading the next chunk
//!   until this one's wait+write completes) is what actually throttles —
//!   nothing here drops a byte.
//! - [`SubscriberBandwidthLimiter`] is ONE bucket shared by every open
//!   connection of ONE subscriber (the aggregate / plan-tier budget), plus
//!   that subscriber's [`MonthlyVolume`] counter.
//! - [`ConnectionBandwidthLimiter`] pairs a subscriber's shared aggregate
//!   limiter with a fresh per-connection [`ByteBucket`] (the per-connection
//!   ceiling) — one of these is built per accepted subscriber connection.
//! - [`SubscriberBandwidthRegistry`] is the box-wide, process-lifetime map
//!   from subscriber key to [`SubscriberBandwidthLimiter`], plus the
//!   monthly-volume persistence that survives a restart.
//!
//! ## Composing the aggregate and the per-connection ceiling
//!
//! [`ConnectionBandwidthLimiter::charge`] waits out the aggregate bucket
//! FIRST, then re-samples the clock and waits out the per-connection bucket
//! second. The two waits are summed, not maxed. A `max` composition is
//! technically tighter (the true bottleneck is whichever bucket is more
//! restrictive), but it requires reserving each bucket's cost at the same
//! projected departure time to stay accurate, which reintroduces exactly the
//! two-values-that-must-stay-in-sync problem the single-atomic design in
//! [`ByteBucket`] exists to avoid. Charging sequentially anchors each
//! bucket's own schedule to the time its bytes actually depart, so neither
//! bucket's accounting can drift — at the cost of being slightly more
//! conservative than the true optimum when both buckets are saturated at
//! once. That trade was a judgement call this brief did not settle; the
//! recorded reasoning is here for whoever revisits it.
//!
//! ## What is not unit-tested here
//!
//! The wire-up through the real V9 handshake, `SubscriberKeyStore`, and the
//! `Tunnel`-to-`Tunnel` pump is exercised (with mocked `Tunnel`s) in
//! `crate::entrance_dispatch`'s own tests, not here — this module tests the
//! cap's arithmetic in isolation, against explicit `Instant`/`SystemTime`
//! values so none of it depends on the real clock or sleeps.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mirage_core::config::SubscriberEntranceConfig;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::subscriber_keys::SubscriberKey;

/// Bytes/sec floor every configurable rate is clamped to, so a pathological
/// near-zero config value (or an absent one defaulted through `unwrap_or`)
/// can never divide-by-zero the arithmetic below. One byte/sec is still a
/// real, if punishing, cap rather than a crash.
const MIN_RATE_BYTES_PER_SEC: u64 = 1;

/// Default aggregate burst when the operator sets `aggregate_rate_bytes_per_sec`
/// but leaves `aggregate_burst_bytes` unset. A flat 4 MiB, chosen to cover an
/// average modern web page (rendering weighs roughly 2-3 MB per HTTP Archive
/// figures) at full LAN speed regardless of the plan's sustained rate, without
/// being so large a multi-second download could ride the burst indefinitely
/// and defeat the cap's point.
pub const DEFAULT_AGGREGATE_BURST_BYTES: u64 = 4 * 1024 * 1024;

/// Default per-connection ceiling, as a fraction of the aggregate rate, when
/// `per_connection_rate_bytes_per_sec` is unset. High enough that a single
/// stream still gets a useful share of the pipe; low enough that one heavy
/// connection cannot fully starve the subscriber's other open connections.
const DEFAULT_PER_CONNECTION_FRACTION: f64 = 0.5;

/// Default degraded floor when `degraded_floor_bytes_per_sec` is unset:
/// 256 KiB/s (~2 Mbit/s) — enough for text, email, and low-bitrate browsing,
/// well below any realistic plan tier, so exhausting the monthly volume is
/// felt immediately but is never a hard stop.
pub const DEFAULT_DEGRADED_FLOOR_BYTES_PER_SEC: u64 = 256 * 1024;

/// Billing-cycle length for [`MonthlyVolume`]: a rolling 30 days measured
/// from the cycle's own start, not the calendar month. A calendar month
/// needs civil-calendar arithmetic for no behavioural gain here — nothing in
/// the config carries a billing anchor date, so "resets every 30 days from
/// whenever this subscriber's counter last rolled over" is the same
/// commitment a calendar month would make ("the meter does not run forever")
/// without the extra arithmetic surface.
const CYCLE_SECS: u64 = 30 * 86_400;

/// How often [`spawn_persistence`] snapshots every live subscriber's monthly
/// volume to disk. Independent of the byte-rate hot path — this only ever
/// touches the filesystem on this cadence, never per chunk.
pub const PERSIST_INTERVAL: Duration = Duration::from_secs(60);

// ─────────────────────────────────────────────────────────────────────────
// ByteBucket — lock-free GCRA byte-rate limiter
// ─────────────────────────────────────────────────────────────────────────

/// A byte-rate token bucket with burst, implemented as a single atomic
/// "theoretical arrival time" (`tat_nanos`) rather than the more obvious
/// `(tokens, last_update)` pair.
///
/// The generic cell-rate algorithm (GCRA) stores one virtual timestamp: the
/// wall-clock time at which the bucket's next byte would depart if every
/// reservation so far had been paced exactly at `rate_bytes_per_sec`. A
/// two-field `(tokens, timestamp)` bucket needs both fields read and written
/// together to stay consistent, which under concurrent access means a mutex
/// or a packed-bits hack; GCRA's one value is a plain `compare_exchange`
/// retry loop — genuinely lock-free, with the usual guarantee that at least
/// one concurrent caller always makes progress per round. This runs on every
/// buffer of every capped connection, so that matters.
#[derive(Debug)]
pub struct ByteBucket {
    rate_bytes_per_sec: AtomicU64,
    burst_bytes: f64,
    epoch: Instant,
    tat_nanos: AtomicI64,
}

impl ByteBucket {
    /// `rate_bytes_per_sec` and `burst_bytes` are both clamped to at least 1
    /// — see [`MIN_RATE_BYTES_PER_SEC`]. The bucket starts full (a caller
    /// gets up to `burst_bytes` immediately with no warm-up).
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        Self {
            rate_bytes_per_sec: AtomicU64::new(rate_bytes_per_sec.max(MIN_RATE_BYTES_PER_SEC)),
            burst_bytes: burst_bytes.max(1) as f64,
            epoch: Instant::now(),
            tat_nanos: AtomicI64::new(0),
        }
    }

    /// Swap the rate in place — used by the monthly-volume degrade/recover
    /// transition. `tat_nanos` is left untouched: it is a pure time
    /// coordinate, not denominated in bytes, so an in-flight schedule keeps
    /// its meaning across a rate change and only prices the NEXT
    /// reservation's cost differently.
    pub fn set_rate(&self, rate_bytes_per_sec: u64) {
        self.rate_bytes_per_sec
            .store(rate_bytes_per_sec.max(MIN_RATE_BYTES_PER_SEC), Ordering::Relaxed);
    }

    /// Reserve `bytes` as of `now`. Always reserves — advances the internal
    /// schedule regardless of the returned wait — so a sustained overshoot
    /// keeps queuing rather than being silently forgiven on the next call;
    /// that is the backpressure this module exists to provide. Returns
    /// `Duration::ZERO` when the bytes are already within budget.
    pub fn reserve(&self, bytes: u64, now: Instant) -> Duration {
        let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed) as f64;
        let period_nanos = 1_000_000_000.0 / rate;
        let cost_nanos = bytes as f64 * period_nanos;
        let burst_nanos = self.burst_bytes * period_nanos;
        // Relative to `self.epoch`, not the Unix epoch — `Instant` has no
        // fixed reference point of its own, so every timestamp used here is
        // measured against the bucket's own construction time instead.
        let now_nanos = now.saturating_duration_since(self.epoch).as_nanos() as i64;

        loop {
            let tat = self.tat_nanos.load(Ordering::Relaxed);
            let start = tat.max(now_nanos);
            let new_tat = start.saturating_add(cost_nanos.round() as i64);
            match self
                .tat_nanos
                .compare_exchange_weak(tat, new_tat, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    let allow_at = new_tat as f64 - burst_nanos;
                    let wait_nanos = (allow_at - now_nanos as f64).max(0.0);
                    return Duration::from_nanos(wait_nanos.round() as u64);
                }
                Err(_) => continue,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// MonthlyVolume — the durable degrade/recover counter
// ─────────────────────────────────────────────────────────────────────────

/// What changed as a result of one [`MonthlyVolume::add_and_check`] call —
/// the caller logs a transition exactly once, never per connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradeTransition {
    NoChange,
    EnteredDegraded,
    Recovered,
}

/// One subscriber's persisted monthly-volume state — the only part of the
/// bandwidth cap that survives a restart. The byte-rate buckets themselves
/// reset on restart, which is correct: a burst allowance is not something to
/// carry across a process restart, but a billing cycle's consumption is.
#[derive(Debug, Clone, Copy)]
pub struct PersistedVolume {
    consumed_bytes: u64,
    cycle_start_unix: u64,
    degraded: bool,
}

/// A subscriber's monthly byte counter and the degrade/recover state
/// machine. `limit_bytes == 0` disables the monthly cap entirely — every
/// call still counts bytes (so a later config change can turn the cap on
/// without losing history) but never degrades.
#[derive(Debug)]
pub struct MonthlyVolume {
    limit_bytes: u64,
    consumed_bytes: AtomicU64,
    cycle_start_unix: AtomicU64,
    degraded: AtomicBool,
}

impl MonthlyVolume {
    fn new(limit_bytes: u64, seed: Option<PersistedVolume>) -> Self {
        let (consumed, cycle_start, degraded) = match seed {
            Some(p) => (p.consumed_bytes, p.cycle_start_unix, p.degraded),
            None => (0, unix_secs(SystemTime::now()), false),
        };
        Self {
            limit_bytes,
            consumed_bytes: AtomicU64::new(consumed),
            cycle_start_unix: AtomicU64::new(cycle_start),
            degraded: AtomicBool::new(degraded),
        }
    }

    /// Whether the counter is degraded RIGHT NOW, with no side effects —
    /// used only to pick a new [`SubscriberBandwidthLimiter`]'s starting
    /// rate. [`add_and_check`](Self::add_and_check) is the only method that
    /// can change this.
    fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// Add `bytes` to the current cycle's consumption (rolling the cycle
    /// over first if `now` has passed the cycle's own 30-day mark), then
    /// report whether the degrade state changed.
    fn add_and_check(&self, bytes: u64, now: SystemTime) -> DegradeTransition {
        let now_secs = unix_secs(now);
        let cycle_start = self.cycle_start_unix.load(Ordering::Relaxed);
        let mut recovered_by_rollover = false;
        if cycle_start == 0 || now_secs >= cycle_start.saturating_add(CYCLE_SECS) {
            self.cycle_start_unix.store(now_secs, Ordering::Relaxed);
            self.consumed_bytes.store(0, Ordering::Relaxed);
            recovered_by_rollover = self.degraded.swap(false, Ordering::Relaxed);
        }
        let consumed = self.consumed_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if self.limit_bytes != 0 && consumed >= self.limit_bytes {
            let was_degraded = self.degraded.swap(true, Ordering::Relaxed);
            if !was_degraded {
                // Takes precedence over a same-tick rollover recovery: the
                // fresh cycle immediately exhausted its own volume, so
                // "entered degraded" is the true current state even though
                // a recovery technically also happened a moment earlier in
                // this same call.
                return DegradeTransition::EnteredDegraded;
            }
        }
        if recovered_by_rollover {
            return DegradeTransition::Recovered;
        }
        DegradeTransition::NoChange
    }

    fn snapshot(&self) -> PersistedVolume {
        PersistedVolume {
            consumed_bytes: self.consumed_bytes.load(Ordering::Relaxed),
            cycle_start_unix: self.cycle_start_unix.load(Ordering::Relaxed),
            degraded: self.degraded.load(Ordering::Relaxed),
        }
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ─────────────────────────────────────────────────────────────────────────
// Resolved config — the raw `Option<u64>` fields, defaulted
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct ResolvedBandwidthCaps {
    aggregate_rate: u64,
    aggregate_burst: u64,
    per_connection_rate: u64,
    per_connection_burst: u64,
    monthly_volume: u64,
    degraded_floor: u64,
}

impl ResolvedBandwidthCaps {
    /// `None` when `aggregate_rate_bytes_per_sec` is unset — the box stays
    /// dark (fully uncapped) until an operator sets at least that one field.
    fn resolve(cfg: &SubscriberEntranceConfig) -> Option<Self> {
        let aggregate_rate = cfg.aggregate_rate_bytes_per_sec?.max(MIN_RATE_BYTES_PER_SEC);
        let aggregate_burst = cfg
            .aggregate_burst_bytes
            .unwrap_or(DEFAULT_AGGREGATE_BURST_BYTES)
            .max(1);
        let per_connection_rate = cfg
            .per_connection_rate_bytes_per_sec
            .unwrap_or_else(|| ((aggregate_rate as f64) * DEFAULT_PER_CONNECTION_FRACTION).round() as u64)
            .max(MIN_RATE_BYTES_PER_SEC);
        // One second of the connection's own ceiling. Not independently
        // configurable — the brief names one per-connection knob, not a
        // rate/burst pair — and a full second is generous enough that the
        // ceiling reads as a sustained-rate cap rather than a stutter.
        let per_connection_burst = per_connection_rate;
        let monthly_volume = cfg.monthly_volume_bytes.unwrap_or(0);
        let degraded_floor = cfg
            .degraded_floor_bytes_per_sec
            .unwrap_or(DEFAULT_DEGRADED_FLOOR_BYTES_PER_SEC)
            .max(MIN_RATE_BYTES_PER_SEC);
        Some(Self {
            aggregate_rate,
            aggregate_burst,
            per_connection_rate,
            per_connection_burst,
            monthly_volume,
            degraded_floor,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SubscriberBandwidthLimiter / ConnectionBandwidthLimiter
// ─────────────────────────────────────────────────────────────────────────

/// One subscriber's aggregate budget (shared by every one of their open
/// connections) and their monthly-volume degrade state.
pub struct SubscriberBandwidthLimiter {
    key: SubscriberKey,
    aggregate: ByteBucket,
    monthly: MonthlyVolume,
    normal_rate: u64,
    degraded_floor: u64,
    per_connection_rate: u64,
    per_connection_burst: u64,
    /// Bytes charged since the last [`SubscriberBandwidthRegistry::
    /// drain_consumption_report`] call — independent of `MonthlyVolume`'s own
    /// persisted running total. This is purely the upward-report cadence's
    /// own counter: it resets to zero on every drain (and, harmlessly, on
    /// every process restart — the monitor loses at most one report
    /// interval's worth of consumption, never the whole cycle, because the
    /// monthly total itself is what's persisted and restored). See
    /// `docs/mirage/plans/edge-role-and-product-tiers-2026-09-17.md` §4.
    report_delta_bytes: AtomicU64,
}

impl SubscriberBandwidthLimiter {
    fn new(key: SubscriberKey, caps: ResolvedBandwidthCaps, seed: Option<PersistedVolume>) -> Self {
        let monthly = MonthlyVolume::new(caps.monthly_volume, seed);
        let starting_rate = if monthly.is_degraded() {
            caps.degraded_floor
        } else {
            caps.aggregate_rate
        };
        Self {
            key,
            aggregate: ByteBucket::new(starting_rate, caps.aggregate_burst),
            monthly,
            normal_rate: caps.aggregate_rate,
            degraded_floor: caps.degraded_floor,
            per_connection_rate: caps.per_connection_rate,
            per_connection_burst: caps.per_connection_burst,
            report_delta_bytes: AtomicU64::new(0),
        }
    }

    /// Snapshot and reset (swap-to-zero) this subscriber's report-delta
    /// counter — bytes charged since the last call. Never touches
    /// `MonthlyVolume`'s own persisted counter.
    fn drain_report_delta(&self) -> u64 {
        self.report_delta_bytes.swap(0, Ordering::Relaxed)
    }

    fn charge_aggregate(&self, bytes: u64) -> Duration {
        self.report_delta_bytes.fetch_add(bytes, Ordering::Relaxed);
        match self.monthly.add_and_check(bytes, SystemTime::now()) {
            DegradeTransition::EnteredDegraded => {
                self.aggregate.set_rate(self.degraded_floor);
                warn!(
                    subscriber = %hex::encode(self.key),
                    floor_bytes_per_sec = self.degraded_floor,
                    "subscriber-bandwidth: monthly volume exhausted — degraded to floor rate"
                );
            }
            DegradeTransition::Recovered => {
                self.aggregate.set_rate(self.normal_rate);
                info!(
                    subscriber = %hex::encode(self.key),
                    rate_bytes_per_sec = self.normal_rate,
                    "subscriber-bandwidth: new billing cycle — recovered to normal rate"
                );
            }
            DegradeTransition::NoChange => {}
        }
        self.aggregate.reserve(bytes, Instant::now())
    }
}

/// A single connection's view of the cap: this connection's own ceiling
/// bucket, plus a shared handle to its subscriber's aggregate budget.
pub struct ConnectionBandwidthLimiter {
    subscriber: Arc<SubscriberBandwidthLimiter>,
    per_connection: ByteBucket,
}

impl ConnectionBandwidthLimiter {
    /// Charge `bytes` against both the subscriber's aggregate budget and
    /// this connection's own ceiling, waiting out each in turn. See the
    /// module doc for why the waits are sequential rather than a `max` of
    /// two independently computed delays.
    pub async fn charge(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let agg_wait = self.subscriber.charge_aggregate(bytes);
        if agg_wait > Duration::ZERO {
            tokio::time::sleep(agg_wait).await;
        }
        let conn_wait = self.per_connection.reserve(bytes, Instant::now());
        if conn_wait > Duration::ZERO {
            tokio::time::sleep(conn_wait).await;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// SubscriberBandwidthRegistry — box-wide, process-lifetime
// ─────────────────────────────────────────────────────────────────────────

/// Box-wide map from subscriber key to that subscriber's live
/// [`SubscriberBandwidthLimiter`], plus the persisted-volume seed loaded at
/// boot. Lives on the edge's own runtime — one instance for the process,
/// shared by every accepted subscriber connection, mirroring
/// [`crate::subscriber_keys::SubscriberKeyStore`]'s own "one shared instance"
/// shape.
///
/// A subscriber's limiter, once created, is never evicted — held for the
/// life of the process so its monthly counter and aggregate schedule stay
/// live across that subscriber's connections coming and going. This is a
/// per-box subscriber count (at most a handful to a few hundred), not a
/// per-connection structure, so unbounded growth here is not a concern the
/// way it would be for e.g. a per-source-IP table.
pub struct SubscriberBandwidthRegistry {
    limiters: Mutex<HashMap<SubscriberKey, Arc<SubscriberBandwidthLimiter>>>,
    seed: Mutex<HashMap<SubscriberKey, PersistedVolume>>,
}

impl SubscriberBandwidthRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            limiters: Mutex::new(HashMap::new()),
            seed: Mutex::new(HashMap::new()),
        })
    }

    /// Seed persisted monthly-volume state loaded from disk at boot, before
    /// any connection has created a live limiter. Call once, before any
    /// connection can reach [`connection_limiter`](Self::connection_limiter)
    /// — a key that already has a live limiter is left alone rather than
    /// overwritten, since that would discard whatever it has counted since
    /// boot.
    pub fn restore(&self, persisted: HashMap<SubscriberKey, PersistedVolume>) {
        let mut seed = self.seed.lock().unwrap_or_else(|p| p.into_inner());
        *seed = persisted;
    }

    /// Build a fresh per-connection limiter for `subscriber`, sharing that
    /// subscriber's aggregate bucket and monthly counter with every other of
    /// their open connections. `None` when this box has no cap configured
    /// (`cfg.aggregate_rate_bytes_per_sec` is `None`) — the caller then runs
    /// that connection fully uncapped, matching today's behaviour.
    ///
    /// `cfg` is resolved into concrete numbers only the FIRST time a given
    /// subscriber is seen; a config value changed later in `cfg` has no
    /// effect on that subscriber's already-created limiter. This matches
    /// `NodeConfig`'s own box-local fields today: they are read once at
    /// boot and a change requires a restart, not a live reconfigure.
    pub fn connection_limiter(
        &self,
        subscriber: SubscriberKey,
        cfg: &SubscriberEntranceConfig,
    ) -> Option<ConnectionBandwidthLimiter> {
        let caps = ResolvedBandwidthCaps::resolve(cfg)?;
        let subscriber_limiter = {
            let mut limiters = self.limiters.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(existing) = limiters.get(&subscriber) {
                Arc::clone(existing)
            } else {
                let seed = self
                    .seed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&subscriber);
                let created = Arc::new(SubscriberBandwidthLimiter::new(subscriber, caps, seed));
                limiters.insert(subscriber, Arc::clone(&created));
                created
            }
        };
        let per_connection = ByteBucket::new(
            subscriber_limiter.per_connection_rate,
            subscriber_limiter.per_connection_burst,
        );
        Some(ConnectionBandwidthLimiter {
            subscriber: subscriber_limiter,
            per_connection,
        })
    }

    /// Snapshot every live subscriber's monthly-volume state for
    /// persistence. Cheap — one small `Copy` struct per subscriber — and
    /// called only from the periodic persistence task, never the data path.
    pub fn snapshot(&self) -> HashMap<SubscriberKey, PersistedVolume> {
        let limiters = self.limiters.lock().unwrap_or_else(|p| p.into_inner());
        limiters.iter().map(|(k, v)| (*k, v.monthly.snapshot())).collect()
    }

    /// Build this cycle's upward consumption report: one
    /// [`SubscriberConsumptionDelta`] per live subscriber that has charged at
    /// least one byte since the last call, draining (swap-to-zero) each
    /// entry's report-delta counter in the same pass so nothing is
    /// double-reported next cycle. A subscriber that charged nothing since
    /// the last drain is omitted entirely — an idle box (or a box with no
    /// bandwidth cap configured, which never creates a limiter at all) drains
    /// an empty `Vec`, and the caller sends no frame for it. Called from the
    /// same periodic loop, on the same cadence, as the persistence snapshot
    /// above — see `node_control_client.rs`'s reconcile loop.
    pub fn drain_consumption_report(&self) -> Vec<SubscriberConsumptionDelta> {
        let limiters = self.limiters.lock().unwrap_or_else(|p| p.into_inner());
        limiters
            .values()
            .filter_map(|limiter| {
                let consumed_bytes = limiter.drain_report_delta();
                if consumed_bytes == 0 {
                    return None;
                }
                Some(SubscriberConsumptionDelta {
                    subscriber_key_hex: hex::encode(limiter.key),
                    consumed_bytes,
                    degraded: limiter.monthly.is_degraded(),
                })
            })
            .collect()
    }
}

/// One subscriber's bandwidth-consumption delta since the last
/// [`SubscriberBandwidthRegistry::drain_consumption_report`] call — kept
/// independent of the node→monitor wire frame type so this module carries no
/// dependency on `node_control_client`'s local mirror; the caller maps this
/// into `NodeFrame::SubscriberConsumptionReport`'s own observation shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberConsumptionDelta {
    pub subscriber_key_hex: String,
    pub consumed_bytes: u64,
    pub degraded: bool,
}

// ─────────────────────────────────────────────────────────────────────────
// Persistence — JSON file, tmp+rename, mirrors `node_toml::resolve_sentry_id`
// ─────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct PersistedVolumeFile {
    subscribers: Vec<PersistedSubscriberEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedSubscriberEntry {
    subscriber_hex: String,
    consumed_bytes: u64,
    cycle_start_unix: u64,
    degraded: bool,
}

fn decode_subscriber_hex(hex_str: &str) -> Option<SubscriberKey> {
    if hex_str.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut out).ok()?;
    Some(out)
}

/// Load the persisted monthly-volume file from disk at boot. A missing file
/// is the ordinary "never persisted before" case — silent. A malformed file
/// is logged and treated the same as missing: every subscriber starts this
/// boot at zero consumption rather than the process refusing to start over
/// a corrupt accounting file.
pub fn load_persisted_volume(path: &Path) -> HashMap<SubscriberKey, PersistedVolume> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "subscriber-bandwidth: volume file read failed — every subscriber starts this boot at zero"
                );
            }
            return HashMap::new();
        }
    };
    let parsed: PersistedVolumeFile = match serde_json::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "subscriber-bandwidth: volume file parse failed — every subscriber starts this boot at zero"
            );
            return HashMap::new();
        }
    };
    parsed
        .subscribers
        .into_iter()
        .filter_map(|entry| {
            let key = decode_subscriber_hex(&entry.subscriber_hex)?;
            Some((
                key,
                PersistedVolume {
                    consumed_bytes: entry.consumed_bytes,
                    cycle_start_unix: entry.cycle_start_unix,
                    degraded: entry.degraded,
                },
            ))
        })
        .collect()
}

/// Write `snapshot` to `path` atomically (tmp file + rename), the same
/// pattern `node_toml::resolve_sentry_id` uses for `sentry-id.txt`.
pub fn persist_volume(path: &Path, snapshot: &HashMap<SubscriberKey, PersistedVolume>) -> std::io::Result<()> {
    let file = PersistedVolumeFile {
        subscribers: snapshot
            .iter()
            .map(|(k, v)| PersistedSubscriberEntry {
                subscriber_hex: hex::encode(k),
                consumed_bytes: v.consumed_bytes,
                cycle_start_unix: v.cycle_start_unix,
                degraded: v.degraded,
            })
            .collect(),
    };
    let body = serde_json::to_string_pretty(&file).map_err(std::io::Error::other)?;
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Spawn a background task that snapshots `registry`'s monthly-volume state
/// to `path` every `interval`. Mirrors
/// `subscriber_keys::spawn_hot_reload`'s shape: a plain `tokio::time::interval`
/// loop, no filesystem-event watcher.
///
/// Skips the write entirely while `registry` has no live subscriber yet
/// (nothing has connected since boot) rather than persisting an empty
/// snapshot — that would clobber a real accounting file from a previous run
/// with an empty one before this boot's first subscriber has even dialled
/// in.
pub fn spawn_persistence(
    registry: Arc<SubscriberBandwidthRegistry>,
    path: PathBuf,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // first tick fires immediately; skip it.
        loop {
            ticker.tick().await;
            let snapshot = registry.snapshot();
            if snapshot.is_empty() {
                continue;
            }
            if let Err(e) = persist_volume(&path, &snapshot) {
                warn!(path = %path.display(), error = %e, "subscriber-bandwidth: periodic persist failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ByteBucket arithmetic ────────────────────────────────────────────

    #[test]
    fn a_full_bucket_allows_exactly_its_burst_then_waits() {
        // 10 bytes/sec, 20-byte burst: the first 20 bytes are free, the next
        // request must wait.
        let bucket = ByteBucket::new(10, 20);
        let now = Instant::now();
        assert_eq!(bucket.reserve(20, now), Duration::ZERO, "burst-sized request is immediate");
        let wait = bucket.reserve(1, now);
        assert!(wait > Duration::ZERO, "past the burst, a request must wait");
    }

    #[test]
    fn wait_matches_the_configured_rate() {
        // 10 bytes/sec, 2-byte burst: after spending the burst, one more
        // byte needs exactly 100ms (1/10th of a second) before it is
        // within budget.
        let bucket = ByteBucket::new(10, 2);
        let now = Instant::now();
        assert_eq!(bucket.reserve(2, now), Duration::ZERO);
        let wait = bucket.reserve(1, now);
        assert_eq!(wait, Duration::from_millis(100), "1 byte at 10 B/s costs 100ms");
    }

    #[test]
    fn burst_drains_and_refills_with_elapsed_time() {
        let bucket = ByteBucket::new(10, 20);
        let t0 = Instant::now();
        // Spend 5 of the 20-byte burst.
        assert_eq!(bucket.reserve(5, t0), Duration::ZERO);
        // Immediately ask for the remaining 15 plus 5 more (20 total) — only
        // 15 is available, so the extra 5 bytes cost 500ms at 10 B/s.
        let wait = bucket.reserve(20, t0);
        assert_eq!(wait, Duration::from_millis(500));
        // After waiting exactly that long, the NEXT byte is immediate again
        // (the bucket is now precisely drained, not in debt).
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!(bucket.reserve(0, t1), Duration::ZERO);
    }

    #[test]
    fn idle_time_refills_only_up_to_the_burst_cap() {
        // A bucket left untouched for a long time must not accumulate more
        // than `burst` bytes of instant capacity — token buckets cap at
        // burst, they do not bank unlimited idle credit.
        let bucket = ByteBucket::new(10, 20);
        let t0 = Instant::now();
        assert_eq!(bucket.reserve(20, t0), Duration::ZERO, "drain the full burst");
        let t1 = t0 + Duration::from_secs(3600); // an hour of idle time
        assert_eq!(
            bucket.reserve(20, t1),
            Duration::ZERO,
            "after a long idle period the burst is fully available again"
        );
        // But not more than the burst: a second burst-sized request right
        // after must wait the full nominal time, exactly as from a cold
        // start — no extra credit carried over from the idle hour.
        let wait = bucket.reserve(20, t1);
        assert_eq!(wait, Duration::from_secs(2), "20 bytes at 10 B/s past a spent burst costs 2s");
    }

    #[test]
    fn a_slow_consumer_is_never_delayed() {
        // A consumer that sends well under the sustained rate must see
        // Duration::ZERO on every single call — the cap must never
        // penalise traffic that was never over budget.
        let bucket = ByteBucket::new(1000, 1000); // 1000 B/s, 1s burst
        let mut now = Instant::now();
        for _ in 0..50 {
            // 100 bytes every 500ms is 200 B/s sustained — well under 1000.
            assert_eq!(bucket.reserve(100, now), Duration::ZERO, "a slow consumer must never wait");
            now += Duration::from_millis(500);
        }
    }

    #[test]
    fn a_dynamic_rate_change_reprices_future_reservations() {
        let bucket = ByteBucket::new(100, 100); // 100 B/s, 100-byte burst
        let t0 = Instant::now();
        assert_eq!(bucket.reserve(100, t0), Duration::ZERO, "spend the whole starting burst");
        // `tat` now sits exactly 1s (100 bytes @ 100 B/s) past `t0`.
        // Degrade the rate tenfold before the next reservation.
        bucket.set_rate(10);
        // At the new rate the SAME fixed 100-byte burst is worth 10s of
        // slack (100 bytes @ 10 B/s), so the still-only-1s-past-t0 `tat` is
        // well inside that slack — one more byte is still free.
        assert_eq!(
            bucket.reserve(1, t0),
            Duration::ZERO,
            "a rate degrade must not retroactively punish an earlier reservation"
        );
        // But its cost was priced at the NEW rate, and a large enough
        // request now exceeds even the enlarged slack — proving the rate in
        // effect at RESERVE time is what governs cost, not the rate that
        // was active when the earlier reservation happened.
        let wait = bucket.reserve(100, t0);
        assert!(wait > Duration::ZERO, "a rate degrade must show up in a subsequent large reservation");
    }

    // ── MonthlyVolume degrade / recover ──────────────────────────────────

    #[test]
    fn under_the_limit_never_degrades() {
        let mv = MonthlyVolume::new(1_000_000, None);
        let now = SystemTime::now();
        assert_eq!(mv.add_and_check(500_000, now), DegradeTransition::NoChange);
        assert!(!mv.is_degraded());
    }

    #[test]
    fn crossing_the_limit_degrades_exactly_once() {
        let mv = MonthlyVolume::new(1_000_000, None);
        let now = SystemTime::now();
        assert_eq!(mv.add_and_check(900_000, now), DegradeTransition::NoChange);
        assert_eq!(
            mv.add_and_check(200_000, now),
            DegradeTransition::EnteredDegraded,
            "crossing the limit must report exactly one transition"
        );
        assert!(mv.is_degraded());
        assert_eq!(
            mv.add_and_check(10, now),
            DegradeTransition::NoChange,
            "staying degraded must not re-report the transition"
        );
    }

    #[test]
    fn a_new_cycle_recovers_and_resets_the_counter() {
        let mv = MonthlyVolume::new(1_000_000, None);
        let t0 = SystemTime::now();
        assert_eq!(mv.add_and_check(1_000_000, t0), DegradeTransition::EnteredDegraded);
        let t1 = t0 + Duration::from_secs(CYCLE_SECS + 1);
        assert_eq!(
            mv.add_and_check(10, t1),
            DegradeTransition::Recovered,
            "the next cycle must recover exactly once"
        );
        assert!(!mv.is_degraded());
        // The counter reset with the cycle: only the 10 bytes from the new
        // cycle are counted, not 1_000_010.
        assert_eq!(mv.snapshot().consumed_bytes, 10);
    }

    #[test]
    fn a_zero_limit_never_degrades() {
        let mv = MonthlyVolume::new(0, None);
        let now = SystemTime::now();
        assert_eq!(
            mv.add_and_check(u64::MAX / 2, now),
            DegradeTransition::NoChange,
            "limit_bytes == 0 disables the monthly cap"
        );
        assert!(!mv.is_degraded());
    }

    // ── SubscriberBandwidthRegistry ──────────────────────────────────────

    fn key(byte: u8) -> SubscriberKey {
        [byte; 32]
    }

    fn cfg_with_rate(rate: u64) -> SubscriberEntranceConfig {
        SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: Some(rate),
            aggregate_burst_bytes: Some(rate), // 1s burst, keeps test math simple
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        }
    }

    #[test]
    fn no_configured_rate_means_no_limiter() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: None,
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        };
        assert!(
            registry.connection_limiter(key(1), &cfg).is_none(),
            "an unconfigured box must stay fully uncapped"
        );
    }

    #[test]
    fn two_subscribers_get_independent_aggregate_budgets() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1000);
        let a = registry.connection_limiter(key(1), &cfg).expect("configured");
        let b = registry.connection_limiter(key(2), &cfg).expect("configured");
        // Spend subscriber A's whole burst directly on the bucket to avoid
        // sleeping in the test.
        let wait_a = a.subscriber.aggregate.reserve(1000, Instant::now());
        assert_eq!(wait_a, Duration::ZERO, "A's own burst covers this");
        let wait_a_over = a.subscriber.aggregate.reserve(1, Instant::now());
        assert!(wait_a_over > Duration::ZERO, "A is now over budget");
        // B's independent bucket is untouched by A's spending.
        let wait_b = b.subscriber.aggregate.reserve(1000, Instant::now());
        assert_eq!(wait_b, Duration::ZERO, "B has its own full budget");
    }

    #[test]
    fn the_same_subscribers_connections_share_one_aggregate() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1000);
        let conn1 = registry.connection_limiter(key(1), &cfg).expect("configured");
        let conn2 = registry.connection_limiter(key(1), &cfg).expect("configured");
        // Spend the whole aggregate burst through the FIRST connection's
        // handle.
        let wait1 = conn1.subscriber.aggregate.reserve(1000, Instant::now());
        assert_eq!(wait1, Duration::ZERO);
        // The SECOND connection (same subscriber) sees the same drained
        // aggregate bucket — proving the two share state, not two separate
        // budgets.
        let wait2 = conn2.subscriber.aggregate.reserve(1, Instant::now());
        assert!(wait2 > Duration::ZERO, "the aggregate is shared across this subscriber's connections");
    }

    #[test]
    fn per_connection_ceiling_binds_tighter_than_a_slack_aggregate() {
        let registry = SubscriberBandwidthRegistry::new();
        let mut cfg = cfg_with_rate(1_000_000); // generous aggregate
        cfg.per_connection_rate_bytes_per_sec = Some(100); // tight per-connection ceiling
        let limiter = registry.connection_limiter(key(1), &cfg).expect("configured");
        // The aggregate has effectively unlimited room, but the
        // per-connection bucket (100 B/s, default 1s burst == 100 bytes)
        // must still gate this connection on its own.
        let wait = limiter.per_connection.reserve(200, Instant::now());
        assert!(wait > Duration::ZERO, "a single connection must not exceed its own ceiling");
    }

    #[test]
    fn defaults_resolve_off_the_aggregate_rate_alone() {
        let cfg = SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: Some(1_000_000),
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        };
        let caps = ResolvedBandwidthCaps::resolve(&cfg).expect("aggregate rate is set");
        assert_eq!(caps.aggregate_burst, DEFAULT_AGGREGATE_BURST_BYTES);
        assert_eq!(caps.per_connection_rate, 500_000, "half the aggregate rate");
        assert_eq!(caps.monthly_volume, 0, "no monthly cap unless set");
        assert_eq!(caps.degraded_floor, DEFAULT_DEGRADED_FLOOR_BYTES_PER_SEC);
    }

    // ── Persistence surviving a reload ───────────────────────────────────

    #[test]
    fn persisted_volume_round_trips_through_disk() {
        let path = std::env::temp_dir().join(format!(
            "mirage-subscriber-bandwidth-test-{}-{}.json",
            std::process::id(),
            line!()
        ));
        let mut snapshot = HashMap::new();
        snapshot.insert(
            key(0xAB),
            PersistedVolume {
                consumed_bytes: 123_456,
                cycle_start_unix: 1_700_000_000,
                degraded: true,
            },
        );
        persist_volume(&path, &snapshot).expect("persist must succeed");
        let loaded = load_persisted_volume(&path);
        let entry = loaded.get(&key(0xAB)).expect("the persisted subscriber must round-trip");
        assert_eq!(entry.consumed_bytes, 123_456);
        assert_eq!(entry.cycle_start_unix, 1_700_000_000);
        assert!(entry.degraded);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_volume_file_yields_an_empty_seed_not_an_error() {
        let path = std::env::temp_dir().join("mirage-subscriber-bandwidth-does-not-exist.json");
        assert!(load_persisted_volume(&path).is_empty());
    }

    // ── Consumption report delta ─────────────────────────────────────────

    #[test]
    fn a_registry_with_no_traffic_drains_an_empty_report() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1000);
        // Creating a limiter (e.g. an accepted connection that never sent a
        // byte) must not, by itself, produce a report entry.
        let _limiter = registry.connection_limiter(key(1), &cfg).expect("configured");
        assert!(
            registry.drain_consumption_report().is_empty(),
            "a subscriber with zero bytes charged must not appear in the report"
        );
    }

    #[test]
    fn an_unconfigured_box_never_creates_a_limiter_so_never_reports() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: None,
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        };
        assert!(registry.connection_limiter(key(1), &cfg).is_none());
        assert!(
            registry.drain_consumption_report().is_empty(),
            "a box with no bandwidth cap configured must never send a consumption report"
        );
    }

    #[test]
    fn charged_bytes_appear_once_in_the_next_drain_then_disappear() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1_000_000);
        let limiter = registry.connection_limiter(key(0x42), &cfg).expect("configured");
        limiter.subscriber.charge_aggregate(500);

        let report = registry.drain_consumption_report();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].subscriber_key_hex, hex::encode(key(0x42)));
        assert_eq!(report[0].consumed_bytes, 500);
        assert!(!report[0].degraded);

        // Draining again with no further traffic yields nothing — the
        // counter was reset, not merely read.
        assert!(
            registry.drain_consumption_report().is_empty(),
            "a drained delta must not be reported twice"
        );
    }

    #[test]
    fn two_subscribers_report_independent_deltas() {
        let registry = SubscriberBandwidthRegistry::new();
        let cfg = cfg_with_rate(1_000_000);
        let a = registry.connection_limiter(key(1), &cfg).expect("configured");
        let b = registry.connection_limiter(key(2), &cfg).expect("configured");
        a.subscriber.charge_aggregate(100);
        b.subscriber.charge_aggregate(200);

        let mut report = registry.drain_consumption_report();
        report.sort_by(|x, y| x.consumed_bytes.cmp(&y.consumed_bytes));
        assert_eq!(report.len(), 2);
        assert_eq!(report[0].consumed_bytes, 100);
        assert_eq!(report[1].consumed_bytes, 200);
    }

    #[test]
    fn a_degraded_subscriber_reports_degraded_true() {
        let registry = SubscriberBandwidthRegistry::new();
        let mut cfg = cfg_with_rate(1_000_000);
        cfg.monthly_volume_bytes = Some(100);
        cfg.degraded_floor_bytes_per_sec = Some(1_000);
        let limiter = registry.connection_limiter(key(9), &cfg).expect("configured");
        limiter.subscriber.charge_aggregate(150); // crosses the 100-byte monthly cap

        let report = registry.drain_consumption_report();
        assert_eq!(report.len(), 1);
        assert!(report[0].degraded, "a subscriber over its monthly volume must report degraded");
    }

    #[test]
    fn a_restart_restores_the_monthly_total_with_the_report_delta_at_zero() {
        // The on-disk file is a restart CACHE for the monthly total, not for
        // the report-delta counter — the delta legitimately starts fresh
        // after every process restart (see `report_delta_bytes`'s doc); at
        // most one report interval of consumption is lost, never the whole
        // cycle, because the monthly total itself survives via `restore`.
        let registry = SubscriberBandwidthRegistry::new();
        let mut seed = HashMap::new();
        seed.insert(
            key(0x55),
            PersistedVolume {
                consumed_bytes: 900,
                cycle_start_unix: unix_secs(SystemTime::now()),
                degraded: false,
            },
        );
        registry.restore(seed);
        let cfg = cfg_with_rate(1_000_000);
        let _limiter = registry.connection_limiter(key(0x55), &cfg).expect("configured");
        assert!(
            registry.drain_consumption_report().is_empty(),
            "a freshly restored (restarted) subscriber must not appear in a report until it charges again"
        );
        // The monthly total itself did survive the restart.
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.get(&key(0x55)).map(|p| p.consumed_bytes), Some(900));
    }

    #[test]
    fn a_registry_seeded_as_degraded_starts_its_limiter_degraded() {
        // Simulates a restart mid-degraded-cycle: the persisted state says
        // this subscriber is already degraded, well within the same 30-day
        // cycle — the freshly created limiter must start at the floor rate,
        // not the normal rate, until the next real charge reconciles it.
        let registry = SubscriberBandwidthRegistry::new();
        let mut seed = HashMap::new();
        seed.insert(
            key(0x77),
            PersistedVolume {
                consumed_bytes: 900,
                cycle_start_unix: unix_secs(SystemTime::now()),
                degraded: true,
            },
        );
        registry.restore(seed);

        let mut cfg = cfg_with_rate(1_000_000);
        cfg.monthly_volume_bytes = Some(1_000);
        cfg.degraded_floor_bytes_per_sec = Some(1_000);
        let limiter = registry.connection_limiter(key(0x77), &cfg).expect("configured");
        assert_eq!(
            limiter.subscriber.aggregate.rate_bytes_per_sec.load(Ordering::Relaxed),
            1_000,
            "a restored degraded subscriber must start at the floor rate"
        );
    }
}
