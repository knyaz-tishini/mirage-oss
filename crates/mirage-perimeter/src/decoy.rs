//! Decoy / honeypot listeners — A-tier deception, extended with tier-2
//! zero-parse "proactive burn" (tarpit / junk-flood / send-first
//! decompression bomb) and adaptive ban escalation.
//!
//! Moved out of `mirage-secd` into this crate (arc3 core/periphery split —
//! see this crate's `lib.rs` module doc for why). The burn mechanisms are
//! unchanged from the pre-move version; the ban/intel wiring that used to
//! reach back into `mirage-secd` in-process is gone (cut 2026-07-31) — see
//! `lib.rs`'s module doc for what replaced it.
//!
//! Binds userspace TCP listeners on ports that legitimate software never
//! touches. Any inbound connection is an unambiguous foe signal: record the
//! touch locally, run the port's configured burn mechanism, and report a
//! typed observation through this [`DecoyState`]'s [`ObservationSink`] —
//! banning the source IP is the arbiter's decision, not this crate's.
//!
//! # Safety discipline (secd runs as root pre-de-root)
//!
//! **The governing law: branch ONLY on `port` (a fact known before accept,
//! zero parse). NEVER read-and-interpret the attacker's bytes to select a
//! response.** Every burn mechanism below is send-only, send-first, or a
//! fixed script:
//!
//! - [`BurnMode::Drop`] — read ≤256 bytes (opaque, intel only), close. The
//!   original tripwire behaviour, unchanged.
//! - [`BurnMode::Tarpit`] — hold the fd, write nothing (or a fixed trickle
//!   byte on a timer), bounded wall-time, never read past the opaque intel
//!   snippet.
//! - [`BurnMode::JunkFlood`] — blast a capped, rate-limited stream of
//!   RNG-at-startup bytes (never attacker-derived), bounded wall-time.
//! - [`BurnMode::Bomb`] — emit a FIXED compile-time send-first decompression
//!   bomb ([`crate::bomb`]) before reading anything.
//!
//! The 256-byte/2s-timeout opaque snippet read (for intel/logging) is
//! preserved as-is for every mode — its RESULT never selects which burn
//! mechanism runs. The only branch is `port → BurnMode`, a compile-time
//! table (or an env override), never `bytes_read → mode`.
//!
//! # Concurrency / fd cap (mandatory prerequisite — ships with every mechanism)
//!
//! `DecoyState::decoy_active` is a shared [`tokio::sync::Semaphore`] bounding
//! concurrent live decoy connections across ALL ports and ALL burn
//! mechanisms. `accept_loop` acquires a permit via `try_acquire_owned`
//! (non-blocking) before spawning the handler; if the budget is exhausted the
//! connection is dropped immediately (load-shed), NEVER queued — a flooded
//! decoy port must never stall the accept loop's ability to keep
//! accepting+immediately-closing other connections. Every mechanism also
//! wraps its hold/write loop in a `tokio::time::timeout` wall-clock cap so a
//! malicious peer advertising a zero receive window cannot pin a permit
//! forever.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use mirage_core::fact_signing::AttackerSignalType;
use mirage_core::perimeter_observation::{confidence_bucket, PerimeterObservation};
use rand::RngCore;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::sink::ObservationSink;

/// Ring-buffer capacity for stored decoy touches.
const TOUCH_RING_CAP: usize = 256;

/// Maximum bytes read from an attacker connection (opaque, never parsed).
const SNIPPET_MAX_BYTES: usize = 256;

/// Read timeout per connection — drop attacker if silent longer than this.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum concurrent live decoy connections across all ports and all burn
/// mechanisms. Sized generously relative to realistic burst-scan
/// concurrency (decoy ports see scanner traffic, not production load) while
/// still bounding the root process's fd/task footprint. Overridable via
/// `MIRAGE_SECD_DECOY_MAX_CONCURRENT` for operators who want to retune
/// without a rebuild.
const DEFAULT_MAX_CONCURRENT_DECOYS: usize = 512;

/// Environment variable overriding [`DEFAULT_MAX_CONCURRENT_DECOYS`].
pub const MAX_CONCURRENT_ENV: &str = "MIRAGE_SECD_DECOY_MAX_CONCURRENT";

/// Wall-clock cap on a tarpit hold. Never hold a socket forever — after this
/// expires the connection is banned+dropped exactly like the instant-ban path.
const MAX_TARPIT_DURATION: Duration = Duration::from_secs(120);

/// Trickle interval: how often the tarpit writes its single fixed byte.
const TARPIT_TRICKLE_INTERVAL: Duration = Duration::from_secs(20);

/// The single fixed byte the tarpit ever writes — compile-time constant,
/// never derived from anything the attacker sent.
const TARPIT_TRICKLE_BYTE: [u8; 1] = [0u8];

/// Wall-clock cap on a junk-flood write loop — bounds the "malicious
/// zero-receive-window" self-DoS risk (a peer that never drains its receive
/// buffer gets the connection killed after this regardless of bytes sent).
const MAX_FLOOD_DURATION: Duration = Duration::from_secs(30);

/// Total bytes ceiling per junk-flood connection.
const MAX_FLOOD_BYTES: usize = 4 * 1024 * 1024;

/// Chunk size per junk-flood write.
const FLOOD_CHUNK_BYTES: usize = 16 * 1024;

/// Delay between junk-flood chunk writes — bounds this connection's egress
/// rate so a single flood connection cannot become a bandwidth-amplification
/// lever.
const FLOOD_CHUNK_DELAY: Duration = Duration::from_millis(50);

/// Size of the fixed RNG-at-startup buffer tiled to fill a junk-flood.
/// Generated ONCE at daemon boot (see [`junk_source`]) — never regenerated
/// per-byte, never derived from attacker input. Keeps the CPU cost of a
/// flood near-zero (memcpy of a static buffer).
const JUNK_SOURCE_BYTES: usize = 64 * 1024;

/// Wall-clock cap on the send-first bomb write — same "malicious receive
/// window" guard as tarpit/flood, applied to the (much shorter) bomb write.
const MAX_BOMB_WRITE_DURATION: Duration = Duration::from_secs(30);

/// How many source addresses [`DecoyState::touchers`] may hold before idle
/// ones are swept. Same shape and same reason as
/// [`crate::ratelimit::SourceRateLimit`]'s and `observe::TouchLedger`'s
/// bounds: a public box is scanned by the whole internet, and without a cap
/// this map grows by one entry per distinct source IP forever.
const MAX_TRACKED_TOUCHERS: usize = 8192;

/// A toucher untouched for this long is dropped by the sweep. Matches
/// `observe::TouchLedger`'s idle window (both track "how often have we seen
/// this source lately", not a rate limit).
const TOUCHER_IDLE_EVICT_SECS: u64 = 300;

/// Per-port burn-mode policy. Selected ONLY by `port` — a fact `accept_loop`
/// already knows before any bytes are read. Never selected by, or dependent
/// on, anything the attacker sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurnMode {
    /// Read the opaque intel snippet, then close immediately. The original
    /// tripwire behaviour — cheapest, fastest to ban.
    Drop,
    /// Hold the fd open, write nothing (or trickle one fixed byte on a
    /// timer), bounded wall-time, never read past the intel snippet.
    Tarpit,
    /// Blast a capped, rate-limited stream of RNG-at-startup bytes, bounded
    /// wall-time.
    JunkFlood,
    /// Emit the fixed send-first decompression bomb before reading anything.
    /// Gated by [`crate::bomb::bomb_enabled`] (default off); falls back to
    /// [`BurnMode::Tarpit`] when the bomb is disabled so the per-port table
    /// stays meaningful either way.
    Bomb,
}

/// Default per-port burn-mode allocation (starting policy, data-driven via
/// the intel stream — retune by editing this table, not by scattering
/// `if port == X` checks).
///
/// - 21 FTP, 23 Telnet, 2323 Telnet-alt, 3389 RDP, 5900 VNC → **Tarpit**:
///   scripted/pooled clients on these ports commonly retry or wait on a slow
///   response — cheap burn, high ROI.
/// - 3306 MySQL, 6379 Redis, 9200 Elasticsearch → **Drop** (instant-ban):
///   scanners on these ports are typically fire-and-forget single-packet or
///   expect an immediate greeting; a tarpit hold has little burn value and
///   isn't worth the fd.
const DEFAULT_PORT_BURN_MODE: &[(u16, BurnMode)] = &[
    (21, BurnMode::Tarpit),
    (23, BurnMode::Tarpit),
    (2323, BurnMode::Tarpit),
    (3306, BurnMode::Drop),
    (3389, BurnMode::Tarpit),
    (5900, BurnMode::Tarpit),
    (6379, BurnMode::Drop),
    (9200, BurnMode::Drop),
];

/// Resolve the configured [`BurnMode`] for `port`. Falls back to
/// [`BurnMode::Drop`] for any port not in [`DEFAULT_PORT_BURN_MODE`] (e.g. a
/// runtime-supplied port list that extends beyond the default 8) — the safe,
/// cheapest default.
#[must_use]
pub fn burn_mode_for_port(port: u16) -> BurnMode {
    DEFAULT_PORT_BURN_MODE
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, mode)| *mode)
        .unwrap_or(BurnMode::Drop)
}

/// Classic botnet-scan ports.  None of these are used by Mirage or any
/// legitimate service on the box; any connection is an unambiguous foe.
///
/// This is the **default** list.  [`spawn`] takes a `&[u16]` parameter so
/// runtime config can supply a different set without recompiling.
///
/// - 21    FTP — scanned by credential-stuffing bots
/// - 23    Telnet — Mirai primary target
/// - 2323  Telnet alt — Mirai secondary target
/// - 3306  MySQL
/// - 3389  RDP — Windows exploitation scanners
/// - 5900  VNC
/// - 6379  Redis — unauthenticated command injection scanners
/// - 9200  Elasticsearch — data-exfil scanners
pub const DEFAULT_DECOY_PORTS: &[u16] = &[21, 23, 2323, 3306, 3389, 5900, 6379, 9200];

/// One recorded decoy touch (a foe that connected to a trap port).
#[derive(Clone, Serialize)]
pub struct DecoyTouch {
    /// Source IP address string.
    pub ip: String,
    /// Decoy port that received the connection.
    pub port: u16,
    /// Unix timestamp of the touch, milliseconds since epoch.
    pub ts_ms: u64,
    /// Opaque snippet of whatever the attacker sent (UTF-8 lossy, or "(empty)"
    /// if nothing was received before the timeout).  Never parsed.
    pub snippet: String,
    /// Which burn mechanism ran for this touch (informational).
    pub burn_mode: String,
}

/// Shared decoy state — cheaply clonable (`Arc` inside).
#[derive(Clone)]
pub struct DecoyState {
    /// Ring buffer of recent touches, newest at the back.
    ring: Arc<Mutex<VecDeque<DecoyTouch>>>,
    /// Monotonic total-touch counter.
    touch_count: Arc<AtomicU64>,
    /// Per-source-IP touch counter — the perimeter's OWN accounting for its
    /// own future decisions (e.g. decoy-vs-jail escalation), entirely local
    /// and independent of any counter the arbiter keeps on its side. Also
    /// doubles as the CURRENTLY-TRACKED distinct-IP set (`len()` == distinct
    /// touchers still within the idle window) — bounded at
    /// [`MAX_TRACKED_TOUCHERS`], idle entries swept every
    /// [`TOUCHER_IDLE_EVICT_SECS`], same cap-and-sweep shape as
    /// `ratelimit::SourceRateLimit` and `observe::TouchLedger`. The `Instant`
    /// is the entry's last-touch time, used only by the sweep.
    touchers: Arc<DashMap<IpAddr, (u32, Instant)>>,
    /// Monotonic count of distinct source IPs first seen touching any decoy
    /// since daemon start — the honest "ever seen" fact `touchers.len()`
    /// used to report before it was bounded. An upper bound, not an exact
    /// live count: an IP evicted by the sweep and seen again later is
    /// counted a second time. See [`DecoyState::distinct_touchers_total`].
    touchers_seen_total: Arc<AtomicU64>,
    /// Concurrency/fd budget shared across ALL decoy ports and ALL burn
    /// mechanisms. `try_acquire_owned` before spawning a handler; exhausted
    /// budget → drop the connection immediately, never queue.
    decoy_active: Arc<Semaphore>,
    /// Fixed RNG-at-startup buffer tiled to fill junk-flood writes. Generated
    /// once at [`DecoyState::new`] time, immutable thereafter.
    junk_source: Arc<Vec<u8>>,
    /// Sink every touch is reported to as a typed [`PerimeterObservation`].
    /// Supplied at construction — this crate defines [`ObservationSink`] and
    /// does not implement it (see `lib.rs`'s module doc).
    sink: Arc<dyn ObservationSink>,
}

impl DecoyState {
    pub fn new(sink: Arc<dyn ObservationSink>) -> Self {
        Self::with_max_concurrent(resolve_max_concurrent(), sink)
    }

    /// Construct with an explicit concurrency budget (used by tests and by
    /// [`DecoyState::new`], which resolves the budget from
    /// [`MAX_CONCURRENT_ENV`] / [`DEFAULT_MAX_CONCURRENT_DECOYS`]).
    pub fn with_max_concurrent(max_concurrent: usize, sink: Arc<dyn ObservationSink>) -> Self {
        let mut junk = vec![0u8; JUNK_SOURCE_BYTES];
        rand::thread_rng().fill_bytes(&mut junk);
        Self {
            ring: Arc::new(Mutex::new(VecDeque::with_capacity(TOUCH_RING_CAP))),
            touch_count: Arc::new(AtomicU64::new(0)),
            touchers: Arc::new(DashMap::new()),
            touchers_seen_total: Arc::new(AtomicU64::new(0)),
            decoy_active: Arc::new(Semaphore::new(max_concurrent)),
            junk_source: Arc::new(junk),
            sink,
        }
    }

    /// Record a touch. Evicts the oldest entry when the ring is full.
    ///
    /// Returns the perimeter's own local touch count for this IP after
    /// recording (see `touchers`' field doc) — the caller uses this to build
    /// the [`PerimeterObservation`] it reports through the sink.
    pub fn record(&self, touch: DecoyTouch) -> u32 {
        self.record_at(touch, Instant::now())
    }

    /// Testable core of [`DecoyState::record`] with the clock supplied —
    /// same split as `ratelimit::SourceRateLimit::allow`/`allow_at`, so the
    /// idle sweep can be exercised without a real sleep.
    fn record_at(&self, touch: DecoyTouch, now: Instant) -> u32 {
        self.touch_count.fetch_add(1, Ordering::Relaxed);
        let ip = touch
            .ip
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        // Same cap-and-sweep shape as `ratelimit::SourceRateLimit` and
        // `observe::TouchLedger`: once over the cap, drop everything idle
        // past the window, THEN record — never refuse to record the current
        // touch, even if the sweep couldn't free enough room.
        if self.touchers.len() > MAX_TRACKED_TOUCHERS {
            self.touchers.retain(|_, (_, last)| {
                now.duration_since(*last).as_secs() < TOUCHER_IDLE_EVICT_SECS
            });
        }
        let perimeter_touch_count = match self.touchers.entry(ip) {
            Entry::Occupied(mut e) => {
                let slot = e.get_mut();
                slot.0 += 1;
                slot.1 = now;
                slot.0
            }
            Entry::Vacant(e) => {
                e.insert((1, now));
                self.touchers_seen_total.fetch_add(1, Ordering::Relaxed);
                1
            }
        };
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= TOUCH_RING_CAP {
            ring.pop_front();
        }
        ring.push_back(touch);
        perimeter_touch_count
    }

    /// Snapshot of recent touches, newest first, capped at `TOUCH_RING_CAP`.
    pub fn recent_touches(&self) -> Vec<DecoyTouch> {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter().rev().cloned().collect()
    }

    /// Monotonic count of all touches since daemon start.
    pub fn touch_count(&self) -> u64 {
        self.touch_count.load(Ordering::Relaxed)
    }

    /// Number of distinct source IPs currently tracked in the local touch
    /// ledger. Bounded at [`MAX_TRACKED_TOUCHERS`] and idle-swept — since the
    /// bound landed this means "currently tracked", not "ever seen"; use
    /// [`DecoyState::distinct_touchers_total`] for the monotonic count.
    pub fn distinct_touchers(&self) -> u64 {
        self.touchers.len() as u64
    }

    /// Monotonic count of distinct source IPs first seen touching any decoy
    /// since daemon start. An upper bound on true distinct-IP cardinality,
    /// not an exact one: an IP evicted by the idle sweep and seen again
    /// later increments this a second time.
    pub fn distinct_touchers_total(&self) -> u64 {
        self.touchers_seen_total.load(Ordering::Relaxed)
    }

    /// Current number of available concurrency permits (metrics/tests only).
    pub fn available_permits(&self) -> usize {
        self.decoy_active.available_permits()
    }

    /// Try to acquire one concurrency/fd permit, non-blocking.
    ///
    /// Returns `None` immediately when the budget is exhausted — callers
    /// MUST treat that as "drop the connection now", never as a reason to
    /// wait; blocking here would let an attacker starve the whole decoy
    /// subsystem by flooding one port.
    fn try_acquire_permit(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.decoy_active).try_acquire_owned().ok()
    }
}

fn resolve_max_concurrent() -> usize {
    std::env::var(MAX_CONCURRENT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_CONCURRENT_DECOYS)
}

/// Spawn an async accept loop for each port in `ports`.
///
/// Bind failures (EADDRINUSE, EACCES) are logged as warnings and silently
/// skipped — a port conflict must NEVER kill the process running this. Every
/// touch is reported through `state`'s [`ObservationSink`] as a
/// [`PerimeterObservation`]; this crate makes no ban/escalation decision
/// itself (that is the arbiter's job — see `lib.rs`'s module doc).
pub fn spawn(state: DecoyState, ports: &[u16]) {
    for &port in ports {
        let state_clone = state.clone();
        tokio::spawn(accept_loop(state_clone, port));
    }
}

async fn accept_loop(state: DecoyState, port: u16) {
    let addr = SocketAddr::from(([0u8, 0, 0, 0], port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(port, error = %e, "[perimeter/decoy] bind failed — skipping port");
            return;
        }
    };
    info!(port, burn_mode = ?burn_mode_for_port(port), "[perimeter/decoy] listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(port, error = %e, "[perimeter/decoy] accept error — continuing");
                continue;
            }
        };

        // Concurrency/fd budget: acquire a permit BEFORE spawning. Exhausted
        // budget → drop immediately, never queue (never let a flooded decoy
        // port stall this accept loop's ability to keep servicing others).
        let Some(permit) = state.try_acquire_permit() else {
            drop(stream);
            continue;
        };

        let ip = peer.ip();
        let state_ref = state.clone();

        tokio::spawn(async move {
            handle_touch(stream, ip, port, state_ref).await;
            drop(permit);
        });
    }
}

async fn handle_touch(stream: tokio::net::TcpStream, ip: IpAddr, port: u16, state: DecoyState) {
    // Read up to SNIPPET_MAX_BYTES with a short timeout — opaque, never
    // parsed. This snippet is captured for every mode identically; its
    // CONTENT never selects the burn mechanism (that decision was already
    // made by `burn_mode_for_port(port)` before this line).
    let mut buf = [0u8; SNIPPET_MAX_BYTES];
    let n = match tokio::time::timeout(READ_TIMEOUT, read_some(&stream, &mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(_)) | Err(_) => 0, // read error or timeout — snippet will be "(empty)"
    };

    let snippet = if n == 0 {
        "(empty)".to_string()
    } else {
        // Store as UTF-8 lossy — opaque, no parsing.
        String::from_utf8_lossy(&buf[..n])
            .chars()
            .map(|c| if c.is_control() { '.' } else { c })
            .collect()
    };

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // ── Burn: branch on PORT only (a fact known before accept) ────────────
    let mode = burn_mode_for_port(port);
    let signal_type = match mode {
        BurnMode::Drop => AttackerSignalType::Decoy,
        BurnMode::Tarpit => AttackerSignalType::Tarpit,
        BurnMode::JunkFlood => AttackerSignalType::Flood,
        BurnMode::Bomb => AttackerSignalType::Bomb,
    };

    info!(%ip, port, snippet_len = n, burn_mode = ?mode, "[perimeter/decoy] touch");

    match mode {
        BurnMode::Drop => {
            drop(stream);
        }
        BurnMode::Tarpit => {
            run_tarpit(stream).await;
        }
        BurnMode::JunkFlood => {
            run_junk_flood(stream, &state).await;
        }
        BurnMode::Bomb => {
            if crate::bomb::bomb_enabled() {
                run_bomb(stream).await;
            } else {
                // Bomb disabled by config — fall back to tarpit so the
                // per-port table stays meaningful either way.
                run_tarpit(stream).await;
            }
        }
    }

    let touch = DecoyTouch {
        ip: ip.to_string(),
        port,
        ts_ms,
        snippet,
        burn_mode: format!("{mode:?}"),
    };

    // Local ledger only — this is the perimeter's OWN accounting for its own
    // future decisions (e.g. decoy-vs-jail escalation), not the arbiter's
    // ban engine. `record` returns the resulting per-IP touch count.
    let perimeter_touch_count = state.record(touch);

    // Report a typed observation — no ban, no escalation policy decided
    // here. Confidence is a deterministic classification of
    // (signal_type, perimeter_touch_count), computed via the shared helper
    // so both planes agree on the same bucket for the same kind of touch.
    let confidence = confidence_bucket(signal_type, perimeter_touch_count);
    state.sink.report(PerimeterObservation {
        ip: ip.to_string(),
        port,
        ts_ms,
        signal_type,
        perimeter_touch_count,
        confidence,
    });
}

/// **Tarpit**: hold the fd, write nothing (or a fixed trickle byte on a
/// timer), bounded wall-time, never read. Burns the attacker's socket-pool
/// slot + wall-clock — almost zero cost to secd (idle fd).
///
/// Zero-parse: the only bytes written are the compile-time-constant
/// [`TARPIT_TRICKLE_BYTE`], on a fixed timer, never derived from anything
/// the peer sent (and this function never reads from `stream` at all).
async fn run_tarpit(mut stream: tokio::net::TcpStream) {
    let hold = async {
        loop {
            tokio::time::sleep(TARPIT_TRICKLE_INTERVAL).await;
            if stream.write_all(&TARPIT_TRICKLE_BYTE).await.is_err() {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(MAX_TARPIT_DURATION, hold).await;
    drop(stream);
}

/// **Junk-flood**: blast a capped, rate-limited stream of RNG-at-startup
/// bytes at the attacker, then close.
///
/// Zero-parse: bytes come from `state.junk_source`, generated once at daemon
/// boot — never derived from, or read from, the peer. Bounded by both a
/// total-bytes cap ([`MAX_FLOOD_BYTES`]) and a wall-clock cap
/// ([`MAX_FLOOD_DURATION`]) — the latter guards against a peer advertising a
/// zero receive window to stall the writer task indefinitely.
async fn run_junk_flood(mut stream: tokio::net::TcpStream, state: &DecoyState) {
    let flood = async {
        let mut sent = 0usize;
        let source: &[u8] = &state.junk_source;
        let mut offset = 0usize;
        while sent < MAX_FLOOD_BYTES {
            let remaining = MAX_FLOOD_BYTES - sent;
            let chunk_len = FLOOD_CHUNK_BYTES.min(remaining);
            let mut chunk = Vec::with_capacity(chunk_len);
            while chunk.len() < chunk_len {
                let take = (chunk_len - chunk.len()).min(source.len() - offset);
                chunk.extend_from_slice(&source[offset..offset + take]);
                offset = (offset + take) % source.len();
            }
            if stream.write_all(&chunk).await.is_err() {
                break;
            }
            sent += chunk.len();
            tokio::time::sleep(FLOOD_CHUNK_DELAY).await;
        }
    };
    let _ = tokio::time::timeout(MAX_FLOOD_DURATION, flood).await;
    drop(stream);
}

/// **Send-first decompression bomb**: emit the FIXED compile-time bomb
/// response ([`crate::bomb::bomb_response`]) unconditionally, before reading
/// anything the peer sent, then close.
///
/// Zero-parse: the response bytes are computed entirely at compile time
/// (see `build.rs`) — this function never reads from `stream`.
async fn run_bomb(mut stream: tokio::net::TcpStream) {
    let write = stream.write_all(crate::bomb::bomb_response());
    let _ = tokio::time::timeout(MAX_BOMB_WRITE_DURATION, write).await;
    drop(stream);
}

/// Read some bytes from `stream` without parsing.
///
/// Uses `readable()` + `try_read` to stay non-blocking — the caller applies
/// a timeout via `tokio::time::timeout`.
async fn read_some(stream: &tokio::net::TcpStream, buf: &mut [u8]) -> std::io::Result<usize> {
    stream.readable().await?;
    match stream.try_read(buf) {
        Ok(n) => Ok(n),
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory [`ObservationSink`] for tests — exactly the kind of
    /// implementation this crate expects a caller to supply, since it
    /// deliberately does not implement the trait itself (see `sink.rs`'s
    /// module doc).
    #[derive(Default)]
    struct RecordingSink {
        observations: Mutex<Vec<PerimeterObservation>>,
    }

    impl ObservationSink for RecordingSink {
        fn report(&self, observation: PerimeterObservation) {
            self.observations
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(observation);
        }
    }

    fn test_sink() -> Arc<RecordingSink> {
        Arc::new(RecordingSink::default())
    }

    #[test]
    fn default_port_burn_mode_matches_documented_policy() {
        assert_eq!(burn_mode_for_port(21), BurnMode::Tarpit);
        assert_eq!(burn_mode_for_port(23), BurnMode::Tarpit);
        assert_eq!(burn_mode_for_port(2323), BurnMode::Tarpit);
        assert_eq!(burn_mode_for_port(3306), BurnMode::Drop);
        assert_eq!(burn_mode_for_port(3389), BurnMode::Tarpit);
        assert_eq!(burn_mode_for_port(5900), BurnMode::Tarpit);
        assert_eq!(burn_mode_for_port(6379), BurnMode::Drop);
        assert_eq!(burn_mode_for_port(9200), BurnMode::Drop);
    }

    #[test]
    fn unknown_port_defaults_to_drop() {
        assert_eq!(burn_mode_for_port(65000), BurnMode::Drop);
    }

    #[test]
    fn decoy_state_semaphore_bounds_concurrency() {
        let state = DecoyState::with_max_concurrent(2, test_sink());
        assert_eq!(state.available_permits(), 2);

        let p1 = state.try_acquire_permit().expect("permit 1");
        let p2 = state.try_acquire_permit().expect("permit 2");
        assert_eq!(state.available_permits(), 0);
        assert!(
            state.try_acquire_permit().is_none(),
            "budget exhausted — third acquire must fail immediately, never block"
        );

        drop(p1);
        assert_eq!(state.available_permits(), 1);
        drop(p2);
        assert_eq!(state.available_permits(), 2);
    }

    #[test]
    fn resolve_max_concurrent_falls_back_to_default_when_unset() {
        // Only assert the fallback path when the env var truly is unset in
        // this test process — avoids interfering with any real override.
        if std::env::var(MAX_CONCURRENT_ENV).is_err() {
            assert_eq!(resolve_max_concurrent(), DEFAULT_MAX_CONCURRENT_DECOYS);
        }
    }

    #[test]
    fn record_bumps_perimeter_local_touch_count_per_ip() {
        let state = DecoyState::with_max_concurrent(4, test_sink());
        let touch = |ip: &str| DecoyTouch {
            ip: ip.to_string(),
            port: 23,
            ts_ms: 1,
            snippet: "(empty)".to_string(),
            burn_mode: "Tarpit".to_string(),
        };

        assert_eq!(state.record(touch("203.0.113.9")), 1);
        assert_eq!(state.record(touch("203.0.113.9")), 2);
        // A distinct IP gets its own independent counter.
        assert_eq!(state.record(touch("203.0.113.10")), 1);
        assert_eq!(state.distinct_touchers(), 2);
    }

    fn decoy_touch(ip: std::net::Ipv4Addr) -> DecoyTouch {
        DecoyTouch {
            ip: ip.to_string(),
            port: 23,
            ts_ms: 1,
            snippet: "(empty)".to_string(),
            burn_mode: "Tarpit".to_string(),
        }
    }

    /// One IP per call, walking through `10.0.<hi>.<lo>` so `n` can run well
    /// past a `u8`'s range without wrapping back over addresses already used.
    fn nth_ip(n: u32) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(10, 0, ((n >> 8) & 0xff) as u8, (n & 0xff) as u8)
    }

    /// Record `batch` fresh distinct IPs, all at `wave_time` — one "wave" of
    /// churn, e.g. one scan sweep. `wave` picks a disjoint IP range per call
    /// so successive waves never re-touch an earlier wave's addresses (that
    /// would exercise the repeat-toucher path instead of the fresh-IP path
    /// this helper is for).
    fn insert_wave(state: &DecoyState, wave: u32, batch: u32, wave_time: Instant) {
        for n in 0..batch {
            state.record_at(decoy_touch(nth_ip(wave * batch + n)), wave_time);
        }
    }

    #[test]
    fn touchers_stays_capped_under_3x_cap_distinct_ips() {
        let state = DecoyState::with_max_concurrent(4, test_sink());
        let base = Instant::now();
        let batch = MAX_TRACKED_TOUCHERS as u32 + 1;
        // Three successive waves of `batch` distinct IPs (3x the cap total),
        // each wave spaced past TOUCHER_IDLE_EVICT_SECS from the last — real
        // churn, not one instant — so each wave's sweep can actually retire
        // the previous wave once it goes idle.
        for wave in 0..3u32 {
            let wave_time =
                base + Duration::from_secs(u64::from(wave) * (TOUCHER_IDLE_EVICT_SECS + 1));
            insert_wave(&state, wave, batch, wave_time);
        }
        assert!(
            state.touchers.len() <= MAX_TRACKED_TOUCHERS + 1,
            "the live map must stay capped across 3x-cap distinct IPs of churn, got {}",
            state.touchers.len()
        );
    }

    #[test]
    fn an_idle_toucher_is_evicted_by_the_sweep() {
        let state = DecoyState::with_max_concurrent(4, test_sink());
        let t0 = Instant::now();
        let stale_ip = nth_ip(0);
        state.record_at(decoy_touch(stale_ip), t0);

        // Fill past the cap with fresh touches, all still within the idle
        // window, at a time far enough past `t0` that only the first entry
        // is idle-expired.
        let sweep_time = t0 + Duration::from_secs(TOUCHER_IDLE_EVICT_SECS + 1);
        for n in 1..=(MAX_TRACKED_TOUCHERS as u32 + 1) {
            state.record_at(decoy_touch(nth_ip(n)), sweep_time);
        }

        assert!(
            state.touchers.get(&IpAddr::V4(stale_ip)).is_none(),
            "an entry idle past TOUCHER_IDLE_EVICT_SECS must be swept once the map is over cap"
        );
    }

    #[test]
    fn distinct_touchers_total_keeps_rising_past_the_cap() {
        let state = DecoyState::with_max_concurrent(4, test_sink());
        let base = Instant::now();
        let batch = MAX_TRACKED_TOUCHERS as u32 + 1;
        for wave in 0..3u32 {
            let wave_time =
                base + Duration::from_secs(u64::from(wave) * (TOUCHER_IDLE_EVICT_SECS + 1));
            insert_wave(&state, wave, batch, wave_time);
        }
        let total = u64::from(batch) * 3;
        assert_eq!(
            state.distinct_touchers_total(),
            total,
            "the monotonic counter counts every fresh IP ever seen, uncapped"
        );
        assert!(
            state.distinct_touchers() <= MAX_TRACKED_TOUCHERS as u64 + 1,
            "meanwhile the live map ({}) stays bounded — total keeps climbing past it",
            state.touchers.len()
        );
    }

    #[ignore = "opens a socket — container only, never the operator box"]
    #[tokio::test]
    async fn handle_touch_reports_observation_and_never_bans() {
        let sink = test_sink();
        let state = DecoyState::with_max_concurrent(4, sink.clone());

        // BurnMode::Drop for port 6379 — fastest path, no tarpit/flood wait.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server_stream, peer) = listener.accept().await.expect("accept");
        drop(client);

        handle_touch(server_stream, peer.ip(), 6379, state).await;

        let observations = sink.observations.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(observations.len(), 1, "exactly one observation reported");
        let observation = &observations[0];
        assert_eq!(observation.ip, peer.ip().to_string());
        assert_eq!(observation.port, 6379);
        assert_eq!(observation.signal_type, AttackerSignalType::Decoy);
        assert_eq!(
            observation.perimeter_touch_count, 1,
            "first touch from this IP"
        );
        assert_eq!(
            observation.confidence,
            confidence_bucket(AttackerSignalType::Decoy, 1)
        );
    }
}
