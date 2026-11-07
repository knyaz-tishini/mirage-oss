//! The UDP face's dispatcher and lifecycle — [`crate::face`]'s peer for
//! datagrams, not an adapter around it. TCP and UDP are both base transports
//! in this stack; this module is where the datagram side gets the same
//! rigour `face.rs` gives the stream side: a bind that survives this
//! fleet's dual-stack kernel quirks, a stop mechanism that provably
//! releases the socket, and counters that count what actually happened.
//!
//! # A UDP face has nothing to accept
//!
//! `face.rs::run_face` is built on `TcpListener::accept()` yielding one
//! exclusively-owned handle per peer. A `UdpSocket` gives no such primitive
//! — every peer's traffic arrives on the SAME socket, so there is no accept
//! loop anywhere in this module, and a reader arriving here from `face.rs`
//! should not go looking for one. What runs instead is a DISPATCHER: one
//! task owns the recv half of a bound socket and demultiplexes every
//! datagram by source address into a bounded map of per-peer channels — the
//! exact shape already proven in production by
//! `mirage_protocol::camouflage::raw_udp::run_dispatcher`. This module
//! reimplements that shape rather than reusing it: `raw_udp.rs`'s
//! dispatcher is wired to a `UdpCamouflageLayer` whose `accept_server` hands
//! back a byte-stream adapter, and
//! `docs/mirage/plans/udp-front-door-u0-2026-09-05.md`'s whole premise is
//! that this front door does not go through that adapter at all — see that
//! plan's "Relationship to the two prior UDP-face documents". The
//! demux-table / idle-sweep LOGIC is copied in spirit, deliberately, because
//! it is the part of `raw_udp.rs` that already survived contact with a
//! production NAT defect (see that module's own doc for the "previous
//! per-peer-ephemeral-socket design" history).
//!
//! # Scope — the dispatcher and its lifecycle ("4a"), plus the eviction seam
//! 4a asked 4b to close
//!
//! Classification, the jail's datagram equivalent, and the relay to the
//! monitor are `crate::udp_relay`'s job now, not this file's — see that
//! module's own doc. What changed HERE, in 4a's own file, is the one thing
//! `udp_relay.rs` cannot do without a hand back into this dispatcher's own
//! peer map: [`UdpSession::evict`]. A session that `udp_relay.rs` has
//! decided is not wire needs the demux-table entry gone on ITS OWN short
//! timer (see `udp_relay::REFUSED_SESSION_DRAIN_MS`), not on this module's
//! passive ten-minute idle sweep — dropping [`UdpSession::inbound`] alone
//! does not do that: the dispatcher only notices a dead receiver on the
//! NEXT datagram from that source, and a source that sent exactly one
//! garbage datagram and nothing more would otherwise sit in the map,
//! unauthenticated, until [`PEER_IDLE_EVICT`] — the real gap 4a's own doc
//! named. [`UdpSession::evict`] is the fix: a handle back into THIS
//! dispatcher's own `peers` map, so a consumer can ask for its own entry to
//! be removed the instant it decides to, not merely mark its own receiver
//! dead and hope a future datagram notices.
//!
//! **Still not built here, and each is a deliberately named seam for a
//! later step, not an oversight:**
//!
//! - **`Surface` wiring** (plan §4). No `SharedUdpFace`, no `ArcSwap`, and
//!   `crate::config::UdpFace` is never named in this file. See
//!   [`run_udp_face`]'s own doc for exactly why and what step 5 still has to
//!   decide.
//! - **Binding the local relay's own box-wide socket, and spawning
//!   `udp_relay::UdpMonitorRelay::run_inbound`.** Plan step 6 — this
//!   dispatcher hands a session's [`UdpSession::socket`] onward, but does
//!   not itself know about `mirage_core::local_dgram_endpoint` at all.
//! - **Wiring [`UdpFaceCounters`] into `stats.rs`/`PerimeterQuery`.** See
//!   that type's own doc — that is plan step 7, out of this brief's scope.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::stats::{AddressFamily, NotWireCounters};

/// When the peer map grows past this, entries idle longer than
/// [`PEER_IDLE_EVICT`] are swept out of it first; if that alone does not
/// bring the map back under the trigger, least-recently-seen entries are
/// evicted next ([`evict_least_recent_until`]) until it does — never a hard
/// admission cap. See `mirage_protocol::camouflage::raw_udp::
/// PEER_SWEEP_TRIGGER`'s own doc for why a hard cap is backwards for exactly
/// this camouflage (`RawUdp` authenticates nothing, so a spoofed
/// source-address spray can mint an entry per packet), and for why the idle
/// sweep ALONE does not bound that spray: a fresh forged entry has a fresh
/// `last_seen`, so the sweep frees none of it, and the map's real bound
/// without the least-recent fallback is `arrival_rate * PEER_IDLE_EVICT`, not
/// this constant. With the fallback, `trigger` is an actual bound on this
/// map's size, matching the fix landed there.
///
/// Duplicated here rather than imported: that constant is `pub(crate)`
/// inside `mirage-protocol`, this crate does not depend on
/// `mirage_protocol::camouflage::raw_udp` for it, and widening another
/// crate's API surface to save one `use` is out of this brief's scope — the
/// plan's own open question 4 proposes promoting it as a separate follow-up,
/// not decided here. If that value ever changes there, this one does not
/// move with it automatically. [`evict_least_recent_until`] below is its own
/// copy for the identical reason, not a third copy of `mirage-protocol`'s:
/// this crate has no shared-helper dependency on that crate to extend.
const PEER_SWEEP_TRIGGER: usize = 8192;

/// Low-water mark the least-recent fallback evicts DOWN TO once it decides
/// to run at all — not back to [`PEER_SWEEP_TRIGGER`] itself.
///
/// This crate's own copy of `mirage_protocol::camouflage::raw_udp::
/// PEER_LOW_WATER_MARK`, duplicated for the identical reason
/// ([`PEER_SWEEP_TRIGGER`]'s doc): evicting exactly to the trigger puts the
/// map right back at the point that fires this fallback again on the very
/// next admission, so a sustained spray would pay the whole O(n) `retain`
/// plus O(n) selection cost on EVERY subsequent datagram instead of roughly
/// once per `PEER_SWEEP_TRIGGER / 8` (1024) admissions — the fix for
/// unbounded memory would have become unbounded CPU and allocator churn
/// instead, reachable by the exact same forged-source spray.
const PEER_LOW_WATER_MARK: usize = PEER_SWEEP_TRIGGER - PEER_SWEEP_TRIGGER / 8;

/// A peer that has sent nothing for this long is dropped by the sweep — the
/// same ten minutes as `mirage_protocol::camouflage::raw_udp::
/// PEER_IDLE_EVICT`, duplicated for the identical reason ([`PEER_SWEEP_TRIGGER`]'s
/// doc).
const PEER_IDLE_EVICT: Duration = Duration::from_secs(600);

/// Bound on one peer's own inbound channel — matches
/// `mirage_protocol::camouflage::raw_udp::PEER_RECV_BUFFER`.
///
/// `pub(crate)` rather than private: `crate::udp_relay`'s own
/// monitor->peer return channel (one per relayed session) is sized off the
/// SAME constant, so the two channels a wire session owns — inbound from
/// the public socket, inbound from the local relay — share one capacity
/// number rather than two that could silently drift apart.
pub(crate) const PEER_CHANNEL_CAPACITY: usize = 64;

// ─────────────────────────────────────────────────────────────────────────
// Counters — the datagram counterpart of `crate::stats::FaceCounters`
// ─────────────────────────────────────────────────────────────────────────

/// Bind bookkeeping for ONE address family of a UDP face — the datagram
/// counterpart of `crate::stats::FamilyBind`. A distinct type rather than a
/// reuse of that one: `crate::stats::FaceCounters` is wired into
/// `PerimeterQuery`/`PerimeterMetrics` today, and this brief's own scope
/// says plainly that UDP counters must NOT be wired into that surface yet
/// (plan step 7) — keeping the type separate now means that wiring, when it
/// happens, is a deliberate step-7 decision rather than something that rode
/// in for free because two structs already happened to look alike.
#[derive(Debug, Default)]
pub struct UdpFamilyBind {
    /// Set true the moment this family's UDP bind succeeds.
    pub bound: AtomicBool,
    /// Why this family is not bound, verbatim from the failing `bind`.
    pub unbound_reason: std::sync::Mutex<Option<String>>,
    /// When this family last stopped being bound (or first failed to bind),
    /// ms since epoch.
    pub unbound_since_ms: AtomicU64,
    /// How many times `bind` has been attempted for this family.
    pub bind_attempts: AtomicU64,
    /// Set once this family's own bind failure was classified permanent —
    /// see [`crate::face::BindFailureKind`].
    pub permanently_absent: AtomicBool,
}

impl UdpFamilyBind {
    fn mark_bound(&self) {
        self.bound.store(true, Ordering::Relaxed);
        if let Ok(mut r) = self.unbound_reason.lock() {
            *r = None;
        }
        self.unbound_since_ms.store(0, Ordering::Relaxed);
        self.permanently_absent.store(false, Ordering::Relaxed);
    }

    fn note_bind_failed(&self, reason: &str, now_ms: u64, permanent: bool) {
        self.bound.store(false, Ordering::Relaxed);
        self.bind_attempts.fetch_add(1, Ordering::Relaxed);
        let _ = self.unbound_since_ms.compare_exchange(
            0,
            now_ms,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        if let Ok(mut r) = self.unbound_reason.lock() {
            *r = Some(reason.to_string());
        }
        if permanent {
            self.permanently_absent.store(true, Ordering::Relaxed);
        }
    }
}

/// One UDP face's counters — the datagram counterpart of
/// `crate::stats::FaceCounters`, in this module's own shape. **Deliberately
/// not reachable from `crate::stats`/`PerimeterQuery` today** — see this
/// module's own doc, "Scope". Defined here so the dispatcher has somewhere
/// honest to count into now; making these readable from outside the process
/// is plan step 7, a separate decision.
#[derive(Debug, Default)]
pub struct UdpFaceCounters {
    /// This face's IPv4 dispatcher (`0.0.0.0:<port>` in production).
    pub v4: UdpFamilyBind,
    /// This face's IPv6 dispatcher (`[::]:<port>` in production) — can be
    /// PERMANENTLY absent on a host with no IPv6 stack; see
    /// [`crate::face::BindFailureKind`].
    pub v6: UdpFamilyBind,
    /// Set true the moment EITHER family binds — the aggregate `crate::
    /// stats::FaceCounters::bound` mirrors for TCP.
    pub bound: AtomicBool,
    /// Datagrams read off either bound socket, before any demux decision.
    pub datagrams_received: AtomicU64,
    pub bytes_received: AtomicU64,
    /// `recv_from` returned an error. Kept apart from a peer's own protocol
    /// failures (there are none of those counted here at all — see this
    /// module's "Scope" doc) because this is a fact about the SOCKET, not
    /// about any peer.
    pub recv_errors: AtomicU64,
    /// A datagram matched an already-known source and was handed to that
    /// peer's own channel successfully.
    pub forwarded: AtomicU64,
    /// A brand new source address was seen and a session was announced for
    /// it — see [`UdpSession`].
    pub sessions_started: AtomicU64,
    /// Sessions currently occupying the peer map. A gauge, not a total —
    /// mirrors `crate::stats::FaceCounters::jail_holding_now`'s shape.
    pub sessions_active: AtomicU64,
    /// A session was removed by the idle sweep ([`PEER_IDLE_EVICT`]) —
    /// never having said anything since it started/last spoke.
    pub sessions_evicted_idle: AtomicU64,
    /// A session was removed by the least-recent fallback
    /// ([`evict_least_recent_until`]) because the idle sweep alone did not
    /// bring the map back under [`PEER_SWEEP_TRIGGER`] — the signature of a
    /// spray minting fresh entries faster than any of them go idle. Kept
    /// apart from `sessions_evicted_idle` on purpose: this counter rising is
    /// the map under genuine pressure, where the idle counter rising alone
    /// is just ordinary churn.
    pub sessions_evicted_lru: AtomicU64,
    /// A session's own inbound channel was full (its reader has stopped
    /// keeping up) and was evicted so the next datagram from that source
    /// starts a fresh one instead of being silently dropped.
    pub sessions_evicted_stalled: AtomicU64,
    /// A session's own inbound channel was already closed (its reader
    /// finished normally) when a further datagram arrived for it — the next
    /// datagram from that source starts a fresh session, same as the
    /// stalled case, but this is the ORDINARY end of a session's life, not
    /// pressure.
    pub sessions_closed: AtomicU64,
    /// How many times the idle sweep actually ran (whether or not it
    /// evicted anything) — see `run_dispatcher`'s own doc for when it runs.
    pub sweep_runs: AtomicU64,
    /// A newly announced session could not be handed off because the
    /// consumer's receiving end was gone — the dispatcher stops when this
    /// happens (see `run_dispatcher`'s own doc), so this is expected to stay
    /// at most 1 per family per process life.
    pub session_announce_dropped: AtomicU64,

    // ── Below: filled by `crate::udp_relay`, not by this dispatcher. Kept
    // on the SAME counters struct rather than a second one, matching this
    // struct's own doc ("somewhere honest to count into now") — one place
    // to look for everything one UDP face has done, whichever module did
    // the counting.
    /// A session's first datagram classified as [`crate::classify::Verdict::
    /// Wire`] and was handed to the relay. The datagram counterpart of
    /// `crate::stats::FaceCounters::wire_routed`.
    pub wire_routed: AtomicU64,
    /// Per-[`crate::classify::NotWireReason`] breakdown of sessions refused
    /// by `crate::udp_relay` — the datagram counterpart of `crate::stats::
    /// FaceCounters::rejected_not_wire`. The same breakdown TYPE as the TCP
    /// side (`crate::stats::NotWireCounters`) rather than a duplicate: the
    /// reasons are the SAME enum (`classify_v9_hello` is shared verbatim —
    /// see `crate::udp_relay`'s own doc), so the shape that counts them
    /// should not fork either.
    pub refused_not_wire: NotWireCounters,
    /// A refused session was drained (its channel read-and-discarded) for
    /// `crate::udp_relay::REFUSED_SESSION_DRAIN_MS` before eviction — the
    /// datagram counterpart of `crate::jail`'s `Disposition::Jail` outcome.
    pub refused_drained: AtomicU64,
    /// A refused session was evicted at once, no drain — the datagram
    /// counterpart of `crate::jail`'s `Disposition::HardCut` outcome.
    pub refused_cut: AtomicU64,
    /// Either refusal outcome above, folded into one total specifically for
    /// [`UdpSession::evict`] bookkeeping — a refused session ALWAYS ends by
    /// asking this dispatcher to remove its own map entry, and this is the
    /// count of that request succeeding, closing the gap 4a's own module
    /// doc named: no refused session waits out [`PEER_IDLE_EVICT`] to leave
    /// the map.
    pub sessions_evicted_refused: AtomicU64,
    /// A datagram failed to relay to the monitor (the local socket returned
    /// an error) or failed to relay back out to the peer (the public socket
    /// returned an error) — folded into one counter because either is the
    /// same fact from this face's point of view: a byte that should have
    /// crossed the relay did not.
    pub relay_send_errors: AtomicU64,
    /// Reading the local relay's own inbound socket
    /// (`mirage_core::local_dgram_endpoint::LocalDgramSocket::recv_envelope`)
    /// returned an error — a fact about the LOCAL channel, never about any
    /// internet peer.
    pub relay_recv_errors: AtomicU64,
    /// An envelope arrived from the monitor addressed to a `(face_port,
    /// peer)` this relay has no live route for — the session already ended
    /// (evicted, cancelled) on the perimeter's side while the monitor was
    /// still replying to it. Expected to be rare, not zero: a session's very
    /// last outbound datagram can race its own teardown.
    pub relay_from_monitor_unmatched: AtomicU64,
    /// An envelope arrived from the monitor for a session whose own
    /// return channel was full — that session's relay loop has stopped
    /// keeping up (or is mid-teardown) and the datagram was dropped rather
    /// than blocking the one shared reader task every OTHER session on this
    /// face also depends on.
    pub relay_from_monitor_dropped: AtomicU64,
    /// Payload bytes sent from a session to the monitor over the local
    /// relay — the datagram counterpart of `crate::stats::FaceCounters::
    /// bytes_to_inner`.
    pub bytes_to_monitor: AtomicU64,
    /// Payload bytes sent from a session back out to its real peer on the
    /// public socket — the datagram counterpart of `crate::stats::
    /// FaceCounters::bytes_to_client`.
    pub bytes_to_client: AtomicU64,
}

impl UdpFaceCounters {
    fn family(&self, family: AddressFamily) -> &UdpFamilyBind {
        match family {
            AddressFamily::V4 => &self.v4,
            AddressFamily::V6 => &self.v6,
        }
    }

    fn is_bound(&self) -> bool {
        self.v4.bound.load(Ordering::Relaxed) || self.v6.bound.load(Ordering::Relaxed)
    }

    /// Record a successful bind for one family, and refresh the aggregate —
    /// the face is reachable the instant ANY family lands.
    pub fn mark_family_bound(&self, family: AddressFamily) {
        self.family(family).mark_bound();
        self.bound.store(true, Ordering::Relaxed);
    }

    /// Record a failed bind for one family — see [`crate::face::BindFailureKind`] for
    /// what `permanent` means.
    pub fn note_family_bind_failed(
        &self,
        family: AddressFamily,
        reason: &str,
        now_ms: u64,
        permanent: bool,
    ) {
        self.family(family).note_bind_failed(reason, now_ms, permanent);
        if !self.is_bound() {
            self.bound.store(false, Ordering::Relaxed);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Bind — the IPv6-only transposition, and the retry loop around both
// families
// ─────────────────────────────────────────────────────────────────────────

/// Bind `bind_addr` (an unspecified-`::`/loopback-`::1` IPv6 address in
/// every production caller) as a genuinely IPv6-only [`UdpSocket`] — the
/// transposition [`crate::face::bind_v6_only`]'s own doc anticipates. See
/// that function's doc for the full measurement this applies unchanged:
/// this fleet's kernels run `net.ipv6.bindv6only=0`, so a plain `[::]` bind
/// silently claims the IPv4 wildcard on the same port too, which would
/// mean two dispatcher tasks racing for one face's port instead of two
/// genuinely independent sockets. The only structural difference from the
/// TCP version: no `listen()` call — there is nothing to accept on a
/// `SOCK_DGRAM` socket.
fn bind_v6_only_udp(bind_addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    // The one line this function exists for — see the doc above.
    socket.set_only_v6(true)?;
    // Matches the v4 half (a plain `UdpSocket::bind` sets `SO_REUSEADDR` on
    // unix already) so a restart's lingering state does not make one family
    // recover faster than the other — same reasoning as
    // `crate::face::bind_v6_only`'s own `set_reuse_address` call.
    socket.set_reuse_address(true)?;
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Pause between UDP bind attempts for a family whose port is not free yet
/// — same value and reasoning as `crate::face::FACE_BIND_RETRY_INTERVAL`:
/// contention here is transient (another process mid-handover), and nothing
/// about that history is specific to TCP.
const UDP_BIND_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Attempts between WARN lines while a UDP bind keeps failing — see
/// `crate::face::FACE_BIND_LOG_EVERY`'s own doc for why this is throttled at
/// all.
const UDP_BIND_LOG_EVERY: u32 = 12;

/// `pub(crate)`: `crate::udp_relay::classify_datagram` needs the same clock
/// read `face.rs::now_ms` gives the TCP path — one function, not a second
/// copy that could read a differently-rounded value.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Everything one UDP face's two dispatchers (IPv4 and IPv6) share — the
/// datagram counterpart of `crate::face::FaceRuntime`. Splitting one face
/// into two bound sockets must never split anything else: both dispatchers
/// count into the SAME [`UdpFaceCounters`], race the SAME
/// [`CancellationToken`], and announce every new session onto the SAME
/// `sessions` channel — private, exactly like `FaceRuntime`, and built
/// internally by [`run_udp_face`] from plain parameters rather than exposed
/// as this module's public surface.
///
/// `pub(crate)`, not `pub`: this crate's own tests (`crate::udp_relay`'s
/// need a real [`run_dispatcher`] to prove eviction against, not a
/// hand-rolled stand-in) build one through [`test_runtime_for`], the only
/// other-module access this type grants. Fields stay private even to
/// `pub(crate)` callers — only this module ever constructs the struct
/// literal.
pub(crate) struct UdpFaceRuntime {
    port: u16,
    label: String,
    counters: Arc<UdpFaceCounters>,
    /// Fired exactly once by whatever retires this face (`Surface::
    /// apply_config`, plan step 5 — not built here). Raced `biased` against
    /// the socket read in [`run_dispatcher`], and checked in
    /// [`bind_udp_with_retry`] too, so a face retired mid-bind stops
    /// retrying instead of chasing a port nobody wants any more — the exact
    /// two places `crate::face::run_face`'s own machinery checks its
    /// `cancel`.
    cancel: CancellationToken,
    /// Where every newly demultiplexed session is announced. The receiving
    /// end belongs to whoever consumes sessions next — see [`UdpSession`]'s
    /// own doc for why this is deliberately the only hand-off this module
    /// makes.
    sessions: mpsc::Sender<UdpSession>,
    /// See [`PEER_SWEEP_TRIGGER`]'s doc. A field, not the bare constant,
    /// purely so this module's own tests can exercise the sweep without
    /// waiting on 8192 real peers or 600 real seconds — [`run_udp_face`]
    /// always constructs this with the real constant.
    peer_sweep_trigger: usize,
    /// See [`PEER_IDLE_EVICT`]'s doc — same reason this is a field.
    peer_idle_evict: Duration,
    /// See [`PEER_LOW_WATER_MARK`]'s doc — same reason this is a field.
    peer_low_water: usize,
    /// Bound on one peer's own inbound channel — see [`PEER_CHANNEL_CAPACITY`].
    peer_channel_capacity: usize,
}

#[cfg(test)]
impl UdpFaceRuntime {
    /// The counters this runtime's dispatcher(s) count into — the one field
    /// a `pub(crate)` caller built through [`test_runtime_for`] needs read
    /// access to, so its own assertions and a session task spawned against
    /// the SAME runtime observe the SAME atomics. Test-only: production code
    /// never needs a runtime's counters back out of it — `run_udp_face`
    /// hands its own `Arc<UdpFaceCounters>` to callers directly, before a
    /// runtime is even built.
    pub(crate) fn counters(&self) -> &Arc<UdpFaceCounters> {
        &self.counters
    }
}

/// Bind one address family of a UDP face, retrying the transient case and
/// giving up on the permanent one — the datagram counterpart of
/// `crate::face::bind_with_retry`. Nothing about the history that function's
/// own doc records (the mshd/`:22` handover, and a missing IPv6 stack being
/// a durable rather than transient condition) is specific to TCP, so the
/// same shape applies here verbatim.
async fn bind_udp_with_retry(
    bind_addr: SocketAddr,
    family: AddressFamily,
    runtime: &UdpFaceRuntime,
) -> Option<UdpSocket> {
    let mut attempt: u32 = 0;
    loop {
        if runtime.cancel.is_cancelled() {
            tracing::info!(
                port = runtime.port,
                label = %runtime.label,
                %family,
                attempt,
                "[perimeter/udp_face] retired before this family ever finished binding — giving up \
                 the retry, nothing to release"
            );
            return None;
        }

        let bind_result = match family {
            AddressFamily::V4 => UdpSocket::bind(bind_addr).await,
            AddressFamily::V6 => bind_v6_only_udp(bind_addr),
        };
        match bind_result {
            Ok(socket) => {
                if attempt > 0 {
                    tracing::info!(
                        port = runtime.port,
                        label = %runtime.label,
                        %family,
                        attempts = attempt + 1,
                        "[perimeter/udp_face] bind succeeded after retrying"
                    );
                }
                runtime.counters.mark_family_bound(family);
                return Some(socket);
            }
            Err(e) => {
                let kind = crate::face::classify_bind_error(&e);
                runtime.counters.note_family_bind_failed(
                    family,
                    &e.to_string(),
                    now_ms(),
                    kind == crate::face::BindFailureKind::Permanent,
                );
                match kind {
                    crate::face::BindFailureKind::Permanent => {
                        tracing::warn!(
                            port = runtime.port,
                            label = %runtime.label,
                            %family,
                            error = %e,
                            "[perimeter/udp_face] this address family is not available on this host \
                             — giving up on it for this face; the other family keeps serving"
                        );
                        return None;
                    }
                    crate::face::BindFailureKind::Transient => {
                        if attempt % UDP_BIND_LOG_EVERY == 0 {
                            tracing::warn!(
                                port = runtime.port,
                                label = %runtime.label,
                                %family,
                                error = %e,
                                attempt = attempt + 1,
                                "[perimeter/udp_face] bind failed — this family is DARK and will \
                                 keep retrying; the other family keeps serving"
                            );
                        }
                        attempt = attempt.saturating_add(1);
                        tokio::select! {
                            () = runtime.cancel.cancelled() => {}
                            () = tokio::time::sleep(UDP_BIND_RETRY_INTERVAL) => {}
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// The dispatcher
// ─────────────────────────────────────────────────────────────────────────

/// One source address's slot in the dispatcher's own peer map. `tx` is the
/// send half of that peer's inbound channel; `last_seen` is what the idle
/// sweep reads.
struct PeerEntry {
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    last_seen: Instant,
}

/// Evict entries from this dispatcher's own peer map, least-recently-seen
/// first, until at most `trigger` remain. Returns how many were removed.
///
/// This crate's own copy of `mirage_protocol::camouflage::raw_udp`'s helper
/// of the same name and shape — see [`PEER_SWEEP_TRIGGER`]'s doc for why it
/// is a copy here rather than a shared dependency on that crate. Call this
/// AFTER the idle sweep, and only when the sweep did not already bring the
/// map back under `trigger`: a spoofed source-address spray mints a FRESH
/// entry per packet, and a fresh entry has a fresh `last_seen`, so the idle
/// sweep frees none of it — this fallback is what makes `trigger` an actual
/// bound on the map instead of a value the sweep alone can miss entirely.
///
/// Idle-first, least-recent-second is the order [`run_dispatcher`]'s own
/// sweep already keeps, and it is deliberate, not arbitrary: an idle entry
/// is provably dead (nothing has read its channel in [`PEER_IDLE_EVICT`]),
/// so dropping it costs no live session and is spent as a free win first.
/// Only entries that survive that free pass are candidates here, and this
/// pass CAN be wrong in a way the idle sweep cannot — it may cut a peer that
/// is merely quiet, not gone — which is exactly why it runs second, after
/// the sweep has already done everything it can without that risk. Because
/// eviction here always removes the smallest `last_seen` first, a session
/// that keeps sending keeps refreshing its own `last_seen` and is always the
/// last entry this function would ever evict, no matter how large the spray
/// creating the pressure is — a spray now pays for its own map growth (its
/// own oldest entries), never the box's memory.
fn evict_least_recent_until(peers: &mut HashMap<SocketAddr, PeerEntry>, trigger: usize) -> usize {
    if peers.len() <= trigger {
        return 0;
    }
    let mut by_age: Vec<(SocketAddr, Instant)> =
        peers.iter().map(|(addr, entry)| (*addr, entry.last_seen)).collect();

    let to_remove = peers.len() - trigger;
    // The `to_remove` oldest entries only need to be identified as a SET to
    // remove, not presented in order, so partitioning around the
    // `(to_remove - 1)`th element by age (`select_nth_unstable_by_key`, O(n)
    // worst case via introselect) does the job a full `sort_by_key` (O(n log
    // n)) would, for less work — matches `mirage_protocol::camouflage::mod`'s
    // own copy of this function. Skipped when `to_remove` covers the whole
    // vec (`trigger == 0`).
    if to_remove < by_age.len() {
        by_age.select_nth_unstable_by_key(to_remove - 1, |(_, last_seen)| *last_seen);
    }

    let mut evicted = 0usize;
    for (addr, _) in by_age.into_iter().take(to_remove) {
        if peers.remove(&addr).is_some() {
            evicted += 1;
        }
    }
    evicted
}

/// Idle sweep, then — ONLY if the idle sweep did not already bring the map
/// back under `trigger` — batch-evict by least-recent `last_seen` down to
/// `low_water`. Returns `(idle_swept, lru_evicted)`.
///
/// This crate's own copy of `mirage_protocol::camouflage::mod::
/// sweep_and_batch_evict`, duplicated for the identical reason
/// [`PEER_SWEEP_TRIGGER`]'s doc gives for [`evict_least_recent_until`] being
/// a copy rather than a shared dependency. See that function's own doc for
/// why the second stage targets `low_water` rather than `trigger` itself,
/// and for why stage separation lives in the inner `if peers.len() > trigger`
/// gate rather than in whether this runs at all.
fn sweep_and_batch_evict(
    peers: &mut HashMap<SocketAddr, PeerEntry>,
    trigger: usize,
    idle_evict: Duration,
    low_water: usize,
) -> (usize, usize) {
    let now = Instant::now();
    let before = peers.len();
    peers.retain(|_, e| now.duration_since(e.last_seen) < idle_evict);
    let idle_swept = before - peers.len();

    let lru_evicted = if peers.len() > trigger {
        evict_least_recent_until(peers, low_water)
    } else {
        0
    };
    (idle_swept, lru_evicted)
}

/// One demultiplexed peer session, announced the moment the dispatcher sees
/// a source address it has never seen before.
///
/// This is the seam plan step 4b (classification) and step 5 (`Surface`
/// wiring) attach to. Nothing in this module reads [`Self::inbound`] or
/// [`Self::socket`] past constructing and announcing them here.
///
/// [`Self::inbound`] is deliberately `mpsc::Receiver<(SocketAddr, Vec<u8>)>`
/// — the EXACT shape `mirage_protocol::transport::udp::UdpPeerSocket::
/// from_relay` consumes on its own `inbound` parameter. That is not a
/// coincidence: a later step's classify-then-relay task can hand this
/// receiver to whatever needs it with no adapter in between. The address
/// riding alongside each payload is redundant here (a session's own channel
/// only ever carries datagrams already known to be from [`Self::peer`]) —
/// it is carried anyway, on purpose, to match `from_relay`'s own shape
/// exactly rather than almost.
///
/// [`Self::socket`] is the SAME bound socket every other session on this
/// family shares. The reply path
/// (`docs/mirage/plans/udp-front-door-u0-2026-09-05.md` §5.3 step 3: "read
/// the next envelope … send_to(peer) on the public socket") needs a handle
/// to it, and this is deliberately not a second bind — see
/// `mirage_protocol::transport::udp`'s own module doc for why a per-peer
/// bind is both a known NAT defect and a perimeter violation.
///
/// [`Self::evict`] is the seam 4b needed that 4a's own doc did not yet have:
/// dropping [`Self::inbound`] alone only marks this peer's entry dead — the
/// dispatcher notices that on the NEXT datagram from this source, which may
/// never come. Sending [`Self::peer`] on this channel asks THIS dispatcher
/// to remove its own map entry right now, whether or not this source ever
/// speaks again. `unbounded`: this is sent at most once per session, by the
/// session itself, and must never be the thing that blocks a
/// classify-then-evict decision.
pub struct UdpSession {
    pub peer: SocketAddr,
    pub family: AddressFamily,
    pub socket: Arc<UdpSocket>,
    pub first_datagram: Vec<u8>,
    pub inbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    pub evict: mpsc::UnboundedSender<SocketAddr>,
}

/// Read datagrams off `socket` forever, demultiplexing by source address —
/// the whole dispatcher. See this module's own doc, "A UDP face has nothing
/// to accept", for why this is not an accept loop and has no TCP analogue
/// to be one.
///
/// The sweep (see [`PEER_SWEEP_TRIGGER`]) is checked on the NEW-peer path
/// only, exactly where `mirage_protocol::camouflage::raw_udp::run_dispatcher`
/// checks it — a face that never sees an unfamiliar source never needs to
/// sweep, so paying for the check on every forwarded datagram would be pure
/// overhead for the common case.
///
/// Ends when `runtime.cancel` fires (racing the socket read `biased`, so a
/// retirement is honoured even on a turn where a datagram is also ready) or
/// when the session-announce channel's receiving end is gone. Either way
/// `socket` is this function's own local variable — the instant it returns,
/// the socket drops and the OS releases the port, exactly like
/// `crate::face::accept_loop`'s own listener.
///
/// A third branch, [`UdpSession::evict`]'s receiving half, is raced
/// alongside the other two — `biased`, second after cancellation and before
/// the socket read, so a pending eviction is always honoured before this
/// turn accepts a fresh datagram (an eviction is cheap and must never be
/// starved by a busy source). See this module's own doc for why this exists
/// at all: it is the one piece of state 4b cannot remove from outside this
/// function, since [`PeerEntry`] and `peers` are both private to this call.
pub(crate) async fn run_dispatcher(socket: UdpSocket, family: AddressFamily, runtime: Arc<UdpFaceRuntime>) {
    let socket = Arc::new(socket);
    let mut peers: HashMap<SocketAddr, PeerEntry> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let port = runtime.port;
    // Held here, never moved out — a session's own `evict` field is a clone
    // of this. Keeping the original alive for the dispatcher's whole life
    // means `evict_rx.recv()` can never permanently return `None` while
    // this loop still runs, which `tokio::select!`'s `Some(..) = ..` arm
    // below relies on (see its own doc in the tokio crate: a pattern that
    // stops matching disables its branch for the rest of the call).
    let (evict_tx, mut evict_rx) = mpsc::unbounded_channel::<SocketAddr>();

    loop {
        let (n, from) = tokio::select! {
            biased;
            () = runtime.cancel.cancelled() => {
                tracing::info!(
                    port,
                    %family,
                    "[perimeter/udp_face] retiring — no longer dispatching, releasing the socket"
                );
                return;
            }
            Some(addr) = evict_rx.recv() => {
                if peers.remove(&addr).is_some() {
                    runtime.counters.sessions_active.fetch_sub(1, Ordering::Relaxed);
                    tracing::debug!(
                        port, %family, src = %addr,
                        "[perimeter/udp_face] session evicted itself (refused, per crate::udp_relay) \
                         — well before the idle sweep would have"
                    );
                }
                // Already gone (idle sweep or a stall/close race won first)
                // is not an error — whichever path got there first already
                // counted it.
                continue;
            }
            recvd = socket.recv_from(&mut buf) => match recvd {
                Ok(pair) => pair,
                Err(e) => {
                    runtime.counters.recv_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(port, %family, error = %e, "[perimeter/udp_face] recv failed — continuing");
                    continue;
                }
            },
        };

        runtime.counters.datagrams_received.fetch_add(1, Ordering::Relaxed);
        runtime.counters.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

        if let Some(entry) = peers.get_mut(&from) {
            // Stamped before the send and the sender cloned out, so the
            // borrow of `peers` ends here and the arms below may remove
            // from it.
            entry.last_seen = Instant::now();
            let tx = entry.tx.clone();
            match tx.try_send((from, buf[..n].to_vec())) {
                Ok(()) => {
                    runtime.counters.forwarded.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tracing::debug!(
                        port, %family, src = %from,
                        "[perimeter/udp_face] peer channel full (reader stalled) — evicting, the \
                         next datagram from this source starts a fresh session"
                    );
                    peers.remove(&from);
                    runtime.counters.sessions_active.fetch_sub(1, Ordering::Relaxed);
                    runtime.counters.sessions_evicted_stalled.fetch_add(1, Ordering::Relaxed);
                    // Fall through: this datagram creates the fresh session.
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    tracing::debug!(
                        port, %family, src = %from,
                        "[perimeter/udp_face] peer channel closed (session ended) — the next \
                         datagram from this source starts a fresh session"
                    );
                    peers.remove(&from);
                    runtime.counters.sessions_active.fetch_sub(1, Ordering::Relaxed);
                    runtime.counters.sessions_closed.fetch_add(1, Ordering::Relaxed);
                    // Fall through: this datagram creates the fresh session.
                }
            }
        }

        // Sweep under pressure, never refuse under pressure — see
        // `PEER_SWEEP_TRIGGER`'s doc for why a hard cap is the wrong shape
        // for this camouflage, and why the idle sweep alone cannot bound a
        // spray.
        if peers.len() > runtime.peer_sweep_trigger {
            // Idle sweep, then — only if that alone did not clear the
            // trigger — a batch evict down to `peer_low_water`, never back
            // to `peer_sweep_trigger` itself: see [`PEER_LOW_WATER_MARK`]'s
            // own doc for why landing exactly on the trigger is the defect,
            // not the fix.
            let (idle_swept, lru_evicted) = sweep_and_batch_evict(
                &mut peers,
                runtime.peer_sweep_trigger,
                runtime.peer_idle_evict,
                runtime.peer_low_water,
            );
            runtime.counters.sweep_runs.fetch_add(1, Ordering::Relaxed);
            if idle_swept > 0 {
                runtime.counters.sessions_evicted_idle.fetch_add(idle_swept as u64, Ordering::Relaxed);
                runtime.counters.sessions_active.fetch_sub(idle_swept as u64, Ordering::Relaxed);
                tracing::debug!(
                    port, %family, evicted = idle_swept, remaining = peers.len(),
                    "[perimeter/udp_face] idle peer sweep"
                );
            }
            if lru_evicted > 0 {
                runtime.counters.sessions_evicted_lru.fetch_add(lru_evicted as u64, Ordering::Relaxed);
                runtime.counters.sessions_active.fetch_sub(lru_evicted as u64, Ordering::Relaxed);
                tracing::debug!(
                    port, %family, evicted = lru_evicted, remaining = peers.len(),
                    "[perimeter/udp_face] least-recent peer eviction (idle sweep alone did not clear the trigger)"
                );
            }
        }

        let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(runtime.peer_channel_capacity);
        peers.insert(from, PeerEntry { tx, last_seen: Instant::now() });
        runtime.counters.sessions_started.fetch_add(1, Ordering::Relaxed);
        runtime.counters.sessions_active.fetch_add(1, Ordering::Relaxed);

        let session = UdpSession {
            peer: from,
            family,
            socket: Arc::clone(&socket),
            first_datagram: buf[..n].to_vec(),
            inbound: rx,
            evict: evict_tx.clone(),
        };
        if runtime.sessions.send(session).await.is_err() {
            runtime.counters.session_announce_dropped.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                port, %family,
                "[perimeter/udp_face] session announce channel closed — nobody is consuming new \
                 sessions, stopping this family's dispatcher"
            );
            return;
        }
    }
}

/// Bind one address family of `runtime.port` and, if that succeeds,
/// dispatch on it forever ([`run_dispatcher`]). If [`bind_udp_with_retry`]
/// gives up on this family — permanently, or because `runtime.cancel` fired
/// mid-bind — this returns immediately having already logged why, leaving
/// the OTHER family's task (spawned separately by [`run_udp_face`])
/// completely unaffected — the datagram counterpart of `crate::face::
/// bind_and_serve`.
async fn bind_and_dispatch(runtime: Arc<UdpFaceRuntime>, unspecified: IpAddr, family: AddressFamily) {
    let bind_addr = SocketAddr::new(unspecified, runtime.port);
    let Some(socket) = bind_udp_with_retry(bind_addr, family, &runtime).await else {
        return;
    };
    tracing::info!(port = runtime.port, label = %runtime.label, %family, "[perimeter/udp_face] listening");
    run_dispatcher(socket, family, runtime).await;
}

/// Bind this face on both `0.0.0.0:<port>` and `[::]:<port>` and dispatch on
/// each forever — the datagram counterpart of `crate::face::run_face`. A
/// bind that fails transiently retries in the background
/// ([`bind_udp_with_retry`]) while the OTHER family serves; a bind that
/// fails permanently ends only that family's half of this task. Returns
/// once BOTH halves end, which for a healthy dual-stack face means "not
/// before `cancel` fires".
///
/// # Why this takes plain parameters, not a `SharedUdpFace`/`ArcSwap` cell
///
/// The plan's own sketch (`docs/mirage/plans/udp-front-door-u0-2026-09-05.md`
/// §4) proposes `SharedUdpFace = Arc<ArcSwap<UdpFace>>`, mirroring
/// `crate::face::SharedFace`, purely for STRUCTURAL parity with the TCP side
/// — its own text says plainly that `RawUdp` has no per-connection-visible
/// field to swap today. Nothing built in this module ever reads a face's
/// camouflage per datagram (classification is plan step 4b, not this one),
/// so there is nothing yet for a hot-swap cell to change the meaning of.
/// Deciding whether that cell is worth adding, and wiring
/// `crate::config::UdpFace` into a call to this function at all, is
/// `Surface`'s job (plan step 5) — this function's own signature is
/// deliberately the same shape `crate::face::run_face` had before `Surface`
/// wiring existed for it either: raw parameters in, a private runtime
/// struct built internally.
///
/// # Stopping a face
///
/// `cancel` is the only way this task ends before both address families are
/// permanently absent on the host — fired exactly once by whatever retires
/// this port (`Surface::apply_config`, plan step 5). Every dispatcher races
/// it `biased` against the socket read ([`run_dispatcher`]), and
/// [`bind_udp_with_retry`] checks it too, so a face retired before it ever
/// finished binding stops retrying instead of chasing a port nobody wants
/// any more — the exact two checks `crate::face::run_face`'s own machinery
/// makes. Either way the bound socket is a plain local variable owned by
/// [`bind_and_dispatch`]'s stack frame: the moment its task returns, the
/// socket drops and the OS releases the port. There is no second handle
/// anywhere that could keep it open.
pub async fn run_udp_face(
    port: u16,
    label: String,
    counters: Arc<UdpFaceCounters>,
    sessions: mpsc::Sender<UdpSession>,
    cancel: CancellationToken,
) {
    let runtime = Arc::new(UdpFaceRuntime {
        port,
        label,
        counters,
        cancel,
        sessions,
        peer_sweep_trigger: PEER_SWEEP_TRIGGER,
        peer_idle_evict: PEER_IDLE_EVICT,
        peer_low_water: PEER_LOW_WATER_MARK,
        peer_channel_capacity: PEER_CHANNEL_CAPACITY,
    });

    let v4 = tokio::spawn(bind_and_dispatch(
        Arc::clone(&runtime),
        Ipv4Addr::UNSPECIFIED.into(),
        AddressFamily::V4,
    ));
    let v6 = tokio::spawn(bind_and_dispatch(
        Arc::clone(&runtime),
        Ipv6Addr::UNSPECIFIED.into(),
        AddressFamily::V6,
    ));
    let _ = tokio::join!(v4, v6);
}

/// Build a bare [`UdpFaceRuntime`] for a test, real `PEER_SWEEP_TRIGGER`/
/// `PEER_IDLE_EVICT`/`PEER_CHANNEL_CAPACITY` — the shape [`run_udp_face`]
/// itself builds, minus the two `tokio::spawn` calls, so a test can drive
/// [`run_dispatcher`] directly against one bound socket instead of a whole
/// dual-stack face.
///
/// `#[cfg(test)] pub(crate)`: this module's own tests use it, and so does
/// `crate::udp_relay`'s test module — proving that a refused session's
/// eviction actually reaches THIS dispatcher's own peer map needs a real
/// [`run_dispatcher`], not a hand-rolled stand-in that could silently drift
/// from what production actually runs.
#[cfg(test)]
pub(crate) fn test_runtime_for(
    port: u16,
    cancel: CancellationToken,
    sessions: mpsc::Sender<UdpSession>,
) -> Arc<UdpFaceRuntime> {
    Arc::new(UdpFaceRuntime {
        port,
        label: format!("test:{port}"),
        counters: Arc::new(UdpFaceCounters::default()),
        cancel,
        sessions,
        peer_sweep_trigger: PEER_SWEEP_TRIGGER,
        peer_idle_evict: PEER_IDLE_EVICT,
        peer_low_water: PEER_LOW_WATER_MARK,
        peer_channel_capacity: PEER_CHANNEL_CAPACITY,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn bound_loopback_udp() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("loopback UDP bind must succeed")
    }

    // ── Two peers, two sessions, each seeing only its own datagrams ──

    #[tokio::test]
    async fn two_peers_land_in_two_sessions_each_seeing_only_its_own_datagrams() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let runtime = test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);

        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, runtime));

        let peer_a = bound_loopback_udp().await;
        let peer_b = bound_loopback_udp().await;
        let a_addr = peer_a.local_addr().expect("peer a has a local addr");
        let b_addr = peer_b.local_addr().expect("peer b has a local addr");

        peer_a.send_to(b"hello-a", server_addr).await.expect("peer a send");
        peer_b.send_to(b"hello-b", server_addr).await.expect("peer b send");

        let mut sessions = HashMap::new();
        for _ in 0..2 {
            let s = sessions_rx.recv().await.expect("two sessions must be announced");
            sessions.insert(s.peer, s);
        }
        assert_eq!(sessions[&a_addr].first_datagram, b"hello-a");
        assert_eq!(sessions[&b_addr].first_datagram, b"hello-b");

        // Second datagram from each — must land ONLY on the matching
        // session's own inbound channel.
        peer_a.send_to(b"again-a", server_addr).await.expect("peer a second send");
        peer_b.send_to(b"again-b", server_addr).await.expect("peer b second send");

        let mut session_a = sessions.remove(&a_addr).expect("session a exists");
        let mut session_b = sessions.remove(&b_addr).expect("session b exists");
        let (from, payload) = session_a.inbound.recv().await.expect("session a receives its own datagram");
        assert_eq!(from, a_addr);
        assert_eq!(payload, b"again-a");
        let (from, payload) = session_b.inbound.recv().await.expect("session b receives its own datagram");
        assert_eq!(from, b_addr);
        assert_eq!(payload, b"again-b");

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── Whole, byte-identical payloads, including a zero-length one ──

    #[tokio::test]
    async fn a_datagrams_payload_arrives_whole_and_byte_identical_including_zero_length() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let runtime = test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);
        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, runtime));

        let peer = bound_loopback_udp().await;
        let peer_addr = peer.local_addr().expect("peer has a local addr");
        let payload = vec![0u8, 1, 2, 3, 255, 254, 253];
        peer.send_to(&payload, server_addr).await.expect("peer send");
        let mut session = sessions_rx.recv().await.expect("session must be announced");
        assert_eq!(session.first_datagram, payload, "the first datagram must arrive byte-identical");

        // A zero-length datagram, sent second — proves the boundary survives
        // the dispatcher's own map lookup and re-forward, not merely the
        // channel underneath it.
        peer.send_to(&[], server_addr).await.expect("peer empty send");
        let (from, empty) = session.inbound.recv().await.expect("the empty datagram must still arrive");
        assert_eq!(from, peer_addr);
        assert!(empty.is_empty(), "a zero-length datagram must arrive as zero bytes, never be dropped");

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── Cancellation releases the socket ──

    #[tokio::test]
    async fn cancelling_the_token_stops_the_dispatcher_and_releases_the_socket() {
        let socket = bound_loopback_udp().await;
        let addr = socket.local_addr().expect("socket has a local addr");
        let (sessions_tx, _sessions_rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let runtime = test_runtime_for(addr.port(), cancel.clone(), sessions_tx);

        let task = tokio::spawn(run_dispatcher(socket, AddressFamily::V4, runtime));

        // Give the loop a real chance to start polling `recv_from` before
        // cancelling it — otherwise this would only prove a task that never
        // ran can be joined, not that a genuinely dispatching loop stops and
        // lets go of its socket.
        tokio::task::yield_now().await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("run_dispatcher must return once cancelled, not hang forever")
            .expect("run_dispatcher task must not panic");

        let rebound = UdpSocket::bind(addr).await;
        assert!(
            rebound.is_ok(),
            "the port must be free once the dispatcher stops — a socket that merely forgot its \
             task would still hold it and fail this exact rebind: {:?}",
            rebound.err()
        );
    }

    // ── The idle sweep evicts a silent peer; the next datagram starts fresh ──

    #[tokio::test]
    async fn the_idle_sweep_evicts_a_silent_peer_and_a_later_datagram_starts_a_fresh_session() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(8);
        let cancel = CancellationToken::new();
        // A trigger of 0 means the sweep check runs on every new-peer
        // arrival regardless of map size, and a 20ms idle window is long
        // enough to assert past reliably without a slow test.
        let runtime = Arc::new(UdpFaceRuntime {
            port: server_addr.port(),
            label: "test".to_string(),
            counters: Arc::new(UdpFaceCounters::default()),
            cancel: cancel.clone(),
            sessions: sessions_tx,
            peer_sweep_trigger: 0,
            peer_idle_evict: Duration::from_millis(20),
            peer_low_water: 0,
            peer_channel_capacity: PEER_CHANNEL_CAPACITY,
        });
        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, Arc::clone(&runtime)));

        let peer = bound_loopback_udp().await;
        let peer_addr = peer.local_addr().expect("peer has a local addr");
        peer.send_to(b"first", server_addr).await.expect("peer first send");
        let first_session = sessions_rx.recv().await.expect("first session must be announced");
        assert_eq!(first_session.peer, peer_addr);

        tokio::time::sleep(Duration::from_millis(60)).await;

        // An unrelated peer's arrival is what triggers the sweep check — it
        // only ever runs on the new-peer path, matching `raw_udp.rs`'s own
        // sweep exactly.
        let other = bound_loopback_udp().await;
        other.send_to(b"other", server_addr).await.expect("other peer send");
        let _other_session = sessions_rx.recv().await.expect("the unrelated peer must also get a session");

        assert_eq!(
            runtime.counters.sessions_evicted_idle.load(Ordering::Relaxed),
            1,
            "the silent peer must have been swept"
        );

        // The original peer speaks again — must be a FRESH session, not
        // routed into the old, now-orphaned channel (nobody was reading
        // `first_session.inbound`, so a misroute here would hang, not just
        // read wrong).
        peer.send_to(b"second", server_addr).await.expect("peer second send");
        let second_session = tokio::time::timeout(Duration::from_secs(5), sessions_rx.recv())
            .await
            .expect("a new session announcement must arrive")
            .expect("the sessions channel must still be open");
        assert_eq!(second_session.peer, peer_addr);
        assert_eq!(second_session.first_datagram, b"second");

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── A spray of fresh sources past the trigger stays bounded ──

    /// The spray case: every source is fresh, so an idle sweep run
    /// immediately before this dispatcher's own least-recent fallback would
    /// have freed nothing. Filling the map with far more distinct sources
    /// than the trigger must still leave it bounded — proven the same way
    /// `mirage_protocol::camouflage::raw_udp`'s own test of this shape
    /// proves it: the oldest sprayed sources must have been evicted (a
    /// resend from them starts a brand new session), the newest must not
    /// have been, and every sprayed source was admitted in the first place.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spray_of_fresh_peers_past_the_trigger_stays_bounded_and_evicts_least_recently_seen() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let trigger = 20;
        let runtime = Arc::new(UdpFaceRuntime {
            port: server_addr.port(),
            label: "test".to_string(),
            counters: Arc::new(UdpFaceCounters::default()),
            cancel: cancel.clone(),
            sessions: sessions_tx,
            peer_sweep_trigger: trigger,
            peer_idle_evict: Duration::from_secs(60),
            peer_low_water: trigger - trigger / 8,
            peer_channel_capacity: PEER_CHANNEL_CAPACITY,
        });
        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, Arc::clone(&runtime)));

        // Drain every announced session as it arrives, recording its peer
        // and keeping the session alive — dropping one would close its
        // `evict` sender's counterpart state in a way unrelated to the
        // fallback under test, same reasoning as the mirage-protocol tests
        // of this shape.
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<SocketAddr>();
        let drain = tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Some(session) = sessions_rx.recv().await {
                let _ = seen_tx.send(session.peer);
                kept.push(session);
            }
            kept
        });

        let spray_count = trigger * 10;
        let mut spray = Vec::with_capacity(spray_count);
        for i in 0..spray_count {
            let client = bound_loopback_udp().await;
            client
                .send_to(format!("spray-{i}").as_bytes(), server_addr)
                .await
                .expect("send spray datagram");
            let local = client.local_addr().expect("spray client has a local addr");
            spray.push((client, local));
        }

        for _ in 0..spray_count {
            tokio::time::timeout(Duration::from_secs(10), seen_rx.recv())
                .await
                .expect("every sprayed peer must be announced promptly")
                .expect("the announce channel must still be open");
        }

        for (client, addr) in spray.iter().take(10) {
            client
                .send_to(b"resend-old", server_addr)
                .await
                .expect("resend from an old spray address");
            let reannounced = tokio::time::timeout(Duration::from_secs(10), seen_rx.recv())
                .await
                .expect("an evicted peer's next datagram must start a fresh session, not vanish")
                .expect("the announce channel must still be open");
            assert_eq!(
                reannounced, *addr,
                "the fresh session must be for the same address that was evicted"
            );
        }

        for (client, _addr) in spray.iter().rev().take(10) {
            client
                .send_to(b"resend-new", server_addr)
                .await
                .expect("resend from a fresh spray address");
        }
        let extra = tokio::time::timeout(Duration::from_millis(500), seen_rx.recv()).await;
        assert!(
            extra.is_err(),
            "the most-recently-seen sprayed peers must still be resident, not re-announced"
        );

        assert!(
            runtime.counters.sessions_evicted_lru.load(Ordering::Relaxed) >= 10,
            "the least-recent fallback counter must reflect the evictions this spray caused"
        );

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
        drop(drain);
    }

    // ── An actively-sending peer survives a spray larger than the whole map ──

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_actively_sending_peer_survives_a_spray_many_times_larger_than_the_whole_map() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let trigger = 5;
        let runtime = Arc::new(UdpFaceRuntime {
            port: server_addr.port(),
            label: "test".to_string(),
            counters: Arc::new(UdpFaceCounters::default()),
            cancel: cancel.clone(),
            sessions: sessions_tx,
            peer_sweep_trigger: trigger,
            peer_idle_evict: Duration::from_secs(60),
            peer_low_water: trigger - trigger / 8,
            peer_channel_capacity: PEER_CHANNEL_CAPACITY,
        });
        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, Arc::clone(&runtime)));

        let active = bound_loopback_udp().await;
        let active_addr = active.local_addr().expect("active peer has a local addr");
        active
            .send_to(b"hello-active", server_addr)
            .await
            .expect("active peer's first datagram");
        let active_session = sessions_rx.recv().await.expect("the active peer's own session must be announced");
        assert_eq!(active_session.peer, active_addr);

        // Drain the active peer's own inbound channel continuously — an
        // undrained real consumer would trip the pre-existing "reader
        // stalled" eviction, unrelated to the fallback under test.
        let (active_reads_tx, mut active_reads_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let active_reader = tokio::spawn(async move {
            let mut inbound = active_session.inbound;
            while let Some((_from, payload)) = inbound.recv().await {
                if active_reads_tx.send(payload).is_err() {
                    return;
                }
            }
        });

        let spray_count = trigger * 50;
        let mut kept = Vec::new();
        for i in 0..spray_count {
            active
                .send_to(b"keepalive", server_addr)
                .await
                .expect("active peer keepalive");
            let spray_client = bound_loopback_udp().await;
            spray_client
                .send_to(format!("spray-{i}").as_bytes(), server_addr)
                .await
                .expect("send spray datagram");
            let session = sessions_rx.recv().await.expect("each sprayed peer must still be announced");
            kept.push(session);
        }

        let reannounced = tokio::time::timeout(Duration::from_millis(300), sessions_rx.recv()).await;
        assert!(
            reannounced.is_err(),
            "the actively-sending peer must never have been evicted, so no second session for it exists"
        );

        active
            .send_to(b"still-here", server_addr)
            .await
            .expect("active peer final datagram");
        let found = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match active_reads_rx.recv().await {
                    Some(payload) if payload == b"still-here" => return true,
                    Some(_) => continue,
                    None => return false,
                }
            }
        })
        .await
        .expect("reading the original session must not hang");
        assert!(
            found,
            "the original session's own inbound channel must still be the one receiving this peer's traffic"
        );

        drop(kept);
        active_reader.abort();
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── A bind failure in one family leaves the other serving ──

    #[tokio::test]
    async fn a_bind_failure_in_one_family_leaves_the_other_serving() {
        let (sessions_tx, mut sessions_rx) = mpsc::channel(4);
        let cancel = CancellationToken::new();
        let runtime = test_runtime_for(0, cancel.clone(), sessions_tx);

        // The v4 half: bound for real, through the exact retry function
        // production uses, so its counters are genuinely marked bound.
        let v4_socket = bind_udp_with_retry(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            AddressFamily::V4,
            &runtime,
        )
        .await
        .expect("v4 loopback bind must succeed");
        let v4_addr = v4_socket.local_addr().expect("v4 socket has a local addr");
        let v4_task = tokio::spawn(run_dispatcher(v4_socket, AddressFamily::V4, Arc::clone(&runtime)));

        // The v6 half of the SAME face: a documentation-only IPv6 prefix
        // (RFC 3849), never assigned to any real interface, so this bind
        // fails PERMANENTLY — `EADDRNOTAVAIL` if this host has an IPv6
        // stack, `EAFNOSUPPORT` if it does not (either way `Permanent`, see
        // `crate::face::classify_bind_error`). This is not a wildcard bind: the
        // address never listens on anything, it only ever fails to bind —
        // this exercises `bind_and_dispatch`'s real give-up path rather than
        // a hand-rolled stand-in for it.
        let v6_addr: IpAddr = "2001:db8::1".parse().expect("valid IPv6 literal");
        tokio::time::timeout(
            Duration::from_secs(5),
            bind_and_dispatch(Arc::clone(&runtime), v6_addr, AddressFamily::V6),
        )
        .await
        .expect("a permanent bind failure must return promptly, not hang");

        assert!(
            runtime.counters.v6.permanently_absent.load(Ordering::Relaxed),
            "the v6 half must have given up permanently"
        );
        assert!(!runtime.counters.v6.bound.load(Ordering::Relaxed));

        // The v4 half, sharing the SAME runtime, was never touched by the v6
        // failure — proved by actually routing a datagram through it, not
        // merely by a counter.
        let peer = bound_loopback_udp().await;
        peer.send_to(b"still-serving", v4_addr).await.expect("peer send to v4");
        let session = tokio::time::timeout(Duration::from_secs(5), sessions_rx.recv())
            .await
            .expect("the v4 dispatcher must still be answering")
            .expect("the sessions channel must still be open");
        assert_eq!(session.first_datagram, b"still-serving");
        assert!(runtime.counters.v4.bound.load(Ordering::Relaxed));

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), v4_task).await;
    }

    // ── The invariant `bind_v6_only_udp` exists to guarantee ──
    //
    // Mirrors `crate::face::a_v6_only_socket_and_a_v4_wildcard_can_share_
    // one_port` exactly, `Type::DGRAM` in place of `Type::STREAM`.
    // `#[ignore]`d for the identical reason: this crate's rule against
    // binding a wildcard address on the operator box, and the behaviour
    // under test (Linux `bindv6only` semantics) cannot be exhibited on the
    // Windows dev host regardless.
    #[ignore = "binds wildcard addresses — container only, never the operator box"]
    #[tokio::test]
    async fn a_v6_only_udp_socket_and_a_v4_wildcard_udp_socket_can_share_one_port() {
        let v6_addr: SocketAddr = "[::]:0".parse().expect("valid v6 unspecified addr");
        let v6 = bind_v6_only_udp(v6_addr).expect("v6-only UDP bind must succeed");
        let port = v6.local_addr().expect("v6 socket has a local addr").port();

        let v4_addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid v4 addr");
        let v4 = UdpSocket::bind(v4_addr).await;

        assert!(
            v4.is_ok(),
            "a v4 wildcard UDP bind on the same port as an open v6-only socket must succeed: {:?}",
            v4.err()
        );

        drop(v6);
        drop(v4);
    }

    // ── The batch fallback lands on the low-water mark, not the trigger ──

    /// Requirements 1+2 of the batching fix, proven exactly via the gauge
    /// this dispatcher already keeps (`sessions_active` tracks `peers.len()`
    /// precisely — every insert and every eviction path updates it) rather
    /// than by inference from resend behaviour.
    ///
    /// `trigger = 16`, `low_water = 14` (the 7/8 shape). This dispatcher
    /// checks the trigger BEFORE inserting the new peer (unlike
    /// `mirage_protocol::camouflage::raw_udp`'s insert-then-check order — see
    /// `run_dispatcher`'s own doc), so the crossing point and the exact
    /// post-eviction count differ by one from that crate's tests of the same
    /// shape: the 18th distinct arrival is the one whose PRE-insert size (17)
    /// first exceeds the trigger, so it evicts 17 - 14 = 3 down to 14, then
    /// still admits itself, landing at 15 (`low_water + 1`) — never at the
    /// trigger (16) or at the trigger + 1 (17) landing evicting back to the
    /// trigger would have produced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_eviction_lands_on_the_low_water_mark_and_further_admissions_do_not_evict_again() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let trigger = 16;
        let runtime = Arc::new(UdpFaceRuntime {
            port: server_addr.port(),
            label: "test".to_string(),
            counters: Arc::new(UdpFaceCounters::default()),
            cancel: cancel.clone(),
            sessions: sessions_tx,
            peer_sweep_trigger: trigger,
            peer_idle_evict: Duration::from_secs(60),
            peer_low_water: trigger - trigger / 8, // 14
            peer_channel_capacity: PEER_CHANNEL_CAPACITY,
        });
        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, Arc::clone(&runtime)));

        let mut kept = Vec::new();
        for i in 0..18u32 {
            let client = bound_loopback_udp().await;
            client
                .send_to(format!("batch-{i}").as_bytes(), server_addr)
                .await
                .expect("send batch datagram");
            let session = sessions_rx.recv().await.expect("every admitted peer must be announced");
            kept.push((client, session));
        }

        // Requirement 1: exactly 3 evicted (17 - 14), landing on the
        // low-water-derived count (14 survivors + the 18th peer itself = 15
        // resident), not on the trigger (16) or trigger + 1 (17).
        assert_eq!(
            runtime.counters.sessions_evicted_lru.load(Ordering::Relaxed),
            3,
            "the batch must evict exactly 3 — down to the low-water mark, not merely 1 (back to the trigger)"
        );
        assert_eq!(
            runtime.counters.sweep_runs.load(Ordering::Relaxed),
            1,
            "the expensive path must have run exactly once so far"
        );
        assert_eq!(
            runtime.counters.sessions_active.load(Ordering::Relaxed),
            15,
            "resident count must be low_water(14) + the just-admitted 18th peer = 15, not the trigger"
        );

        // Requirement 2: one more admission, still under the trigger (15 + 1
        // = 16, not over 16), must not run the expensive path again.
        let client = bound_loopback_udp().await;
        client
            .send_to(b"batch-18", server_addr)
            .await
            .expect("send the 19th datagram");
        let session = sessions_rx.recv().await.expect("the 19th peer must be announced");
        kept.push((client, session));

        assert_eq!(
            runtime.counters.sweep_runs.load(Ordering::Relaxed),
            1,
            "the expensive path must not have run again — the map simply grew by one"
        );
        assert_eq!(
            runtime.counters.sessions_evicted_lru.load(Ordering::Relaxed),
            3,
            "no further eviction — the least-recent counter must be unchanged"
        );
        assert_eq!(runtime.counters.sessions_active.load(Ordering::Relaxed), 16);

        drop(kept);
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── Stage separation: the idle sweep alone must not lead to a low-water cut ──

    /// Requirement 3 (stage separation): a map the idle sweep alone brings
    /// back under the trigger must not then have its live, freshly-arrived
    /// peers cut down to the low-water mark — proven exactly via
    /// `sessions_evicted_lru` staying at 0 while `sessions_evicted_idle`
    /// accounts for every removal.
    ///
    /// 5 peers admitted first are left to age past `idle_evict`; 8 FRESH
    /// peers admitted afterwards are, on their own, more than
    /// `low_water = 7` — so if the least-recent fallback wrongly ran, at
    /// least one of them would have been evicted too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_map_the_sweep_alone_clears_is_not_further_cut_to_the_low_water_mark() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server has a local addr");
        let (sessions_tx, mut sessions_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();
        let trigger = 8;
        let idle_evict = Duration::from_millis(200);
        let runtime = Arc::new(UdpFaceRuntime {
            port: server_addr.port(),
            label: "test".to_string(),
            counters: Arc::new(UdpFaceCounters::default()),
            cancel: cancel.clone(),
            sessions: sessions_tx,
            peer_sweep_trigger: trigger,
            peer_idle_evict: idle_evict,
            peer_low_water: trigger - trigger / 8, // 7
            peer_channel_capacity: PEER_CHANNEL_CAPACITY,
        });
        let dispatch = tokio::spawn(run_dispatcher(server, AddressFamily::V4, Arc::clone(&runtime)));

        let mut kept = Vec::new();
        for i in 0..5u32 {
            let client = bound_loopback_udp().await;
            client
                .send_to(format!("idle-{i}").as_bytes(), server_addr)
                .await
                .expect("send idle datagram");
            let session = sessions_rx.recv().await.expect("idle peer must be announced");
            kept.push((client, session));
        }

        tokio::time::sleep(idle_evict * 3).await;

        // The check runs BEFORE each insert (this dispatcher's own order —
        // see `run_dispatcher`'s doc), using the count already resident: by
        // the 5th of these 8 fresh admissions, 5 idle + 4 fresh = 9 are
        // already resident, so `peers.len() > trigger` (9 > 8) first holds
        // right there. The idle sweep must clear the 5 stale entries at that
        // point, leaving 4 fresh survivors (already `<= trigger`), so the
        // least-recent fallback never runs for the rest of this loop either.
        for i in 0..8u32 {
            let client = bound_loopback_udp().await;
            client
                .send_to(format!("fresh-{i}").as_bytes(), server_addr)
                .await
                .expect("send fresh datagram");
            let session = sessions_rx.recv().await.expect("fresh peer must be announced");
            kept.push((client, session));
        }

        assert_eq!(
            runtime.counters.sessions_evicted_idle.load(Ordering::Relaxed),
            5,
            "the idle sweep alone must remove exactly the 5 stale entries"
        );
        assert_eq!(
            runtime.counters.sessions_evicted_lru.load(Ordering::Relaxed),
            0,
            "the least-recent fallback must never run — the idle sweep already sufficed"
        );
        assert_eq!(
            runtime.counters.sessions_active.load(Ordering::Relaxed),
            8,
            "13 admitted (5 idle + 8 fresh) minus the 5 idle-swept = 8 — every fresh peer survived, \
             none of the live ones cut to low_water(7)"
        );

        drop(kept);
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }
}
