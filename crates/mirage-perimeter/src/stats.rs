//! Per-face atomic counters, and the box-local channel that answers
//! questions about them.
//!
//! # There is no port here any more
//!
//! This used to be a hand-rolled HTTP/1.1 server on `127.0.0.1:19470`: a
//! request-line parser, a status-code table, `Connection: close`, and two
//! GET routes. It is now [`mirage_core::local_endpoint::LocalChannel::
//! PerimeterQuery`] — a unix socket under `/run/mirage`, carrying typed
//! [`mirage_core::perimeter_query::PerimeterRequest`] frames.
//!
//! Three things change, and each is the reason:
//!
//! - **It is not in `ss -lnt`.** A loopback port is still a port: one `bind`
//!   typo or one filter edit from being public, and this fleet has already
//!   booted with every internal port exposed until an operator ran a
//!   command. A socket cannot be reached from the network by any mistake of
//!   configuration.
//! - **The kernel says who is asking.** Anything on the box could open
//!   `:19470`; `SO_PEERCRED` is not forgeable by the byte stream.
//! - **The answer is a Rust value.** The counters below were described TWICE
//!   — here, and again in the operator's reader, which re-derived them from
//!   JSON. The shapes drifted in both directions and one of those drifts
//!   silently hid 1483 routed connections. There is one definition now, in
//!   `mirage_core::perimeter_query`, and a rename is a build error.
//!
//! # This channel is read-only, and named for it
//!
//! `PerimeterQuery`, not "control": nothing on it changes what this process
//! does. The perimeter takes instructions from its sealed capsule and from
//! nowhere else — a daemon holding the box's only public listener must not
//! also expose a way to be reconfigured by whatever else is running beside
//! it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use mirage_core::local_endpoint::LocalChannel;
use mirage_core::perimeter_query::{
    FaceMetrics, FaceState, FaceTransport, NotWireMetrics, ObservationChannelMetrics,
    PerimeterHealth, PerimeterMetrics, PerimeterRequest, PerimeterResponse, UdpFaceMetrics,
};

use crate::classify::NotWireReason;
use crate::config::{PerimeterFace, UdpFace};
use crate::udp_face::UdpFaceCounters;

/// Which IP address family one of a face's two listeners is bound on.
///
/// # Why a face has two of these instead of one
///
/// `crate::face::run_face` used to open exactly one `TcpListener` per face,
/// on `0.0.0.0`, and that listener was the whole story: `FaceCounters::bound`
/// was one boolean because there was exactly one socket for it to describe.
/// The nft surface this fleet runs, though, is an `inet` table — `tcp dport
/// { 22, 80, 443, ... } accept` admits BOTH families — so every face port was
/// already open on IPv6 while nothing bound it there. Proven off-box: an
/// sshd bound to `[::]:22` answered a real client over IPv6 past this exact
/// perimeter, on a box whose only public listener this crate is supposed to
/// be.
///
/// So each face now binds `0.0.0.0:<port>` AND `[::]:<port>`, each its own
/// plain socket with its own accept loop feeding the same classifier and the
/// same per-face state (`crate::face::run_face`'s own doc has the rejected
/// alternative — a single dual-stack socket with `IPV6_V6ONLY=0` — and why:
/// that flag's behaviour differs across kernels, and accepting v4 traffic
/// through a v6 socket erases which family a connection actually arrived on,
/// which this fleet's attribution and stats need to keep). `AddressFamily`
/// is the tag that keeps the two apart everywhere they share code: in
/// `FaceCounters` below, and in every bind/log/counter call `crate::face`
/// makes for either socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    V4,
    V6,
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AddressFamily::V4 => "v4",
            AddressFamily::V6 => "v6",
        })
    }
}

/// Bind bookkeeping for ONE address family of one face — see
/// [`AddressFamily`]'s doc for why a face needs two of these rather than the
/// single flat set `FaceCounters` used to carry.
///
/// A host with IPv6 disabled at the kernel (`net.ipv6.conf.all.disable_ipv6=1`)
/// or simply carrying no IPv6 address at all fails the `[::]` bind
/// permanently — see `crate::face::BindFailureKind` for how that is told
/// apart from the transient case (another daemon holding the port for a
/// moment) that `crate::face::bind_with_retry` already retried before this
/// crate served IPv6 at all. [`Self::permanently_absent`] is that fact, kept
/// apart from `bound: false` alone: a family that has never been tried, one
/// that is still retrying, and one that will NEVER succeed on this host are
/// three different conditions, and only the last of them should stop logging
/// about itself.
#[derive(Debug, Default)]
pub struct FamilyBind {
    /// Set true the moment this family's `TcpListener::bind` succeeds.
    pub bound: AtomicBool,
    /// Why this family is not bound, verbatim from the failing `bind`.
    /// `None` while bound.
    pub unbound_reason: std::sync::Mutex<Option<String>>,
    /// When this family last STOPPED being bound (or first failed to
    /// bind), ms since epoch.
    pub unbound_since_ms: AtomicU64,
    /// How many times `bind` has been attempted for this family since the
    /// process started. Stops rising once [`Self::permanently_absent`] is
    /// set — see `crate::face::bind_with_retry`'s permanent branch, which
    /// gives up after exactly one attempt rather than retrying a condition
    /// that cannot change.
    pub bind_attempts: AtomicU64,
    /// Set once this family's own bind failure was classified permanent
    /// (`crate::face::BindFailureKind::Permanent`) and the retry loop for it
    /// has stopped. A missing IPv6 stack on this host is the case this
    /// exists for; nothing on the IPv4 side of this fleet is expected to
    /// ever set it.
    pub permanently_absent: AtomicBool,
}

impl FamilyBind {
    /// Record a successful bind for this family, and clear whatever dark
    /// state it was carrying — mirrors [`FaceCounters::mark_bound`], one
    /// level down.
    pub fn mark_bound(&self) {
        self.bound.store(true, Ordering::Relaxed);
        if let Ok(mut r) = self.unbound_reason.lock() {
            *r = None;
        }
        self.unbound_since_ms.store(0, Ordering::Relaxed);
        self.permanently_absent.store(false, Ordering::Relaxed);
    }

    /// Record a failed bind for this family: the reason, the attempt count,
    /// when it first went dark, and whether the failure is one worth
    /// retrying — mirrors [`FaceCounters::note_bind_failed`], one level
    /// down.
    pub fn note_bind_failed(&self, reason: &str, now_ms: u64, permanent: bool) {
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

/// Per-[`NotWireReason`]-discriminant rejection counters for one face.
#[derive(Debug, Default)]
pub struct NotWireCounters {
    pub too_short: AtomicU64,
    pub bad_version: AtomicU64,
    pub bad_suite: AtomicU64,
    pub reserved_not_zero: AtomicU64,
    pub timestamp_skew: AtomicU64,
}

impl NotWireCounters {
    /// Record one rejection under its discriminant.
    pub fn record(&self, reason: NotWireReason) {
        let counter = match reason {
            NotWireReason::TooShort(_) => &self.too_short,
            NotWireReason::BadVersion(_) => &self.bad_version,
            NotWireReason::BadSuite(_) => &self.bad_suite,
            NotWireReason::ReservedNotZero => &self.reserved_not_zero,
            NotWireReason::TimestampSkew { .. } => &self.timestamp_skew,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> NotWireMetrics {
        NotWireMetrics {
            too_short: self.too_short.load(Ordering::Relaxed),
            bad_version: self.bad_version.load(Ordering::Relaxed),
            bad_suite: self.bad_suite.load(Ordering::Relaxed),
            reserved_not_zero: self.reserved_not_zero.load(Ordering::Relaxed),
            timestamp_skew: self.timestamp_skew.load(Ordering::Relaxed),
        }
    }
}

/// One face's counters. Held behind an `Arc` and handed to `crate::face`'s
/// task for that face at spawn time — never looked up by port per
/// connection.
#[derive(Debug, Default)]
pub struct FaceCounters {
    /// This face's IPv4 listener (`0.0.0.0:<port>`) — the family every host
    /// on this fleet has, and where a bind failure is always the transient
    /// case `crate::face::bind_with_retry` was built for (another daemon
    /// mid-handover on the same port; see that function's own doc).
    pub v4: FamilyBind,
    /// This face's IPv6 listener (`[::]:<port>`) — the family that can be
    /// PERMANENTLY absent, on a host with IPv6 disabled at the kernel or no
    /// IPv6 address configured at all. See [`FamilyBind::permanently_absent`]
    /// and `crate::face::BindFailureKind`.
    pub v6: FamilyBind,
    /// Set true the moment EITHER family's `TcpListener::bind` succeeds.
    /// `Stats::faces_bound` reports the live count, not the configured
    /// count — a face that failed to bind on every family must show up as
    /// NOT bound rather than silently counted as healthy.
    ///
    /// This is the AGGREGATE over [`Self::v4`]/[`Self::v6`], kept as its own
    /// field (rather than removed now that there are two listeners) because
    /// mshd's door-check and secd's kernel admission (see this module's own
    /// doc, "Who asks what") only ever ask "is anybody serving this port",
    /// never "on which family" — one boolean is the correct answer to that
    /// question. It is [`Self::v4`]/[`Self::v6`] that keep the two families
    /// from being collapsed INTERNALLY: a face serving IPv4 only, because
    /// this host has no IPv6, is a different fact from a face serving both
    /// or neither, and that fact is never lost — it is only this single
    /// summary bit that cannot carry it, by construction of what a boolean
    /// is.
    pub bound: AtomicBool,
    /// Why this face is not bound on EITHER family, prefixed with which one
    /// the reason belongs to (`"v4: ..."` / `"v6: ..."`) — `None` the
    /// instant either family lands. Only rewritten while BOTH
    /// [`Self::v4`] and [`Self::v6`] are dark: a face still served by its
    /// other family is not "unbound", and overwriting this with the
    /// still-live half's silence would misreport a face that is actually
    /// serving. `bound: false` alone cannot tell "nothing has tried yet"
    /// from "something else owns this port", and on 2026-08-28 that was the
    /// whole story on three fleet boxes — see
    /// `mirage_core::perimeter_query::FaceState::unbound_reason`.
    ///
    /// A `Mutex<Option<String>>` rather than an atomic because the value is
    /// a string; it is written once per retry (a minute apart) and read per
    /// query, so contention is not a consideration here.
    pub unbound_reason: std::sync::Mutex<Option<String>>,
    /// When this face last became unreachable on EVERY family it has.
    pub unbound_since_ms: AtomicU64,
    /// Bind attempts made WHILE THE WHOLE FACE WAS DARK, summed across both
    /// families — see [`Self::note_family_bind_failed`]. A family quietly
    /// retrying in the background while the OTHER family already serves
    /// does not add to this: the question this answers is "how troubled is
    /// this face", and a face already being served is not troubled, whatever
    /// its other half is doing. [`Self::v4`]/[`Self::v6`] carry each
    /// family's own full attempt count regardless.
    pub bind_attempts: AtomicU64,
    pub accepted: AtomicU64,
    /// Connections refused before the camouflage strip because their source
    /// address was over its budget (`crate::ratelimit`). Counted separately
    /// from `camo_failed`: "we refused to talk to you" and "you failed to
    /// speak the port's language" are different facts about the box, and
    /// folding them together would hide a throttle behind scan noise.
    pub rate_limited: AtomicU64,
    /// Connections accepted and then dropped because this face's in-flight
    /// budget was full.
    ///
    /// A THIRD distinct fact, kept apart from `rate_limited` for the same
    /// reason that one is kept apart from `camo_failed`: "your address is
    /// over its budget" and "this face is at capacity" say different things
    /// about the box, and only the second one means the face is shedding
    /// load it would otherwise have served.
    ///
    /// It can only be non-zero because the accept loop now accepts BEFORE
    /// it takes a permit. While the permit came first, a full budget did
    /// not refuse anything — it stopped the face accepting at all, which is
    /// unmeasurable from in here and reads from outside as a dead box.
    pub inflight_refused: AtomicU64,
    pub camo_failed: AtomicU64,
    pub peek_timeout: AtomicU64,
    pub wire_routed: AtomicU64,
    /// Connections whose opening bytes were an SSH identification string and
    /// which were handed to the co-located mshd.
    pub ssh_routed: AtomicU64,
    // `ssh_unconfigured` is GONE. It counted SSH-shaped connections dropped
    // because the box had no SSH destination configured — a state that no
    // longer exists: the destination is `LocalChannel::MshdSshSplice`, which
    // cannot be absent (see `crate::config`). A counter that can only ever
    // read 0 is not a measurement, it is a reassurance, and this one would
    // have said "no SSH configuration problem" on a box whose SSH was broken
    // for some other reason. What remains is `inner_dial_failed`, which is
    // the honest fact: mshd did not answer.
    pub rejected_not_wire: NotWireCounters,
    pub inner_dial_failed: AtomicU64,
    /// Rejected connections HELD by the jail rather than closed — see
    /// `crate::jail`. A drop is not a jail, and these two have to be
    /// countable apart or "the jail is engaged" is unverifiable.
    pub jailed: AtomicU64,
    /// Rejected connections closed immediately because this face is
    /// configured `hard_cut`.
    pub hard_cut: AtomicU64,
    /// Wall-clock ms of the last pressure line this face emitted, and the
    /// rejection total it reported at. See
    /// [`FaceCounters::note_rejection_and_maybe_report`] — these two exist
    /// so a face under sustained rejection says so in the journal without
    /// writing a line per connection.
    pub pressure_reported_at_ms: AtomicU64,
    pub pressure_reported_total: AtomicU64,
    /// Rejected connections cut because this face's hold budget was full.
    /// Its own counter, never folded into `hard_cut`: one is a policy and
    /// the other is pressure, and only the second is a reason to look at
    /// the box.
    pub jail_at_capacity: AtomicU64,
    /// Rejections the jail could not act on because duplicating the socket
    /// failed at accept time, so the connection had already closed with the
    /// camouflage strip's copy. Expected to stay at zero; a non-zero value
    /// means the jail is silently not engaging on this face.
    pub jail_no_handle: AtomicU64,
    /// Connections the jail is holding RIGHT NOW — a gauge, not a total.
    /// `jailed` only grows; this is what says whether the per-face hold
    /// budget is under pressure at this instant.
    pub jail_holding_now: AtomicU64,
    pub bytes_to_inner: AtomicU64,
    pub bytes_to_client: AtomicU64,
    /// Routed connections whose flow outlived this face's session-profile
    /// splice ceiling (`crate::timing::splice_backstop`) — see
    /// `crate::face::splice_inward`'s backstop wrap. OBSERVE-ONLY: this
    /// never closes the connection; a nonzero value is measurement, not a
    /// fault.
    pub splice_backstop_observed: AtomicU64,
    /// Wall-clock ms of the last "flow outlived its ceiling" line this face
    /// emitted, and the observed total it reported at — the identical
    /// throttle discipline [`Self::pressure_reported_at_ms`]/
    /// [`Self::pressure_reported_total`] already use, kept as its own pair
    /// so the two independent conditions ("under rejection pressure" vs "a
    /// routed flow ran past its plausible ceiling") never share one clock
    /// and steal each other's report slot.
    pub splice_backstop_reported_at_ms: AtomicU64,
    pub splice_backstop_reported_total: AtomicU64,
}

/// A face reports sustained rejection at most this often. One line per
/// face per minute is legible in a journal; one line per rejected
/// connection is not — this fleet's boxes have taken 80 rejected
/// connections a minute for days.
const PRESSURE_REPORT_INTERVAL_MS: u64 = 60_000;

impl FaceCounters {
    pub fn mark_bound(&self) {
        self.bound.store(true, Ordering::Relaxed);
        // Clear the dark-state fields together with the flag. A stale
        // reason left behind a successful bind would describe a condition
        // that no longer holds, which is the exact failure this whole
        // field set exists to stop.
        if let Ok(mut r) = self.unbound_reason.lock() {
            *r = None;
        }
        self.unbound_since_ms.store(0, Ordering::Relaxed);
    }

    /// Record a failed `bind` for this face: the reason, the attempt count,
    /// and — on the FIRST failure only — when it went dark.
    ///
    /// Called on every retry, not only on the ones that log. The log line
    /// is throttled to one a minute; the counter must not be, or the
    /// operator reads a rate rather than a total.
    pub fn note_bind_failed(&self, reason: &str, now_ms: u64) {
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
    }

    /// Is this face reachable on AT LEAST ONE address family right now?
    /// This is the fact [`Self::bound`] carries, and the fact `Stats::
    /// faces_bound`/`PerimeterRequest::Health`/`::Faces`/`::Metrics`
    /// actually need: none of those readers were ever asking "on which
    /// family", only "is anybody serving this port at all".
    fn is_bound(&self) -> bool {
        self.v4.bound.load(Ordering::Relaxed) || self.v6.bound.load(Ordering::Relaxed)
    }

    fn family(&self, family: AddressFamily) -> &FamilyBind {
        match family {
            AddressFamily::V4 => &self.v4,
            AddressFamily::V6 => &self.v6,
        }
    }

    /// Record a successful bind for ONE address family (see
    /// [`FamilyBind::mark_bound`] for what it updates there), and refresh
    /// the aggregate exactly as [`Self::mark_bound`] always has: the face
    /// counts as reachable the instant ANY family lands, whatever the other
    /// one is doing.
    pub fn mark_family_bound(&self, family: AddressFamily) {
        self.family(family).mark_bound();
        self.mark_bound();
    }

    /// Record a failed bind for ONE address family — see
    /// [`FamilyBind::note_bind_failed`] for the per-family bookkeeping, and
    /// [`Self::bind_attempts`]'s doc for why the AGGREGATE below is only
    /// touched once BOTH families are down. `permanent` distinguishes a
    /// durable host condition (a missing IPv6 stack) from the ordinary
    /// retry case — see `crate::face::BindFailureKind`.
    pub fn note_family_bind_failed(
        &self,
        family: AddressFamily,
        reason: &str,
        now_ms: u64,
        permanent: bool,
    ) {
        self.family(family).note_bind_failed(reason, now_ms, permanent);
        if !self.is_bound() {
            // The whole face is dark, not just this family — the aggregate
            // gets the same treatment `note_bind_failed` always gave a
            // face's single listener, with the reason tagged to say which
            // family it came from.
            self.note_bind_failed(&format!("{family}: {reason}"), now_ms);
        }
    }

    /// Every rejected connection on this face passes here. Emits an INFO
    /// line at most once per [`PRESSURE_REPORT_INTERVAL_MS`], and only when
    /// the face rejected something since the last one.
    ///
    /// # Why this exists
    ///
    /// The per-reason counters above were complete and correct, and the
    /// only thing that read them was `operator-box`'s `/perimeter/stats` —
    /// which reaches them over mshd RPC **through the mesh**. So the one
    /// instrument that could see a face under attack stopped working
    /// exactly when the mesh did. The rejection itself was logged at
    /// `debug`, and the fleet runs at `info`.
    ///
    /// Measured 2026-08-24 on `203.0.113.25`: five sources held ~80
    /// connections a minute against its faces, all dying in `TIME-WAIT`,
    /// for as long as the socket table was sampled — and the perimeter's
    /// journal was **empty**. The box's own instruments reported silence
    /// while it was under continuous load. That is worse than no
    /// instrument, because silence was read as health.
    ///
    /// Promoting the per-connection line to `info` would have buried the
    /// journal, which is why it was `debug` in the first place. A rate is
    /// the right shape for a rate: this reports the DELTA since the last
    /// line, so a steady storm is one line a minute per face and a stopped
    /// storm stops writing.
    pub fn note_rejection_and_maybe_report(&self, port: u16) {
        let total = self.rejection_total();
        // This runs on the reject path of a daemon whose whole job is to
        // absorb floods, so it must not put a clock read on every refused
        // connection. Below `CLOCK_SAMPLE_EVERY` the clock is consulted
        // every time — that is what keeps "the first rejection after quiet
        // reports at once" true for a slow trickle. Above it, one in
        // `CLOCK_SAMPLE_EVERY`, which still lands inside the interval at any
        // rate that makes sampling worth doing.
        const CLOCK_SAMPLE_EVERY: u64 = 16;
        if total > CLOCK_SAMPLE_EVERY && total % CLOCK_SAMPLE_EVERY != 0 {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last_ms = self.pressure_reported_at_ms.load(Ordering::Relaxed);

        // First rejection this process has seen on this face reports at
        // once — the transition from quiet to not-quiet is the event worth
        // knowing, and waiting a minute for it would hide a short burst
        // entirely.
        if last_ms != 0 && now_ms.saturating_sub(last_ms) < PRESSURE_REPORT_INTERVAL_MS {
            return;
        }
        // Claim the slot before formatting: two connections rejected in the
        // same instant must not both report.
        if self
            .pressure_reported_at_ms
            .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let since = total.saturating_sub(self.pressure_reported_total.swap(total, Ordering::Relaxed));
        if since == 0 {
            return;
        }
        let nw = &self.rejected_not_wire;
        tracing::info!(
            port,
            rejected_since_last = since,
            rejected_total = total,
            rate_limited = self.rate_limited.load(Ordering::Relaxed),
            camo_failed = self.camo_failed.load(Ordering::Relaxed),
            peek_timeout = self.peek_timeout.load(Ordering::Relaxed),
            inflight_refused = self.inflight_refused.load(Ordering::Relaxed),
            // `rejection_total` sums this one too, so a reader adding up the
            // printed reasons and comparing them against `rejected_total` was
            // always short by exactly this much — and read the difference as
            // "accepted and unaccounted for". It is not: this line simply did
            // not print it. Every reason in the total is printed here now.
            inner_dial_failed = self.inner_dial_failed.load(Ordering::Relaxed),
            not_wire_too_short = nw.too_short.load(Ordering::Relaxed),
            not_wire_bad_version = nw.bad_version.load(Ordering::Relaxed),
            not_wire_bad_suite = nw.bad_suite.load(Ordering::Relaxed),
            not_wire_reserved = nw.reserved_not_zero.load(Ordering::Relaxed),
            not_wire_skew = nw.timestamp_skew.load(Ordering::Relaxed),
            "[perimeter/face] face under rejection pressure"
        );
    }

    /// Every routed flow that outlives its face's session-profile ceiling
    /// passes here — see `crate::timing::splice_backstop` and
    /// `crate::face::splice_inward`'s backstop wrap. OBSERVE-ONLY: this
    /// never closes the connection, it only counts and, at most once per
    /// [`PRESSURE_REPORT_INTERVAL_MS`] per face, reports it — the identical
    /// throttle [`Self::note_rejection_and_maybe_report`] already uses, and
    /// for the same reason: a fleet that already carries long-held
    /// mesh/customer flows on every face (per the 2026-09-16 sharding
    /// ruling) would otherwise write one line per flow, and a box
    /// legitimately carrying many long sessions would bury its own journal
    /// reporting a condition that is, today, expected rather than
    /// exceptional.
    pub fn note_splice_backstop_observed(&self, port: u16, profile: &'static str, ceiling_ms: u64) {
        self.splice_backstop_observed.fetch_add(1, Ordering::Relaxed);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last_ms = self.splice_backstop_reported_at_ms.load(Ordering::Relaxed);

        // First observation this process has made on this face reports at
        // once — same reasoning as the pressure line: the transition into
        // "this is happening at all" is the event worth knowing.
        if last_ms != 0 && now_ms.saturating_sub(last_ms) < PRESSURE_REPORT_INTERVAL_MS {
            return;
        }
        // Claim the slot before formatting: two flows crossing their
        // ceiling in the same instant must not both report.
        if self
            .splice_backstop_reported_at_ms
            .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let total = self.splice_backstop_observed.load(Ordering::Relaxed);
        let since =
            total.saturating_sub(self.splice_backstop_reported_total.swap(total, Ordering::Relaxed));
        if since == 0 {
            return;
        }
        tracing::info!(
            port,
            profile,
            ceiling_ms,
            observed_since_last = since,
            observed_total = total,
            "[perimeter/face] splice_backstop_observed — a routed flow outlived its face's plausible \
             session ceiling; observe-only, the connection was not cut"
        );
    }

    /// Everything this face refused, however it refused it. Used only by
    /// the pressure line above — the per-reason counters stay the answer to
    /// "why", this is the answer to "how much".
    fn rejection_total(&self) -> u64 {
        let nw = &self.rejected_not_wire;
        self.rate_limited.load(Ordering::Relaxed)
            + self.inflight_refused.load(Ordering::Relaxed)
            + self.camo_failed.load(Ordering::Relaxed)
            + self.peek_timeout.load(Ordering::Relaxed)
            + self.inner_dial_failed.load(Ordering::Relaxed)
            + nw.too_short.load(Ordering::Relaxed)
            + nw.bad_version.load(Ordering::Relaxed)
            + nw.bad_suite.load(Ordering::Relaxed)
            + nw.reserved_not_zero.load(Ordering::Relaxed)
            + nw.timestamp_skew.load(Ordering::Relaxed)
    }
}

/// One face's identity plus its own counters, as `Stats` remembers it.
///
/// Bundled into a single entry — rather than `Stats`'s old parallel
/// `faces`/`counters` vecs — so a face and the counters that count FOR it
/// can never drift apart under concurrent growth. `counters` is never
/// replaced once an entry exists: `Stats::relabel_face` only ever rewrites
/// `camouflage`/`label`, so a port's accumulated totals survive a swap
/// exactly as the listener serving it does — see `crate::run`'s doc, point
/// 3.
#[derive(Clone)]
struct FaceEntry {
    port: u16,
    /// The face's declared purpose, as its stable label. Taken from the
    /// `PerimeterFace` at registration rather than looked up later: the
    /// entry list is what the readout walks, and a purpose fetched from
    /// somewhere else could disagree with the counters beside it.
    purpose: String,
    /// The camouflage's own label (`none`, `tls_real`, …), kept apart from
    /// [`Self::label`] rather than reconstructed by splitting it on a colon.
    camouflage: String,
    label: String,
    counters: Arc<FaceCounters>,
}

/// One UDP face's identity plus its own counters (if it has any), as
/// `Stats` remembers it — the datagram counterpart of [`FaceEntry`].
///
/// # `counters: None` is a real, distinct state — not "not yet wired up"
///
/// A TCP [`FaceEntry`] always has counters, because `crate::face::run_face`
/// is only ever spawned for a port that is actually going to try to bind. A
/// UDP face can be refused before any of that happens at all: its declared
/// purpose's box-local relay never bound at boot
/// (`crate::Surface::bind_local_dgram_relay`), and rather than serve a
/// public socket with nowhere to relay its traffic to, `crate::Surface::
/// apply_config` never spawns a dispatcher for it — see
/// [`Stats::note_udp_face_refused`]. Until that existed, this refusal lived
/// nowhere but a log line: a box could carry a UDP face nobody off the box
/// could prove was ever declared, let alone tell why it never came up.
///
/// `counters: None` is that fact, kept apart from a face that simply has
/// not bound YET — which still gets real, live counters via
/// [`Stats::register_udp_face`] — because the two mean different things for
/// the rest of this process's life: the first can never start counting
/// anything, since the relay it needs cannot change after boot; the second
/// is mid-retry (`udp_face::bind_udp_with_retry`) and its counters are
/// already moving.
#[derive(Clone)]
struct UdpFaceEntry {
    port: u16,
    purpose: String,
    /// The camouflage's own label (`raw_udp`, …) — mirrors [`FaceEntry::
    /// camouflage`], kept apart from [`Self::label`] rather than
    /// reconstructed by splitting it on a colon, for the identical reason.
    camouflage: String,
    label: String,
    counters: Option<Arc<UdpFaceCounters>>,
    /// Set only when `counters` is `None` — verbatim, naming the missing
    /// relay and the purpose that needed it. `None` for a face that
    /// actually runs.
    refused_reason: Option<String>,
}

/// Process-wide stats: the live face list plus the boot instant for uptime.
pub struct Stats {
    started_at: Instant,
    /// Grows and shrinks over the process's life — baseline registers its
    /// own faces at boot, a capsule's faces are added on top once identity
    /// lands, and a port a LATER capsule stops declaring is removed
    /// ([`Self::retire_face`]) — never a baseline one, see
    /// `crate::run::Surface`'s own doc. An [`ArcSwap`]-wrapped `Vec` rather
    /// than a lock: registration, relabelling and retirement happen a
    /// handful of times per process life ([`Self::register_face`],
    /// [`Self::relabel_face`], [`Self::retire_face`]), so a read-copy-update
    /// over a short list costs nothing, and every `PerimeterRequest` reader
    /// ([`Self::health`], [`Self::face_states`], [`Self::snapshot`]) never
    /// blocks on it.
    faces: ArcSwap<Vec<FaceEntry>>,
    /// The live UDP face list — the datagram counterpart of [`Self::faces`].
    /// Starts empty and stays that way on every box that never has a
    /// capsule declare a UDP face (there is no baseline UDP face; see
    /// `crate::config::PerimeterConfig::udp_faces`'s own doc). Grows on
    /// [`Self::register_udp_face`] (a face that runs) and
    /// [`Self::note_udp_face_refused`] (one that never will), shrinks on
    /// [`Self::retire_udp_face`] — the same `ArcSwap`-over-a-short-`Vec`
    /// shape [`Self::faces`] uses, for the identical reason: registration,
    /// refusal and retirement happen a handful of times per process life,
    /// and every `PerimeterRequest` reader must never block on it.
    udp_faces: ArcSwap<Vec<UdpFaceEntry>>,
    /// Attached after construction by `lib.rs::run` — `Stats::new` runs
    /// before the sink exists, and inventing a second set of counters here
    /// would mean the reader and the channel disagreed.
    observation: std::sync::OnceLock<Arc<crate::observe::ObservationChannelStats>>,
}

impl Stats {
    /// Build a fresh, all-zero counter set — one [`FaceCounters`] per entry
    /// in `faces`, in the SAME order. Returns the aggregate [`Stats`] and
    /// the per-face `Arc<FaceCounters>` list so `lib.rs::run` can hand each
    /// face's own counters directly to its `crate::face::run_face` task
    /// (zip by position — no port-keyed lookup, so a hot connection path
    /// never has to handle "this port isn't registered").
    #[must_use]
    pub fn new(faces: &[PerimeterFace]) -> (Arc<Self>, Vec<Arc<FaceCounters>>) {
        let mut entries = Vec::with_capacity(faces.len());
        let mut counters = Vec::with_capacity(faces.len());
        for f in faces {
            let c = Arc::new(FaceCounters::default());
            counters.push(Arc::clone(&c));
            entries.push(FaceEntry {
                port: f.port,
                purpose: f.purpose.label().to_string(),
                camouflage: f.camouflage.label().to_string(),
                label: f.label.clone(),
                counters: c,
            });
        }
        let stats = Arc::new(Self {
            started_at: Instant::now(),
            faces: ArcSwap::from_pointee(entries),
            udp_faces: ArcSwap::from_pointee(Vec::new()),
            observation: std::sync::OnceLock::new(),
        });
        (stats, counters)
    }

    /// Register a face this process has not served before — a genuinely new
    /// port a capsule adds on top of the running surface (`crate::run`,
    /// point 3). Fresh, all-zero counters: nothing has run through this
    /// port yet.
    ///
    /// The caller decides swap-vs-register BEFORE calling either this or
    /// [`Self::relabel_face`] (`crate::run::Surface::
    /// apply_identity_when_ready` keys its own port map on the same `port`
    /// this reads), so this never checks for an existing entry itself —
    /// calling it twice for one port would duplicate that port in
    /// `Faces`/`Metrics`, exactly the drift this module's doc warns about
    /// elsewhere.
    pub fn register_face(&self, face: &PerimeterFace) -> Arc<FaceCounters> {
        let counters = Arc::new(FaceCounters::default());
        let entry = FaceEntry {
            port: face.port,
            purpose: face.purpose.label().to_string(),
            camouflage: face.camouflage.label().to_string(),
            label: face.label.clone(),
            counters: Arc::clone(&counters),
        };
        self.faces.rcu(move |current| {
            let mut next = (**current).clone();
            next.push(entry.clone());
            next
        });
        counters
    }

    /// Update an already-registered face's reported camouflage/label in
    /// place — `crate::run`'s doc, point 3: the port itself is never
    /// re-bound (`crate::face::run_face`'s listener stays open across the
    /// swap), so this leaves `counters` completely untouched and only
    /// changes what this process SAYS it presents on that port. A no-op if
    /// `port` is not yet registered — safer than panicking this crate's
    /// only public listener over a bookkeeping mismatch, though `crate::
    /// run::Surface` never calls this for a port it has not already seen
    /// bound.
    pub fn relabel_face(&self, port: u16, camouflage: &str, label: &str) {
        let camouflage = camouflage.to_string();
        let label = label.to_string();
        self.faces.rcu(move |current| {
            let mut next = (**current).clone();
            if let Some(entry) = next.iter_mut().find(|f| f.port == port) {
                entry.camouflage.clone_from(&camouflage);
                entry.label.clone_from(&label);
            }
            next
        });
    }

    /// Remove a face this process no longer serves — a capsule stopped
    /// declaring this port and `crate::run::Surface::apply_config` has
    /// already confirmed the listener itself stopped accepting before
    /// calling this, so an entry leaving here means the port is genuinely
    /// gone, not merely due to go. A no-op if `port` is not registered, the
    /// same defensive shape as [`Self::relabel_face`] — a bookkeeping
    /// mismatch must not panic this daemon's own front door. Never called
    /// for a baseline port: see `crate::run::Surface::apply_config`'s own
    /// doc for the guard that keeps this from ever happening.
    pub fn retire_face(&self, port: u16) {
        self.faces.rcu(move |current| {
            let mut next = (**current).clone();
            next.retain(|f| f.port != port);
            next
        });
    }

    /// Register a UDP face this process is actually going to run — the
    /// datagram counterpart of [`Self::register_face`]. Fresh, all-zero
    /// counters, handed back so the caller (`crate::Surface::apply_config`)
    /// can give them to `udp_face::run_udp_face`'s dispatcher and to every
    /// session task spawned for this face — the identical hand-off
    /// [`Self::register_face`] already makes for a TCP face.
    ///
    /// Same caller discipline as [`Self::register_face`]: the caller
    /// decides this port is genuinely new — not already running, not
    /// already refused — before calling this. Calling it twice for one
    /// port would duplicate that port in `Metrics`, exactly the drift this
    /// module's doc warns about elsewhere.
    pub fn register_udp_face(&self, face: &UdpFace) -> Arc<UdpFaceCounters> {
        let counters = Arc::new(UdpFaceCounters::default());
        let entry = UdpFaceEntry {
            port: face.port,
            purpose: face.purpose.label().to_string(),
            camouflage: face.camouflage.label().to_string(),
            label: face.label.clone(),
            counters: Some(Arc::clone(&counters)),
            refused_reason: None,
        };
        self.udp_faces.rcu(move |current| {
            let mut next = (**current).clone();
            next.push(entry.clone());
            next
        });
        counters
    }

    /// Record a UDP face this process refuses to run at all — see
    /// [`UdpFaceEntry`]'s own doc for why this is a distinct, permanent
    /// state rather than an ordinary dark face. `reason` is written
    /// verbatim into the reported [`mirage_core::perimeter_query::
    /// UdpFaceMetrics::refused_reason`], naming the purpose and the missing
    /// relay — the same fact `crate::Surface::apply_config`'s own log line
    /// already states in its journal. This call is what makes that fact
    /// readable OFF the box too, closing the exact gap this step exists
    /// for: a UDP face refused for a missing relay used to be
    /// indistinguishable, from outside the process, from one that was
    /// never declared.
    pub fn note_udp_face_refused(&self, face: &UdpFace, reason: &str) {
        let entry = UdpFaceEntry {
            port: face.port,
            purpose: face.purpose.label().to_string(),
            camouflage: face.camouflage.label().to_string(),
            label: face.label.clone(),
            counters: None,
            refused_reason: Some(reason.to_string()),
        };
        self.udp_faces.rcu(move |current| {
            let mut next = (**current).clone();
            next.push(entry.clone());
            next
        });
    }

    /// Remove a UDP face this process no longer serves or no longer
    /// refuses — the datagram counterpart of [`Self::retire_face`]. A no-op
    /// if `port` is not present, the same defensive shape [`Self::
    /// retire_face`] already has.
    pub fn retire_udp_face(&self, port: u16) {
        self.udp_faces.rcu(move |current| {
            let mut next = (**current).clone();
            next.retain(|f| f.port != port);
            next
        });
    }

    /// Every UDP face's counters, in the shape [`Self::snapshot`] reports
    /// them — a face that runs gets its live counters read off its atomics;
    /// a refused face gets every counter at `0`, because there was never a
    /// dispatcher to move any of them, and its own
    /// [`UdpFaceMetrics::refused_reason`] instead of `None`.
    fn udp_face_metrics(&self) -> Vec<UdpFaceMetrics> {
        self.udp_faces
            .load()
            .iter()
            .map(|f| match &f.counters {
                Some(c) => UdpFaceMetrics {
                    label: f.label.clone(),
                    port: f.port,
                    purpose: f.purpose.clone(),
                    bound: c.bound.load(Ordering::Relaxed),
                    refused_reason: None,
                    datagrams_received: c.datagrams_received.load(Ordering::Relaxed),
                    bytes_received: c.bytes_received.load(Ordering::Relaxed),
                    recv_errors: c.recv_errors.load(Ordering::Relaxed),
                    forwarded: c.forwarded.load(Ordering::Relaxed),
                    sessions_started: c.sessions_started.load(Ordering::Relaxed),
                    sessions_active: c.sessions_active.load(Ordering::Relaxed),
                    sessions_evicted_idle: c.sessions_evicted_idle.load(Ordering::Relaxed),
                    sessions_evicted_lru: c.sessions_evicted_lru.load(Ordering::Relaxed),
                    sessions_evicted_stalled: c.sessions_evicted_stalled.load(Ordering::Relaxed),
                    sessions_closed: c.sessions_closed.load(Ordering::Relaxed),
                    sweep_runs: c.sweep_runs.load(Ordering::Relaxed),
                    session_announce_dropped: c.session_announce_dropped.load(Ordering::Relaxed),
                    wire_routed: c.wire_routed.load(Ordering::Relaxed),
                    rejected_not_wire: c.refused_not_wire.snapshot(),
                    refused_drained: c.refused_drained.load(Ordering::Relaxed),
                    refused_cut: c.refused_cut.load(Ordering::Relaxed),
                    sessions_evicted_refused: c.sessions_evicted_refused.load(Ordering::Relaxed),
                    relay_send_errors: c.relay_send_errors.load(Ordering::Relaxed),
                    relay_recv_errors: c.relay_recv_errors.load(Ordering::Relaxed),
                    relay_from_monitor_unmatched: c
                        .relay_from_monitor_unmatched
                        .load(Ordering::Relaxed),
                    relay_from_monitor_dropped: c.relay_from_monitor_dropped.load(Ordering::Relaxed),
                    bytes_to_monitor: c.bytes_to_monitor.load(Ordering::Relaxed),
                    bytes_to_client: c.bytes_to_client.load(Ordering::Relaxed),
                },
                None => UdpFaceMetrics {
                    label: f.label.clone(),
                    port: f.port,
                    purpose: f.purpose.clone(),
                    bound: false,
                    refused_reason: f.refused_reason.clone(),
                    datagrams_received: 0,
                    bytes_received: 0,
                    recv_errors: 0,
                    forwarded: 0,
                    sessions_started: 0,
                    sessions_active: 0,
                    sessions_evicted_idle: 0,
                    sessions_evicted_lru: 0,
                    sessions_evicted_stalled: 0,
                    sessions_closed: 0,
                    sweep_runs: 0,
                    session_announce_dropped: 0,
                    wire_routed: 0,
                    rejected_not_wire: NotWireMetrics::default(),
                    refused_drained: 0,
                    refused_cut: 0,
                    sessions_evicted_refused: 0,
                    relay_send_errors: 0,
                    relay_recv_errors: 0,
                    relay_from_monitor_unmatched: 0,
                    relay_from_monitor_dropped: 0,
                    bytes_to_monitor: 0,
                    bytes_to_client: 0,
                },
            })
            .collect()
    }

    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Count of faces whose listener has actually bound — see
    /// [`FaceCounters::bound`]'s doc for why this is a live signal, not the
    /// configured face count.
    #[must_use]
    pub fn faces_bound(&self) -> usize {
        self.faces
            .load()
            .iter()
            .filter(|f| f.counters.bound.load(Ordering::Relaxed))
            .count()
    }

    /// The cheap read: is this process serving, and on what.
    #[must_use]
    pub fn health(&self, build_id: &str) -> PerimeterHealth {
        PerimeterHealth {
            build_id: build_id.to_string(),
            uptime_secs: self.uptime_secs(),
            faces_bound: self.faces_bound(),
            identity_grace: crate::capsule_boot::GRACE
                .snapshot(crate::capsule_boot::now_ms())
                .active,
        }
    }

    /// The face list — the answer mshd's recovery door turns into "who owns
    /// `:22`", and (since the UDP front door) the same read secd's kernel
    /// admission uses to decide which UDP ports the box accepts.
    ///
    /// The CONFIGURED faces, `bound` flag and all. A perimeter whose `:22`
    /// bind lost the race to that door still intends to serve it, and
    /// omitting it here would have the two processes swap the port back and
    /// forth forever.
    ///
    /// TCP faces first, then every UDP face appended after them — see
    /// [`FaceTransport`]'s own doc for why an older reader (a secd built
    /// before this field existed) still gets the identical TCP-only meaning
    /// it always did on a box with no UDP faces, and simply ignores the new
    /// entries on a box that has some.
    #[must_use]
    pub fn face_states(&self) -> Vec<FaceState> {
        let mut out: Vec<FaceState> = self
            .faces
            .load()
            .iter()
            .map(|f| FaceState {
                label: f.label.clone(),
                port: f.port,
                camouflage: f.camouflage.clone(),
                transport: FaceTransport::Tcp,
                bound: f.counters.bound.load(Ordering::Relaxed),
                unbound_reason: f.counters.unbound_reason.lock().ok().and_then(|r| r.clone()),
                unbound_since_ms: match f.counters.unbound_since_ms.load(Ordering::Relaxed) {
                    0 => None,
                    ms => Some(ms),
                },
                bind_attempts: f.counters.bind_attempts.load(Ordering::Relaxed),
            })
            .collect();
        out.extend(self.udp_faces.load().iter().map(|f| FaceState {
            label: f.label.clone(),
            port: f.port,
            camouflage: f.camouflage.clone(),
            transport: FaceTransport::Udp,
            bound: match &f.counters {
                Some(c) => c.bound.load(Ordering::Relaxed),
                // A refused face never bound and never will — see
                // `UdpFaceEntry`'s own doc.
                None => false,
            },
            // The same fact `udp_face_metrics()` reports as
            // `UdpFaceMetrics::refused_reason`: why this face was refused
            // outright, `None` for one that actually runs. A running UDP
            // face carries no OTHER "why is this dark" text today — unlike
            // a TCP face's per-family retry loop, nothing on this path
            // records a reason for a UDP dispatcher that has not bound yet.
            unbound_reason: f.refused_reason.clone(),
            // Neither is tracked at this face's aggregate for UDP: only its
            // two per-family (`v4`/`v6`) counters know a bind timestamp or
            // an attempt count (`UdpFaceCounters::v4`/`v6`, see
            // `udp_face.rs::UdpFamilyBind`), and there is no aggregate
            // rollup of either the way `FaceCounters` keeps one for TCP.
            // `None`/`0` here says "not tracked at this granularity", not
            // "never happened".
            unbound_since_ms: None,
            bind_attempts: 0,
        }));
        out
    }

    #[must_use]
    pub fn snapshot(&self) -> PerimeterMetrics {
        let faces = self
            .faces
            .load()
            .iter()
            .map(|f| {
                let c = &f.counters;
                FaceMetrics {
                    label: f.label.clone(),
                    port: f.port,
                    purpose: f.purpose.clone(),
                    bound: c.bound.load(Ordering::Relaxed),
                    accepted: c.accepted.load(Ordering::Relaxed),
                    rate_limited: c.rate_limited.load(Ordering::Relaxed),
                    camo_failed: c.camo_failed.load(Ordering::Relaxed),
                    peek_timeout: c.peek_timeout.load(Ordering::Relaxed),
                    wire_routed: c.wire_routed.load(Ordering::Relaxed),
                    ssh_routed: c.ssh_routed.load(Ordering::Relaxed),
                    rejected_not_wire: c.rejected_not_wire.snapshot(),
                    inner_dial_failed: c.inner_dial_failed.load(Ordering::Relaxed),
                    jailed: c.jailed.load(Ordering::Relaxed),
                    hard_cut: c.hard_cut.load(Ordering::Relaxed),
                    jail_at_capacity: c.jail_at_capacity.load(Ordering::Relaxed),
                    jail_no_handle: c.jail_no_handle.load(Ordering::Relaxed),
                    jail_holding_now: c.jail_holding_now.load(Ordering::Relaxed),
                    bytes_to_inner: c.bytes_to_inner.load(Ordering::Relaxed),
                    bytes_to_client: c.bytes_to_client.load(Ordering::Relaxed),
                    splice_backstop_observed: c.splice_backstop_observed.load(Ordering::Relaxed),
                }
            })
            .collect();
        let observation_channel = self
            .observation
            .get()
            .map(|o| ObservationChannelMetrics {
                queued: o.queued.load(Ordering::Relaxed),
                dropped_full: o.dropped_full.load(Ordering::Relaxed),
                sent: o.sent.load(Ordering::Relaxed),
                dropped_io: o.dropped_io.load(Ordering::Relaxed),
                dropped_permission: o.dropped_permission.load(Ordering::Relaxed),
                connects: o.connects.load(Ordering::Relaxed),
            })
            .unwrap_or_default();
        PerimeterMetrics {
            uptime_secs: self.uptime_secs(),
            faces,
            observation_channel,
            identity_grace: crate::capsule_boot::GRACE.snapshot(crate::capsule_boot::now_ms()),
            udp_faces: self.udp_face_metrics(),
        }
    }

    /// Attach the observation channel's counters. Called once, from
    /// `lib.rs::run`, after the sink is spawned.
    pub fn attach_observation(&self, stats: Arc<crate::observe::ObservationChannelStats>) {
        let _ = self.observation.set(stats);
    }
}

/// Answer one question. Pure over `stats`, so the protocol is testable
/// without a socket.
#[must_use]
pub fn answer(stats: &Stats, build_id: &str, req: PerimeterRequest) -> PerimeterResponse {
    match req {
        PerimeterRequest::Health => PerimeterResponse::Health(stats.health(build_id)),
        PerimeterRequest::Faces => PerimeterResponse::Faces(stats.face_states()),
        PerimeterRequest::Metrics => PerimeterResponse::Metrics(Box::new(stats.snapshot())),
    }
}

/// Serve the query channel forever. Returns only if the BIND itself fails —
/// the caller treats that as non-fatal to the perimeter's actual job (see
/// `lib.rs::Surface::bind_baseline`'s call site): a channel nobody can read
/// must never take down the faces that are actually routing traffic.
///
/// It is not harmless either, and the caller says so loudly: mshd's recovery
/// door reads the face list off this channel to decide who owns `:22`, and a
/// channel that never bound makes that read fail — which resolves towards the
/// door HOLDING the port. The safe direction, but the operator's SSH path
/// then arrives without the perimeter's classification and jail.
pub async fn run_query_server(stats: Arc<Stats>, build_id: &'static str) -> std::io::Result<()> {
    mirage_core::local_rpc::serve(LocalChannel::PerimeterQuery, move |req: PerimeterRequest| {
        let stats = Arc::clone(&stats);
        async move { answer(&stats, build_id, req) }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::NotWireReason;
    use mirage_core::mirage::wire::camouflage::TransportCamouflage;

    fn face(port: u16) -> PerimeterFace {
        PerimeterFace {
            port,
            camouflage: TransportCamouflage::None,
            label: format!("none:{port}"),
            purpose: crate::config::FacePurpose::MonitorWire,
        }
    }

    #[test]
    fn fresh_stats_are_all_zero() {
        let (stats, counters) = Stats::new(&[face(443), face(80)]);
        assert_eq!(counters.len(), 2);
        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 2);
        for f in &snap.faces {
            assert_eq!(f.accepted, 0);
            assert!(!f.bound);
        }
        assert_eq!(stats.faces_bound(), 0);
    }

    #[test]
    fn mark_bound_is_reflected_in_faces_bound() {
        let (stats, counters) = Stats::new(&[face(443), face(80)]);
        counters[0].mark_bound();
        assert_eq!(stats.faces_bound(), 1);
        counters[1].mark_bound();
        assert_eq!(stats.faces_bound(), 2);
    }

    // ── The family split (`AddressFamily` / `FamilyBind`) ──
    //
    // These exercise exactly the fact this module's `AddressFamily` doc
    // measures: a face serving IPv4 only is not the same fact as one serving
    // both, or neither, and the aggregate `bound`/`unbound_reason` a wire
    // reader sees must stay honest across every combination of the two.

    #[test]
    fn a_face_bound_on_v4_alone_counts_as_bound() {
        let c = FaceCounters::default();
        c.mark_family_bound(AddressFamily::V4);
        assert!(c.v4.bound.load(Ordering::Relaxed));
        assert!(!c.v6.bound.load(Ordering::Relaxed), "v6 was never touched");
        assert!(
            c.bound.load(Ordering::Relaxed),
            "the aggregate is reachable the instant EITHER family lands"
        );
    }

    #[test]
    fn a_face_dark_on_both_families_is_not_bound() {
        let c = FaceCounters::default();
        c.note_family_bind_failed(AddressFamily::V4, "Address in use (os error 98)", 1_000, false);
        c.note_family_bind_failed(
            AddressFamily::V6,
            "Address family not supported (os error 97)",
            1_000,
            true,
        );
        assert!(!c.bound.load(Ordering::Relaxed));
        let reason = c.unbound_reason.lock().unwrap().clone().unwrap();
        assert!(
            reason.starts_with("v6:"),
            "the aggregate reason names the family the LAST failure came from: {reason}"
        );
    }

    #[test]
    fn one_family_dark_while_the_other_serves_does_not_unbind_the_face() {
        // The exact shape a host with no IPv6 reaches at steady state: v4
        // is up, v6 gave up once and stays permanently absent. The face
        // must read as bound throughout — mshd's door-check and secd's
        // kernel admission only ever ask "is anybody serving this port".
        let c = FaceCounters::default();
        c.mark_family_bound(AddressFamily::V4);
        c.note_family_bind_failed(
            AddressFamily::V6,
            "Address family not supported (os error 97)",
            2_000,
            true,
        );
        assert!(c.bound.load(Ordering::Relaxed), "v4 alone is enough to serve the face");
        assert!(
            c.unbound_reason.lock().unwrap().is_none(),
            "a face that is actually serving must not report a reason for being dark"
        );
        assert!(c.v6.permanently_absent.load(Ordering::Relaxed));
        assert!(!c.v4.permanently_absent.load(Ordering::Relaxed));
    }

    #[test]
    fn a_family_recovering_clears_the_aggregate_dark_state() {
        let c = FaceCounters::default();
        c.note_family_bind_failed(AddressFamily::V4, "Address in use (os error 98)", 1_000, false);
        c.note_family_bind_failed(AddressFamily::V6, "Address in use (os error 98)", 1_000, false);
        assert!(!c.bound.load(Ordering::Relaxed));

        c.mark_family_bound(AddressFamily::V4);
        assert!(c.bound.load(Ordering::Relaxed));
        assert!(c.unbound_reason.lock().unwrap().is_none());
        assert_eq!(c.unbound_since_ms.load(Ordering::Relaxed), 0);
        // The other family's own history is untouched by the aggregate
        // clearing — it never bound and does not pretend otherwise.
        assert!(!c.v6.bound.load(Ordering::Relaxed));
    }

    #[test]
    fn a_transiently_retrying_family_behind_a_served_face_does_not_inflate_the_aggregate_attempts() {
        // v4 is up. v6 keeps failing a transient bind in the background —
        // its OWN attempt count keeps rising, but the face as a whole is not
        // "troubled": it is being served. The aggregate answers a coarser
        // question than the per-family counters do, on purpose.
        let c = FaceCounters::default();
        c.mark_family_bound(AddressFamily::V4);
        for _ in 0..5 {
            c.note_family_bind_failed(AddressFamily::V6, "Address in use (os error 98)", 3_000, false);
        }
        assert_eq!(c.v6.bind_attempts.load(Ordering::Relaxed), 5);
        assert_eq!(
            c.bind_attempts.load(Ordering::Relaxed),
            0,
            "the face was never fully dark, so the aggregate attempt count never moved"
        );
    }

    #[test]
    fn permanently_absent_is_distinct_from_still_retrying() {
        let c = FaceCounters::default();
        c.note_family_bind_failed(AddressFamily::V6, "Address in use (os error 98)", 1_000, false);
        assert!(!c.v6.permanently_absent.load(Ordering::Relaxed), "transient, still retrying");

        c.note_family_bind_failed(
            AddressFamily::V6,
            "Address family not supported (os error 97)",
            1_000,
            true,
        );
        assert!(c.v6.permanently_absent.load(Ordering::Relaxed));
    }

    /// The transition from quiet to rejecting reports at once — a short
    /// burst that ends inside the interval must not go unrecorded.
    #[test]
    fn first_rejection_on_a_face_reports_immediately() {
        let c = FaceCounters::default();
        c.rejected_not_wire.record(NotWireReason::BadVersion(0x47));
        c.note_rejection_and_maybe_report(443);
        assert_ne!(c.pressure_reported_at_ms.load(Ordering::Relaxed), 0);
        assert_eq!(c.pressure_reported_total.load(Ordering::Relaxed), 1);
    }

    /// A steady storm is one line a minute, not one per connection. This is
    /// the whole reason the per-connection line stayed at `debug`.
    #[test]
    fn a_second_rejection_inside_the_interval_does_not_report() {
        let c = FaceCounters::default();
        c.rejected_not_wire.record(NotWireReason::BadVersion(0x47));
        c.note_rejection_and_maybe_report(443);
        let first_at = c.pressure_reported_at_ms.load(Ordering::Relaxed);

        for _ in 0..79 {
            c.rejected_not_wire.record(NotWireReason::TooShort(3));
            c.note_rejection_and_maybe_report(443);
        }
        assert_eq!(
            c.pressure_reported_at_ms.load(Ordering::Relaxed),
            first_at,
            "no second report inside the interval"
        );
        assert_eq!(
            c.pressure_reported_total.load(Ordering::Relaxed),
            1,
            "the snapshot only advances when a line is emitted"
        );
    }

    /// After the interval the line carries the DELTA, so the journal shows
    /// the rate rather than an ever-growing total.
    #[test]
    fn after_the_interval_the_report_carries_the_delta() {
        let c = FaceCounters::default();
        c.rejected_not_wire.record(NotWireReason::BadVersion(0x47));
        c.note_rejection_and_maybe_report(443);

        // 79 more brings the total to 80 — a multiple of the clock-sampling
        // stride, so this call reaches the clock. See CLOCK_SAMPLE_EVERY.
        for _ in 0..79 {
            c.rejected_not_wire.record(NotWireReason::TooShort(3));
        }
        // Age the last report past the interval.
        let aged = c.pressure_reported_at_ms.load(Ordering::Relaxed)
            - (PRESSURE_REPORT_INTERVAL_MS + 1);
        c.pressure_reported_at_ms.store(aged, Ordering::Relaxed);

        c.note_rejection_and_maybe_report(443);
        assert_eq!(
            c.pressure_reported_total.load(Ordering::Relaxed),
            80,
            "the snapshot advances to the new total"
        );
        assert_ne!(c.pressure_reported_at_ms.load(Ordering::Relaxed), aged);
    }

    /// A face that stopped being hit stops writing. Silence has to mean
    /// something again once the storm ends.
    #[test]
    fn a_quiet_face_stops_reporting() {
        let c = FaceCounters::default();
        c.rejected_not_wire.record(NotWireReason::BadVersion(0x47));
        c.note_rejection_and_maybe_report(443);
        let reported_at = c.pressure_reported_at_ms.load(Ordering::Relaxed);

        // Interval elapses with no new rejections: the slot is claimed, the
        // delta is zero, no line.
        let aged = reported_at - (PRESSURE_REPORT_INTERVAL_MS + 1);
        c.pressure_reported_at_ms.store(aged, Ordering::Relaxed);
        c.note_rejection_and_maybe_report(443);
        assert_eq!(
            c.pressure_reported_total.load(Ordering::Relaxed),
            1,
            "nothing new to report"
        );
    }

    #[test]
    fn rejection_total_counts_every_way_a_face_refuses() {
        let c = FaceCounters::default();
        c.rate_limited.fetch_add(2, Ordering::Relaxed);
        c.camo_failed.fetch_add(3, Ordering::Relaxed);
        c.inflight_refused.fetch_add(1, Ordering::Relaxed);
        c.peek_timeout.fetch_add(1, Ordering::Relaxed);
        c.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
        c.rejected_not_wire.record(NotWireReason::ReservedNotZero);
        assert_eq!(c.rejection_total(), 9);
    }

    #[test]
    fn not_wire_counters_break_down_by_discriminant() {
        let (stats, counters) = Stats::new(&[face(443)]);
        counters[0].rejected_not_wire.record(NotWireReason::BadVersion(0x47));
        counters[0].rejected_not_wire.record(NotWireReason::BadVersion(0x50));
        counters[0]
            .rejected_not_wire
            .record(NotWireReason::TimestampSkew { ts_ms: 1, now_ms: 2 });
        let snap = stats.snapshot();
        assert_eq!(snap.faces[0].rejected_not_wire.bad_version, 2);
        assert_eq!(snap.faces[0].rejected_not_wire.timestamp_skew, 1);
        assert_eq!(snap.faces[0].rejected_not_wire.too_short, 0);
    }

    #[test]
    fn dropped_permission_is_a_distinct_counter_and_survives_the_snapshot() {
        let (stats, _counters) = Stats::new(&[face(443)]);
        let observation = Arc::new(crate::observe::ObservationChannelStats::default());
        observation.dropped_permission.fetch_add(1, Ordering::Relaxed);
        observation.dropped_io.fetch_add(2, Ordering::Relaxed);
        stats.attach_observation(Arc::clone(&observation));

        let snap = stats.snapshot();
        assert_eq!(snap.observation_channel.dropped_permission, 1);
        assert_eq!(
            snap.observation_channel.dropped_io, 2,
            "dropped_permission must not fold into dropped_io"
        );
    }

    #[test]
    fn labels_and_ports_survive_into_the_snapshot() {
        let (stats, _counters) = Stats::new(&[face(443), face(22)]);
        let snap = stats.snapshot();
        assert_eq!(snap.faces[0].port, 443);
        assert_eq!(snap.faces[0].label, "none:443");
        assert_eq!(snap.faces[1].port, 22);
    }

    // ── The query protocol ──

    #[test]
    fn the_face_list_carries_the_camouflage_as_its_own_field() {
        // Not reconstructed by splitting the label on a colon: a camouflage
        // label is free to contain one, and mshd asks about the PORT while
        // an operator reads the disguise.
        let (stats, counters) = Stats::new(&[face(22), face(443)]);
        counters[0].mark_bound();

        let PerimeterResponse::Faces(faces) = answer(&stats, "test", PerimeterRequest::Faces)
        else {
            panic!("Faces must be answered with a face list");
        };
        assert_eq!(faces.len(), 2);
        assert_eq!(faces[0].port, 22);
        assert_eq!(faces[0].camouflage, "none");
        assert!(faces[0].bound);
        assert!(!faces[1].bound, "an unbound face still belongs to the perimeter");
    }

    #[test]
    fn a_perimeter_with_no_faces_answers_an_empty_list_not_an_error() {
        // The state a capsule-less boot reaches. "Running with no faces" and
        // "cannot be asked" are different answers, and only the second is a
        // reason for mshd to hold the door on an unreadable read.
        let (stats, _counters) = Stats::new(&[]);
        let PerimeterResponse::Faces(faces) = answer(&stats, "test", PerimeterRequest::Faces)
        else {
            panic!("Faces must be answered with a face list");
        };
        assert!(faces.is_empty());
    }

    #[test]
    fn health_reports_bound_faces_not_configured_ones() {
        let (stats, counters) = Stats::new(&[face(22), face(80), face(443)]);
        counters[0].mark_bound();
        let PerimeterResponse::Health(h) = answer(&stats, "0.1.0", PerimeterRequest::Health) else {
            panic!("Health must be answered with health");
        };
        assert_eq!(h.build_id, "0.1.0");
        assert_eq!(
            h.faces_bound, 1,
            "a face that failed to bind must not be counted as healthy"
        );
    }

    #[test]
    fn every_request_is_answered_by_its_own_variant() {
        let (stats, _counters) = Stats::new(&[face(22)]);
        assert!(matches!(
            answer(&stats, "t", PerimeterRequest::Health),
            PerimeterResponse::Health(_)
        ));
        assert!(matches!(
            answer(&stats, "t", PerimeterRequest::Faces),
            PerimeterResponse::Faces(_)
        ));
        assert!(matches!(
            answer(&stats, "t", PerimeterRequest::Metrics),
            PerimeterResponse::Metrics(_)
        ));
    }

    // ── Growing the surface (`crate::run::Surface`) ──

    /// A capsule adding a genuinely new port must show up in `Faces`
    /// alongside whatever the baseline already registered, with its own
    /// fresh, all-zero counters — the baseline's own faces must not move or
    /// reset.
    #[test]
    fn register_face_adds_a_port_without_disturbing_the_others() {
        let (stats, baseline_counters) = Stats::new(&[face(22), face(80), face(443)]);
        baseline_counters[0].accepted.fetch_add(7, Ordering::Relaxed);

        let new_counters = stats.register_face(&face(8443));
        new_counters.accepted.fetch_add(1, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 4);
        assert!(snap.faces.iter().any(|f| f.port == 8443 && f.accepted == 1));
        assert!(
            snap.faces.iter().any(|f| f.port == 22 && f.accepted == 7),
            "an already-registered face's counters must survive a later registration"
        );
    }

    /// The mechanism behind `crate::run`'s point 3: swapping a port's
    /// reported camouflage/label must never touch that port's counters —
    /// the listener never stopped, so what it already counted is still
    /// true.
    #[test]
    fn relabel_face_changes_the_disguise_and_keeps_the_counters() {
        let (stats, counters) = Stats::new(&[face(443)]);
        counters[0].mark_bound();
        counters[0].wire_routed.fetch_add(3, Ordering::Relaxed);

        stats.relabel_face(443, "tls_real", "tls_real:443");

        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 1, "a swap must never duplicate the port");
        assert_eq!(snap.faces[0].label, "tls_real:443");
        assert!(snap.faces[0].bound, "the listener never stopped");
        assert_eq!(
            snap.faces[0].wire_routed, 3,
            "the port's own history must survive the swap, exactly like its listener does"
        );

        let PerimeterResponse::Faces(faces) = answer(&stats, "t", PerimeterRequest::Faces) else {
            panic!("Faces must be answered with a face list");
        };
        assert_eq!(faces[0].camouflage, "tls_real");
    }

    /// A port `relabel_face` has never heard of is a no-op, not a panic —
    /// this crate's only public listener must not go down over a
    /// bookkeeping mismatch.
    #[test]
    fn relabel_face_on_an_unknown_port_does_nothing() {
        let (stats, _counters) = Stats::new(&[face(22)]);
        stats.relabel_face(9999, "tls_real", "tls_real:9999");
        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 1);
        assert_eq!(snap.faces[0].port, 22);
    }

    // ── Shrinking the surface (`crate::run::Surface::apply_config`) ──

    /// The other half of `register_face`'s own test: retiring a port must
    /// remove exactly that one entry from `Faces`/`Metrics` and leave every
    /// other face's counters untouched.
    #[test]
    fn retire_face_removes_exactly_that_port_and_nothing_else() {
        let (stats, counters) = Stats::new(&[face(22), face(80), face(3000)]);
        counters[0].accepted.fetch_add(4, Ordering::Relaxed);
        counters[2].accepted.fetch_add(9, Ordering::Relaxed);

        stats.retire_face(80);

        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 2, "the retired port must be gone, not merely zeroed");
        assert!(snap.faces.iter().all(|f| f.port != 80), "the readout must not still name 80");
        assert!(
            snap.faces.iter().any(|f| f.port == 22 && f.accepted == 4),
            "an unrelated face's own counters must survive another face's retirement"
        );
        assert!(snap.faces.iter().any(|f| f.port == 3000 && f.accepted == 9));

        let PerimeterResponse::Faces(faces) = answer(&stats, "t", PerimeterRequest::Faces) else {
            panic!("Faces must be answered with a face list");
        };
        assert!(faces.iter().all(|f| f.port != 80), "the query channel must not report it either");
    }

    /// A port `retire_face` has never heard of is a no-op, not a panic —
    /// the same defensive shape [`Stats::relabel_face`] already has.
    #[test]
    fn retire_face_on_an_unknown_port_does_nothing() {
        let (stats, _counters) = Stats::new(&[face(22)]);
        stats.retire_face(9999);
        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 1);
        assert_eq!(snap.faces[0].port, 22);
    }

    /// Retiring the SAME port twice must not panic and must not affect any
    /// other face — the second call finds nothing to remove, exactly like
    /// retiring a port that was never registered.
    #[test]
    fn retiring_the_same_port_twice_is_a_no_op_the_second_time() {
        let (stats, _counters) = Stats::new(&[face(22), face(80)]);
        stats.retire_face(80);
        stats.retire_face(80);
        let snap = stats.snapshot();
        assert_eq!(snap.faces.len(), 1);
        assert_eq!(snap.faces[0].port, 22);
    }

    // ── UDP faces (U0 step 7 — wiring `udp_face::UdpFaceCounters` into this
    // query surface) ──

    fn udp_face(port: u16) -> UdpFace {
        UdpFace {
            port,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: format!("0.0.0.0:{port}").parse().expect("valid bind addr"),
            },
            label: format!("raw_udp:{port}"),
            purpose: crate::config::FacePurpose::MonitorWire,
        }
    }

    /// Proof 1: a registered UDP face is readable over the query surface,
    /// and its counters move when it counts something — the TCP face
    /// registered alongside it is untouched.
    #[test]
    fn a_registered_udp_face_appears_in_metrics_with_moving_counters() {
        let (stats, _counters) = Stats::new(&[face(443)]);
        let udp_counters = stats.register_udp_face(&udp_face(51000));

        udp_counters.mark_family_bound(AddressFamily::V4);
        udp_counters.datagrams_received.fetch_add(5, Ordering::Relaxed);
        udp_counters.wire_routed.fetch_add(2, Ordering::Relaxed);

        let snap = stats.snapshot();
        let reported = snap
            .udp_faces
            .iter()
            .find(|f| f.port == 51000)
            .expect("a registered UDP face must be in the reported set");
        assert!(reported.bound, "a face bound on at least one family reports bound");
        assert_eq!(reported.datagrams_received, 5, "the counters must move");
        assert_eq!(reported.wire_routed, 2);
        assert!(reported.refused_reason.is_none(), "a face that runs is never 'refused'");
        assert_eq!(snap.faces.len(), 1, "the TCP face must be unaffected");
        assert_eq!(snap.faces[0].port, 443);
    }

    /// Proof 2 (the `Stats`-level half): retiring a UDP face removes it from
    /// the reported set, not merely zeroes it. The end-to-end half — that
    /// this only happens after `Surface::apply_config` has actually awaited
    /// the retiring face's join handles, not merely fired its cancel token —
    /// is `mirage_perimeter::tests::a_udp_face_is_gone_from_the_query_
    /// surface_only_after_retirement_completes` in `lib.rs`.
    #[test]
    fn a_retired_udp_face_is_gone_from_the_reported_set() {
        let (stats, _counters) = Stats::new(&[]);
        stats.register_udp_face(&udp_face(51001));
        assert_eq!(stats.snapshot().udp_faces.len(), 1);

        stats.retire_udp_face(51001);

        assert!(
            stats.snapshot().udp_faces.is_empty(),
            "a retired UDP face must be gone from the readout, not merely zeroed"
        );
    }

    /// A port `retire_udp_face` has never heard of is a no-op, not a panic —
    /// the same defensive shape [`Stats::retire_face`] already has.
    #[test]
    fn retire_udp_face_on_an_unknown_port_does_nothing() {
        let (stats, _counters) = Stats::new(&[]);
        stats.register_udp_face(&udp_face(51002));
        stats.retire_udp_face(9999);
        assert_eq!(stats.snapshot().udp_faces.len(), 1);
    }

    /// Proof 3: a UDP face refused for a missing relay is reported as
    /// refused — distinguishable both from a face that runs (`refused_
    /// reason: None`) and from a port nobody ever declared at all (absent
    /// from the list entirely). Every counter on a refused face is
    /// genuinely `0`: there was never a dispatcher to count anything with.
    #[test]
    fn a_refused_udp_face_is_reported_distinct_from_one_never_declared() {
        let (stats, _counters) = Stats::new(&[]);
        stats.note_udp_face_refused(
            &udp_face(51003),
            "perimeter-wire-dgram relay for purpose monitor-wire never bound at boot",
        );

        let snap = stats.snapshot();
        let refused = snap
            .udp_faces
            .iter()
            .find(|f| f.port == 51003)
            .expect("a refused face must be reported, not merely absent");
        assert!(!refused.bound, "a refused face never binds anything");
        assert!(
            refused.refused_reason.as_deref().unwrap().contains("never bound at boot"),
            "the reason must name the missing relay verbatim"
        );
        assert_eq!(refused.datagrams_received, 0);
        assert_eq!(refused.sessions_active, 0);

        assert!(
            snap.udp_faces.iter().all(|f| f.port != 51004),
            "a port nobody ever declared must not appear in the reported set at all"
        );
    }

    /// Proof 4: the state every box on the fleet is in today — no UDP face
    /// ever declared. `Metrics.udp_faces` is empty, and the TCP-only shape
    /// is otherwise unaffected.
    #[test]
    fn a_perimeter_with_no_udp_faces_reports_an_empty_udp_list() {
        let (stats, _counters) = Stats::new(&[face(443), face(80)]);
        let snap = stats.snapshot();
        assert!(snap.udp_faces.is_empty());
        assert_eq!(snap.faces.len(), 2);
    }

    // ── `face_states()` learns about UDP faces (secd's admission read) ──

    /// A registered, bound UDP face shows up in `Faces` alongside the TCP
    /// faces, tagged `FaceTransport::Udp` — this is what lets secd's
    /// `perimeter_admission::admitted_ports` ever admit a UDP port at all.
    #[test]
    fn a_registered_udp_face_appears_in_face_states_as_udp() {
        let (stats, _counters) = Stats::new(&[face(443)]);
        let udp_counters = stats.register_udp_face(&udp_face(51000));
        udp_counters.mark_family_bound(AddressFamily::V4);

        let faces = stats.face_states();
        assert_eq!(faces.len(), 2, "the TCP face and the UDP face both report");
        let udp = faces
            .iter()
            .find(|f| f.port == 51000)
            .expect("the registered UDP face must be in the reported set");
        assert_eq!(udp.transport, FaceTransport::Udp);
        assert!(udp.bound);
        assert_eq!(udp.camouflage, "raw_udp");
        assert_eq!(udp.label, "raw_udp:51000");
        assert!(udp.unbound_reason.is_none());
    }

    /// A UDP face refused for a missing relay reports `bound: false` and
    /// carries the refusal reason — the same fact `udp_face_metrics()`
    /// reports as `refused_reason`, read here through `unbound_reason`.
    #[test]
    fn a_refused_udp_face_appears_unbound_with_its_refusal_reason() {
        let (stats, _counters) = Stats::new(&[]);
        stats.note_udp_face_refused(
            &udp_face(51003),
            "perimeter-wire-dgram relay for purpose monitor-wire never bound at boot",
        );

        let faces = stats.face_states();
        let refused = faces
            .iter()
            .find(|f| f.port == 51003)
            .expect("a refused UDP face must still be reported");
        assert_eq!(refused.transport, FaceTransport::Udp);
        assert!(!refused.bound);
        assert!(refused
            .unbound_reason
            .as_deref()
            .expect("a refused face names why")
            .contains("never bound at boot"));
    }

    /// The state every box on the fleet is in today: no UDP face declared at
    /// all. `face_states()` must answer exactly what it always did — every
    /// TCP entry tagged `Tcp`, and the count unchanged. `#[serde(default)]`
    /// still puts `"transport":"tcp"` on the wire for these entries (see
    /// `mirage_core::perimeter_query::FaceState::transport`'s own doc for why
    /// that is acceptable: an old secd ignores unknown fields), so the
    /// byte-identical claim is proven here at the level that matters — the
    /// TCP entries' own transport and the total count — not at the level of
    /// raw JSON bytes.
    #[test]
    fn a_perimeter_with_no_udp_faces_reports_tcp_only_face_states() {
        let (stats, counters) = Stats::new(&[face(22), face(443)]);
        counters[0].mark_bound();

        let faces = stats.face_states();
        assert_eq!(faces.len(), 2, "no UDP entries appear when none are registered");
        for f in &faces {
            assert_eq!(f.transport, FaceTransport::Tcp);
        }
        assert!(faces.iter().any(|f| f.port == 22 && f.bound));
        assert!(faces.iter().any(|f| f.port == 443 && !f.bound));
    }
}
