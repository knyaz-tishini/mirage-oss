//! What the perimeter answers when something on the box asks it a question.
//!
//! # One definition, and why that is the whole point
//!
//! These types were defined TWICE: once in `mirage-perimeter::stats`, which
//! produced them, and once in `operator-box::perimeter_stats`, which parsed
//! them back out of JSON. Two descriptions of one shape, kept in step by
//! hand. They had already drifted — the operator's copy carried an
//! `ssh_unconfigured` counter the perimeter no longer emits, and for a while
//! the perimeter emitted `ssh_routed` while the operator's copy did not, so
//! serde silently dropped 1483 routed connections and the SSH path read as
//! dead.
//!
//! They live in `mirage-core` so producer and every consumer compile against
//! the same struct. A field renamed is a build error, not a `null`.
//!
//! # QUERY, not control
//!
//! Nothing on this channel changes what the perimeter does. Every variant of
//! [`PerimeterRequest`] is a read, and the name says so — the perimeter is
//! the process chewing on attacker-controlled bytes, and it takes
//! instructions from its sealed capsule and from nowhere else.
//!
//! # Who asks what
//!
//! - **mshd** asks [`PerimeterRequest::Faces`] to decide who owns `:22`. It
//!   used to pull the whole metrics blob and fish `faces[].port` out of the
//!   JSON — a boolean decision made by parsing a diagnostics snapshot. A
//!   typed question now gets a typed answer, with no dependency on a monitor,
//!   which is what makes it work on a box holding no capsule.
//! - **the monitor** asks [`PerimeterRequest::Metrics`] on its telemetry tick
//!   and folds the result into what it already gossips. The monitor is the
//!   box's aggregation plane; that this path did not exist is why the
//!   operator was reading perimeter counters by running `curl` on the box
//!   over mshd's exec channel.
//! - **mshd** also answers [`PerimeterRequest::Metrics`] to the operator when
//!   there is no monitor to have them. Not a fallback — the survival mode
//!   this fleet is built around.
//!
//! # Events push, metrics pull
//!
//! The perimeter PUSHES `LocalSecurityEvent`s to secd and is PULLED for
//! metrics here, and the split is principled rather than incidental: an event
//! is a fact that happened once and is lost if nobody is listening at that
//! instant, while a metric is a value that is still true when somebody gets
//! round to asking. Pushing metrics would need a queue, a backpressure policy
//! and a staleness rule, all to deliver something the asker could have read.

use std::io;

use serde::{Deserialize, Serialize};

/// A question for the perimeter. Every variant is a read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerimeterRequest {
    /// Is it up, which build, how many faces are actually bound.
    Health,
    /// The face list — the one question that decides who owns a port.
    Faces,
    /// Every counter this process keeps.
    Metrics,
}

/// The perimeter's answer. One variant per request, matched by shape rather
/// than by a status code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerimeterResponse {
    Health(PerimeterHealth),
    Faces(Vec<FaceState>),
    Metrics(Box<PerimeterMetrics>),
}

/// The cheap read: is this process serving, and on what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerimeterHealth {
    pub build_id: String,
    pub uptime_secs: u64,
    /// Faces whose listener has actually bound — a live signal, never the
    /// configured count. A face that failed to bind must show up as not
    /// bound rather than be counted as healthy.
    pub faces_bound: usize,
    /// True while this boot serves on a rest capsule rather than one
    /// verified fresh for this boot. Rides on the cheap read too, because
    /// `/health` is the first thing anything checks and "ok" must not read
    /// as "identity fully current".
    pub identity_grace: bool,
}

/// Which transport one face's port is admitted on.
///
/// Every face was TCP until the UDP front door existed, so a reader built
/// before this variant existed — an older secd, an older `Faces` consumer —
/// must keep reading every face as TCP even after a newer perimeter starts
/// reporting a mix. [`Default`] is what makes that agreement automatic: an
/// older WRITER (a perimeter build that never sends this field at all) and a
/// newer READER (a secd that now looks at it) both land on `Tcp` without
/// either side special-casing the other's version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FaceTransport {
    #[default]
    Tcp,
    Udp,
}

/// One face, as the perimeter itself sees it.
///
/// The CONFIGURED list, `bound` flag and all, which is deliberate: a
/// perimeter whose `:22` bind lost a race to mshd's recovery door still
/// intends to serve it, and answering "no" there would have the two
/// processes swap the port back and forth forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaceState {
    /// `"<camouflage>:<port>"` — what the logs and counters key on.
    pub label: String,
    pub port: u16,
    /// Which disguise a client has to get through on this port, not merely
    /// which port it is.
    pub camouflage: String,
    /// TCP or UDP — see [`FaceTransport`]'s own doc for why the default
    /// direction is `Tcp` and why that is deliberate, not merely convenient:
    /// every face reported by a perimeter build that predates this field WAS
    /// TCP, so a secd that now reads `transport` on a face an old perimeter
    /// never labelled gets the fact that was always true, not a guess.
    #[serde(default)]
    pub transport: FaceTransport,
    /// Whether this face's listener is bound right now.
    pub bound: bool,
    /// Why this face is NOT bound, verbatim from the failing `bind`.
    ///
    /// `bound: false` alone says a port is not being served and stops
    /// there. It does not distinguish "nothing has tried yet" from
    /// "something else owns this port", and on 2026-08-28 that difference
    /// was the whole story: three fleet boxes ran an OS `sshd` on
    /// `0.0.0.0:22` while the perimeter retried the same bind every minute
    /// — `Address in use (os error 98)`, attempt 9973 — and said so
    /// nowhere but its own journal. The posture read green throughout, and
    /// the operator's SSH went into that `sshd` rather than into `mshd`.
    ///
    /// `None` while bound. Additive with `#[serde(default)]`: a reader
    /// talking to an older perimeter gets `None`/`0` rather than a parse
    /// failure.
    #[serde(default)]
    pub unbound_reason: Option<String>,
    /// When this face last STOPPED being bound (or first failed to bind),
    /// ms since epoch. A dark face is a different fact at ten seconds and
    /// at nine days, and the count alone cannot tell them apart.
    #[serde(default)]
    pub unbound_since_ms: Option<u64>,
    /// How many times `bind` has been attempted for this face since the
    /// process started. Rises only while the face is dark.
    #[serde(default)]
    pub bind_attempts: u64,
}

/// Every counter this process keeps, in one read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerimeterMetrics {
    pub uptime_secs: u64,
    pub faces: Vec<FaceMetrics>,
    /// State of the observation channel to the arbiter. Process-wide, not
    /// per face — the queue and the socket are one each.
    ///
    /// It is here because a ban ladder whose input channel is dead looks
    /// exactly like an internet with no scanners on it. `sent` climbing is
    /// the only evidence that the arbiter is hearing anything at all, and
    /// `connects` staying at zero is the signature of a secd that never came
    /// up.
    #[serde(default)]
    pub observation_channel: ObservationChannelMetrics,
    /// The full-detail counterpart to [`PerimeterHealth::identity_grace`]'s
    /// terse boolean.
    #[serde(default)]
    pub identity_grace: GraceSnapshot,
    /// Every UDP face's counters, in the same read — the datagram
    /// counterpart of [`Self::faces`]. See [`UdpFaceMetrics`]'s own doc for
    /// the two ways one shows up here (a face that runs, and a face refused
    /// outright).
    ///
    /// `skip_serializing_if`, not merely `default`: a perimeter that has
    /// never declared a UDP face — which, as of this writing, is every box
    /// on the fleet — emits the exact same bytes it always has. An older
    /// reader has no idea this field exists and must never be given a
    /// reason to notice it; a newer reader against an older perimeter (or
    /// one that simply has nothing to report) falls back to the empty list
    /// `#[serde(default)]` gives it. Both directions come from ordinary
    /// JSON-plus-serde behaviour — an unrecognised key is ignored, a missing
    /// one defaults — not from anything special done here; see this
    /// module's own doc for why that is the reason UDP data was added to
    /// this existing struct rather than behind a new [`PerimeterRequest`]
    /// variant, which would only give the SAME-direction guarantee (a
    /// perimeter that does not yet recognise a new request variant fails the
    /// whole read, not merely the new part of it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp_faces: Vec<UdpFaceMetrics>,
}

/// One face's counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaceMetrics {
    pub label: String,
    pub port: u16,
    pub bound: bool,
    pub accepted: u64,
    /// Connections refused before the camouflage strip because their source
    /// address was over its budget. Counted apart from `camo_failed`: "we
    /// refused to talk to you" and "you failed to speak the port's language"
    /// are different facts about the box, and folding them together would
    /// hide a throttle behind scan noise.
    #[serde(default)]
    pub rate_limited: u64,
    pub camo_failed: u64,
    pub peek_timeout: u64,
    /// Which inward service this face's wire traffic is spliced to, as
    /// `FacePurpose::label` — `monitor-wire` or `node-chain`.
    ///
    /// `wire_routed` below is per-face, so control traffic and chain traffic
    /// are already separate NUMBERS. Without this they are not separate
    /// FACTS: a reader seeing 300 on some port cannot say whether the chain
    /// data plane is carrying anything without joining against the box's
    /// signed identity to learn what that port is for. An instrument that
    /// needs a second source to be read is one an operator reads wrong at
    /// three in the morning.
    ///
    /// `#[serde(default)]` gives an empty string from a perimeter that
    /// predates the field. Empty means "not reported", NOT `monitor-wire`:
    /// defaulting to a real purpose would invent a fact rather than admit a
    /// gap, and every face on such a box is monitor-wire anyway.
    #[serde(default)]
    pub purpose: String,
    pub wire_routed: u64,
    /// Connections whose opening bytes were an SSH identification string and
    /// which were handed to the co-located mshd.
    #[serde(default)]
    pub ssh_routed: u64,
    pub rejected_not_wire: NotWireMetrics,
    pub inner_dial_failed: u64,
    /// Rejected connections HELD by the jail rather than closed. A drop is
    /// not a jail, and the two have to be countable apart or "the jail is
    /// engaged" is unverifiable.
    #[serde(default)]
    pub jailed: u64,
    /// Rejected connections closed immediately because this face is
    /// configured `hard_cut`.
    #[serde(default)]
    pub hard_cut: u64,
    /// Rejected connections cut because this face's hold budget was full.
    /// Its own counter, never folded into `hard_cut`: one is a policy and
    /// the other is pressure, and only the second is a reason to look at the
    /// box.
    #[serde(default)]
    pub jail_at_capacity: u64,
    /// Rejections the jail could not act on because duplicating the socket
    /// failed at accept time. Expected to stay at zero; a non-zero value
    /// means the jail is silently not engaging on this face.
    #[serde(default)]
    pub jail_no_handle: u64,
    /// Connections the jail is holding RIGHT NOW — a gauge, not a total.
    /// `jailed` only grows; this is what says whether the per-face hold
    /// budget is under pressure at this instant.
    #[serde(default)]
    pub jail_holding_now: u64,
    pub bytes_to_inner: u64,
    pub bytes_to_client: u64,
    /// Routed (already-classified, already-spliced) connections whose flow
    /// outlived this face's session-profile-derived splice ceiling —
    /// `mirage-perimeter::timing::splice_backstop`. OBSERVE-ONLY: the
    /// connection is never cut for this reason; the number says how many
    /// already-live flows a future enforcement step would have touched, so
    /// that decision has real fleet numbers before anything closes early.
    #[serde(default)]
    pub splice_backstop_observed: u64,
}

impl FaceMetrics {
    /// **Seam A — the camouflage strip.** The connection did not speak the
    /// shape this face wears. A real browser PASSES seam A on a `tls_real`
    /// face (rustls accepts any ClientHello) and FAILS it on a websocket
    /// face whose path it does not know.
    pub fn seam_a(&self) -> u64 {
        self.camo_failed
    }

    /// **Seam B — the inner classification, after the strip.** Opened and
    /// said nothing inside the peek window (a scanner's shape), or said
    /// something that was not a V9 hello.
    ///
    /// Kept apart from [`Self::seam_a`] because the two seams catch different
    /// populations and the jail's disposition turns on which one caught a
    /// connection. One combined "rejected" total would average that away.
    pub fn seam_b(&self) -> u64 {
        let nw = &self.rejected_not_wire;
        self.peek_timeout
            + nw.too_short
            + nw.bad_version
            + nw.bad_suite
            + nw.reserved_not_zero
            + nw.timestamp_skew
    }
}

/// One UDP face's counters — the datagram counterpart of [`FaceMetrics`].
///
/// # Two ways a UDP face can be here, told apart by `refused_reason`
///
/// A UDP face's own relay is bound exactly once, at boot
/// (`mirage-perimeter::Surface::bind_local_dgram_relay`), and never changes
/// for the life of the process. A capsule that declares a UDP face whose
/// declared purpose's relay never bound is refused outright — no socket, no
/// dispatcher, no counters — and until this type existed that refusal lived
/// nowhere but a log line: a box could carry a UDP face nobody off the box
/// could ever prove was declared at all, let alone why it never came up.
///
/// `refused_reason: None` is a face that actually runs — `bound` and every
/// counter below are live, moving numbers. `refused_reason: Some(_)` is a
/// face this process never started — `bound` is always `false` and every
/// counter is always `0`, because there was never a socket or a dispatcher
/// task to count anything with. The two are never conflated: a caller
/// asking "is this port doing anything" reads `refused_reason` first, not
/// `bound` alone — the same discipline [`FaceState::unbound_reason`] already
/// enforces for a TCP face whose bind failed after it started trying. A
/// face with neither state — no entry at all — was simply never declared;
/// see [`PerimeterMetrics::udp_faces`]'s own doc for how that case reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpFaceMetrics {
    pub label: String,
    pub port: u16,
    /// Which inward relay this face's declared purpose routes to —
    /// `monitor-wire` or `node-chain`, the same vocabulary
    /// [`FaceMetrics::purpose`] uses for the TCP side.
    pub purpose: String,
    /// Whether this face's dispatcher is bound right now on at least one
    /// address family. Always `false` for a refused face — see this type's
    /// own doc.
    pub bound: bool,
    /// Why this face was refused outright rather than ever bound at all —
    /// verbatim, naming the missing relay and the purpose that needed it.
    /// `None` for a face that actually runs, whatever `bound` says about it
    /// at this instant.
    #[serde(default)]
    pub refused_reason: Option<String>,
    pub datagrams_received: u64,
    pub bytes_received: u64,
    /// `recv_from` returned an error on this face's bound socket — a fact
    /// about the socket, never about any one peer.
    pub recv_errors: u64,
    /// A datagram matched an already-known source and reached that peer's
    /// own channel.
    pub forwarded: u64,
    pub sessions_started: u64,
    /// Sessions currently occupying this face's peer map — a gauge, not a
    /// total.
    pub sessions_active: u64,
    pub sessions_evicted_idle: u64,
    /// A session evicted by the least-recently-seen fallback because the
    /// idle sweep alone did not bring the peer map back under its trigger —
    /// the signature of a spray minting fresh entries faster than any go
    /// idle. Kept apart from `sessions_evicted_idle` on purpose: this rising
    /// is the map under genuine pressure, where the idle counter alone is
    /// ordinary churn.
    pub sessions_evicted_lru: u64,
    /// A session's own inbound channel was full (its reader stalled) and was
    /// evicted so the next datagram from that source starts fresh.
    pub sessions_evicted_stalled: u64,
    /// A session's own inbound channel was already closed — the ordinary end
    /// of a session's life, not pressure.
    pub sessions_closed: u64,
    /// How many times the idle sweep actually ran, whether or not it evicted
    /// anything.
    pub sweep_runs: u64,
    /// A newly announced session could not be handed off because the
    /// session-consuming end was gone. Expected to stay at most 1 per family
    /// per process life.
    pub session_announce_dropped: u64,
    /// A session's first datagram classified as wire and was handed to the
    /// relay — the datagram counterpart of [`FaceMetrics::wire_routed`].
    pub wire_routed: u64,
    /// Per-reason breakdown of sessions refused as not-wire — the SAME type
    /// [`FaceMetrics::rejected_not_wire`] uses, because the reasons are the
    /// same enum on both transports.
    pub rejected_not_wire: NotWireMetrics,
    /// A refused session was drained before eviction — the datagram
    /// counterpart of a jailed TCP connection.
    pub refused_drained: u64,
    /// A refused session was evicted at once, no drain — the datagram
    /// counterpart of a hard-cut TCP connection.
    pub refused_cut: u64,
    /// Either refusal outcome above, folded into the count of a refused
    /// session successfully removing its own dispatcher-map entry — no
    /// refused session waits out the idle sweep to leave the map.
    pub sessions_evicted_refused: u64,
    /// A datagram failed to relay to the monitor/node, or failed to relay
    /// back out to the peer.
    pub relay_send_errors: u64,
    /// Reading the local relay's own inbound socket returned an error — a
    /// fact about the LOCAL channel, never about any internet peer.
    pub relay_recv_errors: u64,
    /// An envelope arrived from the monitor/node for a session that had
    /// already ended on this face's side.
    pub relay_from_monitor_unmatched: u64,
    /// An envelope arrived from the monitor/node for a session whose own
    /// return channel was full.
    pub relay_from_monitor_dropped: u64,
    /// Payload bytes sent from a session to the monitor/node over the local
    /// relay — the datagram counterpart of [`FaceMetrics::bytes_to_inner`].
    pub bytes_to_monitor: u64,
    /// Payload bytes sent from a session back out to its real peer — the
    /// datagram counterpart of [`FaceMetrics::bytes_to_client`].
    pub bytes_to_client: u64,
}

/// Rejections after the strip, split by what was wrong with the hello.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotWireMetrics {
    #[serde(default)]
    pub too_short: u64,
    #[serde(default)]
    pub bad_version: u64,
    #[serde(default)]
    pub bad_suite: u64,
    #[serde(default)]
    pub reserved_not_zero: u64,
    #[serde(default)]
    pub timestamp_skew: u64,
}

/// The perimeter's channel to the arbiter, as a number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationChannelMetrics {
    /// Observations accepted onto the queue.
    #[serde(default)]
    pub queued: u64,
    /// Shed because the queue was full.
    #[serde(default)]
    pub dropped_full: u64,
    /// Written to secd's socket. THE number that says the ban ladder has an
    /// input: rising seam counters with a flat `sent` is a box whose arbiter
    /// is hearing nothing.
    #[serde(default)]
    pub sent: u64,
    /// Taken off the queue and lost — secd not listening, or a write error.
    #[serde(default)]
    pub dropped_io: u64,
    /// A durable socket-ownership refusal, never expected to clear on its
    /// own the way `dropped_io` is.
    #[serde(default)]
    pub dropped_permission: u64,
    /// Times the perimeter (re)connected to secd. Zero with a non-zero
    /// `dropped_io` is the signature of an arbiter that never came up.
    #[serde(default)]
    pub connects: u64,
}

/// Serialisable read of the perimeter's identity-grace state.
///
/// Moved here from `mirage-perimeter::capsule_boot` with the rest of the
/// wire shapes; the `GraceState` atomics that produce it stay in that crate,
/// being nobody else's business. No deadline field on purpose: grace has
/// none — `capsule_not_after_ms` is the one ceiling that applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceSnapshot {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub entered_at_ms: u64,
    #[serde(default)]
    pub age_ms: u64,
    /// `issued_at_ms` of the ONE slice this process took from the keeper
    /// while classifying its own boot provenance — set at most once, the
    /// instant that slice was judged inherited (see [`Self::active`]), and
    /// never refreshed afterwards even though this role goes on serving for
    /// days. This is NOT the machine capsule's current state: a role that
    /// never re-takes its slice carries a number that only ever gets
    /// staler. Read the keeper's own [`Self::renewal`] (specifically
    /// `keeper_capsule_not_after_ms`) for what the capsule's expiry actually
    /// is right now.
    #[serde(default)]
    pub capsule_issued_at_ms: u64,
    /// `not_after_ms` of that SAME one-time boot slice — the same caveat as
    /// [`Self::capsule_issued_at_ms`] applies in full: never refreshed,
    /// never the machine's live capsule state. A field that computed
    /// "expired" straight off this number used to read "expired 12 days"
    /// for a perimeter that had been serving fine for over a day while the
    /// keeper's own capsule was healthy the whole time — measured fleet-wide
    /// 2026-09-23. Nothing on this struct computes an expiry off this field
    /// any more; see [`Self::renewal`].
    #[serde(default)]
    pub capsule_not_after_ms: u64,
    #[serde(default)]
    pub resolved_at_ms: u64,
    /// The keeper's own renewal-stall state, when the local read this
    /// process already uses to reach the keeper can see one — see
    /// [`RenewalSnapshot`]'s own doc. `None` covers two different facts a
    /// reader must not conflate: nothing is stalled, and the keeper could
    /// not be asked this round. This is the ONLY place this struct reports
    /// a capsule-expiry number the keeper itself stands behind
    /// (`RenewalSnapshot::keeper_capsule_not_after_ms`) — the two fields
    /// above are this process's own stale boot-time copy and must never be
    /// read as a live expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal: Option<RenewalSnapshot>,
}

/// The keeper's renewal-stall state, mirrored onto `/perimeter/stats` — see
/// [`crate::machine_identity_query::RenewalStallState`] for the keeper's own
/// richer local-socket answer this is built from. `expired_for_ms` is
/// deliberately not duplicated here — "how far past due" stays a
/// keeper-local computation this snapshot does not need to repeat.
///
/// [`Self::keeper_capsule_not_after_ms`] IS duplicated here, on purpose and
/// unlike `expired_for_ms`: it is the one capsule-expiry number this whole
/// crate is allowed to show an operator, because it comes straight from the
/// keeper's own live RAM cache rather than from any per-role process's own
/// once-per-boot copy of a slice — see that field's own doc, and
/// `mirage_core::machine_identity_query::RenewalStallState::
/// capsule_not_after_ms` for the incident this replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalSnapshot {
    pub due_since_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_opened_ms: Option<u64>,
    /// The keeper's LIVE `not_after_ms` for the machine capsule it is
    /// currently serving, mirrored verbatim from
    /// `mirage_core::machine_identity_query::RenewalStallState::
    /// capsule_not_after_ms`. Named explicitly `keeper_...` rather than bare
    /// `capsule_not_after_ms` so it can never be confused with
    /// [`GraceSnapshot::capsule_not_after_ms`], this process's own stale
    /// boot-time copy — the two fields answer different questions and a
    /// shared name would invite exactly the conflation that produced a
    /// fleet-wide false "expired 12 days" alert, 2026-09-23.
    /// `#[serde(default, skip_serializing_if)]` for the same reason as
    /// `window_opened_ms`: a keeper predating this field, or a round this
    /// process could not ask at all, must read as "we don't know", never as
    /// a false zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keeper_capsule_not_after_ms: Option<u64>,
}

// ── Consumer-side classification, shared so two consumers cannot drift ────

/// Does an error from asking [`PerimeterRequest::Faces`] mean nobody holds
/// the query channel at all, as opposed to a perimeter that holds it and
/// answered badly?
///
/// # Why this lives here, once
///
/// Two consumers resolve this exact question to decide who owns a port:
/// mshd's recovery door (`mirage2mshd::ssh_server::
/// perimeter_owns_the_door_port`) stands `:22` down only on POSITIVE proof
/// the perimeter serves it, and secd's kernel filter
/// (`mirage-secd::perimeter_admission`) admits exactly the perimeter's
/// reported ports and falls back to the recovery door alone otherwise. Both
/// are two halves of ONE handover and must be driven by the SAME fact —
/// measured on `nl-example-203.0.113.30`, 2026-08-18: the perimeter was serving
/// 22/80/443 while the kernel admitted `tcp dport 22` alone, because the two
/// answers had drifted. This predicate is the one place "is anybody even
/// there" gets decided, so a second consumer gets the SAME answer by
/// construction instead of a copied paragraph staying in sync by hand.
///
/// `NotFound` is the socket file absent — the perimeter has never bound this
/// boot. `ConnectionRefused` is a file left behind by a dead process, and on
/// the Windows loopback-TCP arm it is a port nothing holds. Everything else
/// — a timeout, a malformed frame, a permission refusal — means something IS
/// there, and that is the case worth a human's attention: see each
/// consumer's own doc for how it logs the difference apart.
#[must_use]
pub fn channel_is_unheld(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face(port: u16, camo: &str) -> FaceState {
        FaceState {
            label: format!("{camo}:{port}"),
            port,
            camouflage: camo.into(),
            transport: FaceTransport::Tcp,
            bound: true,
            unbound_reason: None,
            unbound_since_ms: None,
            bind_attempts: 0,
        }
    }

    /// A dark face carries WHY, since when, and how many attempts — the
    /// three things `bound: false` alone cannot say, and the three that
    /// were only ever in the journal until 2026-08-28.
    fn dark_face(port: u16, camo: &str, reason: &str, attempts: u64) -> FaceState {
        FaceState {
            label: format!("{camo}:{port}"),
            port,
            camouflage: camo.into(),
            transport: FaceTransport::Tcp,
            bound: false,
            unbound_reason: Some(reason.to_string()),
            unbound_since_ms: Some(1_787_900_000_000),
            bind_attempts: attempts,
        }
    }

    #[test]
    fn a_dark_face_says_why_and_for_how_long() {
        let f = dark_face(22, "none", "Address in use (os error 98)", 9973);
        assert!(!f.bound);
        assert_eq!(f.bind_attempts, 9973);
        assert!(f.unbound_reason.as_deref().unwrap().contains("Address in use"));
        assert!(f.unbound_since_ms.is_some());
    }

    /// A bound face must carry no stale reason — a leftover explanation of
    /// a condition that no longer holds is the exact defect the whole field
    /// set exists to remove.
    #[test]
    fn a_bound_face_carries_no_reason() {
        let f = face(443, "https");
        assert!(f.bound);
        assert!(f.unbound_reason.is_none());
        assert!(f.unbound_since_ms.is_none());
    }

    /// Older perimeters do not send the new fields; a reader must get
    /// defaults rather than a parse failure, or a mixed fleet goes blind
    /// during a roll.
    #[test]
    fn an_old_perimeters_face_still_parses() {
        let legacy = r#"{"label":"none:22","port":22,"camouflage":"none","bound":true}"#;
        let f: FaceState = serde_json::from_str(legacy).expect("legacy face parses");
        assert!(f.bound);
        assert_eq!(f.bind_attempts, 0);
        assert!(f.unbound_reason.is_none());
        // A face reported by a perimeter build that predates `transport` was
        // always TCP — the default must land on that fact, not merely on
        // some arbitrary variant.
        assert_eq!(f.transport, FaceTransport::Tcp);
    }

    #[test]
    fn the_door_question_is_answered_by_the_face_list_alone() {
        // The decision mshd makes on this: does the perimeter serve :22?
        // It is a boolean over a typed list, not a field fished out of a
        // metrics blob.
        let faces = vec![face(22, "none"), face(443, "tls_real")];
        assert!(faces.iter().any(|f| f.port == 22));
        let without = vec![face(80, "websocket"), face(443, "tls_real")];
        assert!(!without.iter().any(|f| f.port == 22));
    }

    #[test]
    fn a_face_that_failed_to_bind_still_belongs_to_the_perimeter() {
        // The CONFIGURED list, `bound` flag and all — a perimeter whose :22
        // bind lost a race still intends to serve it, and saying otherwise
        // has the two processes swap the port forever.
        let mut f = face(22, "none");
        f.bound = false;
        let faces = vec![f];
        assert!(faces.iter().any(|f| f.port == 22));
        assert!(!faces[0].bound);
    }

    #[test]
    fn every_response_round_trips() {
        let cases = vec![
            PerimeterResponse::Health(PerimeterHealth {
                build_id: "0.1.0".into(),
                uptime_secs: 61,
                faces_bound: 3,
                identity_grace: true,
            }),
            PerimeterResponse::Faces(vec![face(22, "none")]),
            PerimeterResponse::Metrics(Box::new(PerimeterMetrics {
                uptime_secs: 61,
                faces: vec![],
                observation_channel: ObservationChannelMetrics::default(),
                identity_grace: GraceSnapshot::default(),
                udp_faces: vec![],
            })),
        ];
        for c in cases {
            let raw = serde_json::to_vec(&c).expect("encodes");
            let back: PerimeterResponse = serde_json::from_slice(&raw).expect("decodes");
            assert_eq!(back, c);
        }
    }

    #[test]
    fn requests_are_legible_in_a_log() {
        // These land in journals during incidents. `"faces"` reads; a bare
        // discriminant does not.
        assert_eq!(serde_json::to_string(&PerimeterRequest::Faces).unwrap(), "\"faces\"");
        assert_eq!(serde_json::to_string(&PerimeterRequest::Metrics).unwrap(), "\"metrics\"");
    }

    #[test]
    fn channel_is_unheld_covers_exactly_not_found_and_connection_refused() {
        assert!(channel_is_unheld(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(channel_is_unheld(&io::Error::from(io::ErrorKind::ConnectionRefused)));
        // Held, but answering badly — the OTHER half of the split, and it
        // must NOT collapse into "unheld": a perimeter that is there and
        // wrong is a fault, not an ordinary absence.
        assert!(!channel_is_unheld(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!channel_is_unheld(&io::Error::new(io::ErrorKind::InvalidData, "malformed frame")));
        assert!(!channel_is_unheld(&io::Error::from(io::ErrorKind::PermissionDenied)));
    }

    #[test]
    fn the_two_seams_are_counted_apart() {
        // A scanner that opens and says nothing (seam B) and a client that
        // speaks the wrong shape for the port (seam A) must not add up into
        // one "rejected" number: the jail's disposition depends on which.
        //
        // Numbers measured on ru-hostkey-203.0.113.10, 53 minutes of uptime.
        let f = FaceMetrics {
            label: "none:22".into(),
            port: 22,
            bound: true,
            accepted: 494,
            rate_limited: 0,
            camo_failed: 0,
            peek_timeout: 57,
            // A port-22 face on a real box: its wire traffic goes to the
            // monitor. SSH is routed by the opening bytes, not by purpose.
            purpose: "monitor-wire".into(),
            wire_routed: 274,
            ssh_routed: 146,
            rejected_not_wire: NotWireMetrics { bad_version: 17, ..Default::default() },
            inner_dial_failed: 0,
            jailed: 0,
            hard_cut: 0,
            jail_at_capacity: 0,
            jail_no_handle: 0,
            jail_holding_now: 0,
            bytes_to_inner: 1,
            bytes_to_client: 2,
            splice_backstop_observed: 0,
        };
        assert_eq!(f.seam_b(), 74);
        assert_eq!(f.seam_a(), 0);
    }

    #[test]
    fn an_additive_counter_is_not_a_parse_failure_for_an_older_peer() {
        // Both binaries are on the fleet at once during a roll. A perimeter
        // built before the jail existed emits none of those keys, and the
        // correct reading of their absence is "this build cannot report it",
        // never a parse failure that blanks every other counter on the box.
        let raw = r#"{
            "label": "tls_real:443", "port": 443, "bound": true, "accepted": 1,
            "camo_failed": 0, "peek_timeout": 0, "wire_routed": 1,
            "rejected_not_wire": {},
            "inner_dial_failed": 0, "bytes_to_inner": 1, "bytes_to_client": 2
        }"#;
        let f: FaceMetrics = serde_json::from_str(raw).expect("must parse");
        assert_eq!(f.jailed, 0);
        assert_eq!(f.ssh_routed, 0);
        assert_eq!(f.rejected_not_wire.bad_version, 0);
        assert_eq!(f.splice_backstop_observed, 0);
    }

    // ── UDP faces on `PerimeterMetrics` (U0 step 7) ──

    fn udp_face_metrics(port: u16, bound: bool, refused_reason: Option<&str>) -> UdpFaceMetrics {
        UdpFaceMetrics {
            label: format!("raw_udp:{port}"),
            port,
            purpose: "monitor-wire".into(),
            bound,
            refused_reason: refused_reason.map(str::to_string),
            datagrams_received: 4,
            bytes_received: 400,
            recv_errors: 0,
            forwarded: 3,
            sessions_started: 1,
            sessions_active: 1,
            sessions_evicted_idle: 0,
            sessions_evicted_lru: 0,
            sessions_evicted_stalled: 0,
            sessions_closed: 0,
            sweep_runs: 0,
            session_announce_dropped: 0,
            wire_routed: 1,
            rejected_not_wire: NotWireMetrics::default(),
            refused_drained: 0,
            refused_cut: 0,
            sessions_evicted_refused: 0,
            relay_send_errors: 0,
            relay_recv_errors: 0,
            relay_from_monitor_unmatched: 0,
            relay_from_monitor_dropped: 0,
            bytes_to_monitor: 40,
            bytes_to_client: 40,
        }
    }

    /// A face that runs and a face refused outright round-trip alike — the
    /// two states [`UdpFaceMetrics::refused_reason`]'s own doc tells apart.
    #[test]
    fn a_udp_face_metrics_round_trips_bound_and_refused_alike() {
        let cases = vec![
            udp_face_metrics(51000, true, None),
            udp_face_metrics(51001, false, Some("perimeter-wire-dgram relay never bound at boot")),
        ];
        for f in cases {
            let raw = serde_json::to_vec(&f).expect("encodes");
            let back: UdpFaceMetrics = serde_json::from_slice(&raw).expect("decodes");
            assert_eq!(back, f);
        }
    }

    /// The state every box on the fleet is in today: no UDP faces declared
    /// at all. The wire shape for that box must be byte-identical to what it
    /// always was — no reader gains a reason to notice this field exists
    /// until a box actually reports something on it.
    #[test]
    fn a_metrics_response_with_no_udp_faces_omits_the_key_entirely() {
        let metrics = PerimeterMetrics {
            uptime_secs: 61,
            faces: vec![],
            observation_channel: ObservationChannelMetrics::default(),
            identity_grace: GraceSnapshot::default(),
            udp_faces: vec![],
        };
        let raw = serde_json::to_value(&metrics).expect("encodes");
        assert!(
            raw.get("udp_faces").is_none(),
            "an empty udp_faces list must not appear in the wire shape at all: {raw}"
        );
    }

    /// A perimeter built before this field existed emits none of these keys.
    /// The correct reading of their absence is "this build cannot report
    /// it", never a parse failure that blanks every other counter on the
    /// box — the same discipline `an_additive_counter_is_not_a_parse_
    /// failure_for_an_older_peer` already proves for `FaceMetrics`.
    #[test]
    fn an_old_perimeters_metrics_without_udp_faces_still_parses() {
        let legacy = r#"{
            "uptime_secs": 10,
            "faces": [],
            "observation_channel": {},
            "identity_grace": {}
        }"#;
        let m: PerimeterMetrics = serde_json::from_str(legacy).expect("legacy metrics parses");
        assert!(m.udp_faces.is_empty());
    }

    /// The forward direction of the same guarantee: a NEW perimeter
    /// reporting UDP faces must not break an OLD reader whose own
    /// `PerimeterMetrics` has no `udp_faces` field at all — this is what
    /// makes extending this struct, rather than adding a new
    /// `PerimeterRequest` variant, the compatible choice. Simulated here by
    /// decoding into `serde_json::Value` and reading exactly the fields an
    /// old struct would have — `serde_json::from_str` into a struct with an
    /// unknown extra key ignores it by default (no `deny_unknown_fields`
    /// anywhere on this type), which is the property being exercised.
    #[test]
    fn a_new_perimeters_udp_faces_do_not_break_a_reader_that_does_not_know_the_field() {
        let modern = PerimeterMetrics {
            uptime_secs: 5,
            faces: vec![],
            observation_channel: ObservationChannelMetrics::default(),
            identity_grace: GraceSnapshot::default(),
            udp_faces: vec![udp_face_metrics(51002, true, None)],
        };
        let raw = serde_json::to_string(&modern).expect("encodes");

        #[derive(Deserialize)]
        struct OldPerimeterMetrics {
            uptime_secs: u64,
            faces: Vec<FaceMetrics>,
        }
        let old: OldPerimeterMetrics =
            serde_json::from_str(&raw).expect("an old reader's struct must still parse");
        assert_eq!(old.uptime_secs, 5);
        assert!(old.faces.is_empty());
    }

    // ── GraceSnapshot's renewal ──

    /// A `GraceSnapshot` from a perimeter built before `renewal` existed
    /// carries no such key — the same additive discipline every other field
    /// on this type already gets. `capsule_expired_for_ms` is gone entirely
    /// (2026-09-23 fix) — an older reader that still expects the key simply
    /// never sees it, and a legacy WIRE blob that still carries it (from a
    /// not-yet-rolled perimeter) must not fail the whole snapshot either,
    /// since unknown keys are ignored by default.
    #[test]
    fn an_old_grace_snapshot_without_renewal_still_parses() {
        let legacy = r#"{
            "active": true,
            "entered_at_ms": 1,
            "age_ms": 2,
            "capsule_issued_at_ms": 3,
            "capsule_not_after_ms": 4,
            "resolved_at_ms": 0
        }"#;
        let g: GraceSnapshot = serde_json::from_str(legacy).expect("legacy grace snapshot parses");
        assert_eq!(g.renewal, None);
    }

    /// A not-yet-rolled perimeter's wire blob still carries the retired
    /// `capsule_expired_for_ms` key — a rolled reader must ignore it rather
    /// than fail the whole snapshot over a field it no longer has.
    #[test]
    fn a_grace_snapshot_carrying_the_retired_expired_for_ms_key_still_parses() {
        let legacy = r#"{
            "active": true,
            "entered_at_ms": 1,
            "age_ms": 2,
            "capsule_issued_at_ms": 3,
            "capsule_not_after_ms": 4,
            "resolved_at_ms": 0,
            "capsule_expired_for_ms": 1036800000
        }"#;
        let g: GraceSnapshot = serde_json::from_str(legacy).expect("legacy grace snapshot parses");
        assert_eq!(g.capsule_issued_at_ms, 3);
    }

    /// A snapshot reporting nothing wrong omits `renewal` entirely —
    /// `skip_serializing_if`, not merely `default`, so a healthy fleet's
    /// wire bytes stay minimal.
    #[test]
    fn a_healthy_grace_snapshot_omits_renewal() {
        let raw = serde_json::to_value(GraceSnapshot::default()).expect("encodes");
        assert!(raw.get("renewal").is_none());
    }

    /// A snapshot actively reporting a keeper-side renewal stall round-trips
    /// byte for byte, and the ONE expiry number it carries is the keeper's
    /// live one — [`RenewalSnapshot::keeper_capsule_not_after_ms`] — never
    /// this process's own stale boot-time
    /// [`GraceSnapshot::capsule_not_after_ms`].
    #[test]
    fn a_grace_snapshot_with_renewal_round_trips_the_keepers_live_expiry() {
        let g = GraceSnapshot {
            active: true,
            entered_at_ms: 1_700_000_000_000,
            age_ms: 500,
            capsule_issued_at_ms: 1_699_996_400_000,
            capsule_not_after_ms: 1_700_082_800_000,
            resolved_at_ms: 0,
            renewal: Some(RenewalSnapshot {
                due_since_ms: 1_699_996_400_000 + 6 * 60 * 60_000,
                window_opened_ms: Some(1_700_082_500_000),
                keeper_capsule_not_after_ms: Some(1_700_150_000_000),
            }),
        };
        let raw = serde_json::to_vec(&g).expect("encodes");
        let back: GraceSnapshot = serde_json::from_slice(&raw).expect("decodes");
        assert_eq!(back, g);
        assert_ne!(
            back.renewal.expect("just set").keeper_capsule_not_after_ms,
            Some(back.capsule_not_after_ms),
            "the keeper's live expiry and this process's own stale boot-time copy must be free to \
             differ — that gap is exactly the fact this fix makes visible instead of hiding"
        );
    }
}
