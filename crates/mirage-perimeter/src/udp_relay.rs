//! Step 4b of `docs/mirage/plans/udp-front-door-u0-2026-09-05.md`:
//! classification, the datagram equivalent of the jail, and the relay to
//! the monitor — everything `crate::udp_face`'s own module doc named as a
//! seam for this file, standing on the dispatcher 4a built
//! (`mirage2web@0540840`).
//!
//! # This module is NOT wired into `Surface`
//!
//! [`run_udp_session`] is what a future consumer of `crate::udp_face::
//! run_udp_face`'s `sessions` channel should spawn, one task per announced
//! [`crate::udp_face::UdpSession`] — and [`UdpMonitorRelay::run_inbound`] is
//! what that same consumer should spawn once per UDP face (or once per
//! process, if a future box ever runs more than one — see
//! [`UdpMonitorRelay`]'s own doc). Neither call exists yet: that is plan
//! step 5, a different brief, and `crate::config::UdpFace`/`crate::lib::
//! Surface` are untouched by this file.
//!
//! # 1. One classifier, two callers, no adaptation
//!
//! `crate::face`'s TCP path reads a byte prefix off a stream and can go back
//! for more (`crate::classify::SSH_DECISION_LEN`, then the rest, staged
//! because the two protocols multiplexed on a TCP face disagree about who
//! speaks first — see `crate::classify`'s own doc). A datagram has no
//! "going back for more": [`crate::udp_face::UdpSession::first_datagram`]
//! IS the whole first message, read once, by the dispatcher, before this
//! module ever sees it. [`classify_datagram`] therefore hands the whole
//! buffer straight to [`crate::classify::classify_v9_hello`], unchanged —
//! that function already takes `&[u8]` and has never itself read from a
//! socket (`classify.rs`'s own doc says as much), so there is no
//! stream-shaped logic to factor out of it and no second V9-hello
//! recogniser written here. `crate::classify` is touched by NOTHING in this
//! file. Test [`tests::the_shared_classifier_agrees_with_itself_whether_
//! assembled_whole_or_staged`] is the proof this does not quietly drift:
//! it reproduces `face.rs`'s own staged-read reassembly byte for byte and
//! shows it produces input identical to a datagram's whole buffer, so the
//! one function underneath both callers cannot disagree with itself.
//!
//! Same doctrine as `crate::classify`'s own module doc, restated because it
//! matters here too: [`crate::classify::Verdict::Wire`] means "worth the
//! monitor's time", never "authenticated". The monitor still runs the real
//! V9 handshake (`mirage_protocol::core::udp_handshake`) behind every
//! session this module relays.
//!
//! # 2. Closing 4a's own gap: a short, NAMED disposal bound
//!
//! 4a's module doc named the hole plainly: a session nobody classifies
//! leaves `crate::udp_face`'s peer map only through the passive ten-minute
//! idle sweep — reachable, unauthenticated, by anyone who sends exactly one
//! datagram and then goes quiet. [`REFUSED_SESSION_DRAIN_MS`] is the fix:
//! [`refuse_session`] drains (discards) whatever else arrives from a
//! refused source for that bound, then asks the dispatcher to remove its
//! own map entry via [`crate::udp_face::UdpSession::evict`] — a channel back
//! into `crate::udp_face::run_dispatcher` added specifically so this can
//! happen without waiting for a passive sweep or a lucky second datagram.
//!
//! This is deliberately its OWN constant, not a reuse of `crate::jail::
//! JailConfig::hold_ms` — see point 3 below for why a duration calibrated to
//! outlast a TCP scanner's timeout buys nothing here, and
//! [`REFUSED_SESSION_DRAIN_MS`]'s own doc for the value actually chosen and
//! why.
//!
//! # 3. Refusal: drop, not hold-and-reply — and why that is not TCP's answer degraded
//!
//! `crate::jail`'s whole value for TCP is erasing a DISTINGUISHABLE SIGNAL: a
//! socket-based prober can tell an instant `close()`/RST apart from a
//! connection held open and quiet, because TCP's connect/accept handshake
//! gives the prober a stateful thing to watch. Holding the connection open
//! (reading, discarding, answering nothing) makes "wrong protocol" look
//! identical to "right protocol, quiet server" from outside.
//!
//! **UDP has no analogous signal for a "hold" to erase.** There is no
//! connect/accept step a prober's socket can observe succeeding or failing.
//! The only wire-visible facts are (a) whether any reply datagram ever
//! arrives, and (b) whether the kernel emits an ICMP port-unreachable — and
//! (b) is already fully decided by the socket being bound at all, before any
//! application-level choice this module makes. A datagram sent to a bound,
//! silent UDP port produces IDENTICAL wire behaviour whether this code
//! tracks the sender for two seconds or zero: the sender cannot observe our
//! own internal bookkeeping, because nothing on the wire ever reports it.
//! Reading `crate::jail`'s reasoning and mechanically copying "hold instead
//! of drop" onto UDP would be cargo-culting a defence against a signal that
//! does not exist here.
//!
//! **What WOULD change wire behaviour is replying — and that is worse, not
//! better.** [`crate::classify::classify_v9_hello`] authenticates nothing
//! (point 1). A reply to an unrecognised datagram is therefore a reply to
//! ANY forged source address a scanner cares to spoof: it (1) confirms to
//! whoever receives it that something live sits behind this port — exactly
//! the tell a scanner wants and the one thing `crate::jail`'s silence
//! promise for TCP is careful never to give either — and (2) turns this
//! face into a reflector: an attacker spoofing a victim's address as the
//! source gets this box to send that victim a reply it never asked for, the
//! textbook UDP amplification/reflection primitive, on a camouflage
//! (`RawUdp`) whose own upstream doc already accepts that a spoofed source
//! pays nothing to reach this point (`crate::udp_face::PEER_SWEEP_TRIGGER`'s
//! own doc). Every reply this module could send is a reply this module
//! should not send.
//!
//! **Conclusion: drop.** No datagram is ever written back to a source this
//! module has not classified as wire. [`REFUSED_SESSION_DRAIN_MS`]'s short
//! window is not a deception tactic — it cannot be one, per the paragraph
//! above — it is a cheap absorber for an immediate retry burst from the
//! SAME (possibly spoofed) source, so a source that sends three garbage
//! datagrams half a second apart pays this box one classify-and-refuse
//! cycle instead of three. `crate::jail::Disposition` is still honoured,
//! because the plan's own §2 table calls for it and reusing the existing,
//! operator-resolved policy surface is correct even though its meaning
//! narrows for this transport: `Disposition::Jail` drains for
//! [`REFUSED_SESSION_DRAIN_MS`] before evicting; `Disposition::HardCut`
//! evicts at once. Neither disposition EVER sends a byte — the axis this
//! config knob controls for UDP is purely "how long do we keep discarding
//! from a known-refused source before forgetting it", not "do we pretend to
//! be quiet or loud", because UDP gives this module no "loud" to fall back
//! to that would not also be an amplifier.
//!
//! # 4. The relay: two different transport types, so not `copy_bidirectional`
//!
//! A classified [`crate::classify::Verdict::Wire`] session's datagrams cross
//! `mirage_core::local_dgram_endpoint` to the monitor and back, per plan
//! §5.3. [`UdpMonitorRelay`] wraps the ONE box-local socket every UDP face
//! this process runs shares (`mirage_core::local_dgram_endpoint`'s own "one
//! pair serves the whole box" doctrine) and demultiplexes inbound envelopes
//! by `(face_port, peer)` — not `peer` alone, because the plan's own §5.3
//! step 4 demuxes the monitor side the same way, and a relay that dropped
//! `face_port` from its own routing key would silently rely on no two UDP
//! faces this box ever runs sharing one real peer's `SocketAddr` at the same
//! instant, which is not a guarantee this module can make on the monitor's
//! behalf.
//!
//! [`relay_session`] is the loop plan §5.3 step 3 describes: one direction
//! at a time, alternating, because the public socket
//! (`crate::udp_face::UdpSession::socket`) and the local relay
//! (`mirage_core::local_dgram_endpoint::LocalDgramSocket`) are different
//! concrete types with no shared `AsyncRead + AsyncWrite` for
//! `tokio::io::copy_bidirectional` to drive. It ends the instant the
//! session's own cancellation token fires or either side's channel closes,
//! and deregisters itself from [`UdpMonitorRelay`]'s routing table on every
//! exit path — no task here outlives the session it was spawned for.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use mirage_core::local_dgram_endpoint::{DgramEnvelope, LocalDgramSocket};

use crate::classify::{classify_v9_hello, Verdict};
use crate::jail::Disposition;
use crate::udp_face::{UdpFaceCounters, UdpSession, PEER_CHANNEL_CAPACITY};

/// How long a refused session's demux-table entry is drained (discarded,
/// never answered) before [`refuse_session`] asks
/// [`crate::udp_face::run_dispatcher`] to remove it, under
/// [`Disposition::Jail`] — see this module's doc, point 3, for why a LONGER
/// duration buys no camouflage value here the way `crate::jail::
/// DEFAULT_HOLD_MS` (30s) does for TCP: nothing on the wire ever reports how
/// long this box kept its own bookkeeping.
///
/// 600x shorter than `crate::udp_face::PEER_IDLE_EVICT` (600s / ten
/// minutes) — the bound 4a's own module doc flagged as the real gap this
/// closes. Long enough that a source retrying a few times inside one second
/// (the shape an ordinary misconfigured client, not a deliberate flood,
/// actually produces) is absorbed by the SAME refused session instead of
/// spawning a fresh classify-and-refuse cycle per retry; short enough that
/// this can never become a durable, unauthenticated hold on a map slot a
/// spoofed source paid nothing to open.
pub const REFUSED_SESSION_DRAIN_MS: u64 = 1_000;

/// Classify one whole datagram — see this module's doc, point 1.
///
/// Never reads anything past `first_datagram`: there is no follow-on read
/// to perform and no buffer to grow. `now_ms` comes from
/// [`crate::udp_face::now_ms`] rather than a second clock read implemented
/// here, for the identical reason [`PEER_CHANNEL_CAPACITY`] is imported
/// rather than duplicated.
fn classify_datagram(first_datagram: &[u8], max_skew_ms: u64) -> Verdict {
    classify_v9_hello(first_datagram, crate::udp_face::now_ms(), max_skew_ms)
}

/// The box-local relay to the monitor, shared by every session this UDP face
/// (or, per `mirage_core::local_dgram_endpoint`'s own doctrine, every UDP
/// face this box runs) classifies as wire.
///
/// Wraps an ALREADY-BOUND [`LocalDgramSocket`] — binding the box-wide
/// rendezvous socket is plan step 6 (`Surface::bind_baseline`, once per
/// process, before any UDP face exists), not this type's job. `routes` is
/// this relay's own demux table, keyed by `(face_port, peer)` exactly as the
/// monitor's own dispatcher demuxes the other direction (plan §5.3 step 4)
/// — see this module's doc, point 4, for why `face_port` is part of the key
/// rather than an assumption this relay leaves to the monitor alone.
pub struct UdpMonitorRelay {
    socket: Arc<LocalDgramSocket>,
    routes: DashMap<(u16, SocketAddr), mpsc::Sender<Vec<u8>>>,
}

impl UdpMonitorRelay {
    /// Wrap `socket` for use by every session this process relays.
    #[must_use]
    pub fn new(socket: Arc<LocalDgramSocket>) -> Arc<Self> {
        Arc::new(Self { socket, routes: DashMap::new() })
    }

    /// Whether this relay currently has a live route for `(face_port,
    /// peer)` — `true` from the moment [`relay_session`] registers a
    /// classified-wire session until it deregisters, on every exit path
    /// (cancellation, either side's channel closing). Test-only: production
    /// code has no reason to ask this question, since a route's presence is
    /// exactly `relay_session`'s own bookkeeping and nothing outside it
    /// acts on the answer. Added specifically so `Surface::apply_config`'s
    /// own retirement tests (`lib.rs`) can prove a live session is actually
    /// gone after retirement, not merely that its dispatcher stopped.
    #[cfg(test)]
    pub(crate) fn has_route(&self, face_port: u16, peer: SocketAddr) -> bool {
        self.routes.contains_key(&(face_port, peer))
    }

    /// Read every envelope the monitor sends back, forever, routing each to
    /// the matching live session's own return channel.
    ///
    /// ONE task per relay (not one per peer, not one per session) reads
    /// [`LocalDgramSocket::recv_envelope`] — mirrors `crate::udp_face::
    /// run_dispatcher` reading its own public socket once and demultiplexing
    /// afterward, for the identical reason: the underlying socket is shared,
    /// so exactly one task may own its receive half.
    ///
    /// Ends when `cancel` fires. A live route with nobody home
    /// ([`UdpFaceCounters::relay_from_monitor_unmatched`]) or one whose
    /// return channel is full ([`UdpFaceCounters::relay_from_monitor_
    /// dropped`]) are both counted and never fatal to this loop — a stale or
    /// slow session must not stop every OTHER session on this relay from
    /// hearing back.
    pub async fn run_inbound(self: Arc<Self>, counters: Arc<UdpFaceCounters>, cancel: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    tracing::info!("[perimeter/udp_relay] retiring — no longer reading the local relay");
                    return;
                }
                recvd = self.socket.recv_envelope() => match recvd {
                    Ok((envelope, payload)) => {
                        let key = (envelope.face_port, envelope.peer);
                        match self.routes.get(&key) {
                            Some(tx) => {
                                if tx.try_send(payload).is_err() {
                                    counters.relay_from_monitor_dropped.fetch_add(1, Ordering::Relaxed);
                                    tracing::debug!(
                                        face_port = envelope.face_port, peer = %envelope.peer,
                                        "[perimeter/udp_relay] this session's return channel is full or \
                                         closed — dropping this reply rather than blocking every other \
                                         session on this relay"
                                    );
                                }
                            }
                            None => {
                                counters.relay_from_monitor_unmatched.fetch_add(1, Ordering::Relaxed);
                                tracing::debug!(
                                    face_port = envelope.face_port, peer = %envelope.peer,
                                    "[perimeter/udp_relay] no live session for this envelope — it likely \
                                     ended (evicted/cancelled) while the monitor was still replying"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        counters.relay_recv_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(error = %e, "[perimeter/udp_relay] local relay recv failed — continuing");
                    }
                },
            }
        }
    }
}

/// Classify one announced session and either relay it to the monitor or
/// refuse it — the whole of step 4b's per-session decision.
///
/// This is the function plan step 5 should spawn, one task per
/// [`crate::udp_face::UdpSession`] read off `crate::udp_face::run_udp_face`'s
/// `sessions` channel. Not called from anywhere in this crate today — see
/// this module's doc, "This module is NOT wired into `Surface`".
pub async fn run_udp_session(
    session: UdpSession,
    face_port: u16,
    relay: Arc<UdpMonitorRelay>,
    counters: Arc<UdpFaceCounters>,
    max_skew_ms: u64,
    disposition: Disposition,
    cancel: CancellationToken,
) {
    match classify_datagram(&session.first_datagram, max_skew_ms) {
        // The datagram side does not route on `target_hint` yet — this
        // module is not wired into `Surface` at all (see its own module
        // doc), and widening `dgram_relay_for` the way `crate::face::
        // inward_target` was widened is out of this change's scope. The
        // hint still round-trips through the shared classifier untouched;
        // only its consumption here is deferred.
        Verdict::Wire(_target_hint) => {
            counters.wire_routed.fetch_add(1, Ordering::Relaxed);
            relay_session(session, face_port, relay, counters, cancel).await;
        }
        Verdict::Ssh => {
            // Unreachable in production: `classify_v9_hello` never returns
            // this (see `crate::classify`'s own doc) — `RawUdp` carries no
            // SSH-shaped inner protocol to disambiguate, and this module
            // never calls `crate::classify::looks_like_ssh` at all. Kept
            // explicit, matching `crate::face::handle_connection`'s own
            // defensive branch for the identical case, so a future variant
            // cannot fall through a catch-all here unnoticed. No
            // `NotWireReason` fits this outcome, so none is fabricated —
            // only the refusal itself is counted.
            tracing::warn!(
                face_port, peer = %session.peer,
                "[perimeter/udp_relay] classifier returned Ssh on a UDP face — refusing"
            );
            refuse_session(session, &counters, disposition, &cancel).await;
        }
        Verdict::NotWire(reason) => {
            counters.refused_not_wire.record(reason);
            tracing::debug!(
                face_port, peer = %session.peer, ?reason,
                "[perimeter/udp_relay] not wire — refusing"
            );
            refuse_session(session, &counters, disposition, &cancel).await;
        }
    }
}

/// Relay one classified-wire session to the monitor and back, for the rest
/// of its life. See this module's doc, point 4.
async fn relay_session(
    mut session: UdpSession,
    face_port: u16,
    relay: Arc<UdpMonitorRelay>,
    counters: Arc<UdpFaceCounters>,
    cancel: CancellationToken,
) {
    let (from_monitor_tx, mut from_monitor_rx) = mpsc::channel::<Vec<u8>>(PEER_CHANNEL_CAPACITY);
    relay.routes.insert((face_port, session.peer), from_monitor_tx);

    let envelope = DgramEnvelope { face_port, peer: session.peer };

    // The ClientHello that decided this is wire — the monitor cannot read
    // its own first datagram (plan §5.3 step 4: by the time a session
    // exists to read it, the bytes that created it are already consumed),
    // so this is handed over explicitly, once, before the ordinary loop
    // starts.
    match relay.socket.send_envelope(envelope, &session.first_datagram).await {
        Ok(()) => {
            counters
                .bytes_to_monitor
                .fetch_add(session.first_datagram.len() as u64, Ordering::Relaxed);
        }
        Err(e) => {
            counters.relay_send_errors.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                face_port, peer = %session.peer, error = %e,
                "[perimeter/udp_relay] failed to relay the classifying hello to the monitor — \
                 abandoning this session"
            );
            relay.routes.remove(&(face_port, session.peer));
            return;
        }
    }

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            recvd = session.inbound.recv() => match recvd {
                Some((_, payload)) => {
                    let n = payload.len() as u64;
                    match relay.socket.send_envelope(envelope, &payload).await {
                        Ok(()) => { counters.bytes_to_monitor.fetch_add(n, Ordering::Relaxed); }
                        Err(_) => { counters.relay_send_errors.fetch_add(1, Ordering::Relaxed); }
                    }
                }
                // The dispatcher evicted this peer (idle sweep, stall, or a
                // fresh session under the same address) — this session's
                // life is over from the public side.
                None => break,
            },
            recvd = from_monitor_rx.recv() => match recvd {
                Some(payload) => {
                    let n = payload.len() as u64;
                    match session.socket.send_to(&payload, session.peer).await {
                        Ok(_) => { counters.bytes_to_client.fetch_add(n, Ordering::Relaxed); }
                        Err(_) => { counters.relay_send_errors.fetch_add(1, Ordering::Relaxed); }
                    }
                }
                // `UdpMonitorRelay::run_inbound` stopped (retiring) — this
                // session's return path is gone.
                None => break,
            },
        }
    }

    relay.routes.remove(&(face_port, session.peer));
}

/// The datagram equivalent of `crate::jail::dispose` — see this module's
/// doc, point 3, for why drop (never a reply) is the whole mechanism and
/// [`REFUSED_SESSION_DRAIN_MS`] is a churn absorber, not camouflage.
async fn refuse_session(
    mut session: UdpSession,
    counters: &UdpFaceCounters,
    disposition: Disposition,
    cancel: &CancellationToken,
) {
    if disposition == Disposition::HardCut {
        let _ = session.evict.send(session.peer);
        counters.refused_cut.fetch_add(1, Ordering::Relaxed);
        counters.sessions_evicted_refused.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let drain_deadline = tokio::time::sleep(Duration::from_millis(REFUSED_SESSION_DRAIN_MS));
    tokio::pin!(drain_deadline);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            () = &mut drain_deadline => break,
            recvd = session.inbound.recv() => {
                if recvd.is_none() {
                    // The dispatcher already removed this entry some other
                    // way (idle sweep raced us) — nothing left to drain.
                    break;
                }
                // Discard. Never inspected, never answered — see point 3.
            }
        }
    }
    let _ = session.evict.send(session.peer);
    counters.refused_drained.fetch_add(1, Ordering::Relaxed);
    counters.sessions_evicted_refused.fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::NotWireReason;
    use crate::udp_face::run_dispatcher;
    use mirage_core::local_endpoint::{plan_from_resolution, AccountResolution};
    use mirage_core::local_dgram_endpoint::LocalDgramEndpoint;
    use mirage_protocol::auth::v9::{TargetHint, V9ClientHello, WIRE_VERSION_V9};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    const NOW: u64 = 1_700_000_000_000;
    const SKEW: u64 = 300_000;

    fn hello_bytes(ts_ms: u64) -> Vec<u8> {
        V9ClientHello {
            version: WIRE_VERSION_V9,
            suite_ids: [0x01, 0x00, 0x00],
            e_pub_c: [0xAA; 32],
            ts_ms,
            client_proof: [0xBB; 16],
            client_static_pub: [0xCC; 32],
            cred_scheme: 0,
            target_hint: TargetHint::Legacy.to_byte(),
        }
        .to_wire()
        .to_vec()
    }

    /// A hello timestamped against the REAL clock — for any test that drives
    /// [`run_udp_session`] end to end. [`classify_datagram`] reads
    /// `crate::udp_face::now_ms()` internally rather than taking a caller-
    /// supplied "now" (unlike [`classify_v9_hello`] itself, which the
    /// classifier-agreement tests below call directly with the fixed `NOW`/
    /// `SKEW` constants) — so any hello meant to classify as
    /// [`Verdict::Wire`] through the real pipeline must carry a timestamp
    /// close to the actual wall clock, not the arbitrary historical `NOW`
    /// used where the clock is supplied explicitly.
    fn fresh_hello() -> Vec<u8> {
        hello_bytes(crate::udp_face::now_ms())
    }

    async fn bound_loopback_udp() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.expect("loopback UDP bind must succeed")
    }

    /// Root-only grant — matches `mirage_core::local_dgram_endpoint`'s own
    /// test helper; nothing in this crate's tests runs as anyone else.
    fn root_only_plan() -> mirage_core::local_endpoint::BindPlan {
        plan_from_resolution(AccountResolution::NotRequested)
    }

    /// A fresh, unused local-relay endpoint on whichever arm this target
    /// actually builds — unix scratch path on unix, loopback UDP (OS
    /// assigned port) everywhere else, mirroring `mirage_core::
    /// local_dgram_endpoint`'s own test helper of the same shape.
    #[cfg(unix)]
    fn fresh_relay_endpoint(name: &str) -> LocalDgramEndpoint {
        let dir = std::env::temp_dir()
            .join(format!("mirage-udp-relay-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        LocalDgramEndpoint::UnixDgram(dir.join("ch.sock"))
    }
    #[cfg(not(unix))]
    fn fresh_relay_endpoint(_name: &str) -> LocalDgramEndpoint {
        LocalDgramEndpoint::UdpLoopback(SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    #[cfg(unix)]
    fn managed_dir_for(ep: &LocalDgramEndpoint) -> Option<std::path::PathBuf> {
        match ep {
            LocalDgramEndpoint::UnixDgram(path) => path.parent().map(std::path::Path::to_path_buf),
            LocalDgramEndpoint::UdpLoopback(_) => None,
        }
    }
    #[cfg(not(unix))]
    fn managed_dir_for(_ep: &LocalDgramEndpoint) -> Option<std::path::PathBuf> {
        None
    }

    /// Bind a perimeter-side and a monitor-side [`LocalDgramSocket`], paired
    /// at each other — the test-scope stand-in for the two fixed,
    /// process-wide sockets `mirage_core::local_dgram_endpoint::
    /// LocalDgramChannel::{PerimeterWireDgram,MonitorWireDgram}` bind in
    /// production (plan step 6, not built here).
    async fn paired_relay_sockets() -> (Arc<LocalDgramSocket>, Arc<LocalDgramSocket>) {
        let perimeter_ep = fresh_relay_endpoint("perimeter");
        let monitor_ep = fresh_relay_endpoint("monitor");
        let plan = root_only_plan();

        let mut perimeter = LocalDgramSocket::bind(
            perimeter_ep.clone(),
            monitor_ep.clone(),
            managed_dir_for(&perimeter_ep).as_deref(),
            &plan,
        )
        .await
        .expect("bind perimeter-side relay socket");
        let perimeter_real = perimeter.local_endpoint().clone();

        let mut monitor = LocalDgramSocket::bind(
            monitor_ep.clone(),
            perimeter_real.clone(),
            managed_dir_for(&monitor_ep).as_deref(),
            &plan,
        )
        .await
        .expect("bind monitor-side relay socket");
        // On the loopback-UDP arm, both ports are OS-assigned — point each
        // side at what the other one actually got.
        perimeter.set_peer_endpoint(monitor.local_endpoint().clone());
        monitor.set_peer_endpoint(perimeter_real);

        (Arc::new(perimeter), Arc::new(monitor))
    }

    fn test_runtime_channel() -> (mpsc::Sender<crate::udp_face::UdpSession>, mpsc::Receiver<crate::udp_face::UdpSession>) {
        mpsc::channel(4)
    }

    // ── 1. A plausible V9 hello classifies as wire and reaches the relay ──

    #[tokio::test]
    async fn a_wire_session_relays_its_hello_byte_identical_to_the_monitor() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server addr");
        let (sessions_tx, mut sessions_rx) = test_runtime_channel();
        let cancel = CancellationToken::new();
        let runtime = crate::udp_face::test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);
        let counters = Arc::clone(runtime.counters());
        let dispatch = tokio::spawn(run_dispatcher(server, crate::stats::AddressFamily::V4, runtime));

        let (perimeter_sock, monitor_sock) = paired_relay_sockets().await;
        let relay = UdpMonitorRelay::new(perimeter_sock);

        let client = bound_loopback_udp().await;
        let client_addr = client.local_addr().expect("client addr");
        let hello = fresh_hello();
        client.send_to(&hello, server_addr).await.expect("send hello");

        let session = sessions_rx.recv().await.expect("session announced");
        assert_eq!(session.first_datagram, hello);

        let session_task = tokio::spawn(run_udp_session(
            session,
            server_addr.port(),
            Arc::clone(&relay),
            Arc::clone(&counters),
            SKEW,
            Disposition::Jail,
            cancel.clone(),
        ));

        let (envelope, payload) = tokio::time::timeout(Duration::from_secs(5), monitor_sock.recv_envelope())
            .await
            .expect("the monitor must receive the relayed hello")
            .expect("recv_envelope must succeed");
        assert_eq!(envelope.face_port, server_addr.port());
        assert_eq!(envelope.peer, client_addr);
        assert_eq!(payload, hello, "the relayed payload must be byte-identical to the wire hello");
        assert_eq!(counters.wire_routed.load(Ordering::Relaxed), 1);

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), session_task).await;
    }

    // ── 2. A non-wire datagram is refused, counted, and evicted fast ──

    #[tokio::test]
    async fn a_garbage_datagram_is_refused_counted_and_gone_well_before_the_idle_sweep() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server addr");
        let (sessions_tx, mut sessions_rx) = test_runtime_channel();
        let cancel = CancellationToken::new();
        let runtime = crate::udp_face::test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);
        let counters = Arc::clone(runtime.counters());
        let dispatch = tokio::spawn(run_dispatcher(server, crate::stats::AddressFamily::V4, runtime));

        let (perimeter_sock, _monitor_sock) = paired_relay_sockets().await;
        let relay = UdpMonitorRelay::new(perimeter_sock);

        let client = bound_loopback_udp().await;
        client.send_to(b"not a mirage hello", server_addr).await.expect("send garbage");

        let session = sessions_rx.recv().await.expect("session announced");
        assert_eq!(counters.sessions_active.load(Ordering::Relaxed), 1);

        let started = std::time::Instant::now();
        run_udp_session(session, server_addr.port(), relay, Arc::clone(&counters), SKEW, Disposition::Jail, cancel.clone())
            .await;
        let elapsed = started.elapsed();

        assert_eq!(counters.refused_not_wire.too_short.load(Ordering::Relaxed), 1, "too short must be the recorded reason");
        assert_eq!(counters.refused_drained.load(Ordering::Relaxed), 1);
        assert_eq!(counters.sessions_evicted_refused.load(Ordering::Relaxed), 1);
        assert!(
            elapsed < Duration::from_secs(30),
            "a refused session must be gone in well under the 600s idle sweep, took {elapsed:?}"
        );

        // Prove "gone" against the dispatcher's OWN bookkeeping, not merely
        // this task's local view of the session: the eviction request has
        // to actually reach `run_dispatcher` and remove its map entry.
        tokio::time::timeout(Duration::from_secs(5), async {
            while counters.sessions_active.load(Ordering::Relaxed) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the dispatcher must process the eviction and drop sessions_active to zero");

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    #[tokio::test]
    async fn a_hard_cut_face_refuses_at_once_with_no_drain() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server addr");
        let (sessions_tx, mut sessions_rx) = test_runtime_channel();
        let cancel = CancellationToken::new();
        let runtime = crate::udp_face::test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);
        let counters = Arc::clone(runtime.counters());
        let dispatch = tokio::spawn(run_dispatcher(server, crate::stats::AddressFamily::V4, runtime));

        let (perimeter_sock, _monitor_sock) = paired_relay_sockets().await;
        let relay = UdpMonitorRelay::new(perimeter_sock);

        let client = bound_loopback_udp().await;
        client.send_to(b"garbage", server_addr).await.expect("send garbage");
        let session = sessions_rx.recv().await.expect("session announced");

        let started = std::time::Instant::now();
        run_udp_session(session, server_addr.port(), relay, Arc::clone(&counters), SKEW, Disposition::HardCut, cancel.clone())
            .await;
        let elapsed = started.elapsed();

        assert_eq!(counters.refused_cut.load(Ordering::Relaxed), 1);
        assert_eq!(counters.refused_drained.load(Ordering::Relaxed), 0, "hard cut must never drain");
        assert!(
            elapsed < Duration::from_millis(REFUSED_SESSION_DRAIN_MS),
            "hard cut must be at least as fast as a jail drain, took {elapsed:?}"
        );

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
    }

    // ── 3. A monitor reply goes back out the SAME public socket ──

    #[tokio::test]
    async fn a_monitor_reply_returns_to_the_right_peer_from_the_same_public_socket() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server addr");
        let (sessions_tx, mut sessions_rx) = test_runtime_channel();
        let cancel = CancellationToken::new();
        let runtime = crate::udp_face::test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);
        let counters = Arc::clone(runtime.counters());
        let dispatch = tokio::spawn(run_dispatcher(server, crate::stats::AddressFamily::V4, runtime));

        let (perimeter_sock, monitor_sock) = paired_relay_sockets().await;
        let relay = UdpMonitorRelay::new(perimeter_sock);
        let inbound_task = tokio::spawn(Arc::clone(&relay).run_inbound(Arc::clone(&counters), cancel.clone()));

        let client = bound_loopback_udp().await;
        let client_addr = client.local_addr().expect("client addr");
        let hello = fresh_hello();
        client.send_to(&hello, server_addr).await.expect("send hello");

        let session = sessions_rx.recv().await.expect("session announced");
        let session_task = tokio::spawn(run_udp_session(
            session,
            server_addr.port(),
            Arc::clone(&relay),
            Arc::clone(&counters),
            SKEW,
            Disposition::Jail,
            cancel.clone(),
        ));

        let (_envelope, _payload) = tokio::time::timeout(Duration::from_secs(5), monitor_sock.recv_envelope())
            .await
            .expect("monitor receives the hello")
            .expect("recv_envelope succeeds");

        let reply_envelope = DgramEnvelope { face_port: server_addr.port(), peer: client_addr };
        monitor_sock
            .send_envelope(reply_envelope, b"server-hello-reply")
            .await
            .expect("monitor sends its reply over the local relay");

        let mut buf = [0u8; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("the client must receive the monitor's reply")
            .expect("recv_from must succeed");
        assert_eq!(&buf[..n], b"server-hello-reply");
        assert_eq!(
            from, server_addr,
            "the reply must arrive FROM the dispatcher's own bound socket, never a new one"
        );

        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), dispatch).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), session_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), inbound_task).await;
    }

    // ── 4. Cancellation releases everything the 4b pipeline added ──

    #[tokio::test]
    async fn cancelling_releases_the_dispatcher_and_the_relay_reader_and_the_session() {
        let server = bound_loopback_udp().await;
        let server_addr = server.local_addr().expect("server addr");
        let (sessions_tx, mut sessions_rx) = test_runtime_channel();
        let cancel = CancellationToken::new();
        let runtime = crate::udp_face::test_runtime_for(server_addr.port(), cancel.clone(), sessions_tx);
        let counters = Arc::clone(runtime.counters());
        let dispatch = tokio::spawn(run_dispatcher(server, crate::stats::AddressFamily::V4, runtime));

        let (perimeter_sock, _monitor_sock) = paired_relay_sockets().await;
        let relay = UdpMonitorRelay::new(perimeter_sock);
        let inbound_task = tokio::spawn(Arc::clone(&relay).run_inbound(Arc::clone(&counters), cancel.clone()));

        let client = bound_loopback_udp().await;
        client.send_to(&fresh_hello(), server_addr).await.expect("send hello");
        let session = sessions_rx.recv().await.expect("session announced");
        let session_task = tokio::spawn(run_udp_session(
            session,
            server_addr.port(),
            Arc::clone(&relay),
            Arc::clone(&counters),
            SKEW,
            Disposition::Jail,
            cancel.clone(),
        ));

        // Give every task a real turn to start before cancelling — proving a
        // task that never ran can be joined proves nothing.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(5), dispatch)
            .await
            .expect("the dispatcher must stop")
            .expect("dispatcher task must not panic");
        tokio::time::timeout(Duration::from_secs(5), inbound_task)
            .await
            .expect("the relay's inbound reader must stop")
            .expect("inbound task must not panic");
        tokio::time::timeout(Duration::from_secs(5), session_task)
            .await
            .expect("the session's relay loop must stop")
            .expect("session task must not panic");

        let rebound = UdpSocket::bind(server_addr).await;
        assert!(
            rebound.is_ok(),
            "the public port must be free once the dispatcher stops: {:?}",
            rebound.err()
        );
    }

    // ── 5. The shared classifier cannot drift between the two callers ──

    #[test]
    fn the_shared_classifier_agrees_with_itself_whether_assembled_whole_or_staged() {
        let whole = hello_bytes(NOW);

        // The datagram path: the whole buffer, once — exactly what
        // `classify_datagram` hands `classify_v9_hello`.
        let datagram_verdict = classify_v9_hello(&whole, NOW, SKEW);

        // `crate::face::handle_connection`'s own staged reassembly,
        // reproduced bit for bit rather than re-described: the first
        // `SSH_DECISION_LEN` bytes into one slice, the rest into another
        // slice of the SAME backing array.
        let mut staged = [0u8; crate::classify::V9_CLIENT_HELLO_LEN];
        let (opening, rest) = staged.split_at_mut(crate::classify::SSH_DECISION_LEN);
        opening.copy_from_slice(&whole[..crate::classify::SSH_DECISION_LEN]);
        rest.copy_from_slice(&whole[crate::classify::SSH_DECISION_LEN..]);
        let staged_verdict = classify_v9_hello(&staged, NOW, SKEW);

        assert_eq!(
            datagram_verdict, staged_verdict,
            "one shared classifier, byte-identical input from either caller, must agree with itself"
        );
        assert_eq!(datagram_verdict, Verdict::Wire(TargetHint::Legacy));
    }

    #[test]
    fn a_reason_that_does_not_classify_as_wire_still_agrees_across_both_assemblies() {
        let mut whole = hello_bytes(NOW);
        whole[0] = 0x08; // wrong version byte
        let datagram_verdict = classify_v9_hello(&whole, NOW, SKEW);

        let mut staged = [0u8; crate::classify::V9_CLIENT_HELLO_LEN];
        let (opening, rest) = staged.split_at_mut(crate::classify::SSH_DECISION_LEN);
        opening.copy_from_slice(&whole[..crate::classify::SSH_DECISION_LEN]);
        rest.copy_from_slice(&whole[crate::classify::SSH_DECISION_LEN..]);
        let staged_verdict = classify_v9_hello(&staged, NOW, SKEW);

        assert_eq!(datagram_verdict, staged_verdict);
        assert_eq!(datagram_verdict, Verdict::NotWire(NotWireReason::BadVersion(0x08)));
    }
}
