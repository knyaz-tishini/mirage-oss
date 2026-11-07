//! `mirage-perimeter` — the box's public front door.
//!
//! # What this crate is
//!
//! Every public port a box answers Mirage on used to be bound directly by
//! the monitor. This crate is the daemon that stands in front of it
//! instead: it owns every attacker-facing byte, terminates the outer
//! camouflage (`mirage-protocol::camouflage::pipeline::strip_tcp_server`),
//! classifies whether what remains looks like Mirage wire
//! (`classify::classify_v9_hello`), and either splices the connection
//! through to the co-located monitor on loopback (`face::route_to_inner`)
//! or rejects it. It is a real deployable service: `[[bin]] name =
//! "mirage-perimeter"`, capsule-booted identity (`capsule_boot`,
//! `identity`, `bootstrap`), a config resolved strictly from that capsule
//! (`config`), one accept-loop task per public face (`face`), and a
//! box-local query channel (`stats`) that answers typed questions about its
//! faces, health and counters over a unix socket — no port, no HTTP.
//!
//! # Two boot shapes — the capsule and the STANDALONE box
//!
//! The fleet shape is [`run`]: bind the baseline, wait for a capsule, add
//! the faces that capsule declares on top of it.
//!
//! The STANDALONE shape is [`run_standalone`]: the face list comes from a
//! local config ([`config::PerimeterConfig::from_local_faces`]), the wire
//! key from a wire-only identity ([`identity::Identity::wire_only`]), and
//! there is no capsule, no declaration, no charter and no keeper to wait
//! for. That is the box a user installs on their own server.
//!
//! What does NOT differ is the machinery: the accept loop, the classifier,
//! the inward splice by a face's own purpose, the rate limiter, the jail
//! and the query channel are the SAME code on both paths —
//! [`Surface::bind_surface`] is the one place a face is bound, and
//! [`Surface::bind_standalone`] hands it the local list where
//! [`Surface::bind_baseline`] hands it the baseline. A standalone box
//! binds EXACTLY the faces its config names: no baseline underneath it,
//! and no capsule on top of it.
//!
//! Decoys, honeypots and jails are the PERIMETER — not the policy-
//! enforcement core. `mirage-secd` used to construct a `DecoyState` and
//! spawn tripwire listeners unconditionally at boot (no policy gate, no
//! directive, no config — eight trap ports live on every fleet box
//! regardless of any operator decision). That is two jobs done by one
//! daemon: `mirage-secd` is the policy-enforcement core (Tier2 policy, the
//! warden pair protocol, kernel-event batching + delivery, patch/reboot
//! scheduling, egress, sysctl/module hardening, the ban engine, posture +
//! inventory reporting) and must not also run the periphery. This crate is
//! deliberately a SEPARATE `ServiceRole` (`Perimeter`, not `Secd`) for the
//! same reason: a daemon that enforces kernel policy must not also run the
//! box's only public listener.
//!
//! # Interim scope — REJECT is the only non-wire outcome today
//!
//! This crate does NOT build decoy/jail/honeypot dispatch. Every
//! connection that fails [`classify::classify_v9_hello`] is simply
//! rejected — the connection is dropped, full stop (`face::
//! handle_connection`'s own doc marks the exact seam). This is a
//! deliberate interim decision, not an oversight: routing a `BadVersion`
//! HTTP probe to a decoy, a near-miss `TimestampSkew` to a jail, or
//! anything else to a honeypot is a real classification problem this crate
//! does not yet solve, and shipping a REJECT-only front door that at least
//! terminates camouflage and defends the monitor correctly is strictly
//! better than not shipping one while that problem gets solved.
//!
//! # The core/periphery edge (cut 2026-07-31)
//!
//! At the move, `decoy.rs` still called directly into `mirage-secd`'s
//! `banengine`/`intel`/`fw` modules — in-process `Arc`-shared state that
//! cannot survive the perimeter becoming a genuinely separate process. That
//! edge is now cut: this crate has no dependency on `mirage-secd` at all
//! (check `Cargo.toml`). In its place:
//!
//! - **The perimeter does not ban.** Applying an nft rule is the arbiter's
//!   act (`mirage-secd::fw::ban_for`), not the periphery's.
//! - **The perimeter does not compute escalation policy.** Mapping an
//!   offense count to a ban TTL (`mirage-secd::fw::escalated_ban_ttl_ms`) is
//!   a policy decision, and policy decisions belong to the root arbiter.
//! - **The perimeter reports.** `decoy.rs` emits a typed
//!   [`mirage_core::perimeter_observation::PerimeterObservation`] — the
//!   touching IP, the decoy port, a signal classification, the perimeter's
//!   own local touch ledger for that IP, and a deterministic confidence
//!   bucket — through an [`sink::ObservationSink`] supplied at
//!   [`decoy::DecoyState`] construction. This crate defines that trait and
//!   does not implement it: consuming the reported rows is the arbiter's
//!   job, once the arbiter is reachable as a separate process. `DecoyState`
//!   keeps its OWN per-IP touch counter (not secd's `BanEngineState`) purely
//!   for its own future decoy-vs-jail decisions.
//!
//! `PerimeterObservation` lives in `mirage-core` rather than in either
//! plane's crate — see that module's doc for why.
//!
//! # What is still genuinely open
//!
//! - **The 3-way classifier ahead of decoy/jail/honeypot dispatch** — today
//!   `classify::NotWireReason` is recorded but every reason takes the same
//!   REJECT action (see "Interim scope" above and `face::
//!   handle_connection`'s marked seam). Nothing yet decides "decoy vs jail
//!   vs honeypot" for a given non-wire touch.
//! - **Jail and honeypot as their own components** (possibly their own
//!   binaries) alongside decoy — not built here. `decoy.rs`/`bomb.rs` (the
//!   pre-daemon library seed) are unused by the daemon boot path today;
//!   wiring them into a face's REJECT arm is exactly the seam above.
//! - **A concrete [`sink::ObservationSink`] implementation** that actually
//!   reaches the arbiter (IPC or wire) once perimeter and arbiter are
//!   separate processes — today only test recorders exist.

pub mod bomb;
pub mod bootstrap;
pub mod capsule_boot;
pub mod classify;
pub mod config;
pub mod decoy;
pub mod face;
pub mod identity;
pub mod jail;
pub mod observe;
pub mod ratelimit;
pub mod sink;
pub mod stats;
pub mod timing;
pub mod udp_face;
pub mod udp_relay;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use mirage_core::capsule::CapsuleServiceConfig;
use mirage_core::crypto::KeyPair;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{ConfigError, PerimeterConfig};
use crate::face::{SharedFace, SharedKeypair};
use crate::identity::Identity;
use crate::jail::Disposition;

/// How often the surface re-asks the keeper which capsule this box holds.
///
/// The whole exchange is a request and a reply over a unix socket inside
/// one box — the same socket, and the same order of cadence, as
/// `identity_boot::MACHINE_SLICE_RETRY_MS`'s own retry. Nothing is logged
/// and nothing is touched when the answer has not changed
/// ([`Surface::watch_for_a_new_capsule`]), so the steady-state cost of this
/// is one local round trip every few seconds for the life of the process,
/// against the alternative of a box that cannot take a capsule until
/// somebody restarts the daemon by hand.
///
/// Reuses [`mirage_core::identity_boot::MACHINE_SLICE_WATCH_INTERVAL`]
/// rather than its own literal — that constant's own doc names this crate's
/// detection loop as the working reference its generalised watcher was
/// built from, so the two cadences are the same number by construction, not
/// by two people picking `5` independently and being free to drift apart
/// the next time either is touched.
const CAPSULE_WATCH_INTERVAL: Duration = mirage_core::identity_boot::MACHINE_SLICE_WATCH_INTERVAL;

/// Grace delay before process exit — gives tracing/logging a chance to
/// flush. Mirrors `mirage-secd`/`mirage-warden`'s constant of the same
/// name/value.
pub const SHUTDOWN_GRACE_MS: u64 = 100;

/// Brief delay (ms) before process exit on panic — mirrors `mirage-secd`'s
/// `PANIC_SLEEP_MS`.
pub const PANIC_SLEEP_MS: u64 = 100;

/// Daemon entry point. Blocks forever under normal operation — exit is by
/// process signal or panic->respawn (systemd `Restart=always`). Unlike the
/// per-role capsule model this replaced, there is no renewal loop left to
/// exit through: the keeper owns the machine capsule's whole lifetime, and
/// this process only ever reads it (`capsule_boot::acquire_identity` at
/// boot, then `capsule_boot::reacquire_identity` on a cadence — see
/// [`Surface::apply_identity_when_ready`] for why the read repeats).
///
/// # Why the surface cannot wait for an identity
///
/// An identity arrives THROUGH this surface: the keeper's own answer to
/// `capsule_boot::acquire_identity` still has to reach this box over
/// whatever this process fronts, and an operator's manual delivery
/// (`POST /capsule/seed/target`) reaches it the same way. A surface that
/// waits for an identity before it binds anything can therefore never
/// receive one on its own — the wait and the only thing that could end it
/// sit on opposite sides of a door that has not opened yet. `us-example-203.0.113.10` paid for exactly this on 2026-08-18: the pre-fix perimeter
/// waited on `acquire_identity` before binding a single socket, and once a
/// capsule DID land the same process then handed `:22` away from mshd's own
/// recovery listener — so a box that lost that race, or that raced it again
/// on the next reboot, had nothing of its own left standing to answer
/// either the mesh or the operator.
///
/// The baseline surface ([`config::PerimeterConfig::baseline`]) is
/// hardening that stands on its own, independent of the mesh: it needs no
/// identity to bind, none to classify a connection, and none to splice
/// `:22` through to the co-located mshd. An identity only ever ADDS to it —
/// mesh function for the wire faces, persona camouflage on top of the
/// baseline's own ports — and never gates whether this box answers at all.
///
/// # Boot sequence
///
/// 1. [`Surface::bind_baseline`] binds `:22`/`:80`/`:443` with
///    `TransportCamouflage::None` and starts routing on them immediately —
///    the SAME `face::run_face` accept loop, classifier and splice a
///    capsule-declared face uses; no second mechanism.
/// 2. [`Surface::bind_local_dgram_relay`] binds this process's own two
///    box-local datagram relay sockets — one per inward destination a UDP
///    face's declared purpose can route to (monitor, node) — once each,
///    unconditionally, whether or not a capsule ever declares a UDP face of
///    either purpose. See that method's own doc for why both are awaited
///    directly here rather than spawned the way step 1's query channel is:
///    a session task added in step 4 below must never be able to race
///    either bind.
/// 3. This box's identity is acquired in a background task
///    (`Surface::apply_identity_when_ready`, wrapping
///    `capsule_boot::acquire_identity`) — however long that takes, the
///    surface bound in steps 1-2 keeps serving.
/// 4. When it lands, every capsule-declared face is added on top of the
///    running surface: a port the baseline already bound is swapped in
///    place — bind-then-swap, never unbind-then-bind, so `:22`/`:80`/`:443`
///    stay listening continuously — and a genuinely new port (TCP or UDP)
///    is bound fresh. Applying the same capsule twice is a no-op the second
///    time, never a double bind.
/// 5. Before an identity lands, a non-SSH connection on the baseline is
///    handled exactly as a non-wire connection is handled on any other
///    face today — no new disposition (`crate::jail`).
/// 6. A keeper that never answers, or a capsule that does not resolve to a
///    valid face list, degrades this box to the baseline forever — never to
///    nothing.
pub async fn run() -> Result<()> {
    let mut surface = Surface::bind_baseline();
    surface.bind_local_dgram_relay().await;
    tokio::spawn(surface.apply_identity_when_ready());

    tracing::info!("[perimeter] boot sequence complete — supervising forever");
    std::future::pending::<()>().await;
    Ok(())
}

/// Everything that can be wrong with a STANDALONE boot.
///
/// A standalone box has no capsule to refuse and no keeper to wait for, so
/// the only thing left to refuse is the face list itself — and it is
/// refused rather than half-honoured, for the reason `crate::config`'s own
/// module doc gives.
#[derive(Debug, Error)]
pub enum PerimeterError {
    /// The resolved config declares no face at all.
    #[error(
        "the standalone face list is empty — this box would bind nothing on any public port \
         while reporting healthy; refusing to boot dark"
    )]
    NoFaces,
    /// The resolved config is not internally consistent — a zero port, or
    /// two faces on one port.
    #[error("the standalone face list is not valid: {0}")]
    Config(#[from] ConfigError),
}

/// Refuse a standalone config that would bind fewer doors than it claims,
/// or none at all.
///
/// The same checks `crate::config::PerimeterConfig::from_local_faces`
/// makes on the way IN, re-made on the way in through `run_standalone`
/// too — because a caller may hand this function a config it built by
/// hand, and a config whose two faces share one port would leave the
/// second one retrying a bind forever while the process reported healthy.
///
/// The port check is PER TRANSPORT, as it is on the way in: a TCP face and
/// a UDP face may carry the same number, because TCP and UDP are separate
/// socket spaces. Two faces on the same transport may not.
fn validate_standalone_config(config: &PerimeterConfig) -> Result<(), PerimeterError> {
    if config.faces.is_empty() && config.udp_faces.is_empty() {
        return Err(PerimeterError::NoFaces);
    }
    let mut seen_tcp: HashSet<u16> = HashSet::with_capacity(config.faces.len());
    let mut seen_udp: HashSet<u16> = HashSet::with_capacity(config.udp_faces.len());
    for face in &config.faces {
        if face.port == 0 {
            return Err(ConfigError::ZeroPort.into());
        }
        if !seen_tcp.insert(face.port) {
            return Err(ConfigError::DuplicatePort(face.port).into());
        }
    }
    for face in &config.udp_faces {
        if face.port == 0 {
            return Err(ConfigError::ZeroPort.into());
        }
        if !seen_udp.insert(face.port) {
            return Err(ConfigError::DuplicatePort(face.port).into());
        }
    }
    Ok(())
}

/// Daemon entry point for the STANDALONE perimeter — the box a user
/// installs on their own server, with no keeper, no capsule and no mesh
/// behind it.
///
/// What it does, in order:
///
/// 1. Binds EXACTLY the faces `cfg` names — and nothing else. There is no
///    baseline underneath: `:22`/`:80`/`:443` stay closed unless the
///    operator's own face list names them, because there is no capsule
///    here to be hardened against and a closed door is a smaller promise
///    than an open one nobody asked for.
/// 2. Binds the box-local datagram relays and the UDP faces `cfg` names,
///    if it names any — the same relays, the same refusal rules and the
///    same per-face purpose routing a capsule-declared UDP face gets.
/// 3. Serves the box-local query channel, so `PerimeterRequest::Health`
///    answers with this box's real `faces_bound` count and every other
///    typed request works as it does on the capsule path.
///
/// What it does NOT do, by construction: wait for a capsule, ask a keeper
/// for one, acquire an identity, or talk to the monitor. The face list
/// and the wire key are handed in, and the faces those two name are bound
/// and served.
///
/// The inward splice of a wire-classified connection follows the face's
/// own `FacePurpose` exactly as it does on the capsule path — the
/// destination is a box-local channel, not a monitor API call.
pub async fn run_standalone(cfg: PerimeterConfig, identity: Identity) -> Result<(), PerimeterError> {
    let config = Arc::new(cfg);
    let mut surface = Surface::bind_standalone(Arc::clone(&config), &identity)?;

    // The relays exist for UDP faces alone. A TCP-only standalone config
    // never binds them, and so never touches a box-local socket path it
    // has no use for.
    if !config.udp_faces.is_empty() {
        surface.bind_local_dgram_relay().await;
        surface.apply_udp_faces(&config).await;
    }

    surface.serve_queries();

    tracing::info!("[perimeter] standalone boot sequence complete — supervising forever");
    std::future::pending::<()>().await;
    Ok(())
}

/// One entry in [`Surface::ports`]: a live face plus the means to stop it.
///
/// `cancel` and `face` are two different cells for two different lifetimes.
/// `face` is swapped on every capsule that still declares this port — the
/// listener never notices. `cancel` fires exactly once, the moment a
/// capsule stops declaring this port at all: every accept loop
/// (`crate::face::accept_loop`) races it against `listener.accept()`, and
/// `handle` is that same task's [`JoinHandle`] — [`Surface::apply_config`]
/// awaits it after firing `cancel` so that "retired" in
/// [`Surface::ports`]/`Surface::stats` never claims more than what already
/// happened: the listener has actually returned and the OS has actually
/// taken the port back, not merely been asked to.
struct BoundFace {
    face: SharedFace,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

/// One entry in [`Surface::udp_ports`]: a live UDP face plus the means to
/// stop it — the datagram counterpart of [`BoundFace`].
///
/// # Why this holds two handles where `BoundFace` holds one
///
/// A UDP face has no `TcpListener::accept()` loop to hand a per-connection
/// task its own independent fd — every peer's traffic shares the one bound
/// socket `udp_face::run_udp_face` owns (see that module's own doc, "A UDP
/// face has nothing to accept"). `docs/mirage/plans/
/// udp-front-door-u0-2026-09-05.md` §1.5 names the consequence plainly:
/// retiring the socket ends every live peer session on it in the same
/// instant, because a session has no fd of its own to keep running on once
/// the socket is gone. This struct turns that from an assumption into an
/// assertable fact: `dispatch` is [`udp_face::run_udp_face`]'s own join
/// handle (both address families joined internally — see that function's
/// own doc), and `sessions` is [`run_udp_sessions`]'s own join handle — the
/// per-session supervisor that spawns one task per session
/// [`udp_face::run_udp_face`] announces and does not return until every one
/// of them has actually finished, not merely been told to. [`Surface::
/// apply_config`] awaits BOTH before a retired UDP port leaves [`Surface::
/// udp_ports`], so "gone from the map" means the socket is released AND
/// every peer session it was carrying has ended — not merely asked to,
/// matching the promise [`BoundFace`]'s own doc makes for TCP, extended to
/// cover the one extra thing a UDP face owns that a TCP face's listener
/// does not.
struct BoundUdpFace {
    /// Fired exactly once by whatever retires this UDP port
    /// (`Surface::apply_config`). Raced by `udp_face::run_udp_face`'s own
    /// dispatcher(s) AND by every session [`run_udp_sessions`] has spawned
    /// for this face — one signal reaches both, which is exactly what makes
    /// "cancel, then await both handles" a genuine proof of full teardown
    /// rather than a proof of the socket alone.
    cancel: CancellationToken,
    /// `udp_face::run_udp_face`'s own join handle.
    dispatch: JoinHandle<()>,
    /// [`run_udp_sessions`]'s own join handle.
    sessions: JoinHandle<()>,
}

/// The per-session supervisor for one UDP face: spawn one task
/// (`udp_relay::run_udp_session`) per session `udp_face::run_udp_face`
/// announces on `sessions`, and do not return until every one of them has
/// actually finished — the seam [`BoundUdpFace`]'s own doc names as what
/// makes this crate's retirement proof cover a UDP face's live sessions,
/// not merely its socket.
///
/// Ends its own announce-reading loop on whichever comes first: `cancel`
/// firing (the face is being retired) or `sessions` closing (`udp_face::
/// run_udp_face` itself returned — both address families permanently gave
/// up). Either way, every session task already spawned is still tracked in
/// `live`, and this function does not return until [`tokio::task::
/// JoinSet::join_next`] has drained it empty — every one of
/// `udp_relay::run_udp_session`'s own exit paths (relayed to completion,
/// refused and evicted, or this same `cancel` reaching it too, since it is
/// handed a clone of it) is a task this loop will observe finishing before
/// giving this function's own caller its join handle back.
async fn run_udp_sessions(
    mut sessions: mpsc::Receiver<udp_face::UdpSession>,
    face_port: u16,
    relay: Arc<udp_relay::UdpMonitorRelay>,
    counters: Arc<udp_face::UdpFaceCounters>,
    max_skew_ms: u64,
    disposition: Disposition,
    cancel: CancellationToken,
) {
    let mut live = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            maybe_session = sessions.recv() => match maybe_session {
                Some(session) => {
                    live.spawn(udp_relay::run_udp_session(
                        session,
                        face_port,
                        Arc::clone(&relay),
                        Arc::clone(&counters),
                        max_skew_ms,
                        disposition,
                        cancel.clone(),
                    ));
                }
                None => break,
            },
        }
    }
    // Drain every session this face ever announced — the proof that
    // retiring a UDP face ends its live sessions, not merely its
    // dispatcher. A session already mid-teardown for its own reason
    // (refused and evicted, or classified wire and relaying) finishes on
    // its own; one still relaying is ended by the SAME `cancel` this loop
    // itself just raced, since every spawn above hands it a clone.
    while live.join_next().await.is_some() {}
}

/// Which fixed box-local channel a UDP face's declared [`config::
/// FacePurpose`] routes to — the datagram counterpart of `crate::face::
/// inward_target`, which makes the identical decision for a TCP face's
/// purpose. Pure, and used only to NAME the destination in a refusal log
/// line: [`Surface::dgram_relay_for`] is the function that actually selects
/// which bound relay a session is routed through.
fn udp_relay_channel_for(
    purpose: config::FacePurpose,
) -> mirage_core::local_dgram_endpoint::LocalDgramChannel {
    match purpose {
        config::FacePurpose::MonitorWire => {
            mirage_core::local_dgram_endpoint::LocalDgramChannel::PerimeterWireDgram
        }
        config::FacePurpose::NodeChain => {
            mirage_core::local_dgram_endpoint::LocalDgramChannel::PerimeterNodeChainDgram
        }
        config::FacePurpose::EdgeEntrance => {
            mirage_core::local_dgram_endpoint::LocalDgramChannel::PerimeterEdgeChainDgram
        }
    }
}

/// Everything the running surface needs in order to change after boot.
///
/// [`Self::bind_baseline`] builds one, binding the baseline surface
/// synchronously; `run` then hands it to exactly one background task
/// ([`Self::apply_identity_when_ready`]), which owns it for the rest of the
/// process's life. Nothing else ever touches [`Self::ports`] — the query
/// channel (`stats::run_query_server`) reads `Self::stats` independently
/// and needs no lock of its own, since `stats::Stats`'s own internals are
/// already safe to read from any task (see that type's doc).
struct Surface {
    stats: Arc<stats::Stats>,
    /// ONE limiter for every face, baseline and capsule-added alike — a
    /// source address gets one budget for the whole box, not one per
    /// generation of faces it happens to hit. See `ratelimit`'s module doc.
    rate_limit: Arc<ratelimit::SourceRateLimit>,
    sink: Arc<observe::SecdSink>,
    /// This process's wire identity — a boot-only random key until
    /// [`Self::apply_identity_when_ready`] swaps in the real one. Shared by
    /// every face, baseline and capsule-added, because there is exactly one
    /// identity per process, never one per port.
    keypair: SharedKeypair,
    /// Every currently-bound port's live face, keyed by port — how
    /// [`Self::apply_config`] tells "swap the face already serving this
    /// port" apart from "bind a genuinely new one" apart from "this port is
    /// no longer declared at all". See [`BoundFace`].
    ports: HashMap<u16, BoundFace>,
    /// Every currently-bound UDP port's live face — the datagram
    /// counterpart of [`Self::ports`]. See [`BoundUdpFace`] for what "live"
    /// proves on retirement, and `config::PerimeterConfig::udp_faces`'s own
    /// doc for why this only ever grows from a capsule
    /// ([`Self::apply_config`]), never from [`Self::bind_baseline`] — there
    /// is no baseline UDP face.
    udp_ports: HashMap<u16, BoundUdpFace>,
    /// Every UDP port this surface has refused to bind at all, because its
    /// declared purpose's box-local relay never bound at boot — see [`Self::
    /// apply_config`]'s own doc, "UDP faces route by their own declared
    /// purpose". Kept apart from [`Self::udp_ports`] because a refused port
    /// never has a [`BoundUdpFace`] to retire: there is no dispatcher, no
    /// session supervisor, nothing to cancel or await, only a
    /// `stats::Stats::note_udp_face_refused` entry. This set exists so a
    /// LATER capsule that stops declaring a refused port is still noticed —
    /// [`Self::apply_config`]'s retirement pass reads it exactly like
    /// [`Self::udp_ports`]'s own keys — and so a capsule that keeps
    /// redeclaring an already-refused port is not re-refused (and re-logged,
    /// and re-registered in `stats`) on every reapplication.
    udp_refused: HashSet<u16>,
    /// The box-local relay to the monitor, for a UDP face whose declared
    /// purpose is [`config::FacePurpose::MonitorWire`] — bound once, at
    /// boot, by [`Self::bind_local_dgram_relay`], independent of whether
    /// any UDP face is ever declared. `None` only if that bind itself
    /// failed; see that method's own doc for what this surface does then
    /// (every TCP face keeps serving; a capsule that later declares a
    /// `MonitorWire`-purposed UDP face is refused rather than served with
    /// nowhere to relay its wire traffic to).
    dgram_relay_monitor: Option<Arc<udp_relay::UdpMonitorRelay>>,
    /// The box-local relay to the co-located node, for a UDP face whose
    /// declared purpose is [`config::FacePurpose::NodeChain`] — the
    /// datagram counterpart of [`Self::dgram_relay_monitor`], bound to
    /// [`mirage_core::local_dgram_endpoint::LocalDgramChannel::
    /// PerimeterNodeChainDgram`] by the same [`Self::bind_local_dgram_relay`]
    /// call. [`Self::dgram_relay_for`] is the one place that picks between
    /// this field and [`Self::dgram_relay_monitor`] — purely from the
    /// face's own declared purpose, never from anything else about the
    /// face — and a face whose purpose's relay is `None` here is refused
    /// rather than served through the other one.
    dgram_relay_node: Option<Arc<udp_relay::UdpMonitorRelay>>,
    /// The box-local relay to the co-located `mirage-edge` unit, for a UDP
    /// face whose declared purpose is [`config::FacePurpose::EdgeEntrance`]
    /// — the [`Self::dgram_relay_node`] sibling for a box that runs no
    /// `mirage-node` at all, bound to
    /// [`mirage_core::local_dgram_endpoint::LocalDgramChannel::
    /// PerimeterEdgeChainDgram`] by the same [`Self::bind_local_dgram_relay`]
    /// call. `None` only if that bind itself failed; the same refuse-rather-
    /// than-misroute rule [`Self::dgram_relay_monitor`]'s own doc states
    /// applies here too.
    dgram_relay_edge: Option<Arc<udp_relay::UdpMonitorRelay>>,
    /// Set the first time a `MonitorWire`-purposed UDP face is added —
    /// `udp_relay::UdpMonitorRelay::run_inbound` is spawned then, against
    /// THAT face's own counters, and never spawned a second time: the
    /// monitor relay pair is shared by every `MonitorWire`-purposed UDP face
    /// this process ever adds (`mirage_core::local_dgram_endpoint`'s own
    /// "one pair serves the whole box" doctrine), not owned by any single
    /// one of them. There is at most one UDP face of either purpose on any
    /// box that exists today (`config::PerimeterConfig::udp_faces`'s own
    /// doc), so tying this reader to the first such face's counters is
    /// exact, not an approximation; a future box running more than one
    /// would need this reader wired to something other than a single
    /// face's counters — named here as the seam, not solved, since nothing
    /// today can reach that case.
    dgram_relay_monitor_inbound: Option<JoinHandle<()>>,
    /// The same bookkeeping as [`Self::dgram_relay_monitor_inbound`], for
    /// the node relay — set the first time a `NodeChain`-purposed UDP face
    /// is added, reading from [`Self::dgram_relay_node`]'s own counters.
    dgram_relay_node_inbound: Option<JoinHandle<()>>,
    /// The same bookkeeping as [`Self::dgram_relay_monitor_inbound`], for
    /// the edge relay — set the first time an `EdgeEntrance`-purposed UDP
    /// face is added, reading from [`Self::dgram_relay_edge`]'s own
    /// counters.
    dgram_relay_edge_inbound: Option<JoinHandle<()>>,
}

impl Surface {
    /// Bind the baseline surface — point 1 of `run`'s doc. Reuses
    /// `face::run_face` for every one of [`config::PerimeterConfig::
    /// baseline`]'s faces exactly as a capsule-declared face is bound:
    /// nothing here is a second accept loop or a second classifier.
    fn bind_baseline() -> Self {
        let config = Arc::new(PerimeterConfig::baseline());

        // The port list is RENDERED, never spelled out by hand — a message
        // that names a surface has to read the surface, not assume it.
        let bound: Vec<String> = config.faces.iter().map(|f| f.label.clone()).collect();
        tracing::warn!(
            faces = config.faces.len(),
            surface = %bound.join(","),
            wire_channel = %mirage_core::local_endpoint::LocalChannel::MonitorWireSplice.endpoint(),
            ssh_channel = %mirage_core::local_endpoint::LocalChannel::MshdSshSplice.endpoint(),
            "[perimeter] binding the baseline surface — no identity yet, and none required to \
             answer. Wire is routed to the monitor and SSH-shaped bytes to mshd exactly as a \
             capsule-declared face would; what an identity adds on top is persona camouflage and \
             mesh function, never the right to answer at all."
        );

        // A locally generated key for as long as this boot runs on the
        // baseline alone. Every baseline face is `TransportCamouflage::
        // None`, which `strip_tcp_server` never reads a keypair for — only
        // `Reality` does, and no baseline face is `Reality` — so this is a
        // placeholder its signature requires, not a credential anything
        // downstream trusts. See `face::SharedKeypair`'s own doc.
        let keypair: SharedKeypair = Arc::new(ArcSwap::from_pointee(KeyPair::generate()));

        let surface = Self::bind_surface(config, keypair);
        surface.serve_queries();
        surface
    }

    /// Bind the STANDALONE surface — exactly the faces a local config
    /// named, and nothing else.
    ///
    /// No baseline underneath: a standalone box has no capsule to be
    /// hardened against, so `:22`/`:80`/`:443` stay closed unless the
    /// operator's own face list names them. Everything else is the
    /// baseline's own machinery — the same `face::run_face` accept loop,
    /// classifier and inward splice, the same rate limiter, the same
    /// observation channel — reached through [`Self::bind_surface`], which
    /// is the ONE place a face is bound.
    ///
    /// The wire keypair is the one the operator handed this boot, not a
    /// boot-only placeholder: on the standalone path there is no later
    /// capsule to swap a real key in for.
    fn bind_standalone(
        config: Arc<PerimeterConfig>,
        identity: &Identity,
    ) -> Result<Self, PerimeterError> {
        validate_standalone_config(&config)?;

        // The port list is RENDERED, never spelled out by hand — a message
        // that names a surface has to read the surface, not assume it.
        let bound: Vec<String> = config.faces.iter().map(|f| f.label.clone()).collect();
        tracing::warn!(
            faces = config.faces.len(),
            surface = %bound.join(","),
            "[perimeter] binding the standalone surface — exactly the faces the local config \
             named, with no capsule, no declaration and no baseline underneath them. Wire is \
             routed by each face's own purpose exactly as a capsule-declared face would be"
        );

        let keypair: SharedKeypair = Arc::new(ArcSwap::from_pointee(identity.wire_keypair.clone()));
        Ok(Self::bind_surface(config, keypair))
    }

    /// Bind `config`'s TCP faces and build the surface around them — the
    /// ONE place a face is bound, shared by the baseline surface and the
    /// standalone one so the two cannot drift apart on what a bound face
    /// is.
    ///
    /// Reuses `face::run_face` for every face exactly as a capsule-declared
    /// face is bound: nothing here is a second accept loop or a second
    /// classifier.
    fn bind_surface(config: Arc<PerimeterConfig>, keypair: SharedKeypair) -> Self {
        let (stats, face_counters) = stats::Stats::new(&config.faces);
        let rate_limit = Arc::new(ratelimit::SourceRateLimit::new(
            config.accept_per_ip_per_sec,
            config.accept_burst,
        ));

        // The observation channel. Spawned BEFORE the faces so the first
        // rejected touch of this process's life has somewhere to go, and
        // deliberately not awaited on: if secd is not listening yet, the
        // drain task retries in the background while the faces serve.
        let sink = observe::SecdSink::spawn();
        stats.attach_observation(sink.stats());

        let mut ports = HashMap::with_capacity(config.faces.len());
        for (face, counters) in config.faces.clone().into_iter().zip(face_counters) {
            let port = face.port;
            let shared: SharedFace = Arc::new(ArcSwap::from_pointee(face));
            let cancel = CancellationToken::new();
            let handle = tokio::spawn(face::run_face(
                Arc::clone(&shared),
                Arc::clone(&config),
                Arc::clone(&keypair),
                counters,
                Arc::clone(&rate_limit),
                Arc::clone(&sink),
                cancel.clone(),
            ));
            ports.insert(port, BoundFace { face: shared, cancel, handle });
        }

        Self {
            stats,
            rate_limit,
            sink,
            keypair,
            ports,
            // No baseline UDP face — see `config::PerimeterConfig::
            // udp_faces`'s own doc. `dgram_relay_monitor`, `dgram_relay_node`
            // and `dgram_relay_edge` all start `None`: `run` binds them
            // separately via `Self::bind_local_dgram_relay`, deliberately
            // after this constructor returns rather than inside it — see
            // that method's own doc for why.
            udp_ports: HashMap::new(),
            udp_refused: HashSet::new(),
            dgram_relay_monitor: None,
            dgram_relay_node: None,
            dgram_relay_edge: None,
            dgram_relay_monitor_inbound: None,
            dgram_relay_node_inbound: None,
            dgram_relay_edge_inbound: None,
        }
    }

    /// Spawn the box-local query channel — the typed socket this daemon
    /// answers [`stats::PerimeterRequest`]s on, and the channel
    /// `PerimeterRequest::Health` (and its `faces_bound`) is asked over.
    ///
    /// Fire-and-forget, because it SERVES forever: nothing that binds
    /// could await it without hanging the whole boot on a call that never
    /// returns.
    fn serve_queries(&self) {
        let build_id = env!("CARGO_PKG_VERSION");
        let query_stats = Arc::clone(&self.stats);
        tokio::spawn(async move {
            if let Err(e) = stats::run_query_server(query_stats, build_id).await {
                // Not fatal — the faces keep routing — but not harmless
                // either, and the line says which. mshd's recovery door
                // reads the face list off this channel to decide who owns
                // `:22`; with the channel gone that read fails, and an
                // unreadable face list resolves towards the door HOLDING
                // the port. The operator still gets in, without this
                // daemon's classification and jail.
                tracing::error!(
                    error = %e,
                    channel = %mirage_core::local_endpoint::LocalChannel::PerimeterQuery.endpoint(),
                    "[perimeter/query] the query channel did not bind — every face keeps serving, \
                     but nothing on this box can read this daemon's faces, health or counters, \
                     and mshd will hold :22 rather than hand it over"
                );
            }
        });
    }

    /// Bind this process's own three box-local datagram relay sockets — the
    /// rendezvous points every UDP face's session tasks send classified-wire
    /// traffic through, one per inward destination a face's declared
    /// [`config::FacePurpose`] can route to (`mirage_core::
    /// local_dgram_endpoint`'s module doc, "one pair serves the whole
    /// box"): [`config::FacePurpose::MonitorWire`] toward the co-located
    /// monitor over [`mirage_core::local_dgram_endpoint::LocalDgramChannel::
    /// PerimeterWireDgram`], [`config::FacePurpose::NodeChain`] toward the
    /// co-located node over [`mirage_core::local_dgram_endpoint::
    /// LocalDgramChannel::PerimeterNodeChainDgram`], [`config::FacePurpose::
    /// EdgeEntrance`] toward the co-located `mirage-edge` unit over
    /// [`mirage_core::local_dgram_endpoint::LocalDgramChannel::
    /// PerimeterEdgeChainDgram`]. All three are bound exactly once, here,
    /// regardless of whether this boot ever adds a single UDP face of any
    /// purpose: `config::PerimeterConfig::udp_faces` only ever grows from a
    /// capsule, and a capsule can only be applied after this method has
    /// already returned (see `run`'s own boot sequence), so every bind
    /// always has time to finish before the first UDP face of any purpose
    /// could exist.
    ///
    /// # Why this is awaited directly, unlike `Self::bind_baseline`'s
    /// `stats::run_query_server` spawn
    ///
    /// `run_query_server` is fire-and-forget because it SERVES forever —
    /// nothing in `bind_baseline` could await it without hanging the whole
    /// boot on a call that never returns. `LocalDgramChannel::bind` is the
    /// opposite shape: one bind call that returns, not a loop. Awaiting both
    /// here, before `run` ever spawns `Self::apply_identity_when_ready`, is
    /// what actually delivers this method's own promise — "a session task
    /// never races its own boot" is only a guarantee if both binds are
    /// provably finished before anything that could need either one starts,
    /// not merely finished quickly in practice.
    ///
    /// # Failure handling — matches `stats::run_query_server`'s own
    /// convention, PER DESTINATION
    ///
    /// A bind failure on any channel is logged and otherwise swallowed, and
    /// the three channels are independent: one failing does not stop the
    /// others from being attempted or from serving. [`Self::
    /// dgram_relay_monitor`], [`Self::dgram_relay_node`] or [`Self::
    /// dgram_relay_edge`] — whichever channel failed — stays `None`;
    /// [`Self::apply_config`]'s UDP add branch (via [`Self::
    /// dgram_relay_for`]) refuses to add a face whose declared purpose needs
    /// that specific relay, naming the purpose and the channel, and every
    /// other face (TCP, and any UDP face whose purpose's relay DID bind)
    /// keeps serving untouched — the identical shape `bind_baseline`
    /// already uses when `PerimeterQuery` fails to bind: log an ERROR
    /// naming the cost, never a panic, never touching a single face.
    async fn bind_local_dgram_relay(&mut self) {
        self.dgram_relay_monitor = Self::bind_one_dgram_relay(
            mirage_core::local_dgram_endpoint::LocalDgramChannel::PerimeterWireDgram,
        )
        .await;
        self.dgram_relay_node = Self::bind_one_dgram_relay(
            mirage_core::local_dgram_endpoint::LocalDgramChannel::PerimeterNodeChainDgram,
        )
        .await;
        self.dgram_relay_edge = Self::bind_one_dgram_relay(
            mirage_core::local_dgram_endpoint::LocalDgramChannel::PerimeterEdgeChainDgram,
        )
        .await;
    }

    /// Bind one of the three channels [`Self::bind_local_dgram_relay`] binds
    /// at boot — factored out so the monitor-bound, node-bound and
    /// edge-bound relay log and fail identically rather than as three
    /// hand-written copies of the same lines free to drift apart. See that
    /// method's own doc for the full reasoning, which applies to every
    /// channel equally.
    async fn bind_one_dgram_relay(
        channel: mirage_core::local_dgram_endpoint::LocalDgramChannel,
    ) -> Option<Arc<udp_relay::UdpMonitorRelay>> {
        match channel.bind().await {
            Ok(socket) => {
                tracing::info!(
                    channel = channel.label(),
                    "[perimeter/udp_relay] box-local datagram relay bound — ready for the first UDP \
                     face declaring this destination, whenever (if ever) a capsule declares one"
                );
                Some(udp_relay::UdpMonitorRelay::new(Arc::new(socket)))
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    channel = channel.label(),
                    "[perimeter/udp_relay] this box-local datagram relay did not bind — every TCP \
                     face and every OTHER UDP destination keep serving, but a UDP face whose \
                     declared purpose routes to this channel will be refused rather than served \
                     with nowhere to relay its traffic to"
                );
                None
            }
        }
    }

    /// Which of this surface's three box-local relays a UDP face's declared
    /// [`config::FacePurpose`] routes to — the ONE decision [`Self::
    /// apply_config`]'s UDP add branch makes, exactly the datagram
    /// counterpart of `crate::face::inward_target`, which makes the
    /// identical decision for a TCP face's purpose. Factored out as its own
    /// method so a test can prove the mapping directly, without going
    /// through a wildcard bind. `None` means that purpose's relay never
    /// bound at boot (see [`Self::bind_local_dgram_relay`]) — the caller
    /// refuses the face rather than falling back to another relay, which
    /// would be exactly the misrouting this split exists to prevent.
    fn dgram_relay_for(&self, purpose: config::FacePurpose) -> Option<Arc<udp_relay::UdpMonitorRelay>> {
        match purpose {
            config::FacePurpose::MonitorWire => self.dgram_relay_monitor.clone(),
            config::FacePurpose::NodeChain => self.dgram_relay_node.clone(),
            config::FacePurpose::EdgeEntrance => self.dgram_relay_edge.clone(),
        }
    }

    /// Acquire this box's identity, apply it, and keep watching for the next
    /// one — points 2-5 of `run`'s doc. Consumes `self`: this task owns the
    /// surface for the rest of the process's life.
    ///
    /// # Why this does not stop after the first capsule
    ///
    /// It used to. It read the keeper once, applied whatever came back, and
    /// returned — and on real hardware that single read lands, every time,
    /// on a capsule with no faces in it. `mirage-warden` self-issues an
    /// identity the instant it starts, so that a box with no mesh still
    /// runs; a self-issued capsule carries `CapsuleServiceConfig::default()`,
    /// which declares no faces at all; `config::PerimeterConfig::from_capsule`
    /// correctly refuses that (`ConfigError::NoFaces` — a box must not bind
    /// nothing while reporting healthy). The operator-signed capsule that
    /// actually names this box's faces is a network delivery, so it always
    /// arrives afterwards — measured at 35 s afterwards on
    /// `us-example-203.0.113.25`, 2026-08-20 — by which time the only task that
    /// could have applied it had already returned. That box then served the
    /// bare baseline for the next twenty hours and took its declared `:3000`
    /// only when this daemon was restarted by hand.
    ///
    /// So the capsule is re-read on a cadence ([`CAPSULE_WATCH_INTERVAL`]),
    /// and every way this function can fail to apply one becomes a reason to
    /// keep watching rather than a reason to stop: an identity that could not
    /// be acquired, a capsule that does not resolve to a valid face list, and
    /// an application that simply finished all lead to the same watch. Point
    /// 5 is preserved exactly — a box that cannot take a capsule degrades to
    /// the baseline, never to nothing — but it now degrades WHILE STILL
    /// LOOKING, so an operator's capsule lands on a running daemon instead of
    /// needing one restarted underneath it. See
    /// `docs/mirage/plans/perimeter-rereads-its-capsule-2026-08-21.md`.
    async fn apply_identity_when_ready(mut self) {
        // The boot read — the only one that says anything about provenance
        // or arms the grace window. See `capsule_boot::reacquire_identity`'s
        // own doc for why every read after this one deliberately does
        // neither.
        let applied = match capsule_boot::acquire_identity().await {
            Ok(identity) => {
                // States what was READ, not what will be done with it. It
                // used to promise "adding this box's declared faces", and
                // then the very next line was often the `NoFaces` refusal —
                // a journal that announces an action it did not take is
                // worse than one that says less. Whether faces were added
                // is `apply_identity`'s own line to write.
                tracing::info!(
                    perimeter_id = %identity.perimeter_id,
                    mesh_id = %identity.mesh_id,
                    shortname = %identity.shortname,
                    faces = %CapsuleMark::of(&identity.perimeter_id, &identity.service_config)
                        .faces_field(),
                    "[perimeter] this box's identity came back from the keeper"
                );
                let mark = CapsuleMark::of(&identity.perimeter_id, &identity.service_config);
                self.apply_identity(&identity).await;
                Some(mark)
            }
            Err(e) => {
                // Point 5, one step earlier than a malformed capsule: an
                // identity this box could not even ACQUIRE degrades it to
                // the baseline the exact same way — the surface
                // `Self::bind_baseline` already bound is serving and stays
                // that way. What is no longer true is that this ends the
                // task: `capsule_boot::acquire_identity` returns `Err` only
                // on conditions retrying cannot fix, but "this read cannot
                // be fixed by retrying" is not "the next capsule an operator
                // delivers cannot fix it", and the watch below is what lets
                // that capsule land.
                tracing::error!(
                    error = %e,
                    "[perimeter/capsule] could not acquire this box's identity from the keeper — \
                     staying on the baseline surface (22/80/443, no persona faces, no mesh \
                     function) rather than this box's front door, and watching for the next \
                     capsule"
                );
                None
            }
        };

        self.watch_for_a_new_capsule(applied).await;
    }

    /// Re-read the keeper on a cadence, and apply whatever it now holds.
    ///
    /// Never returns.
    ///
    /// Silent while the answer does not change — which, on a healthy box, is
    /// the whole life of the process. A line every [`CAPSULE_WATCH_INTERVAL`]
    /// saying nothing happened would bury the one poll that matters under the
    /// thousands that did not, and this daemon's journal is already the place
    /// an operator looks to find out what the box's surface is.
    ///
    /// `last` moves forward on every CHANGE, whether that change was applied
    /// or refused, for the same reason: a capsule this daemon has already
    /// refused once earns one ERROR, not one every few seconds until somebody
    /// replaces it. A refused capsule is not retried, because nothing about
    /// re-reading the same bytes would resolve differently; what unblocks the
    /// box is a DIFFERENT capsule, and that is precisely what this notices.
    async fn watch_for_a_new_capsule(mut self, mut last: Option<CapsuleMark>) {
        loop {
            tokio::time::sleep(CAPSULE_WATCH_INTERVAL).await;

            let identity = match capsule_boot::reacquire_identity().await {
                Ok(identity) => identity,
                Err(e) => {
                    // `debug`, not `error`: this is a poll, not a boot. A
                    // keeper that is briefly unreachable — restarting, or
                    // mid-admission — changes nothing about the surface,
                    // which keeps serving whatever it last applied, and the
                    // next turn of this loop asks again.
                    tracing::debug!(
                        error = %e,
                        "[perimeter/capsule] re-read of this box's capsule did not resolve — the \
                         surface is unchanged, asking again"
                    );
                    continue;
                }
            };

            let mark = CapsuleMark::of(&identity.perimeter_id, &identity.service_config);
            if last.as_ref() == Some(&mark) {
                continue;
            }

            tracing::warn!(
                was = %CapsuleMark::render_id(last.as_ref()),
                now = %mark.self_id,
                was_faces = %CapsuleMark::render_faces(last.as_ref()),
                now_faces = %mark.faces_field(),
                "[perimeter/capsule] this box now holds a different capsule than the surface was \
                 built from — taking it, with nothing restarted. What that changed on the \
                 surface is the lines that follow this one"
            );

            self.apply_identity(&identity).await;
            last = Some(mark);
        }
    }

    /// Put one capsule's identity onto the live surface: the wire key, then
    /// every face the capsule declares.
    ///
    /// Idempotent, and safe on a surface that is already serving — which is
    /// exactly what [`Self::watch_for_a_new_capsule`] asks of it. A capsule
    /// that does not resolve is logged here and changes nothing at all, the
    /// wire key included.
    async fn apply_identity(&mut self, identity: &Identity) {
        // Strict by construction (see `config`'s module doc): a malformed
        // face list must never bind fewer ports than declared while
        // reporting healthy. Point 5: it degrades this box to the baseline
        // instead — never to nothing, and never by tearing down what is
        // already serving.
        let config = match PerimeterConfig::from_capsule(&identity.service_config) {
            Ok(cfg) => Arc::new(cfg),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    self_id = %identity.perimeter_id,
                    "[perimeter/capsule] this box's capsule does not resolve to a valid face \
                     list — keeping the surface already bound rather than taking a malformed \
                     one, and watching for the next capsule"
                );
                return;
            }
        };

        // The real identity FIRST, the faces SECOND — see `face::
        // SharedKeypair`'s doc. Ordering it this way means a connection
        // that already observes a swapped-in camouflage can never observe
        // the boot-only key that came with the baseline; the reverse order
        // could, for the width of one `ArcSwap::store`.
        self.keypair.store(Arc::new(identity.wire_keypair.clone()));

        self.apply_config(config).await;
    }

    /// Put one resolved [`PerimeterConfig`] onto the live surface — the part
    /// of [`Self::apply_identity`] that does not need an [`Identity`] at
    /// all, split out so it is directly callable (this crate's own tests do
    /// exactly that, on hand-built configs, rather than assembling a signed
    /// capsule just to reach it).
    ///
    /// # Order: add and swap FIRST, retire SECOND
    ///
    /// Never negotiable, and enforced by the shape of this function, not by
    /// a comment above it: the surface must never be momentarily empty or
    /// narrower than the union of the old and new face lists. Every face
    /// `config` declares is added or swapped in the first loop before the
    /// second loop ever looks at what to retire, so a port that is BOTH
    /// declared by `config` AND currently bound is never at risk of being
    /// read as "gone" — the two loops partition `self.ports.keys()`
    /// disjointly by construction (declared vs. not), never by timing.
    ///
    /// # What it does to a port `config` no longer declares
    ///
    /// Retires it — UNLESS it is one of [`config::PerimeterConfig::
    /// baseline_ports`], which are kept and warned about instead. See
    /// `config.rs`'s module doc: "Getting a capsule must not be able to
    /// close the door that not having one leaves open" — an operator's way
    /// in must never be a face a capsule can simply omit. Retiring a port
    /// means firing its [`BoundFace::cancel`] and then AWAITING its
    /// [`BoundFace::handle`] before this function returns: by the time a
    /// port is gone from `self.ports`/`self.stats`, its listener has
    /// already stopped accepting and the OS has already taken the port
    /// back — not "asked to", confirmed.
    ///
    /// # Idempotence
    ///
    /// Applying the same `config` twice is a no-op the second time,
    /// retirement included. The add/swap loop already was (an `ArcSwap::
    /// store` of an equal value); the retire loop is too, because after the
    /// first application `self.ports.keys()` no longer contains anything
    /// `config` does not declare (baseline ports aside — those were never
    /// removed, only kept, so there is nothing for a second pass to do to
    /// them beyond the same harmless keep).
    ///
    /// # UDP faces — the same discipline, run after the TCP pass
    ///
    /// `config.udp_faces` gets its own add/swap-then-retire pass, entirely
    /// after the TCP pass above (`docs/mirage/plans/
    /// udp-front-door-u0-2026-09-05.md` §4). The two maps (`self.ports`,
    /// `self.udp_ports`) are keyed per transport, and the kernel keeps its
    /// socket spaces per transport too: a capsule that names the same port
    /// as both a TCP and a UDP face is still refused by
    /// `config::ConfigError::DuplicatePort`, while a STANDALONE config may
    /// publish TCP 443 and UDP 443 side by side (see
    /// [`config::PerimeterConfig::from_local_faces`]). Either way a UDP
    /// face being added never has to wait on a TCP face's retirement or
    /// vice versa; the two passes could equally run in the other order. Unlike
    /// the TCP retirement above, there is no baseline-port guard for UDP:
    /// [`config::PerimeterConfig::baseline`] declares `udp_faces` empty and
    /// nothing in `mirage_core::persona` ever mints a UDP camouflage (see
    /// that field's own doc), so every UDP port this surface has ever bound
    /// came from a capsule — a capsule that stops declaring it is retired
    /// outright, with no baseline standing underneath it the way
    /// `:22`/`:80`/`:443` stand underneath a TCP face. And unlike a TCP
    /// port's retirement, a UDP port's retirement also ends every live peer
    /// session it was carrying — see [`BoundUdpFace`]'s own doc for why
    /// that costs a second join handle TCP's retirement does not need.
    ///
    /// # UDP faces route by their own declared purpose
    ///
    /// A UDP face's [`config::FacePurpose`] — carried on `config::UdpFace::
    /// purpose`, the datagram counterpart of `config::PerimeterFace::
    /// purpose` — picks which of [`Self::dgram_relay_monitor`]/[`Self::
    /// dgram_relay_node`] the add branch spawns its session supervisor
    /// against ([`Self::dgram_relay_for`]), exactly the decision
    /// `crate::face::inward_target` makes for a TCP face's purpose. A face
    /// whose purpose's relay never bound at boot is refused outright,
    /// naming both the purpose and the channel — never silently served
    /// through the OTHER relay, which would be exactly the misrouting this
    /// split exists to prevent (chain data-plane traffic delivered to the
    /// control plane, or the reverse).
    async fn apply_config(&mut self, config: Arc<PerimeterConfig>) {
        for face in &config.faces {
            match self.ports.get(&face.port) {
                Some(bound) => {
                    // Point 3: bind-then-swap, never unbind-then-bind. The
                    // listener `face::run_face` bound for this port —
                    // either at baseline time or by an earlier capsule
                    // application — is untouched and never stops
                    // accepting; only which face the NEXT accepted
                    // connection is judged under changes. Idempotent: the
                    // SAME capsule applied again just stores an equal
                    // value here.
                    bound.face.store(Arc::new(face.clone()));
                    self.stats.relabel_face(face.port, face.camouflage.label(), &face.label);
                    tracing::info!(
                        port = face.port,
                        label = %face.label,
                        "[perimeter/face] swapped onto the capsule's declared face — this port \
                         never stopped listening"
                    );
                }
                None => {
                    // A genuinely new port the capsule adds — bind it
                    // fresh, exactly as `Self::bind_baseline` bound the
                    // baseline's own three. Recorded in `self.ports` before
                    // the SAME capsule (or an identical retry) can ever see
                    // it as new again.
                    let shared: SharedFace = Arc::new(ArcSwap::from_pointee(face.clone()));
                    let counters = self.stats.register_face(face);
                    let cancel = CancellationToken::new();
                    let handle = tokio::spawn(face::run_face(
                        Arc::clone(&shared),
                        Arc::clone(&config),
                        Arc::clone(&self.keypair),
                        counters,
                        Arc::clone(&self.rate_limit),
                        Arc::clone(&self.sink),
                        cancel.clone(),
                    ));
                    self.ports.insert(face.port, BoundFace { face: shared, cancel, handle });
                    tracing::info!(
                        port = face.port,
                        label = %face.label,
                        "[perimeter/face] added on top of the baseline surface"
                    );
                }
            }
        }

        // Retirement — SECOND, on purpose (see this function's own doc).
        // Never the baseline's own ports: `PerimeterConfig::baseline_ports`
        // is read fresh rather than hardcoded, so this guard cannot drift
        // from the surface it protects.
        let declared: HashSet<u16> = config.faces.iter().map(|f| f.port).collect();
        let baseline_ports = PerimeterConfig::baseline_ports();

        let stale: Vec<u16> =
            self.ports.keys().filter(|port| !declared.contains(port)).copied().collect();

        let mut retiring: Vec<(u16, JoinHandle<()>)> = Vec::new();
        for port in stale {
            if baseline_ports.contains(&port) {
                tracing::warn!(
                    port,
                    "[perimeter/face] the capsule's declared faces omit a baseline port — \
                     keeping it bound anyway: getting a capsule must not be able to close the \
                     door that not having one leaves open"
                );
                continue;
            }

            // Removed from `self.ports` up front, before this listener has
            // actually stopped — a retired port must never again be read as
            // "swap the existing one" by the add/swap loop above on some
            // future call while this one is still shutting down. `cancel`
            // fires for every stale port before any of them is awaited, so
            // they all start unwinding concurrently rather than one after
            // another.
            if let Some(bound) = self.ports.remove(&port) {
                bound.cancel.cancel();
                retiring.push((port, bound.handle));
            }
        }

        for (port, handle) in retiring {
            // Confirmed, not assumed: this is what makes "gone from
            // `self.ports`" and "gone from `self.stats`" mean the listener
            // has actually returned and the OS has actually released the
            // port, matching the promise `BoundFace`'s own doc makes.
            if let Err(e) = handle.await {
                tracing::error!(
                    port,
                    error = %e,
                    "[perimeter/face] this port's accept task ended in a panic while retiring — \
                     the port is released either way, since a panicked task holds nothing"
                );
            }
            self.stats.retire_face(port);
            tracing::warn!(
                port,
                "[perimeter/face] retired — the capsule no longer declares this port and its \
                 listener has stopped accepting"
            );
        }

        // ── UDP faces — add and swap FIRST, retire SECOND, same discipline
        // as the TCP pass above, run entirely after it. See this function's
        // own doc, "UDP faces", for why the two passes never have to
        // coordinate with each other.
        self.apply_udp_faces(&config).await;

        let declared_udp: HashSet<u16> = config.udp_faces.iter().map(|f| f.port).collect();
        let stale_udp: Vec<u16> =
            self.udp_ports.keys().filter(|port| !declared_udp.contains(port)).copied().collect();

        let mut retiring_udp: Vec<(u16, BoundUdpFace)> = Vec::new();
        for port in stale_udp {
            // No baseline-port guard here, unlike the TCP retirement above:
            // there is no baseline UDP face to protect — see this
            // function's own doc, "UDP faces".
            if let Some(bound) = self.udp_ports.remove(&port) {
                // Fires once; `udp_face::run_udp_face`'s dispatcher(s) and
                // every session `run_udp_sessions` has spawned for this
                // face race the SAME token — see `BoundUdpFace`'s own doc
                // for why one signal reaches both.
                bound.cancel.cancel();
                retiring_udp.push((port, bound));
            }
        }

        for (port, bound) in retiring_udp {
            // Confirmed, not assumed, and in two parts: the socket (via
            // `dispatch`) and every live peer session it was carrying (via
            // `sessions`) — see `BoundUdpFace`'s own doc for why retiring a
            // UDP face has to prove both, unlike the TCP path.
            if let Err(e) = bound.dispatch.await {
                tracing::error!(
                    port,
                    error = %e,
                    "[perimeter/udp_face] this UDP face's dispatcher ended in a panic while \
                     retiring — the socket is released either way, since a panicked task holds \
                     nothing"
                );
            }
            if let Err(e) = bound.sessions.await {
                tracing::error!(
                    port,
                    error = %e,
                    "[perimeter/udp_face] this UDP face's session supervisor ended in a panic \
                     while retiring — every session it was tracking is gone either way, since a \
                     panicked task holds nothing"
                );
            }
            // Only now — after BOTH handles above have actually been
            // awaited, not merely after `bound.cancel.cancel()` was fired —
            // does this port leave `self.stats`. "Gone from the query
            // surface" must mean the same thing here that it already means
            // for `self.ports`/`self.stats.retire_face` on the TCP side:
            // the socket is released and every session it was carrying has
            // ended, not merely asked to.
            self.stats.retire_udp_face(port);
            tracing::warn!(
                port,
                "[perimeter/udp_face] retired — the capsule no longer declares this UDP port, its \
                 socket has stopped dispatching, and every live session it was carrying has ended"
            );
        }

        // A previously refused UDP port this capsule no longer declares
        // leaves the reported set too — see `Self::udp_refused`'s own doc.
        // There is no `BoundUdpFace` to cancel or await here, only the
        // `stats` entry `Stats::note_udp_face_refused` wrote, so this is a
        // synchronous removal, not a retirement proof like the loop above.
        let stale_refused_udp: Vec<u16> =
            self.udp_refused.iter().filter(|port| !declared_udp.contains(port)).copied().collect();
        for port in stale_refused_udp {
            self.udp_refused.remove(&port);
            self.stats.retire_udp_face(port);
            tracing::info!(
                port,
                "[perimeter/udp_face] a previously refused UDP face is no longer declared — \
                 removed from the reported set"
            );
        }
    }

    /// Add every UDP face `config` declares that this surface is not
    /// already serving — the UDP half of [`Self::apply_config`], split out
    /// so the STANDALONE path can bind its own UDP faces through the same
    /// code a capsule-declared one goes through.
    ///
    /// The box-local relays must already be bound when this runs: the
    /// relay a face's declared purpose routes through is bound exactly
    /// once, at boot, by [`Self::bind_local_dgram_relay`], and a face whose
    /// purpose's relay never bound is refused here rather than served with
    /// nowhere to relay its traffic to.
    async fn apply_udp_faces(&mut self, config: &PerimeterConfig) {
        for face in &config.udp_faces {
            if self.udp_ports.contains_key(&face.port) {
                // `RawUdp` carries no per-connection-visible field the way a
                // TCP face's camouflage/label is swappable — see
                // `udp_face::UdpFace`'s own doc and `udp_face::run_udp_face`'s
                // "why this takes plain parameters" section. There is
                // nothing to swap on an already-bound UDP port; logged so a
                // capsule that keeps re-declaring the same UDP face is
                // visible in the journal without claiming an action that
                // did not happen.
                tracing::info!(
                    port = face.port,
                    label = %face.label,
                    "[perimeter/udp_face] already serving this UDP face — RawUdp carries no \
                     swappable field, so nothing changes"
                );
                continue;
            }

            if self.udp_refused.contains(&face.port) {
                // Already refused by an earlier capsule application, for a
                // reason that cannot change for the life of this process —
                // see `Self::udp_refused`'s own doc: the relay a face's
                // purpose needs is bound exactly once, at boot. Not
                // re-logged at `error` on every capsule that keeps
                // redeclaring it, and not re-registered with `stats` either
                // — see [`Stats::register_udp_face`]'s own doc on why
                // calling its refusal counterpart twice for one port would
                // duplicate that port in `Metrics`.
                tracing::debug!(
                    port = face.port,
                    label = %face.label,
                    "[perimeter/udp_face] still refused — this face's relay never bound at boot, \
                     and that cannot change without a restart"
                );
                continue;
            }

            // The face's own declared purpose picks which of the two
            // box-local relays it routes through — never anything else
            // about the face. See `Self::dgram_relay_for`'s own doc.
            let channel = udp_relay_channel_for(face.purpose);
            let Some(relay) = self.dgram_relay_for(face.purpose) else {
                tracing::error!(
                    port = face.port,
                    label = %face.label,
                    purpose = face.purpose.label(),
                    channel = channel.label(),
                    "[perimeter/udp_face] the box-local datagram relay for this face's declared \
                     purpose never bound at boot — refusing to add this UDP face rather than \
                     serve a public socket with nowhere to relay its traffic to"
                );
                // What used to end at the log line above is now also a fact
                // `stats::Stats` can answer over `PerimeterQuery` — the
                // specific gap this step exists to close: a UDP face
                // refused for a missing relay must be distinguishable, from
                // OFF the box, from one that was never declared at all. See
                // `mirage_core::perimeter_query::UdpFaceMetrics::
                // refused_reason`'s own doc.
                let reason = format!(
                    "{} relay for purpose {} never bound at boot",
                    channel.label(),
                    face.purpose.label()
                );
                self.stats.note_udp_face_refused(face, &reason);
                self.udp_refused.insert(face.port);
                continue;
            };

            let counters = self.stats.register_udp_face(face);
            let cancel = CancellationToken::new();
            let (sessions_tx, sessions_rx) = mpsc::channel(udp_face::PEER_CHANNEL_CAPACITY);

            let dispatch = tokio::spawn(udp_face::run_udp_face(
                face.port,
                face.label.clone(),
                Arc::clone(&counters),
                sessions_tx,
                cancel.clone(),
            ));

            // Lazily start the ONE reader every UDP face of THIS purpose
            // this process ever adds shares — see `Self::
            // dgram_relay_monitor_inbound`'s own doc for why it is tied to
            // this first face's counters rather than re-spawned per face.
            // The monitor-purposed, node-purposed and edge-purposed readers
            // are three independent slots, one per relay, so adding the
            // first face of any purpose never skips starting another
            // purpose's own reader later.
            let inbound_already_started = match face.purpose {
                config::FacePurpose::MonitorWire => self.dgram_relay_monitor_inbound.is_some(),
                config::FacePurpose::NodeChain => self.dgram_relay_node_inbound.is_some(),
                config::FacePurpose::EdgeEntrance => self.dgram_relay_edge_inbound.is_some(),
            };
            if !inbound_already_started {
                let handle = tokio::spawn(
                    Arc::clone(&relay).run_inbound(Arc::clone(&counters), CancellationToken::new()),
                );
                match face.purpose {
                    config::FacePurpose::MonitorWire => self.dgram_relay_monitor_inbound = Some(handle),
                    config::FacePurpose::NodeChain => self.dgram_relay_node_inbound = Some(handle),
                    config::FacePurpose::EdgeEntrance => self.dgram_relay_edge_inbound = Some(handle),
                }
            }

            let disposition = config.jail.disposition_for(face.port);
            let sessions = tokio::spawn(run_udp_sessions(
                sessions_rx,
                face.port,
                relay,
                counters,
                config.max_skew_ms,
                disposition,
                cancel.clone(),
            ));

            self.udp_ports.insert(face.port, BoundUdpFace { cancel, dispatch, sessions });
            tracing::info!(
                port = face.port,
                label = %face.label,
                purpose = face.purpose.label(),
                "[perimeter/udp_face] added"
            );
        }
    }
}

/// What the live surface was last built from: which capsule, and which faces
/// it declared.
///
/// The comparison [`Surface::watch_for_a_new_capsule`] makes to decide
/// whether there is anything to do. Built from the capsule's own
/// `control_plane_endpoints` rather than from a resolved
/// [`PerimeterConfig`], deliberately: a capsule that does NOT resolve still
/// has to produce a mark, because a box sitting on a faceless self-issued
/// capsule must be able to tell "the same refusal as last time, say nothing"
/// apart from "a different capsule, look again". Marking only what applied
/// would leave it re-logging the same refusal forever.
///
/// `self_id` and the face set, and nothing else. A capsule that changes only
/// a process-wide setting — `perimeter_inner_addr`, a timeout, the accept
/// budget — does not re-apply, because `face::run_face` captures those when
/// a face is spawned and they are not swappable under a running one.
/// Re-applying on such a change would put a line in the journal claiming an
/// effect the process did not have.
#[derive(Debug, PartialEq, Eq)]
struct CapsuleMark {
    /// The capsule's `self_id`, as `identity::Identity` carries it.
    self_id: String,
    /// `(port, camouflage label)` for every declared face, sorted by port so
    /// that two capsules declaring the same surface in a different order
    /// compare equal — the order endpoints happen to be listed in is not a
    /// change to this box's surface, and must not be reported as one.
    faces: Vec<(u16, &'static str)>,
}

impl CapsuleMark {
    /// Takes the two fields it reads rather than a whole
    /// [`identity::Identity`]: what a capsule means to the live surface is
    /// its id and the faces it declares, and a constructor that says so is
    /// one a test can call without standing up a signed envelope and a
    /// charter to reach two strings.
    fn of(self_id: &str, service_config: &CapsuleServiceConfig) -> Self {
        let mut faces: Vec<(u16, &'static str)> = service_config
            .control_plane_endpoints
            .iter()
            .map(|endpoint| (endpoint.port, endpoint.camouflage.label()))
            .collect();
        faces.sort_unstable();
        Self { self_id: self_id.to_string(), faces }
    }

    /// This mark's face set as one journal field.
    fn faces_field(&self) -> String {
        if self.faces.is_empty() {
            return "<none>".to_string();
        }
        self.faces
            .iter()
            .map(|(port, camouflage)| format!("{camouflage}:{port}"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The same, for the mark that may not exist yet — the surface has been
    /// through a boot that acquired nothing.
    fn render_faces(mark: Option<&Self>) -> String {
        mark.map_or_else(|| "<none>".to_string(), Self::faces_field)
    }

    /// This mark's capsule id, or a placeholder for a surface that never had
    /// one.
    fn render_id(mark: Option<&Self>) -> &str {
        mark.map_or("<none>", |m| m.self_id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use mirage_core::capsule::CapsuleControlEndpoint;
    use mirage_core::mirage::wire::camouflage::TransportCamouflage;
    use mirage_core::perimeter_query::{PerimeterRequest, PerimeterResponse};

    use super::*;

    fn config_with(faces: &[(u16, TransportCamouflage)]) -> CapsuleServiceConfig {
        CapsuleServiceConfig {
            control_plane_endpoints: faces
                .iter()
                .map(|(port, camouflage)| CapsuleControlEndpoint {
                    port: *port,
                    camouflage: camouflage.clone(),
                    wire_version: None,
                    purpose: None,
                })
                .collect(),
            ..Default::default()
        }
    }

    fn mark(self_id: &str, faces: &[(u16, TransportCamouflage)]) -> CapsuleMark {
        CapsuleMark::of(self_id, &config_with(faces))
    }

    /// The two camouflages this box's own persona actually declares. Their
    /// inner fields are irrelevant here — the mark compares
    /// `TransportCamouflage::label`, which is the variant, not its settings.
    fn ws() -> TransportCamouflage {
        TransportCamouflage::WebSocket { path: "/".to_string(), host: "example.test".to_string() }
    }

    fn tls() -> TransportCamouflage {
        TransportCamouflage::TlsReal { sni: "example.test".to_string(), alpn: Vec::new() }
    }

    /// The steady state, and the one this has to get right or the fix is
    /// worse than the defect: a box whose capsule has not moved must produce
    /// an equal mark every poll. Otherwise the watch re-applies, and re-logs,
    /// every few seconds for the life of the process.
    #[test]
    fn the_same_capsule_read_twice_is_not_a_change() {
        let faces = [(22, TransportCamouflage::None), (443, TransportCamouflage::None)];
        assert_eq!(mark("cap-1", &faces), mark("cap-1", &faces));
    }

    /// The defect this whole change exists for, reduced to its comparison.
    /// warden's faceless self-issued capsule, then the operator's capsule
    /// naming `:3000` — measured 35 s apart on `us-example-203.0.113.25`. These
    /// must not compare equal, or the surface polls forever and never notices
    /// the port it was told to bind.
    #[test]
    fn the_operator_capsule_that_follows_a_faceless_self_issued_one_is_a_change() {
        let self_issued = mark("self-issued", &[]);
        let operator = mark(
            "operator",
            &[
                (22, TransportCamouflage::None),
                (80, ws()),
                (443, tls()),
                (3000, ws()),
            ],
        );
        assert_ne!(self_issued, operator);
        assert_eq!(self_issued.faces_field(), "<none>");
        assert!(operator.faces_field().contains("3000"));
    }

    /// A re-issued capsule keeping the same surface is still a change: the
    /// wire key travels with the capsule, and a box still serving under the
    /// old key after a rotation is holding a credential the operator believes
    /// is retired.
    #[test]
    fn a_new_capsule_id_on_an_unchanged_face_set_is_still_a_change() {
        let faces = [(22, TransportCamouflage::None)];
        assert_ne!(mark("cap-1", &faces), mark("cap-2", &faces));
    }

    /// The order endpoints happen to be listed in is not a change to this
    /// box's surface, and reporting it as one would re-apply and re-log on a
    /// box nothing happened to.
    #[test]
    fn declaring_the_same_faces_in_another_order_is_not_a_change() {
        let ascending =
            mark("cap-1", &[(22, TransportCamouflage::None), (443, tls())]);
        let descending =
            mark("cap-1", &[(443, tls()), (22, TransportCamouflage::None)]);
        assert_eq!(ascending, descending);
    }

    /// Same port, different camouflage, is a change — the port stays bound,
    /// but what the next connection on it is judged under does not.
    #[test]
    fn the_same_port_under_a_different_camouflage_is_a_change() {
        assert_ne!(
            mark("cap-1", &[(443, TransportCamouflage::None)]),
            mark("cap-1", &[(443, tls())]),
        );
    }

    /// A mark with no faces renders as something a human can read in a
    /// journal line, not as an empty field that looks like a logging bug.
    #[test]
    fn a_surface_that_never_took_a_capsule_renders_readably() {
        assert_eq!(CapsuleMark::render_id(None), "<none>");
        assert_eq!(CapsuleMark::render_faces(None), "<none>");
        let m = mark("cap-1", &[(80, ws())]);
        assert_eq!(CapsuleMark::render_id(Some(&m)), "cap-1");
        assert_eq!(CapsuleMark::render_faces(Some(&m)), "websocket:80");
    }

    // ── `Surface::apply_config` — add, swap, retire ──
    //
    // These build a `Surface` directly (its fields are private to this
    // crate, and `mod tests` is a descendant of the module that defines
    // them) rather than through a signed capsule — reaching `apply_config`
    // needs a resolved `PerimeterConfig`, not an `Identity`, and building a
    // `DeclaredIdentity` just to exercise it would test the signing path a
    // second time for no benefit to this one. `PerimeterConfig::
    // from_capsule` is still used for every config below, so the strict
    // parsing this module's own doc describes is exercised for real.
    //
    // Nothing here binds a wildcard address. `face::run_face` is the only
    // thing in this crate that does (`0.0.0.0`/`[::]`), and this box that
    // runs `cargo test` must never open a public listener, however briefly
    // — see `face.rs`'s own test-module doc. A currently-bound port that a
    // test needs to be REAL (to prove a retirement releases the actual OS
    // socket) is a genuine loopback listener instead; a port that a test
    // only needs to exist as a bookkeeping entry (the baseline-keep guard,
    // idempotence, a swap) holds no socket at all. The one behaviour that
    // cannot be reached this way — a genuinely NEW port going through the
    // real `face::run_face` — is exercised by the `#[ignore]`d test below,
    // container-only, exactly like this crate's other wildcard-binding
    // test.

    fn test_face(port: u16) -> config::PerimeterFace {
        config::PerimeterFace {
            port,
            camouflage: TransportCamouflage::None,
            label: format!("test:{port}"),
            purpose: config::FacePurpose::MonitorWire,
        }
    }

    fn fake_shared_face(port: u16) -> SharedFace {
        Arc::new(ArcSwap::from_pointee(test_face(port)))
    }

    /// The UDP counterpart of [`test_face`] — used only by the step-7 query-
    /// surface tests below, to register a matching `stats::Stats` entry for
    /// a hand-built [`BoundUdpFace`].
    fn test_udp_face(port: u16) -> config::UdpFace {
        config::UdpFace {
            port,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: format!("0.0.0.0:{port}").parse().expect("valid bind addr"),
            },
            label: format!("raw_udp:{port}"),
            purpose: config::FacePurpose::MonitorWire,
        }
    }

    /// A currently-bound port backed by a REAL loopback listener — for
    /// tests that need to prove a retirement releases the actual OS socket,
    /// not merely that a task ended. Accepts and immediately drops
    /// connections until `cancel` fires, then returns — the same stop
    /// contract `face::accept_loop` keeps; `crate::face`'s own tests prove
    /// THAT contract holds for the real accept loop, so this stand-in only
    /// needs to prove `Surface::apply_config` drives it correctly.
    async fn real_bound_face() -> (u16, BoundFace) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind must succeed");
        let port = listener.local_addr().expect("listener has a local addr").port();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                loop {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return,
                        accepted = listener.accept() => {
                            if let Ok((stream, _)) = accepted {
                                drop(stream);
                            }
                        }
                    }
                }
            }
        });
        (port, BoundFace { face: fake_shared_face(port), cancel, handle })
    }

    /// A currently-bound port backed by NO socket at all — for tests that
    /// only exercise a keep/retire DECISION or a swap, where binding
    /// anything real (baseline ports above all: `:22`/`:80`/`:443`) would
    /// risk this box's own ports for no benefit to what is under test.
    fn bound_without_a_socket(port: u16, cancel: CancellationToken) -> BoundFace {
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move {
                cancel.cancelled().await;
            }
        });
        BoundFace { face: fake_shared_face(port), cancel, handle }
    }

    fn test_surface(ports: HashMap<u16, BoundFace>, faces: &[config::PerimeterFace]) -> Surface {
        let (stats, _counters) = stats::Stats::new(faces);
        Surface {
            stats,
            rate_limit: Arc::new(ratelimit::SourceRateLimit::new(1_000.0, 1_000.0)),
            sink: observe::SecdSink::spawn(),
            keypair: Arc::new(ArcSwap::from_pointee(KeyPair::generate())),
            ports,
            // No UDP faces and no bound relay by default — the UDP-specific
            // tests below set `udp_ports`/`dgram_relay_monitor`/
            // `dgram_relay_node`/`dgram_relay_edge` themselves via
            // struct-update syntax, exactly like `test_face`/
            // `fake_shared_face` are only pulled in by the tests that need
            // them.
            udp_ports: HashMap::new(),
            udp_refused: HashSet::new(),
            dgram_relay_monitor: None,
            dgram_relay_node: None,
            dgram_relay_edge: None,
            dgram_relay_monitor_inbound: None,
            dgram_relay_node_inbound: None,
            dgram_relay_edge_inbound: None,
        }
    }

    fn resolved_config(faces: &[(u16, TransportCamouflage)]) -> Arc<PerimeterConfig> {
        Arc::new(
            PerimeterConfig::from_capsule(&config_with(faces))
                .expect("a single well-formed face must parse"),
        )
    }

    /// Test 1: a capsule that drops a non-baseline port closes it — gone
    /// from `self.ports`, gone from the stats readout, and its socket
    /// genuinely released, proven by rebinding the exact same address.
    #[tokio::test]
    async fn a_dropped_non_baseline_port_is_retired_and_its_socket_released() {
        let (dropped_port, dropped_bound) = real_bound_face().await;
        // Never bound for real: this port is only ever the target of the
        // SWAP branch below, which touches no socket at all.
        let kept_port = 39_001u16;
        let kept_bound = bound_without_a_socket(kept_port, CancellationToken::new());

        let mut ports = HashMap::new();
        ports.insert(dropped_port, dropped_bound);
        ports.insert(kept_port, kept_bound);
        let faces = [test_face(dropped_port), test_face(kept_port)];
        let mut surface = test_surface(ports, &faces);

        surface.apply_config(resolved_config(&[(kept_port, TransportCamouflage::None)])).await;

        assert!(
            !surface.ports.contains_key(&dropped_port),
            "a port the new capsule no longer declares must leave self.ports"
        );
        assert!(surface.ports.contains_key(&kept_port), "the still-declared port must remain");

        let snap = surface.stats.snapshot();
        assert!(
            snap.faces.iter().all(|f| f.port != dropped_port),
            "the dropped port must leave the stats readout too"
        );
        assert!(snap.faces.iter().any(|f| f.port == kept_port));

        let rebound = tokio::net::TcpListener::bind(format!("127.0.0.1:{dropped_port}")).await;
        assert!(
            rebound.is_ok(),
            "the retired port's socket must be free — a leaked listener that merely forgot its \
             task would still hold it and fail this exact rebind: {:?}",
            rebound.err()
        );
    }

    /// Test 2: a capsule that drops a BASELINE port does not close it, and
    /// the port's task is never even asked to stop.
    #[tokio::test]
    async fn a_dropped_baseline_port_is_kept_bound_never_retired() {
        let baseline_port = *PerimeterConfig::baseline_ports().iter().next().expect("non-empty");
        let baseline_cancel = CancellationToken::new();
        let baseline_bound = bound_without_a_socket(baseline_port, baseline_cancel.clone());

        let declared_port = 39_002u16;
        let declared_bound = bound_without_a_socket(declared_port, CancellationToken::new());

        let mut ports = HashMap::new();
        ports.insert(baseline_port, baseline_bound);
        ports.insert(declared_port, declared_bound);
        let faces = [test_face(baseline_port), test_face(declared_port)];
        let mut surface = test_surface(ports, &faces);

        surface.apply_config(resolved_config(&[(declared_port, TransportCamouflage::None)])).await;

        assert!(
            surface.ports.contains_key(&baseline_port),
            "a baseline port must never close just because a capsule omits it"
        );
        assert!(
            !baseline_cancel.is_cancelled(),
            "a kept baseline port's listener must never even be asked to stop"
        );
        let snap = surface.stats.snapshot();
        assert!(snap.faces.iter().any(|f| f.port == baseline_port), "the readout must still show it");
    }

    /// Test 3: applying the SAME capsule twice is a no-op — nothing
    /// rebound, nothing retired the second time.
    #[tokio::test]
    async fn applying_the_same_config_twice_retires_and_rebinds_nothing() {
        let port = 39_003u16;
        let cancel = CancellationToken::new();
        let bound = bound_without_a_socket(port, cancel.clone());
        let mut ports = HashMap::new();
        ports.insert(port, bound);
        let faces = [test_face(port)];
        let mut surface = test_surface(ports, &faces);

        let config = resolved_config(&[(port, TransportCamouflage::None)]);
        surface.apply_config(Arc::clone(&config)).await;
        assert!(surface.ports.contains_key(&port));
        assert!(!cancel.is_cancelled());

        surface.apply_config(config).await;

        assert!(surface.ports.contains_key(&port), "the port must still be there after a repeat apply");
        assert!(!cancel.is_cancelled(), "a repeat apply of the same capsule must retire nothing");
        assert_eq!(
            surface.stats.snapshot().faces.len(),
            1,
            "a repeat apply must not duplicate or drop the one face"
        );
    }

    /// Test 4: one application can add and drop in the same call — order
    /// matters (`Surface::apply_config`'s own doc), and this proves both
    /// actually happened, not just that the source lines are in the right
    /// order. The "add" half spawns the REAL `face::run_face` on a wildcard
    /// address, so — like this crate's other wildcard-binding test — this
    /// is container-only.
    #[ignore = "binds wildcard addresses — container only, never the operator box"]
    #[tokio::test]
    async fn one_apply_adds_and_drops_in_the_same_call() {
        let (dropped_port, dropped_bound) = real_bound_face().await;
        // A port nothing else in this suite uses — run only in the musl
        // container per the `#[ignore]` above, never on the operator box.
        let added_port = 39_100u16;

        let mut ports = HashMap::new();
        ports.insert(dropped_port, dropped_bound);
        let faces = [test_face(dropped_port)];
        let mut surface = test_surface(ports, &faces);

        surface.apply_config(resolved_config(&[(added_port, TransportCamouflage::None)])).await;

        assert!(surface.ports.contains_key(&added_port), "the newly declared port must be added");
        assert!(
            !surface.ports.contains_key(&dropped_port),
            "the port the capsule stopped declaring must be retired in the same application"
        );

        let snap = surface.stats.snapshot();
        assert!(snap.faces.iter().any(|f| f.port == added_port));
        assert!(snap.faces.iter().all(|f| f.port != dropped_port));

        let rebound = tokio::net::TcpListener::bind(format!("127.0.0.1:{dropped_port}")).await;
        assert!(rebound.is_ok(), "the retired port's socket must be free: {:?}", rebound.err());
    }

    /// Test 5: the existing swap behaviour still passes unchanged — an
    /// already-bound port under a new camouflage/label stays on its exact
    /// same task, never rebound and never retired.
    #[tokio::test]
    async fn swapping_an_already_bound_port_never_touches_its_task() {
        let port = 39_004u16;
        let cancel = CancellationToken::new();
        let bound = bound_without_a_socket(port, cancel.clone());
        let mut ports = HashMap::new();
        ports.insert(port, bound);
        let faces = [test_face(port)];
        let mut surface = test_surface(ports, &faces);

        surface.apply_config(resolved_config(&[(port, tls())])).await;

        assert!(surface.ports.contains_key(&port), "a swap must never remove the port");
        assert!(!cancel.is_cancelled(), "a swap must never touch the existing task's cancel token");
        let states = surface.stats.face_states();
        assert_eq!(states.len(), 1, "a swap must never duplicate the port");
        assert_eq!(states[0].camouflage, "tls_real");
    }

    // ── `Surface::apply_config` — UDP faces (plan step 5) ──
    //
    // Same loopback-only discipline as the TCP tests above: a UDP face
    // ADDED for real goes through `udp_face::run_udp_face`, which binds
    // `0.0.0.0`/`[::]` exactly like `face::run_face` does for TCP — so the
    // one test that exercises a real add is `#[ignore]`d, container-only,
    // mirroring `one_apply_adds_and_drops_in_the_same_call` above. Every
    // RETIREMENT test instead seeds `self.udp_ports` with a stand-in built
    // from the real dispatcher (`udp_face::run_dispatcher`) bound to a real
    // LOOPBACK socket — the identical trick `real_bound_face` uses for TCP
    // — so the release proof is genuine without ever binding a wildcard.
    //
    // The box-local relay these tests hand `Surface` is always a fresh,
    // ephemeral-port/temp-path pair (`test_relay_pair`), never the fixed
    // production `LocalDgramChannel` — binding that fixed channel is
    // `Surface::bind_local_dgram_relay`'s own job, exercised by `run`, not
    // by these tests, and a FIXED port shared across every test in this
    // binary would race parallel `cargo test` execution.

    fn raw_udp_endpoint(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: format!("0.0.0.0:{port}").parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: None,
        }
    }

    /// [`raw_udp_endpoint`], with the signed `purpose` field set explicitly
    /// — used by the purpose-routing tests below to declare a `NodeChain`
    /// face rather than relying on the `MonitorWire` default.
    fn raw_udp_endpoint_with_purpose(port: u16, purpose: config::FacePurpose) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: format!("0.0.0.0:{port}").parse().expect("valid bind addr"),
            },
            wire_version: None,
            purpose: Some(purpose),
        }
    }

    /// [`resolved_config`], plus one `RawUdp` endpoint per port in
    /// `udp_ports` — the mixed-config shape plan §4 says a single `apply_
    /// config` call must handle correctly (TCP and UDP passes independent
    /// of each other).
    fn resolved_config_with_udp(
        tcp_faces: &[(u16, TransportCamouflage)],
        udp_ports: &[u16],
    ) -> Arc<PerimeterConfig> {
        let mut cfg = config_with(tcp_faces);
        for port in udp_ports {
            cfg.control_plane_endpoints.push(raw_udp_endpoint(*port));
        }
        Arc::new(
            PerimeterConfig::from_capsule(&cfg).expect("a well-formed mixed TCP/UDP config must parse"),
        )
    }

    #[cfg(unix)]
    static DGRAM_TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fresh, never-reused box-local datagram endpoint — a temp-dir unix
    /// socket path on unix (sequenced, so two tests in the same process
    /// never collide on the same path), OS-assigned loopback UDP port
    /// everywhere else. Mirrors `udp_relay.rs`'s own test helper of the
    /// same shape, kept as a separate copy here rather than a shared
    /// `pub(crate)` export — see this crate's own convention of duplicating
    /// small test-only fixtures rather than growing cross-module test APIs
    /// for them.
    #[cfg(unix)]
    fn fresh_dgram_endpoint(name: &str) -> mirage_core::local_dgram_endpoint::LocalDgramEndpoint {
        let seq = DGRAM_TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("mirage-perimeter-lib-udp-test-{name}-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        mirage_core::local_dgram_endpoint::LocalDgramEndpoint::UnixDgram(dir.join("ch.sock"))
    }
    #[cfg(not(unix))]
    fn fresh_dgram_endpoint(_name: &str) -> mirage_core::local_dgram_endpoint::LocalDgramEndpoint {
        mirage_core::local_dgram_endpoint::LocalDgramEndpoint::UdpLoopback(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            0,
        )))
    }

    #[cfg(unix)]
    fn dgram_managed_dir(
        ep: &mirage_core::local_dgram_endpoint::LocalDgramEndpoint,
    ) -> Option<std::path::PathBuf> {
        match ep {
            mirage_core::local_dgram_endpoint::LocalDgramEndpoint::UnixDgram(path) => {
                path.parent().map(std::path::Path::to_path_buf)
            }
            mirage_core::local_dgram_endpoint::LocalDgramEndpoint::UdpLoopback(_) => None,
        }
    }
    #[cfg(not(unix))]
    fn dgram_managed_dir(
        _ep: &mirage_core::local_dgram_endpoint::LocalDgramEndpoint,
    ) -> Option<std::path::PathBuf> {
        None
    }

    /// Root-only grant — nothing in this crate's tests runs as anyone else.
    fn dgram_bind_plan() -> mirage_core::local_endpoint::BindPlan {
        mirage_core::local_endpoint::plan_from_resolution(
            mirage_core::local_endpoint::AccountResolution::NotRequested,
        )
    }

    /// Bind two `LocalDgramSocket`s, paired at each other — the test-scope
    /// stand-in for EITHER of the two fixed, process-wide relay pairs
    /// `Surface::bind_local_dgram_relay` binds in production
    /// (monitor-bound or node-bound). This helper does not care which: both
    /// pairs are the identical mechanism, bound to a different fixed
    /// channel — see `mirage_core::local_dgram_endpoint`'s own module doc.
    /// Returns the perimeter side already wrapped in a live
    /// [`udp_relay::UdpMonitorRelay`] (what `Surface::dgram_relay_monitor`
    /// or `Surface::dgram_relay_node` actually holds, depending which one a
    /// caller wires it into) and the bare other-side socket, for a test to
    /// read off directly the way the monitor's or the node's own dispatcher
    /// eventually will.
    async fn test_relay_pair() -> (
        Arc<udp_relay::UdpMonitorRelay>,
        Arc<mirage_core::local_dgram_endpoint::LocalDgramSocket>,
    ) {
        let perimeter_ep = fresh_dgram_endpoint("perimeter");
        let monitor_ep = fresh_dgram_endpoint("monitor");
        let plan = dgram_bind_plan();

        let mut perimeter = mirage_core::local_dgram_endpoint::LocalDgramSocket::bind(
            perimeter_ep.clone(),
            monitor_ep.clone(),
            dgram_managed_dir(&perimeter_ep).as_deref(),
            &plan,
        )
        .await
        .expect("bind perimeter-side relay socket");
        let perimeter_real = perimeter.local_endpoint().clone();

        let mut monitor = mirage_core::local_dgram_endpoint::LocalDgramSocket::bind(
            monitor_ep.clone(),
            perimeter_real.clone(),
            dgram_managed_dir(&monitor_ep).as_deref(),
            &plan,
        )
        .await
        .expect("bind monitor-side relay socket");
        // On the loopback-UDP arm both ports are OS-assigned — point each
        // side at what the other one actually got.
        perimeter.set_peer_endpoint(monitor.local_endpoint().clone());
        monitor.set_peer_endpoint(perimeter_real);

        (udp_relay::UdpMonitorRelay::new(Arc::new(perimeter)), Arc::new(monitor))
    }

    /// A V9 `ClientHello`, timestamped against the REAL clock — required
    /// because `udp_relay::classify_datagram` reads `udp_face::now_ms()`
    /// internally rather than taking a caller-supplied "now".
    fn fresh_udp_hello() -> Vec<u8> {
        mirage_protocol::auth::v9::V9ClientHello {
            version: mirage_protocol::auth::v9::WIRE_VERSION_V9,
            suite_ids: [0x01, 0x00, 0x00],
            e_pub_c: [0xAA; 32],
            ts_ms: udp_face::now_ms(),
            client_proof: [0xBB; 16],
            client_static_pub: [0xCC; 32],
            cred_scheme: 0,
            target_hint: mirage_protocol::auth::v9::TargetHint::Legacy.to_byte(),
        }
        .to_wire()
        .to_vec()
    }

    /// A real, loopback-bound `BoundUdpFace` — composed from the SAME
    /// pieces `Surface::apply_config`'s own UDP add branch spawns
    /// (`udp_face::run_dispatcher` + [`run_udp_sessions`]), just bound to
    /// `127.0.0.1:0` instead of the wildcard `udp_face::run_udp_face`
    /// insists on. `Surface::apply_config`'s retirement logic is agnostic
    /// to which of the two produced a `BoundUdpFace`'s handles — it only
    /// ever cancels and awaits them — so this stand-in proves the SAME
    /// retirement path a real wildcard-bound face would go through, without
    /// this test binding one.
    async fn spawn_loopback_udp_face(
        relay: Arc<udp_relay::UdpMonitorRelay>,
        disposition: Disposition,
    ) -> (u16, BoundUdpFace) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("loopback UDP bind must succeed");
        let port = socket.local_addr().expect("socket has a local addr").port();
        let (sessions_tx, sessions_rx) = mpsc::channel(udp_face::PEER_CHANNEL_CAPACITY);
        let cancel = CancellationToken::new();
        let runtime = udp_face::test_runtime_for(port, cancel.clone(), sessions_tx);
        let counters = Arc::clone(runtime.counters());

        let dispatch = tokio::spawn(udp_face::run_dispatcher(socket, stats::AddressFamily::V4, runtime));
        let sessions = tokio::spawn(run_udp_sessions(
            sessions_rx,
            port,
            relay,
            counters,
            config::DEFAULT_MAX_SKEW_MS,
            disposition,
            cancel.clone(),
        ));

        (port, BoundUdpFace { cancel, dispatch, sessions })
    }

    /// Test 1: a config carrying a `RawUdp` face brings up a UDP face; the
    /// TCP face in the same config is unaffected. Binds a real wildcard UDP
    /// socket (`udp_face::run_udp_face`, through the real add branch) —
    /// container-only, same reasoning as `one_apply_adds_and_drops_in_the_
    /// same_call` above.
    #[ignore = "binds wildcard addresses — container only, never the operator box"]
    #[tokio::test]
    async fn a_raw_udp_face_is_added_and_a_tcp_face_in_the_same_config_is_unaffected() {
        let tcp_port = 39_300u16;
        let tcp_cancel = CancellationToken::new();
        let tcp_bound = bound_without_a_socket(tcp_port, tcp_cancel.clone());
        let mut ports = HashMap::new();
        ports.insert(tcp_port, tcp_bound);
        let faces = [test_face(tcp_port)];
        let mut surface = test_surface(ports, &faces);

        let (relay, _monitor_sock) = test_relay_pair().await;
        surface.dgram_relay_monitor = Some(relay);

        let udp_port = 39_301u16;
        let config = resolved_config_with_udp(&[(tcp_port, TransportCamouflage::None)], &[udp_port]);
        surface.apply_config(config).await;

        assert!(surface.udp_ports.contains_key(&udp_port), "the RawUdp face must be added");
        assert!(surface.ports.contains_key(&tcp_port), "the TCP face in the same config must be untouched");
        assert!(!tcp_cancel.is_cancelled(), "the TCP face's task must never even be asked to stop");
    }

    /// Test 2: a later config that drops a UDP face retires it with proof
    /// of release — after `apply_config` returns, the same address binds
    /// successfully. Mirrors `a_dropped_non_baseline_port_is_retired_and_
    /// its_socket_released` above, `UdpSocket` in place of `TcpListener`.
    #[tokio::test]
    async fn a_dropped_udp_face_is_retired_and_its_socket_released() {
        let (relay, _monitor_sock) = test_relay_pair().await;
        let (udp_port, bound) = spawn_loopback_udp_face(Arc::clone(&relay), Disposition::Jail).await;

        // A TCP face must stay declared too, or the config would be empty
        // (`ConfigError::NoFaces`) — not itself under test here, matching
        // the TCP retirement test's own `kept_port`.
        let kept_tcp_port = 39_310u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.udp_ports.insert(udp_port, bound);
        surface.dgram_relay_monitor = Some(relay);

        surface.apply_config(resolved_config(&[(kept_tcp_port, TransportCamouflage::None)])).await;

        assert!(
            !surface.udp_ports.contains_key(&udp_port),
            "a UDP port the new capsule no longer declares must leave self.udp_ports"
        );
        assert!(surface.ports.contains_key(&kept_tcp_port), "the still-declared TCP face must remain");

        let rebound = tokio::net::UdpSocket::bind(format!("127.0.0.1:{udp_port}")).await;
        assert!(
            rebound.is_ok(),
            "the retired UDP port's socket must be free — a leaked dispatcher that merely forgot \
             its task would still hold it and fail this exact rebind: {:?}",
            rebound.err()
        );
    }

    /// Step 7 proof #2 (the end-to-end half): a bound UDP face is readable
    /// over the query surface, and a retired one is gone from it — asserted
    /// only AFTER `apply_config` has RETURNED, i.e. after both
    /// `BoundUdpFace` handles have actually been awaited, never merely after
    /// `cancel.cancel()` was fired. This is the same "never claims a face
    /// that still exists, never lags behind reality" property
    /// `Stats::retire_face` was already built for on the TCP side —
    /// `stats::tests::a_retired_udp_face_is_gone_from_the_reported_set`
    /// proves the `Stats`-level half in isolation; this proves the whole
    /// pipeline `Surface::apply_config` actually drives.
    #[tokio::test]
    async fn a_udp_face_is_gone_from_the_query_surface_only_after_retirement_completes() {
        let (relay, _monitor_sock) = test_relay_pair().await;
        let (udp_port, bound) = spawn_loopback_udp_face(Arc::clone(&relay), Disposition::Jail).await;

        let kept_tcp_port = 39_311u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);

        // Registered through `Stats` exactly as the real add branch does
        // (`Surface::apply_config`'s `let counters = self.stats.
        // register_udp_face(face);`) — this test builds `bound` by hand
        // (see `spawn_loopback_udp_face`'s own doc for why that is still a
        // faithful stand-in for the dispatcher/session machinery), but the
        // registration itself must go through the one path `Stats` exposes.
        let counters = surface.stats.register_udp_face(&test_udp_face(udp_port));
        surface.udp_ports.insert(udp_port, bound);
        surface.dgram_relay_monitor = Some(relay);

        // Proof 1: readable, and its counters move.
        counters.datagrams_received.fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        counters.mark_family_bound(stats::AddressFamily::V4);
        let before = surface.stats.snapshot();
        let reported = before
            .udp_faces
            .iter()
            .find(|f| f.port == udp_port)
            .expect("the bound UDP face must be in the reported set before retirement");
        assert!(reported.bound);
        assert_eq!(reported.datagrams_received, 3, "the counters must move");

        // Proof 2: `apply_config` is awaited in full before this assertion
        // runs — by the time it returns, `bound.dispatch`/`bound.sessions`
        // have both already been joined (see `Surface::apply_config`'s UDP
        // retirement loop), so this is checked after retirement completed,
        // not merely after it was requested.
        surface.apply_config(resolved_config(&[(kept_tcp_port, TransportCamouflage::None)])).await;

        let after = surface.stats.snapshot();
        assert!(
            after.udp_faces.iter().all(|f| f.port != udp_port),
            "a retired UDP face must be gone from the query surface, not merely marked unbound"
        );
    }

    /// Step 7 proof #3: a UDP face whose declared purpose's relay never
    /// bound at boot is reported as REFUSED, not merely absent — the
    /// specific gap this step exists to close (see `Surface::apply_config`'s
    /// own doc, "UDP faces route by their own declared purpose"). Neither
    /// `dgram_relay_monitor` nor `dgram_relay_node` is wired up here, the
    /// exact condition `Self::dgram_relay_for` returns `None` for on a real
    /// box whose `bind_local_dgram_relay` call has not yet run (or failed).
    #[tokio::test]
    async fn a_udp_face_refused_for_a_missing_relay_is_reported_as_refused_not_absent() {
        let kept_tcp_port = 39_312u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);

        let udp_port = 39_313u16;
        let never_declared_port = 39_314u16;
        let config = resolved_config_with_udp(&[(kept_tcp_port, TransportCamouflage::None)], &[udp_port]);
        surface.apply_config(config).await;

        assert!(
            !surface.udp_ports.contains_key(&udp_port),
            "a refused face must never be added to the live, dispatching surface"
        );

        let snap = surface.stats.snapshot();
        let reported = snap
            .udp_faces
            .iter()
            .find(|f| f.port == udp_port)
            .expect("a refused face must still be REPORTED, not merely absent");
        assert!(!reported.bound, "a refused face never binds anything");
        assert!(
            reported.refused_reason.is_some(),
            "a refused face must name why, distinguishing it from a face that was never declared"
        );

        // The other half of "distinguishable": a port no capsule has ever
        // named must not appear in the reported set at all.
        assert!(
            snap.udp_faces.iter().all(|f| f.port != never_declared_port),
            "a port nobody ever declared must read as absent, not as refused"
        );

        // Re-applying the identical config must not re-refuse (and
        // re-register) the same port a second time.
        surface
            .apply_config(resolved_config_with_udp(
                &[(kept_tcp_port, TransportCamouflage::None)],
                &[udp_port],
            ))
            .await;
        let snap_again = surface.stats.snapshot();
        assert_eq!(
            snap_again.udp_faces.iter().filter(|f| f.port == udp_port).count(),
            1,
            "a port already known to be refused must not be registered a second time"
        );
    }

    /// Test 3: retiring a UDP face ends its live per-peer sessions — proven
    /// against the relay's OWN routing table, not merely by the dispatcher
    /// having stopped. A session is registered on `relay` the moment it
    /// classifies as wire (`udp_relay::relay_session`) and deregistered on
    /// every exit path, cancellation included — so `has_route` going from
    /// `true` to `false` across retirement is exactly "this session existed
    /// before and is gone after".
    #[tokio::test]
    async fn retiring_a_udp_face_ends_its_live_sessions_not_merely_the_dispatcher() {
        let (relay, monitor_sock) = test_relay_pair().await;
        let (udp_port, bound) = spawn_loopback_udp_face(Arc::clone(&relay), Disposition::Jail).await;

        let kept_tcp_port = 39_320u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.udp_ports.insert(udp_port, bound);
        surface.dgram_relay_monitor = Some(Arc::clone(&relay));

        // Establish a live, classified-wire session.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let client_addr = client.local_addr().expect("client has a local addr");
        client
            .send_to(&fresh_udp_hello(), format!("127.0.0.1:{udp_port}"))
            .await
            .expect("send hello");

        // Wait for the monitor side to see the relayed hello — proof the
        // session is live, and the exact routing key to check afterward.
        let (envelope, _payload) = tokio::time::timeout(Duration::from_secs(5), monitor_sock.recv_envelope())
            .await
            .expect("the monitor must receive the relayed hello")
            .expect("recv_envelope must succeed");
        assert_eq!(envelope.peer, client_addr);
        assert!(
            relay.has_route(udp_port, client_addr),
            "the live session must be registered on the relay before retirement"
        );

        surface.apply_config(resolved_config(&[(kept_tcp_port, TransportCamouflage::None)])).await;

        assert!(!surface.udp_ports.contains_key(&udp_port));
        assert!(
            !relay.has_route(udp_port, client_addr),
            "retiring the face must end its live session too, not merely stop the dispatcher"
        );
    }

    /// Test 4: applying the same config twice, with a UDP face declared, is
    /// a no-op the second time — nothing rebinds, nothing retires. Mirrors
    /// `applying_the_same_config_twice_retires_and_rebinds_nothing` above.
    #[tokio::test]
    async fn applying_the_same_config_twice_with_a_udp_face_retires_and_rebinds_nothing() {
        let (relay, _monitor_sock) = test_relay_pair().await;
        let (udp_port, bound) = spawn_loopback_udp_face(Arc::clone(&relay), Disposition::Jail).await;
        let udp_cancel = bound.cancel.clone();

        let kept_tcp_port = 39_330u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.udp_ports.insert(udp_port, bound);
        surface.dgram_relay_monitor = Some(relay);

        let config = resolved_config_with_udp(&[(kept_tcp_port, TransportCamouflage::None)], &[udp_port]);
        surface.apply_config(Arc::clone(&config)).await;
        assert!(surface.udp_ports.contains_key(&udp_port));
        assert!(!udp_cancel.is_cancelled());

        surface.apply_config(config).await;
        assert!(
            surface.udp_ports.contains_key(&udp_port),
            "the UDP port must still be there after a repeat apply"
        );
        assert!(!udp_cancel.is_cancelled(), "a repeat apply of the same capsule must retire nothing");

        // Tidy up the still-running loopback dispatcher/session tasks this
        // test never routes through `apply_config`'s own retirement path —
        // no assertion depends on this, it is only hygiene.
        udp_cancel.cancel();
    }

    // ── UDP faces route by their OWN declared purpose (the U0 defect fix) ──
    //
    // Before this diff, `Surface::apply_config`'s UDP add branch always
    // selected the monitor relay regardless of `face.purpose` — a face
    // declared `NodeChain` had its data-plane traffic delivered to the
    // control plane, which cannot consume it. The tests below exercise
    // `Surface::dgram_relay_for` — the exact selection `apply_config` calls
    // — and the same loopback dispatch/session plumbing `apply_config`'s
    // add branch spawns, without ever binding a wildcard address, so none
    // of them need `#[ignore]`.

    /// Pure proof of the selection `Surface::apply_config`'s UDP add branch
    /// makes: a `MonitorWire` face resolves the monitor relay, a
    /// `NodeChain` face resolves the node relay, an `EdgeEntrance` face
    /// resolves the edge relay, and no purpose ever resolves another
    /// purpose's relay.
    #[tokio::test]
    async fn dgram_relay_for_selects_the_relay_matching_the_faces_own_purpose() {
        let (monitor_relay, _monitor_sock) = test_relay_pair().await;
        let (node_relay, _node_sock) = test_relay_pair().await;
        let (edge_relay, _edge_sock) = test_relay_pair().await;

        let placeholder_port = 39_340u16;
        let faces = [test_face(placeholder_port)];
        let mut surface = test_surface(HashMap::new(), &faces);
        surface.dgram_relay_monitor = Some(Arc::clone(&monitor_relay));
        surface.dgram_relay_node = Some(Arc::clone(&node_relay));
        surface.dgram_relay_edge = Some(Arc::clone(&edge_relay));

        let resolved_monitor = surface
            .dgram_relay_for(config::FacePurpose::MonitorWire)
            .expect("the monitor relay is bound");
        let resolved_node = surface
            .dgram_relay_for(config::FacePurpose::NodeChain)
            .expect("the node relay is bound");
        let resolved_edge = surface
            .dgram_relay_for(config::FacePurpose::EdgeEntrance)
            .expect("the edge relay is bound");

        assert!(
            Arc::ptr_eq(&resolved_monitor, &monitor_relay),
            "MonitorWire must resolve the monitor relay"
        );
        assert!(Arc::ptr_eq(&resolved_node, &node_relay), "NodeChain must resolve the node relay");
        assert!(Arc::ptr_eq(&resolved_edge, &edge_relay), "EdgeEntrance must resolve the edge relay");
        assert!(
            !Arc::ptr_eq(&resolved_monitor, &resolved_node)
                && !Arc::ptr_eq(&resolved_monitor, &resolved_edge)
                && !Arc::ptr_eq(&resolved_node, &resolved_edge),
            "no two purposes may ever resolve to the same relay"
        );
    }

    /// A face whose purpose's relay never bound at boot is refused outright
    /// — never silently served through the OTHER relay, which would be
    /// exactly the misrouting this split exists to prevent. Goes through
    /// the real `Surface::apply_config` add branch: the relay lookup fails
    /// before `udp_face::run_udp_face` is ever spawned, so this never
    /// touches a wildcard socket.
    #[tokio::test]
    async fn a_face_whose_purpose_has_no_bound_relay_is_refused_not_served_through_the_other_one() {
        let (monitor_relay, _monitor_sock) = test_relay_pair().await;

        let kept_tcp_port = 39_343u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        // The monitor relay IS bound; the node relay is NOT.
        surface.dgram_relay_monitor = Some(monitor_relay);
        surface.dgram_relay_node = None;

        let node_face_port = 39_344u16;
        let mut cfg = config_with(&[(kept_tcp_port, TransportCamouflage::None)]);
        cfg.control_plane_endpoints
            .push(raw_udp_endpoint_with_purpose(node_face_port, config::FacePurpose::NodeChain));
        let config = Arc::new(
            PerimeterConfig::from_capsule(&cfg).expect("a well-formed mixed TCP/UDP config must parse"),
        );

        surface.apply_config(config).await;

        assert!(
            !surface.udp_ports.contains_key(&node_face_port),
            "a face whose declared purpose's relay never bound must not be added at all"
        );
    }

    /// The test that would have caught the defect: a UDP face declared
    /// `NodeChain` must relay its classified-wire hello to the NODE relay,
    /// byte-identical, and the MONITOR relay pair must receive nothing at
    /// all for this session.
    #[tokio::test]
    async fn a_node_chain_face_relays_its_hello_to_the_node_and_never_to_the_monitor() {
        let (monitor_relay, monitor_sock) = test_relay_pair().await;
        let (node_relay, node_sock) = test_relay_pair().await;

        let kept_tcp_port = 39_345u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.dgram_relay_monitor = Some(monitor_relay);
        surface.dgram_relay_node = Some(Arc::clone(&node_relay));

        // Built exactly the way `Surface::apply_config`'s UDP add branch
        // builds it for a `NodeChain` face — `dgram_relay_for` selects the
        // node relay, `spawn_loopback_udp_face` is the loopback stand-in
        // for the wildcard `udp_face::run_udp_face` add branch spawns (same
        // trick `retiring_a_udp_face_ends_its_live_sessions_not_merely_the_
        // dispatcher` above uses).
        let selected = surface
            .dgram_relay_for(config::FacePurpose::NodeChain)
            .expect("the node relay is bound");
        assert!(Arc::ptr_eq(&selected, &node_relay), "a NodeChain face must select the node relay");
        let (udp_port, bound) = spawn_loopback_udp_face(selected, Disposition::Jail).await;
        let udp_cancel = bound.cancel.clone();
        surface.udp_ports.insert(udp_port, bound);

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let client_addr = client.local_addr().expect("client has a local addr");
        let hello = fresh_udp_hello();
        client.send_to(&hello, format!("127.0.0.1:{udp_port}")).await.expect("send hello");

        let (envelope, payload) = tokio::time::timeout(Duration::from_secs(5), node_sock.recv_envelope())
            .await
            .expect("the node must receive the relayed hello")
            .expect("recv_envelope must succeed");
        assert_eq!(envelope.face_port, udp_port);
        assert_eq!(envelope.peer, client_addr);
        assert_eq!(payload, hello, "the relayed payload must be byte-identical to the wire hello");

        // The assertion that would have caught the defect: the monitor pair
        // must receive NOTHING for this session — a NodeChain face's
        // data-plane traffic must never be delivered to the control plane.
        let leaked_to_monitor =
            tokio::time::timeout(Duration::from_millis(300), monitor_sock.recv_envelope()).await;
        assert!(
            leaked_to_monitor.is_err(),
            "a NodeChain face's traffic must never reach the monitor relay"
        );

        udp_cancel.cancel();
    }

    /// A reply arriving from the node side must go back out to the right
    /// peer through the face's own bound socket — exactly the return path
    /// the monitor side already has (`udp_relay::tests::
    /// a_monitor_reply_returns_to_the_right_peer_from_the_same_public_
    /// socket`), proven here for the node relay specifically: the wiring
    /// `Surface::apply_config`'s UDP add branch does for a `NodeChain`
    /// face's own `dgram_relay_node_inbound` reader.
    #[tokio::test]
    async fn a_node_chain_faces_reply_returns_to_the_right_peer_from_the_same_public_socket() {
        let (node_relay, node_sock) = test_relay_pair().await;
        let inbound_cancel = CancellationToken::new();
        let node_inbound = tokio::spawn(Arc::clone(&node_relay).run_inbound(
            Arc::new(udp_face::UdpFaceCounters::default()),
            inbound_cancel.clone(),
        ));

        let (udp_port, bound) = spawn_loopback_udp_face(Arc::clone(&node_relay), Disposition::Jail).await;
        let udp_cancel = bound.cancel.clone();

        let kept_tcp_port = 39_346u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.dgram_relay_node = Some(Arc::clone(&node_relay));
        surface.udp_ports.insert(udp_port, bound);

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let client_addr = client.local_addr().expect("client has a local addr");
        client
            .send_to(&fresh_udp_hello(), format!("127.0.0.1:{udp_port}"))
            .await
            .expect("send hello");

        let (_envelope, _payload) = tokio::time::timeout(Duration::from_secs(5), node_sock.recv_envelope())
            .await
            .expect("the node must receive the hello")
            .expect("recv_envelope must succeed");

        let reply_envelope = mirage_core::local_dgram_endpoint::DgramEnvelope {
            face_port: udp_port,
            peer: client_addr,
        };
        node_sock
            .send_envelope(reply_envelope, b"node-hello-reply")
            .await
            .expect("the node sends its reply over the local relay");

        let mut buf = [0u8; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("the client must receive the node's reply")
            .expect("recv_from must succeed");
        assert_eq!(&buf[..n], b"node-hello-reply");
        assert_eq!(
            from,
            std::net::SocketAddr::from(([127, 0, 0, 1], udp_port)),
            "the reply must arrive FROM the face's own bound socket, never a new one"
        );

        udp_cancel.cancel();
        inbound_cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), node_inbound).await;
    }

    // ── Edge symmetry: same proof, the edge relay ────────────────────────
    //
    // An Edge box runs no `mirage-node` at all
    // (`docs/mirage/plans/2026-09-24-edge-as-entry.md`), so an
    // `EdgeEntrance`-purposed UDP face must relay through its OWN box-local
    // channel — never the monitor's, never the node's — exactly the same
    // proof the `NodeChain` tests above give for the node relay.

    /// The `EdgeEntrance` counterpart of
    /// `a_node_chain_face_relays_its_hello_to_the_node_and_never_to_the_monitor`:
    /// a UDP face declared `EdgeEntrance` must relay its classified-wire
    /// hello to the EDGE relay, byte-identical, and neither the MONITOR nor
    /// the NODE relay pair may receive anything at all for this session.
    #[tokio::test]
    async fn an_edge_entrance_face_relays_its_hello_to_the_edge_and_never_to_the_monitor_or_node() {
        let (monitor_relay, monitor_sock) = test_relay_pair().await;
        let (node_relay, node_sock) = test_relay_pair().await;
        let (edge_relay, edge_sock) = test_relay_pair().await;

        let kept_tcp_port = 39_347u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.dgram_relay_monitor = Some(monitor_relay);
        surface.dgram_relay_node = Some(node_relay);
        surface.dgram_relay_edge = Some(Arc::clone(&edge_relay));

        // Built exactly the way `Surface::apply_config`'s UDP add branch
        // builds it for an `EdgeEntrance` face — `dgram_relay_for` selects
        // the edge relay, `spawn_loopback_udp_face` is the loopback
        // stand-in for the wildcard `udp_face::run_udp_face` add branch
        // spawns, same as the `NodeChain` test above.
        let selected = surface
            .dgram_relay_for(config::FacePurpose::EdgeEntrance)
            .expect("the edge relay is bound");
        assert!(Arc::ptr_eq(&selected, &edge_relay), "an EdgeEntrance face must select the edge relay");
        let (udp_port, bound) = spawn_loopback_udp_face(selected, Disposition::Jail).await;
        let udp_cancel = bound.cancel.clone();
        surface.udp_ports.insert(udp_port, bound);

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let client_addr = client.local_addr().expect("client has a local addr");
        let hello = fresh_udp_hello();
        client.send_to(&hello, format!("127.0.0.1:{udp_port}")).await.expect("send hello");

        let (envelope, payload) = tokio::time::timeout(Duration::from_secs(5), edge_sock.recv_envelope())
            .await
            .expect("the edge unit must receive the relayed hello")
            .expect("recv_envelope must succeed");
        assert_eq!(envelope.face_port, udp_port);
        assert_eq!(envelope.peer, client_addr);
        assert_eq!(payload, hello, "the relayed payload must be byte-identical to the wire hello");

        // Neither the monitor pair nor the node pair may receive anything
        // for this session — an EdgeEntrance face's data-plane traffic must
        // never be delivered to either.
        let leaked_to_monitor =
            tokio::time::timeout(Duration::from_millis(300), monitor_sock.recv_envelope()).await;
        assert!(
            leaked_to_monitor.is_err(),
            "an EdgeEntrance face's traffic must never reach the monitor relay"
        );
        let leaked_to_node =
            tokio::time::timeout(Duration::from_millis(300), node_sock.recv_envelope()).await;
        assert!(leaked_to_node.is_err(), "an EdgeEntrance face's traffic must never reach the node relay");

        udp_cancel.cancel();
    }

    /// The `EdgeEntrance` counterpart of
    /// `a_node_chain_faces_reply_returns_to_the_right_peer_from_the_same_public_socket`:
    /// a reply arriving from the edge side must go back out to the right
    /// peer through the face's own bound socket, proven here for the edge
    /// relay's own `dgram_relay_edge_inbound` reader.
    #[tokio::test]
    async fn an_edge_entrance_faces_reply_returns_to_the_right_peer_from_the_same_public_socket() {
        let (edge_relay, edge_sock) = test_relay_pair().await;
        let inbound_cancel = CancellationToken::new();
        let edge_inbound = tokio::spawn(Arc::clone(&edge_relay).run_inbound(
            Arc::new(udp_face::UdpFaceCounters::default()),
            inbound_cancel.clone(),
        ));

        let (udp_port, bound) = spawn_loopback_udp_face(Arc::clone(&edge_relay), Disposition::Jail).await;
        let udp_cancel = bound.cancel.clone();

        let kept_tcp_port = 39_348u16;
        let kept_tcp_bound = bound_without_a_socket(kept_tcp_port, CancellationToken::new());
        let mut ports = HashMap::new();
        ports.insert(kept_tcp_port, kept_tcp_bound);
        let faces = [test_face(kept_tcp_port)];
        let mut surface = test_surface(ports, &faces);
        surface.dgram_relay_edge = Some(Arc::clone(&edge_relay));
        surface.udp_ports.insert(udp_port, bound);

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
        let client_addr = client.local_addr().expect("client has a local addr");
        client
            .send_to(&fresh_udp_hello(), format!("127.0.0.1:{udp_port}"))
            .await
            .expect("send hello");

        let (_envelope, _payload) = tokio::time::timeout(Duration::from_secs(5), edge_sock.recv_envelope())
            .await
            .expect("the edge unit must receive the hello")
            .expect("recv_envelope must succeed");

        let reply_envelope = mirage_core::local_dgram_endpoint::DgramEnvelope {
            face_port: udp_port,
            peer: client_addr,
        };
        edge_sock
            .send_envelope(reply_envelope, b"edge-hello-reply")
            .await
            .expect("the edge unit sends its reply over the local relay");

        let mut buf = [0u8; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("the client must receive the edge unit's reply")
            .expect("recv_from must succeed");
        assert_eq!(&buf[..n], b"edge-hello-reply");
        assert_eq!(
            from,
            std::net::SocketAddr::from(([127, 0, 0, 1], udp_port)),
            "the reply must arrive FROM the face's own bound socket, never a new one"
        );

        udp_cancel.cancel();
        inbound_cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), edge_inbound).await;
    }

    // ── the STANDALONE path — `run_standalone` ──
    //
    // A standalone box has no capsule, no keeper and no mesh: the face
    // list comes from a local config and the wire key from a wire-only
    // identity. What has to be true is that the surface it comes up with
    // is EXACTLY the faces that list named — no baseline underneath, no
    // capsule on top — and that it answers the readiness question the
    // same way every other surface does.
    //
    // The end-to-end test binds a real listener, so — like this crate's
    // other wildcard-binding tests — it is `#[ignore]`d and container-only.
    // What CAN be proven here without a wildcard bind is the part that
    // decides WHETHER a standalone surface may come up at all.

    /// A standalone config resolved from a local face list.
    fn standalone_config(faces: Vec<config::PerimeterFace>) -> PerimeterConfig {
        PerimeterConfig::from_local_faces(
            faces,
            "127.0.0.1:29444".parse().expect("valid inner addr"),
        )
        .expect("a local face list must parse")
    }

    /// A standalone surface with no face at all would bind nothing on any
    /// public port while reporting healthy — refused, on the way in.
    #[test]
    fn a_standalone_config_with_no_faces_is_refused() {
        let mut cfg = standalone_config(vec![test_face(39_400)]);
        cfg.faces.clear();
        let err = validate_standalone_config(&cfg).unwrap_err();
        assert!(matches!(err, PerimeterError::NoFaces), "got {err:?}");
    }

    /// Two faces on one port would leave the second one retrying a bind
    /// forever while the process reported healthy — refused, on the way in.
    #[test]
    fn a_standalone_config_with_two_faces_on_one_port_is_refused() {
        let mut cfg = standalone_config(vec![test_face(39_401)]);
        cfg.faces.push(test_face(39_401));
        let err = validate_standalone_config(&cfg).unwrap_err();
        assert!(
            matches!(err, PerimeterError::Config(ConfigError::DuplicatePort(39_401))),
            "got {err:?}"
        );
    }

    /// The same port NUMBER on two transports is two doors, not one door
    /// opened twice: TCP and UDP are separate socket spaces, and an ordinary
    /// server serves HTTPS and QUIC side by side. The check on the way in
    /// must not refuse what the kernel is happy to bind.
    #[test]
    fn a_standalone_config_may_hold_one_port_number_on_both_transports() {
        let cfg = standalone_config(vec![
            test_face(39_403),
            config::PerimeterFace {
                port: 39_403,
                camouflage: TransportCamouflage::RawUdp {
                    bind_addr: "0.0.0.0:39403".parse().expect("valid bind addr"),
                },
                label: "raw_udp:39403".into(),
                purpose: config::FacePurpose::NodeChain,
            },
        ]);
        validate_standalone_config(&cfg).expect("TCP and UDP are separate socket spaces");
        assert_eq!(cfg.faces.len(), 1);
        assert_eq!(cfg.udp_faces.len(), 1);
        assert_eq!(cfg.faces[0].port, cfg.udp_faces[0].port);
    }

    /// And two UDP faces on one number are still refused — the rule is per
    /// transport, not per number.
    #[test]
    fn a_standalone_config_with_two_udp_faces_on_one_port_is_refused() {
        let udp_face = config::UdpFace {
            port: 39_404,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: "0.0.0.0:39404".parse().expect("valid bind addr"),
            },
            label: "raw_udp:39404".into(),
            purpose: config::FacePurpose::NodeChain,
        };
        let mut cfg = standalone_config(vec![config::PerimeterFace {
            port: 39_404,
            camouflage: TransportCamouflage::RawUdp {
                bind_addr: "0.0.0.0:39404".parse().expect("valid bind addr"),
            },
            label: "raw_udp:39404".into(),
            purpose: config::FacePurpose::NodeChain,
        }]);
        cfg.udp_faces.push(udp_face);
        let err = validate_standalone_config(&cfg).unwrap_err();
        assert!(
            matches!(err, PerimeterError::Config(ConfigError::DuplicatePort(39_404))),
            "got {err:?}"
        );
    }

    /// A zero port is refused here too, for the same reason it is refused
    /// on the way in: "port 0" is a request for "any port", and a
    /// perimeter that binds a port nobody chose is not serving what the
    /// operator asked for.
    #[test]
    fn a_standalone_config_with_a_zero_port_is_refused() {
        let mut cfg = standalone_config(vec![test_face(39_402)]);
        cfg.faces[0].port = 0;
        let err = validate_standalone_config(&cfg).unwrap_err();
        assert!(
            matches!(err, PerimeterError::Config(ConfigError::ZeroPort)),
            "got {err:?}"
        );
    }

    /// The end-to-end standalone surface: a face list the operator wrote
    /// down, a wire-only identity, no capsule and no keeper — and the
    /// face really binds.
    ///
    /// The face goes through the REAL `face::run_face` on a wildcard
    /// address, so — like this crate's other wildcard-binding tests — this
    /// is container-only.
    ///
    /// The readiness answer is read through `stats::answer`, which is the
    /// very function the query channel serves every request with, so what
    /// this proves about `PerimeterRequest::Health` is what an operator
    /// asking over that channel is told. The channel itself is NOT bound
    /// here: it is a fixed box-local path (`/run/mirage/perimeter/
    /// query.sock` on unix) with no way to point it at a scratch
    /// directory, and a test must not write into a system directory.
    #[ignore = "binds wildcard addresses — container only, never the operator box"]
    #[tokio::test]
    async fn a_standalone_surface_binds_its_face_and_answers_health() {
        // An OS-assigned free port: bind a loopback socket on port 0,
        // read what the OS gave it, and let it go. The face then binds
        // that same port for real.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind must succeed");
        let port = probe.local_addr().expect("listener has a local addr").port();
        drop(probe);

        let cfg = standalone_config(vec![test_face(port)]);
        let identity = Identity::wire_only(KeyPair::generate());

        let surface = Surface::bind_standalone(Arc::new(cfg), &identity)
            .expect("a standalone surface must bind");

        assert_eq!(
            surface.ports.keys().copied().collect::<Vec<u16>>(),
            vec![port],
            "the standalone surface must carry EXACTLY the faces the local config named — no \
             baseline underneath, no capsule on top"
        );

        // The listener is the accept task's, so the bind lands
        // asynchronously — wait for the live signal rather than for a
        // schedule.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while surface.stats.faces_bound() == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(surface.stats.faces_bound(), 1, "the standalone face must really bind");

        // The very answer the query channel serves.
        let stats = Arc::clone(&surface.stats);
        let PerimeterResponse::Health(health) =
            stats::answer(&stats, "test", PerimeterRequest::Health)
        else {
            panic!("Health must be answered with health");
        };
        assert_eq!(health.faces_bound, 1, "Health must report the bound face");
    }
}
