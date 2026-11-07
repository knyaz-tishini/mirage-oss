//! One face = one bound port, served over two accept loops (one per address
//! family — see "A face is two sockets, not one" below). This is where
//! every decision this crate's module doc describes actually happens per
//! connection: strip camouflage, read the first
//! [`crate::classify::V9_CLIENT_HELLO_LEN`] bytes, classify, and either
//! splice through to the inner monitor or drop the connection — identically
//! for both families, in the one shared [`accept_loop`].
//!
//! A single connection's failure — a bad camouflage handshake, a peer that
//! never sends a full hello, an inner-dial timeout — never kills its accept
//! loop, and one face's failure never touches another's: `lib.rs::run`
//! spawns one independent task per face. A bind failure only ever ends the
//! affected family's half of that task (see `run_face`'s own doc), and every
//! OTHER family and every OTHER face keep serving regardless. The other way
//! a family's half ends is deliberate: `crate::run::Surface::apply_config`
//! retiring this port fires a [`tokio_util::sync::CancellationToken`] both
//! halves race against `listener.accept()` — see `run_face`'s own doc,
//! "Stopping a face".
//!
//! # A face's camouflage and this process's keypair can change under it
//!
//! [`run_face`] binds its port exactly once and never rebinds it for the
//! task's whole life — but WHICH [`PerimeterFace`] (camouflage, label) and
//! which wire [`KeyPair`] govern the next accepted connection can, because
//! the baseline surface (`crate::config::PerimeterConfig::baseline`) binds
//! `:22`/`:80`/`:443` before any identity exists, and a capsule's own
//! declared faces are added on top of it once one lands
//! (`crate::run::Surface::apply_identity_when_ready`) — a port the baseline
//! already bound is swapped in place, never unbound and rebound. [`SharedFace`]
//! and [`SharedKeypair`] carry that: an [`arc_swap::ArcSwap`] cell `run_face`
//! reads fresh for every accepted connection, so a swap changes what the
//! NEXT connection is judged under and never touches the listener itself or
//! a connection already in flight.
//!
//! # A face is two sockets, not one
//!
//! [`run_face`] used to open exactly one `TcpListener`, on `0.0.0.0:<port>`
//! — IPv4 only. The nft surface this fleet runs is an `inet` table, and
//! `tcp dport { 22, 80, 443, ... } accept` admits BOTH address families:
//! every face port was already open on IPv6 while nothing on the box bound
//! it there. Proven off-box before it was closed by other means: an sshd
//! bound to `[::]:22` answered a real client over IPv6 while `[::]:2222`,
//! not admitted, timed out — the filter was sound, the gap was the unbound
//! family, and an admitted port with nothing bound is a port the next
//! daemon to start can claim.
//!
//! So each face now binds `0.0.0.0:<port>` AND `[::]:<port>`: two plain
//! sockets, each its own [`tokio::net::TcpListener`] and its own accept
//! loop ([`bind_and_serve`] binds one, [`accept_loop`] runs it), feeding
//! the SAME classifier and the SAME per-face state — [`FaceRuntime`] is
//! what both loops of one face share, so splitting the listener never
//! splits anything else.
//!
//! **This is deliberately not one dual-stack socket with `IPV6_V6ONLY=0`.**
//! That flag's behaviour is not portable — whether and how a v6 socket
//! admits v4 traffic differs across kernels and distributions — and even
//! where it works, it erases which family a connection actually arrived
//! on. This fleet's attribution and stats need to keep that: `jail.rs` /
//! `sink.rs` price a source by address, and folding two families through
//! one accept path would report every v4-mapped connection as if it were
//! native IPv6. Two listeners keep the fact intact for free.
//!
//! A missing IPv6 stack — disabled at the kernel
//! (`net.ipv6.conf.all.disable_ipv6=1`) or simply no v6 address configured
//! at all — must not take the face down: it is a normal, permanent
//! condition on some hosts, and [`bind_with_retry`] tells that apart from
//! the ordinary transient case (see [`BindFailureKind`]) so the v4 half
//! keeps serving and the v6 half says why exactly once instead of
//! retrying forever. [`crate::stats::FaceCounters`] tracks the two
//! families apart ([`crate::stats::FamilyBind`]) rather than folding them
//! into the single boolean it used to be — see that module's own doc.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use mirage_core::crypto::KeyPair;
use mirage_protocol::auth::v9::TargetHint;
use mirage_protocol::camouflage::pipeline::{strip_tcp_server, BidiStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::classify::{
    classify_v9_hello, looks_like_ssh, NotWireReason, Verdict, SSH_DECISION_LEN,
    V9_CLIENT_HELLO_LEN,
};
use crate::config::{FacePurpose, PerimeterConfig, PerimeterFace};
use crate::ratelimit::SourceRateLimit;
use crate::stats::{AddressFamily, FaceCounters};

/// A face's camouflage/label, live-swappable exactly once per port — see
/// this module's doc, "A face's camouflage and this process's keypair can
/// change under it". [`run_face`] loads the current value fresh for every
/// accepted connection; the listener it bound at task start never changes.
pub type SharedFace = Arc<ArcSwap<PerimeterFace>>;

/// This process's wire identity, live-swappable exactly once — from a
/// locally generated boot-only key (`crate::run::Surface::bind_baseline`)
/// to the real one a landed capsule carries
/// (`crate::run::Surface::apply_identity_when_ready`). Every baseline
/// camouflage is [`crate::config::PerimeterFace`]'s `TransportCamouflage::
/// None`, which `strip_tcp_server` never reads the keypair for — only
/// `Reality` does, and no baseline face is `Reality` — so the boot-only key
/// is a placeholder `strip_tcp_server`'s signature requires, never a
/// credential anything downstream trusts.
pub type SharedKeypair = Arc<ArcSwap<KeyPair>>;

/// Seam A — the camouflage strip refused, timed out or errored. The peer did
/// not speak this face's outer protocol.
///
/// This is why `mirage-secd::banengine::touch_ledger` prices both seams as
/// anonymous probing, never as a credential ledger, however the connection
/// began: nothing reaches this seam WITH a credential attached, so there is
/// nothing here a "reaching the door is free" rule could apply to.
const SEAM_A: mirage_core::fact_signing::AttackerSignalType =
    mirage_core::fact_signing::AttackerSignalType::PerimeterCamoFailed;

/// Seam B — the camouflage came off and what was inside was neither a V9
/// hello nor an SSH banner (including "nothing at all, within the window").
///
/// The crux this face cannot resolve on its own: a real SSH client that
/// opened a connection here and hung up before finishing its own
/// identification string — an aborted client, a bare TCP connect-scan probe
/// against `:22`, a health-checker — looks EXACTLY like this, byte for
/// byte. No additional information distinguishes "gave up early" from
/// "never meant to finish", so both are reported identically and priced as
/// anonymous probing on `mirage-secd`'s side (`banengine::touch_ledger`) —
/// never on either credential ledger, because no credential was ever
/// offered here to reject. What DOES separate an SSH-shaped connection from
/// this seam is finishing its identification string, which routes it to
/// `route_ssh` below instead — an outcome this seam, by definition, never
/// reaches.
const SEAM_B: mirage_core::fact_signing::AttackerSignalType =
    mirage_core::fact_signing::AttackerSignalType::PerimeterNotWire;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Pause between bind attempts for a face whose port is not free yet.
///
/// Matched to mshd's own door-check interval (`ssh_server::DOOR_CHECK_INTERVAL`),
/// because the contention this retries is with that process: the two hand `:22`
/// back and forth at boot, and a retry slower than the other side's release
/// check turns a two-tick handover into a long one.
const FACE_BIND_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Attempts between WARN lines while a bind keeps failing. The first failure
/// always logs; after that, one line a minute rather than one every five
/// seconds — a face that cannot bind is a durable condition, and repeating it
/// twelve times a minute buries the rest of the journal.
const FACE_BIND_LOG_EVERY: u32 = 12;

/// Whether a failed `bind` is worth trying again, or a permanent property of
/// this host that no amount of retrying changes.
///
/// [`bind_with_retry`]'s retry loop was built for exactly one failure mode —
/// another daemon holds the port right now and will let go (`EADDRINUSE`),
/// see that function's own doc for the mshd/`:22` handover this fleet
/// actually hits. Binding `[::]:<port>` on a box with IPv6 turned off at the
/// kernel (`net.ipv6.conf.all.disable_ipv6=1`) or carrying no IPv6 address
/// at all fails too, but for a durable reason: `EAFNOSUPPORT` when the
/// address family itself does not exist on this host, `EADDRNOTAVAIL` when
/// the family exists but nothing here can bind to it. Neither of those
/// clears on its own — the host's IPv6 configuration is not going to change
/// while this process runs — so retrying it forever is not "waiting out a
/// handover" the way the transient case is; it is a log line a minute for
/// the rest of this process's life for a fact that was already true at the
/// very first attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindFailureKind {
    /// Worth retrying — the transient case [`bind_with_retry`] was built
    /// for.
    Transient,
    /// A durable property of this host. Retrying changes nothing; the
    /// caller says so once and stops.
    Permanent,
}

/// Classify a failed `bind` as [`BindFailureKind::Transient`] or
/// [`BindFailureKind::Permanent`] — see that type's doc for what each means.
///
/// `EADDRNOTAVAIL` has a stable [`io::ErrorKind`] (`AddrNotAvailable`) and is
/// matched through it; `EAFNOSUPPORT` does not — unlike `AddrInUse` /
/// `AddrNotAvailable`, no stable `ErrorKind` variant names it, so it is read
/// off the raw OS error number directly. `97` is `EAFNOSUPPORT` on every
/// unix this crate targets; `10047` is `WSAEAFNOSUPPORT` on the dev-only
/// Windows arm (`mirage_core::local_endpoint::LocalChannel`'s own doc has
/// the rest of that arm's story). Anything else — `EADDRINUSE` above all —
/// is transient: some other process holding the port is not a property of
/// the host, and clears on its own.
pub(crate) fn classify_bind_error(e: &io::Error) -> BindFailureKind {
    if e.kind() == io::ErrorKind::AddrNotAvailable {
        return BindFailureKind::Permanent;
    }
    match e.raw_os_error() {
        #[cfg(unix)]
        Some(97) => BindFailureKind::Permanent,
        #[cfg(windows)]
        Some(10047) => BindFailureKind::Permanent,
        _ => BindFailureKind::Transient,
    }
}

/// Listen backlog passed to [`socket2::Socket::listen`] for the v6-only
/// socket — matched to the `1024` `tokio`'s own `TcpListener::bind` passes
/// for the v4 socket (via `mio`), so splitting one listener into two never
/// also quietly shrinks either one's kernel backlog.
const V6_LISTEN_BACKLOG: i32 = 1024;

/// Bind `bind_addr` (an unspecified-`::`/loopback-`::1` IPv6 address in
/// every caller today) as a genuinely IPv6-ONLY socket, then hand it to
/// tokio as an ordinary [`tokio::net::TcpListener`].
///
/// # Why this exists — measured on the live fleet, not assumed
///
/// `tokio::net::TcpListener::bind` has no way to set `IPV6_V6ONLY` before
/// the bind syscall runs, so a plain `[::]:<port>` bind inherits whatever
/// the host defaults to. Checked directly on every box in this fleet:
///
/// ```text
/// net.ipv6.conf.all.disable_ipv6 = 0     (IPv6 is enabled)
/// net.ipv6.bindv6only            = 0     (so [::] is DUAL-STACK)
/// ```
///
/// With `bindv6only=0`, `[::]:<port>` claims the IPv4 wildcard on the SAME
/// port too. Two `bind_and_serve` tasks racing for one face's port would
/// then mean: whichever wins takes BOTH families on one socket; the loser
/// gets `EADDRINUSE`, which is ordinarily [`BindFailureKind::Transient`], so
/// it retries forever accepting nothing; and
/// [`crate::stats::FaceCounters`] would report the loser's family as
/// unbound while its traffic is in fact being carried by the winner's
/// socket — a lie on exactly the axis this dual-stack change exists to make
/// honest. This is the second half of why one dual-stack socket was
/// rejected for this design at all (see this module's doc, "A face is two
/// sockets, not one"): it is not merely that a dual-stack accept path hides
/// which family a connection answered on — on THIS fleet's kernels, getting
/// two genuinely independent sockets in the first place requires setting
/// `IPV6_V6ONLY` explicitly, because the host default is the opposite of
/// what two separate listeners need.
///
/// The IPv4 half (`bind_with_retry`'s other branch) is untouched: plain
/// `tokio::net::TcpListener::bind`, exactly as it was before dual-stack
/// existed. Only the v6 path needs `socket2` at all — see this crate's
/// `Cargo.toml` for why that dependency is not a new supply-chain item.
fn bind_v6_only(bind_addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    // The one line this whole function exists for — see the doc above.
    socket.set_only_v6(true)?;
    // Rust's `std::net::TcpListener::bind` sets `SO_REUSEADDR` on unix, so
    // the v4 half has always had it and a hand-built socket does not. Without
    // it the two families rebind differently after a restart: TIME_WAIT from
    // this face's own accepted connections blocks the v6 bind for up to a
    // minute while v4 comes straight back. It would recover — `EADDRINUSE`
    // is Transient and the retry loop is doing its job — but the new
    // per-family reporting would show v6 dark after every roll and read as a
    // flaky IPv6 stack, which is a lie about the host. Match the halves.
    socket.set_reuse_address(true)?;
    socket.bind(&bind_addr.into())?;
    socket.listen(V6_LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// Bind one address family of `face.port`, retrying until it succeeds — or,
/// for [`BindFailureKind::Permanent`], giving up.
///
/// **This used to be a one-shot, and the face went DARK for the life of the
/// process if the port was busy for even a moment.** That is not a theoretical
/// window: mshd's recovery door holds `:22` on a box whose perimeter does not
/// serve it (`mirage2mshd::ssh_server::spawn_recovery_door`), releases it the
/// moment this process's face list claims the port — and by then the one bind
/// attempt was long gone. The two would deadlock politely, each waiting for
/// the other, with `:22` free and nobody on it.
///
/// A failed bind is transient far more often than it is permanent, and the
/// permanent case (another daemon owns the port for good) costs one log line a
/// minute and a task that is doing nothing else. The family stays counted as
/// NOT bound throughout, so `PerimeterRequest::Health` and `::Metrics` keep
/// telling the truth while this retries.
///
/// That policy is unchanged from before dual-stack existed and applies as-is
/// to the transient case on EITHER family. What is new is
/// [`BindFailureKind::Permanent`] — a missing IPv6 stack on this host, which
/// is not a handover to wait out and does not clear on its own. Retrying
/// that forever would spend the rest of this process's life re-discovering a
/// fact the first attempt already knew, so this returns `None` instead: the
/// caller ([`bind_and_serve`]) reads that as "this family will never serve on
/// this host" and does not spawn an accept loop for it, while the OTHER
/// family's own task, entirely independent, keeps retrying or serving as
/// normal.
///
/// A THIRD way to stop retrying, alongside success and
/// [`BindFailureKind::Permanent`]: `cancel` firing. A face can be retired
/// (`crate::run::Surface::apply_config`) while one of its families is still
/// mid-handover with whatever held the port before it — without this check
/// that family would keep retrying forever for a port this process no
/// longer wants, on a capsule that has already moved on.
async fn bind_with_retry(
    bind_addr: SocketAddr,
    family: AddressFamily,
    face: &PerimeterFace,
    counters: &Arc<FaceCounters>,
    cancel: &CancellationToken,
) -> Option<tokio::net::TcpListener> {
    let mut attempt: u32 = 0;
    loop {
        if cancel.is_cancelled() {
            tracing::info!(
                port = face.port,
                label = %face.label,
                %family,
                attempt,
                "[perimeter/face] retired before this family ever finished binding — giving up \
                 the retry, nothing to release"
            );
            return None;
        }

        // The v4 path is the exact call this function always made; the v6
        // path goes through `bind_v6_only` instead of a plain
        // `TcpListener::bind` — see that function's doc for why a plain
        // bind is not safe to use for `[::]` on this fleet.
        let bind_result = match family {
            AddressFamily::V4 => tokio::net::TcpListener::bind(bind_addr).await,
            AddressFamily::V6 => bind_v6_only(bind_addr),
        };
        match bind_result {
            Ok(l) => {
                if attempt > 0 {
                    tracing::info!(
                        port = face.port,
                        label = %face.label,
                        %family,
                        attempts = attempt + 1,
                        "[perimeter/face] bind succeeded after retrying — the port was held by \
                         something else and has been released"
                    );
                }
                counters.mark_family_bound(family);
                return Some(l);
            }
            Err(e) => {
                let kind = classify_bind_error(&e);
                // Counted on EVERY attempt, whichever kind — an operator
                // asking "how many times has this family tried" deserves the
                // true count, even for the permanent case, which stops after
                // exactly one.
                counters.note_family_bind_failed(
                    family,
                    &e.to_string(),
                    now_ms(),
                    kind == BindFailureKind::Permanent,
                );
                match kind {
                    BindFailureKind::Permanent => {
                        // Logged once, unconditionally — there will never be
                        // a second attempt to throttle against. See this
                        // function's own doc and `BindFailureKind`'s.
                        tracing::warn!(
                            port = face.port,
                            label = %face.label,
                            %family,
                            error = %e,
                            "[perimeter/face] this address family is not available on this host — \
                             giving up on it for this face; every other family and every other \
                             face keep serving"
                        );
                        return None;
                    }
                    BindFailureKind::Transient => {
                        // The journal line was the only record of this until
                        // 2026-08-28, and a line an operator has to go looking
                        // for is not a fact — attempt 9973 on
                        // `tr-hostkey-203.0.113.14` had been written once a
                        // minute for days while every fleet readout showed
                        // the box green.
                        if attempt % FACE_BIND_LOG_EVERY == 0 {
                            tracing::warn!(
                                port = face.port,
                                label = %face.label,
                                %family,
                                error = %e,
                                attempt = attempt + 1,
                                "[perimeter/face] bind failed — this family is DARK and will keep \
                                 retrying; every other family and every other face keep serving"
                            );
                        }
                        attempt = attempt.saturating_add(1);
                        // Cancellable, not a plain sleep: a face retired
                        // while this family is mid-retry must not wait out
                        // the rest of this interval before the loop-top
                        // check above ever runs again.
                        tokio::select! {
                            () = cancel.cancelled() => {}
                            () = tokio::time::sleep(FACE_BIND_RETRY_INTERVAL) => {}
                        }
                    }
                }
            }
        }
    }
}

/// Everything one face's two accept loops (IPv4 and IPv6) share, so that
/// splitting one listener into two never splits anything ELSE — the same
/// semaphore budget, the same jail budget and disposition, the same
/// counters, the same live camouflage/keypair cells. See this module's doc,
/// "A face is two sockets, not one".
struct FaceRuntime {
    face: SharedFace,
    config: Arc<PerimeterConfig>,
    keypair: SharedKeypair,
    counters: Arc<FaceCounters>,
    rate_limit: Arc<SourceRateLimit>,
    sink: Arc<crate::observe::SecdSink>,
    semaphore: Arc<Semaphore>,
    jail_budget: Arc<crate::jail::FaceJail>,
    disposition: crate::jail::Disposition,
    port: u16,
    /// This face's stop signal — held by `crate::run::Surface` and fired
    /// exactly once, when a capsule retires this port. Every accept loop
    /// ([`accept_loop`]) races it against `listener.accept()`; the retry
    /// loop that precedes a successful bind ([`bind_with_retry`]) checks it
    /// too, so a face retired before it ever finished binding does not spend
    /// the rest of the process's life retrying a port nobody wants anymore.
    /// See `run_face`'s own doc, "Stopping a face".
    cancel: CancellationToken,
}

/// Bind this face on both `0.0.0.0:<port>` and `[::]:<port>`, and accept on
/// each forever — see this module's doc, "A face is two sockets, not one",
/// for why two plain sockets rather than one dual-stack one.
///
/// A bind that fails transiently does not end this task: it retries (see
/// [`bind_with_retry`]) and the face is reported as NOT bound until at least
/// one family succeeds, while every other face this process bound keeps
/// answering and the process as a whole keeps reporting healthy on
/// `PerimeterRequest::Health` (`faces_bound` there is the live count, not the
/// configured one, precisely so this condition is visible there too — see
/// `crate::stats::FaceCounters::bound`'s doc). A bind that fails PERMANENTLY
/// — the missing-IPv6-stack case — ends only that family's half of this
/// task; the other keeps going exactly as if the first had never existed.
///
/// The port `face` names at the moment this task starts is bound EXACTLY
/// ONCE per family and never rebound for this task's whole life — there is
/// no code path in this function that closes either listener and reopens it.
/// What CAN change, via a plain `ArcSwap::store` on `face`/`keypair`, is which
/// [`PerimeterFace`] and which [`KeyPair`] the NEXT accepted connection is
/// handled under: `face.load_full()`/`keypair.load_full()` are read fresh
/// once per accept, at the bottom of the loop, never once at task start.
/// That is the whole mechanism behind `crate::run::Surface::
/// apply_identity_when_ready` swapping a capsule's declared camouflage onto
/// a port the baseline surface already bound — see this module's own doc.
///
/// Concurrency is bounded by acquiring a permit from a `max_inflight`-sized
/// semaphore BEFORE each `accept()` — once every permit is held, this loop
/// simply stops calling `accept()` until one frees, so the kernel's own
/// backlog absorbs the burst instead of this process queueing unboundedly
/// in userspace. The semaphore is shared by BOTH families' accept loops, so
/// a flood arriving over one family spends the same budget a flood over the
/// other would — a face has one hold budget, not one per listener.
///
/// # Stopping a face
///
/// `cancel` is the ONLY way this task ever ends before both address
/// families are permanently absent on the host — fired exactly once, by
/// `crate::run::Surface::apply_config`, when a capsule stops declaring this
/// port. Every accept loop below races it against `listener.accept()`
/// ([`accept_loop`]), and [`bind_with_retry`] checks it too so a face
/// retired before it ever finished binding stops retrying instead of
/// spending the rest of the process's life on a port nobody wants. Either
/// way the listener is a plain local variable owned by [`bind_and_serve`]'s
/// stack frame: the moment its task returns, the listener drops and the OS
/// releases the port — there is no second handle anywhere that could keep
/// it open.
pub async fn run_face(
    face: SharedFace,
    config: Arc<PerimeterConfig>,
    keypair: SharedKeypair,
    counters: Arc<FaceCounters>,
    rate_limit: Arc<SourceRateLimit>,
    sink: Arc<crate::observe::SecdSink>,
    cancel: CancellationToken,
) {
    let boot_face = face.load_full();
    let port = boot_face.port;
    // One hold budget per face, owned by both accept loops and shared with
    // every connection task they spawn — a flood on one face must not be
    // able to spend another face's slots, whichever family it arrived on.
    let semaphore = Arc::new(Semaphore::new(config.max_inflight));
    let jail_budget = Arc::new(crate::jail::FaceJail::new(config.jail.max_held_per_face));
    // The port never changes for this task's life, so the disposition it
    // maps to does not either — unlike `face`/`keypair`, this is captured
    // once. See `crate::config::PerimeterConfig`'s own doc for why jail
    // settings are not part of what a swap changes.
    let disposition = config.jail.disposition_for(port);
    drop(boot_face);

    let runtime = Arc::new(FaceRuntime {
        face,
        config,
        keypair,
        counters,
        rate_limit,
        sink,
        semaphore,
        jail_budget,
        disposition,
        port,
        cancel,
    });

    // Two independent tasks, one per family — never a `select!` over one
    // shared listener, and never a second face-wide accept loop that reads
    // from either socket. A permanently absent family's task ends quickly
    // ([`bind_and_serve`] logs why, once) and simply never accepts anything;
    // the other keeps running until either the host permanently lacks it too
    // or `runtime.cancel` fires — see "Stopping a face" above. This returns
    // once BOTH end, which for a healthy dual-stack face means "not before
    // this face is retired".
    let v4 = tokio::spawn(bind_and_serve(
        Arc::clone(&runtime),
        std::net::Ipv4Addr::UNSPECIFIED.into(),
        AddressFamily::V4,
    ));
    let v6 = tokio::spawn(bind_and_serve(
        Arc::clone(&runtime),
        std::net::Ipv6Addr::UNSPECIFIED.into(),
        AddressFamily::V6,
    ));
    let _ = tokio::join!(v4, v6);
}

/// Bind one address family of `runtime.port` and, if that succeeds, accept
/// on it forever ([`accept_loop`]). If [`bind_with_retry`] gives up on this
/// family permanently — OR because `runtime.cancel` fired before this
/// family ever finished binding — this returns immediately having already
/// logged why, leaving the OTHER family's task, spawned separately by
/// [`run_face`], completely unaffected.
async fn bind_and_serve(runtime: Arc<FaceRuntime>, unspecified: std::net::IpAddr, family: AddressFamily) {
    let boot_face = runtime.face.load_full();
    let bind_addr = SocketAddr::new(unspecified, runtime.port);
    let Some(listener) =
        bind_with_retry(bind_addr, family, &boot_face, &runtime.counters, &runtime.cancel).await
    else {
        return;
    };
    tracing::info!(port = runtime.port, label = %boot_face.label, %family, "[perimeter/face] listening");
    drop(boot_face);
    accept_loop(listener, family, runtime).await;
}

/// Accept forever on one already-bound listener, feeding every connection
/// through the SAME classifier and SAME per-face state
/// ([`FaceRuntime`]) the other family's loop uses — this is the one place
/// that body lives; extracted here specifically so a dual-stack face never
/// ends up with two copies of it. `family` travels only as far as the debug
/// log line below; `handle_connection` and everything past it neither knows
/// nor cares which socket a connection arrived on.
async fn accept_loop(listener: tokio::net::TcpListener, family: AddressFamily, runtime: Arc<FaceRuntime>) {
    let port = runtime.port;
    loop {
        // ACCEPT FIRST, then decide.
        //
        // This loop used to take the in-flight permit BEFORE `accept()`, so
        // a face whose budget was fully held simply stopped accepting: new
        // connections completed in the kernel, sat in the backlog and were
        // never handed to userspace. From outside that is indistinguishable
        // from a dead box — connect succeeds and nothing ever answers.
        //
        // Measured in exactly that shape on `mirage2mshd`'s recovery door,
        // 2026-08-18, which carried the identical ordering: four of our own
        // fleet boxes dialling a few times a second each held every slot,
        // and a live box read as dead for fourteen minutes. The door was
        // fixed the same way; this is the same defect in the process that
        // owns EVERY public port on the box, so it cannot keep it.
        //
        // Refusing on a connection we are already holding costs one accept
        // and one close. Refusing by not accepting costs the whole face.
        //
        // Raced against `runtime.cancel`, `biased` towards it: a capsule
        // that retired this port wants this loop to stop, even on a turn
        // where a connection also happened to be ready to accept. `listener`
        // is this function's own local variable — the instant this task
        // returns below, it drops and the OS releases the port. Nothing
        // else anywhere holds a second handle to it.
        let (stream, peer) = tokio::select! {
            biased;
            () = runtime.cancel.cancelled() => {
                tracing::info!(
                    port,
                    %family,
                    "[perimeter/face] retiring — no longer accepting, releasing the port"
                );
                return;
            }
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!(port, %family, error = %e, "[perimeter/face] accept failed — retrying");
                    continue;
                }
            },
        };

        let permit = match Arc::clone(&runtime.semaphore).try_acquire_owned() {
            Ok(p) => p,
            // At budget. Silence, like every other refusal on this face —
            // and counted, because a face that is shedding load is a fact
            // an operator needs and a log line per drop is its own flood.
            Err(_) => {
                runtime.counters.inflight_refused.fetch_add(1, Ordering::Relaxed);
                drop(stream);
                continue;
            }
        };

        // Per-source budget, spent BEFORE the camouflage strip — which on the
        // `tls_real` face is a full TLS handshake, i.e. the expensive part a
        // flood is trying to buy. Refusal is silence, like every other
        // non-wire outcome here today.
        if !runtime.rate_limit.allow(peer.ip()) {
            runtime.counters.rate_limited.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                port,
                %family,
                %peer,
                "[perimeter/face] source over its accept budget — dropping"
            );
            drop(stream);
            continue;
        }

        // Loaded fresh for every connection, never once at task start — see
        // `run_face`'s own doc. A connection accepted the instant after
        // a swap is judged under the face/identity it actually landed on;
        // one accepted the instant before keeps whatever was current then,
        // since `handle_connection` below never re-reads either cell.
        let face_now = runtime.face.load_full();
        let keypair_now = runtime.keypair.load_full();
        let config = Arc::clone(&runtime.config);
        let counters = Arc::clone(&runtime.counters);
        let jail_budget = Arc::clone(&runtime.jail_budget);
        let sink = Arc::clone(&runtime.sink);
        let disposition = runtime.disposition;
        tokio::spawn(async move {
            let _permit = permit; // held for the connection's lifetime.
            handle_connection(
                stream,
                peer,
                &face_now,
                &config,
                &keypair_now,
                &counters,
                &jail_budget,
                disposition,
                &sink,
            )
            .await;
        });
    }
}

/// Run every time-bounded step of one connection's life, from raw accept to
/// either "routed to the monitor" or "rejected".
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    face: &PerimeterFace,
    config: &PerimeterConfig,
    keypair: &KeyPair,
    counters: &FaceCounters,
    jail_budget: &crate::jail::FaceJail,
    disposition: crate::jail::Disposition,
    sink: &crate::observe::SecdSink,
) {
    counters.accepted.fetch_add(1, Ordering::Relaxed);

    // Keep a second handle on the socket BEFORE the strip consumes the first.
    // Without it a camouflage failure closes the connection inside
    // `strip_tcp_server` and seam A cannot be jailed at all — see
    // `crate::jail::duplicate`.
    let (stream, spare) = crate::jail::duplicate(stream);

    let camo_result = tokio::time::timeout(
        Duration::from_millis(config.camo_timeout_ms),
        strip_tcp_server(stream, &face.camouflage, keypair),
    )
    .await;

    let mut stripped = match camo_result {
        Ok(Ok(Some(stripped))) => stripped,
        Ok(Ok(None)) => {
            // The camouflage layer itself rejected the connection (wrong
            // SNI, unexpected upgrade path, ...). SEAM A.
            counters.camo_failed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(port = face.port, %peer, "[perimeter/face] camouflage layer rejected the connection");
            jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_A).await;
            return;
        }
        Ok(Err(e)) => {
            counters.camo_failed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(port = face.port, %peer, error = %e, "[perimeter/face] camouflage strip failed");
            jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_A).await;
            return;
        }
        Err(_elapsed) => {
            counters.camo_failed.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(port = face.port, %peer, "[perimeter/face] camouflage strip timed out");
            jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_A).await;
            return;
        }
    };

    // The read is staged, and it has to be: a Mirage client sends the whole
    // 97-byte hello up front, an SSH client sends a short identification
    // string and then waits for the server's. Reading 97 bytes first would
    // hold every SSH connection until the peek timeout and then reject it,
    // while the peer waited for a banner nobody was going to send. So: read
    // only enough to tell the two apart, then read the rest if it is not SSH.
    let mut hello = [0u8; V9_CLIENT_HELLO_LEN];
    let (opening, rest) = hello.split_at_mut(SSH_DECISION_LEN);
    if !read_bounded(&mut stripped, opening, config, face, counters, peer).await {
        // SEAM B: the camouflage came off and then nothing arrived inside the
        // window. That is a scanner's shape — connect, say nothing, move on.
        drop(stripped);
        jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_B).await;
        return;
    }

    if looks_like_ssh(opening) {
        // Carried. The spare has no further use and must go now: two live
        // handles on a spliced socket would keep it open past the splice.
        drop(spare);
        route_ssh(stripped, opening, face, config, counters, peer, sink).await;
        return;
    }

    if !read_bounded(&mut stripped, rest, config, face, counters, peer).await {
        drop(stripped);
        jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_B).await;
        return;
    }

    match classify_v9_hello(&hello, now_ms(), config.max_skew_ms) {
        Verdict::Wire(target_hint) => {
            drop(spare);
            route_to_inner(stripped, &hello, face, config, counters, peer, sink, target_hint).await;
        }
        Verdict::Ssh => {
            // Unreachable: `classify_v9_hello` never returns this — the SSH
            // decision is made above, on the opening bytes, because that is
            // the only point at which it CAN be made without deadlocking.
            // Kept so adding the variant does not silently fall into a
            // catch-all somewhere.
            counters.peek_timeout.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(port = face.port, %peer, "[perimeter/face] classifier returned Ssh after the opening bytes — jailing");
            drop(stripped);
            jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_B).await;
        }
        Verdict::NotWire(reason) => {
            counters.rejected_not_wire.record(reason);
            tracing::debug!(port = face.port, %peer, ?reason, "[perimeter/face] not wire — jailing");

            // ── SEAM B ──────────────────────────────────────────────────
            // Every reason gets the same treatment, and that is deliberate:
            // the JAIL does not vary by why the payload was wrong, because
            // the answer it gives is the same one in every case — nothing.
            // What varies per reason is the OBSERVATION reported to the
            // arbiter (`crate::sink`), and what varies per FACE is jail vs
            // hard cut. Neither of those is a fork in this match.
            match reason {
                NotWireReason::TooShort(_)
                | NotWireReason::BadVersion(_)
                | NotWireReason::BadSuite(_)
                | NotWireReason::ReservedNotZero
                | NotWireReason::TimestampSkew { .. } => {
                    drop(stripped);
                    jail_seam(spare, disposition, jail_budget, config, counters, sink, peer.ip(), face.port, SEAM_B).await;
                }
            }
        }
    }
}

/// Hand a rejected connection to this face's disposition, and count what
/// happened.
///
/// Takes the spare by value — whatever it decides, this is where the socket's
/// life ends. `None` means the duplication failed at accept time and the
/// connection has already closed with the strip's copy: the pre-jail
/// behaviour, degraded but never broken.
#[allow(clippy::too_many_arguments)]
async fn jail_seam(
    spare: Option<TcpStream>,
    disposition: crate::jail::Disposition,
    jail_budget: &crate::jail::FaceJail,
    config: &PerimeterConfig,
    counters: &FaceCounters,
    sink: &crate::observe::SecdSink,
    peer_ip: std::net::IpAddr,
    port: u16,
    seam: mirage_core::fact_signing::AttackerSignalType,
) {
    // Report BEFORE disposing, and unconditionally — including the
    // `jail_no_handle` path below. What the arbiter needs to know is that
    // this address failed at this seam; whether we then held the socket for
    // 30 seconds or never had a handle on it is our problem, not evidence
    // about the peer.
    sink.observe(peer_ip, port, seam);
    // ...and to this box's own journal, rate-limited to one line per face
    // per minute. The arbiter is a mesh-plane consumer; a box under attack
    // has to be able to say so locally. See
    // `FaceCounters::note_rejection_and_maybe_report`.
    counters.note_rejection_and_maybe_report(port);

    let Some(socket) = spare else {
        counters.jail_no_handle.fetch_add(1, Ordering::Relaxed);
        return;
    };
    match crate::jail::dispose(
        socket,
        disposition,
        jail_budget,
        &counters.jail_holding_now,
        config.jail.hold_ms,
    )
    .await
    {
        crate::jail::JailOutcome::Held => counters.jailed.fetch_add(1, Ordering::Relaxed),
        crate::jail::JailOutcome::Cut => counters.hard_cut.fetch_add(1, Ordering::Relaxed),
        crate::jail::JailOutcome::AtCapacity => {
            counters.jail_at_capacity.fetch_add(1, Ordering::Relaxed)
        }
    };
}

/// Fill `buf` from the stripped stream under the face's peek timeout.
/// Returns `false` when the connection died or ran out of time — the caller
/// has nothing left to do in that case, and the counter is already bumped.
async fn read_bounded(
    stripped: &mut Box<dyn BidiStream>,
    buf: &mut [u8],
    config: &PerimeterConfig,
    face: &PerimeterFace,
    counters: &FaceCounters,
    peer: SocketAddr,
) -> bool {
    match tokio::time::timeout(
        Duration::from_millis(config.peek_timeout_ms),
        stripped.read_exact(buf),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            counters.peek_timeout.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                port = face.port, %peer, error = %e,
                "[perimeter/face] connection closed before the opening bytes arrived"
            );
            false
        }
        Err(_elapsed) => {
            counters.peek_timeout.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(port = face.port, %peer, "[perimeter/face] timed out waiting for the opening bytes");
            false
        }
    }
}

/// Interval between inner-dial retry attempts while a connection is still
/// within [`PerimeterConfig::inner_dial_timeout_ms`] — see
/// [`dial_inner_retrying`]'s own doc for why this retries at all.
///
/// Short enough that the boot-time gap that doc measures (the co-located
/// monitor's or mshd's unix socket not existing yet for the first stretch of
/// its own startup) costs a handful of attempts rather than a meaningful
/// slice of the budget; long enough that a genuinely absent inner service —
/// a real misconfiguration, not a boot race — is not redialled dozens of
/// times a second for the whole budget just to fail the same way each time.
const INNER_DIAL_RETRY_INTERVAL: Duration = Duration::from_millis(200);

/// Dial `channel`, retrying on failure until `deadline` instead of giving up
/// after the very first attempt.
///
/// # Why a retry belongs here at all
///
/// Measured on `nl-hostkey-203.0.113.11`, 2026-08-30, during the fleet's
/// reboot verification — the perimeter's own journal for that boot:
///
/// ```text
/// 18:12:27  WARN [perimeter/face] could not reach the co-located monitor —
///           dropping a connection that had already classified port=22
///           peer=31.57.44.221:50695 endpoint=unix:/run/mirage/monitor/wire.sock
///           error=No such file or directory (os error 2)
/// 18:12:30  INFO [perimeter] this box's identity came back from the keeper ...
/// ```
///
/// A face binds and starts accepting the instant this process starts —
/// deliberately: see [`bind_with_retry`]'s own doc for the DARK-face history
/// that makes "accept immediately, do not wait for anything downstream to be
/// ready" non-negotiable for the LISTENER. But the co-located monitor (and
/// mshd) are separate units with their own boot sequences, and neither's unix
/// socket exists for the first stretch of it. A connection that classifies
/// as wire (or SSH) inside that window used to get exactly ONE dial attempt,
/// which does not time out — `connect()` on a unix-socket path that does not
/// exist yet fails immediately with `ENOENT`, it does not wait — so the
/// `inner_dial_timeout_ms` budget that already exists for this dial went
/// almost entirely unused and the peer was dropped a few hundred
/// microseconds after the socket it needed would have appeared.
///
/// Three ways to close this were weighed, not just this one:
///
/// - **Refuse to accept until the inner target is reachable** was rejected.
///   It would mean either delaying the face's own bind (the exact DARK-face
///   regression [`bind_with_retry`] exists to prevent) or binding and then
///   not calling `accept()` for a while — which [`accept_loop`]'s own doc
///   already identifies as a worse failure than a drop: "refusing by not
///   accepting costs the whole face", measured as a live box reading dead
///   for fourteen minutes on `mirage2mshd`'s recovery door. Making an entire
///   face look closed for a few seconds at every cold boot, fleet-wide, to
///   save a handful of connections that land in a boot race, is a bigger
///   surface change than the problem it solves.
/// - **Hold the connection in [`crate::jail`] and retry behind it** was
///   rejected too, and for a sharper reason: `jail::dispose` is built to
///   answer a probe with silence — its `hold` loop READS AND DISCARDS
///   whatever the peer sends and never writes a byte back, which is exactly
///   right for a connection already judged not-wire-and-not-ours, and exactly
///   wrong for a connection that already classified as wire and is meant to
///   be spliced through, byte for byte, once the inner side answers. Reusing
///   it here would silently corrupt the one case it should never touch. The
///   jail's per-face hold budget is sized for hostile traffic under
///   `crate::jail::DEFAULT_MAX_HELD_PER_FACE`, not for "how many legitimate
///   connections land in a few-second boot race", so it is the wrong
///   instrument on both axes: what it does to the bytes, and what it is
///   budgeted for.
/// - **Retry the dial itself, bounded by the timeout the connection already
///   pays** is what this function does. It spends the SAME budget
///   `inner_dial_timeout_ms` already reserved for this connection — that
///   config's whole meaning was already "how long is this caller willing to
///   wait for the inner side before giving up", and a fast `ENOENT` failure
///   is exactly as much "the inner side is not ready yet" as a slow hang is.
///   Nothing about the classification, the face's bind, or any OTHER
///   connection's handling changes: this is local to one already-accepted,
///   already-classified connection's own dial.
async fn dial_inner_retrying(
    channel: mirage_core::local_endpoint::LocalChannel,
    deadline: tokio::time::Instant,
) -> io::Result<mirage_core::local_endpoint::LocalStream> {
    loop {
        match channel.connect().await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(INNER_DIAL_RETRY_INTERVAL.min(deadline - now)).await;
            }
        }
    }
}

/// Hand an SSH-shaped connection to the co-located mshd, which terminates
/// SSH itself.
///
/// This is the front door's second inward destination, and the thing that
/// makes it a router. The destination is
/// [`mirage_core::local_endpoint::LocalChannel::MshdSshSplice`] —
/// unconditional, with no configured alternative and no way to be absent.
/// It used to be `config.ssh_addr`, an `Option<SocketAddr>` the capsule
/// filled in, which meant a capsule that omitted the field closed the
/// operator's way in on an otherwise healthy box. See `config`'s note beside
/// the deleted `DEFAULT_SSH_ADDR`.
///
/// The dial retries within `config.inner_dial_timeout_ms` instead of failing
/// on the first attempt — see [`dial_inner_retrying`]'s doc for the boot-time
/// race this closes and the two alternatives that were rejected for it.
async fn route_ssh(
    stripped: Box<dyn BidiStream>,
    opening: &[u8],
    face: &PerimeterFace,
    config: &PerimeterConfig,
    counters: &FaceCounters,
    peer: SocketAddr,
    sink: &crate::observe::SecdSink,
) {
    let channel = mirage_core::local_endpoint::LocalChannel::MshdSshSplice;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(config.inner_dial_timeout_ms);
    let dial = tokio::time::timeout_at(deadline, dial_inner_retrying(channel, deadline)).await;

    let inner: Box<dyn BidiStream> = match dial {
        Ok(Ok(stream)) => Box::new(stream),
        Ok(Err(e)) => {
            counters.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                port = face.port, %peer, endpoint = %channel.endpoint(), error = %e,
                "[perimeter/face] could not reach the co-located mshd after retrying within the \
                 dial budget — dropping a connection that had already classified as SSH"
            );
            return;
        }
        Err(_elapsed) => {
            counters.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                port = face.port, %peer, endpoint = %channel.endpoint(),
                "[perimeter/face] dialling the co-located mshd timed out"
            );
            return;
        }
    };

    splice_inward(
        stripped, opening, inner, InnerKind::Ssh, face, counters, peer, Some(sink),
    )
    .await;
}

/// Which inward destination a spliced connection went to. Affects the
/// counters and the log wording; the splice mechanics (dial, write the
/// preamble, `copy_bidirectional`) are identical for all of them — each
/// announces the real client to its destination with the same typed
/// [`mirage_core::perimeter_preamble::PerimeterPreamble`]. The `Verdict` the
/// preamble carries is the only thing that differs between them.
///
/// Deliberately no catch-all arm on any match over this enum anywhere in
/// this module: a fourth destination must be a compile error at every site
/// that routes by kind, not a silent fall-through into whichever arm
/// happened to be last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnerKind {
    Monitor,
    Ssh,
    /// A face declared [`FacePurpose::NodeChain`] — chain data-plane
    /// traffic, spliced to the co-located node over
    /// [`mirage_core::local_endpoint::LocalChannel::NodeChainSplice`]
    /// instead of the monitor. See [`inward_target`].
    NodeChain,
    /// A face declared [`FacePurpose::EdgeEntrance`] — an Edge box's own
    /// client-entrance traffic, spliced to the co-located `mirage-edge`
    /// unit over
    /// [`mirage_core::local_endpoint::LocalChannel::EdgeChainSplice`]
    /// instead of the monitor or the node. Classified and jailed exactly
    /// like [`InnerKind::NodeChain`] — see [`inward_target`] and
    /// [`splice_inward`] — only the inner target differs: an Edge box runs
    /// no `mirage-node` at all
    /// (`docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Perimeter face
    /// target and capsule change").
    Edge,
}

impl InnerKind {
    /// Prose name for the "could not reach ..." / "dialling ... timed out"
    /// class of log lines in [`route_to_inner`] — a register [`InnerKind`]'s
    /// short `dest` strings in [`splice_inward`] are deliberately NOT: those
    /// are terse structured-log field values, this reads naturally inside a
    /// sentence. Kept as its own exhaustive match so a fourth destination
    /// cannot silently inherit an old sentence.
    fn dial_failure_label(self) -> &'static str {
        match self {
            InnerKind::Monitor => "the co-located monitor",
            InnerKind::Ssh => "the co-located mshd",
            InnerKind::NodeChain => "the co-located node",
            InnerKind::Edge => "the co-located edge unit",
        }
    }
}

/// Which local channel and [`InnerKind`] a wire verdict routes to — the one
/// decision [`route_to_inner`] used to make by hardcoding both. Pure and
/// unit-testable without a live socket, unlike `route_to_inner` itself,
/// which cannot be exercised without a real dial — see this module's test
/// module.
///
/// # Precedence — the hint wins when it names a destination
///
/// `hint` is the hello's `target_hint` byte, carried on
/// [`Verdict::Wire`](crate::classify::Verdict::Wire) — see
/// [`mirage_protocol::auth::v9::TargetHint`]'s own doc for the wire byte
/// and why `Legacy` is the only value any sender in this codebase emits
/// today. `TargetHint::Legacy` falls all the way through to `purpose` —
/// the face's own declared [`FacePurpose`] — which is EXACTLY this
/// function's old, single-argument behaviour: nothing about routing a
/// hello with no hint changes by this byte having been added to the wire.
/// `TargetHint::Monitor`/`TargetHint::Node` override `purpose` outright,
/// per connection, regardless of what this face is declared to carry.
///
/// Deliberately no catch-all arm on either level of this match: a fourth
/// [`TargetHint`](mirage_protocol::auth::v9::TargetHint) variant or a third
/// [`FacePurpose`] must be a compile error here, the same discipline
/// [`InnerKind`]'s own doc states for the destinations themselves.
fn inward_target(
    purpose: FacePurpose,
    hint: TargetHint,
) -> (mirage_core::local_endpoint::LocalChannel, InnerKind) {
    match hint {
        TargetHint::Monitor => (
            mirage_core::local_endpoint::LocalChannel::MonitorWireSplice,
            InnerKind::Monitor,
        ),
        TargetHint::Node => (
            mirage_core::local_endpoint::LocalChannel::NodeChainSplice,
            InnerKind::NodeChain,
        ),
        TargetHint::Legacy => match purpose {
            FacePurpose::MonitorWire => (
                mirage_core::local_endpoint::LocalChannel::MonitorWireSplice,
                InnerKind::Monitor,
            ),
            FacePurpose::NodeChain => (
                mirage_core::local_endpoint::LocalChannel::NodeChainSplice,
                InnerKind::NodeChain,
            ),
            FacePurpose::EdgeEntrance => (
                mirage_core::local_endpoint::LocalChannel::EdgeChainSplice,
                InnerKind::Edge,
            ),
        },
    }
}

/// Splice a connection already classified as wire through to its inward
/// destination — the co-located monitor over
/// [`mirage_core::local_endpoint::LocalChannel::MonitorWireSplice`] or the
/// co-located node over
/// [`mirage_core::local_endpoint::LocalChannel::NodeChainSplice`], decided by
/// [`inward_target`] from the face's declared [`FacePurpose`] and the
/// hello's own `target_hint` together: dial the socket, announce the real
/// peer with a `PerimeterPreamble`, forward the buffered hello bytes (the
/// destination never sees the camouflage that was already stripped, but it
/// must see every hello byte this listener already consumed), then relay
/// bidirectionally until either side closes.
///
/// The destination is a unix socket on a linux box and loopback TCP on
/// Windows — `LocalChannel` makes that choice at compile time, exactly as
/// `route_ssh` reaches mshd. It was `config.inner_addr`, a loopback TCP
/// address the client's bytes were prefixed with a SIGNED PROXY v2 header on;
/// over a socket whose mode admits only root and the perimeter's own uid,
/// checked by `SO_PEERCRED` at accept, the writer is already authenticated
/// and the preamble needs no signature — see `mirage_core::perimeter_preamble`.
///
/// The dial retries within `config.inner_dial_timeout_ms` instead of failing
/// on the first attempt — see [`dial_inner_retrying`]'s doc for the boot-time
/// race this closes (this is the exact call site the measurement in that doc
/// was taken from) and the two alternatives that were rejected for it.
async fn route_to_inner(
    stripped: Box<dyn BidiStream>,
    hello: &[u8; V9_CLIENT_HELLO_LEN],
    face: &PerimeterFace,
    config: &PerimeterConfig,
    counters: &FaceCounters,
    peer: SocketAddr,
    sink: &crate::observe::SecdSink,
    target_hint: TargetHint,
) {
    let (channel, kind) = inward_target(face.purpose, target_hint);
    let dest_name = kind.dial_failure_label();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(config.inner_dial_timeout_ms);
    let dial = tokio::time::timeout_at(deadline, dial_inner_retrying(channel, deadline)).await;

    let inner: Box<dyn BidiStream> = match dial {
        Ok(Ok(stream)) => Box::new(stream),
        Ok(Err(e)) => {
            counters.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                port = face.port, %peer, endpoint = %channel.endpoint(), error = %e,
                "[perimeter/face] could not reach {dest_name} after retrying within \
                 the dial budget — dropping a connection that had already classified"
            );
            return;
        }
        Err(_elapsed) => {
            counters.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                port = face.port, %peer, endpoint = %channel.endpoint(),
                "[perimeter/face] dialling {dest_name} timed out — dropping a \
                 connection that had already classified"
            );
            return;
        }
    };

    splice_inward(stripped, hello, inner, kind, face, counters, peer, Some(sink)).await;
}

/// Replay the bytes this face already consumed into an already-dialled
/// inward stream, then relay until either side closes.
///
/// The replay is not optional: the destination never sees the camouflage
/// that was stripped here, but it must see every protocol byte this listener
/// read off the connection to make its routing decision — the monitor needs
/// the whole ClientHello, mshd needs the start of the identification string.
///
/// The dial belongs to the CALLER: the two destinations are the same KIND of
/// thing now — both [`mirage_core::local_endpoint::LocalChannel`], a unix
/// socket on a box and loopback TCP on the dev-only Windows arm — but they
/// are different channels, so each caller opens its own. Both arrive here as
/// `Box<dyn BidiStream>` and are spliced identically.
async fn splice_inward(
    mut stripped: Box<dyn BidiStream>,
    prefix: &[u8],
    mut inner: Box<dyn BidiStream>,
    kind: InnerKind,
    face: &PerimeterFace,
    counters: &FaceCounters,
    peer: SocketAddr,
    sink: Option<&crate::observe::SecdSink>,
) {
    let dest = match kind {
        InnerKind::Monitor => "monitor",
        InnerKind::Ssh => "mshd",
        InnerKind::NodeChain => "node",
        InnerKind::Edge => "edge",
    };
    let inward_dest = match kind {
        InnerKind::Ssh => mirage_core::local_security_event::InwardDest::Mshd,
        InnerKind::Monitor => mirage_core::local_security_event::InwardDest::Monitor,
        // An Edge face is a node-chain face with a different inner target —
        // see `InnerKind::Edge`'s own doc — so it is classified as the same
        // `InwardDest::NodeChain` security event `NodeChain` already is,
        // rather than a new mirage-core variant nothing downstream reads
        // differently yet.
        InnerKind::NodeChain | InnerKind::Edge => mirage_core::local_security_event::InwardDest::NodeChain,
    };
    let observed_at_ms = now_ms();

    // The WAF's own record of an ADMITTED touch: who, on which face, to
    // which destination. It says nothing about whether the peer is the
    // operator — routing was decided on the opening bytes, which anything
    // can produce.
    //
    // It used to carry the loopback dial's ephemeral port, and secd JOINED it
    // to the destination's authentication report on that port inside a
    // 60-second window. That join is gone: the address now travels WITH the
    // connection, in the preamble below, so the destination reports an
    // address it was told rather than one a third daemon reconstructed.
    if let Some(sink) = sink {
        sink.routed_inward(peer.ip(), face.port, inward_dest.clone());
    }

    // Both destinations get the SAME typed `PerimeterPreamble` ahead of the
    // relay — the real peer, this face's port and camouflage, the verdict,
    // and the bytes it was made on. It carries no signature, and that is not
    // an omission: it arrives on a unix socket (loopback TCP only on the
    // dev-only Windows arm) whose mode admits root and the perimeter's own
    // uid, checked by `SO_PEERCRED` at accept. The socket IS the
    // authentication, and a peer able to forge this is already able to read
    // the box's keys. This replaced the monitor's SIGNED PROXY v2 header,
    // whose signature only existed because loopback TCP could not say who
    // wrote it — see `mirage_core::perimeter_preamble`, "Why this needs no
    // signature".
    let to_send: std::borrow::Cow<'_, [u8]> = {
        let preamble = mirage_core::perimeter_preamble::PerimeterPreamble {
            peer: peer.to_string(),
            face_port: face.port,
            face_camouflage: face.camouflage.label().to_string(),
            verdict: inward_dest,
            first_bytes: prefix.to_vec(),
            observed_at_ms,
        };
        match preamble.encode() {
            Ok(mut framed) => {
                framed.extend_from_slice(prefix);
                std::borrow::Cow::Owned(framed)
            }
            Err(e) => {
                // Encoding cannot fail on the fields above (all owned, all
                // bounded, the opening truncated by `encode`), so this is
                // unreachable in practice. It refuses rather than splicing
                // WITHOUT the preamble: the destination reads one first, and a
                // connection that skipped it would look like a peer speaking
                // an unknown protocol.
                counters.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    port = face.port, %peer, dest, error = %e,
                    "[perimeter/face] cannot encode the inward preamble — dropping"
                );
                return;
            }
        }
    };

    if let Err(e) = inner.write_all(&to_send).await {
        counters.inner_dial_failed.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            port = face.port, %peer, dest, error = %e,
            "[perimeter/face] failed to replay the buffered opening bytes inward"
        );
        return;
    }

    match kind {
        // All three are a `Verdict::Wire` connection routed inward —
        // `NodeChain` and `Edge` differ only in WHICH inward channel they
        // went to, not in what kind of verdict produced them, so they share
        // `wire_routed` rather than getting a counter of their own.
        InnerKind::Monitor | InnerKind::NodeChain | InnerKind::Edge => {
            counters.wire_routed.fetch_add(1, Ordering::Relaxed)
        }
        InnerKind::Ssh => counters.ssh_routed.fetch_add(1, Ordering::Relaxed),
    };
    tracing::debug!(port = face.port, %peer, dest, "[perimeter/face] routed inward");

    match relay_with_backstop(&mut stripped, &mut inner, face, counters).await {
        Ok((to_inner, to_client)) => {
            counters.bytes_to_inner.fetch_add(to_inner, Ordering::Relaxed);
            counters.bytes_to_client.fetch_add(to_client, Ordering::Relaxed);
            tracing::debug!(port = face.port, %peer, dest, to_inner, to_client, "[perimeter/face] connection closed");
        }
        Err(e) => {
            tracing::debug!(port = face.port, %peer, dest, error = %e, "[perimeter/face] relay ended with an error");
        }
    }
}

/// The existing `copy_bidirectional` relay, wrapped in the session-profile
/// backstop — see `crate::timing::splice_backstop` and this crate's
/// `docs/mirage/plans/face-behaviour-and-camouflage-2026-09-17.md` for why.
///
/// **OBSERVE-ONLY**: `copy_fut` is pinned once and polled to completion
/// across every loop iteration below, so the backstop deadline firing NEVER
/// drops or cancels it — the relay finishes exactly as if this wrap did not
/// exist. The deadline arm is disabled by its own `if !backstop_fired` guard
/// after it fires once, so a connection held well past its ceiling reports
/// (via [`FaceCounters::note_splice_backstop_observed`], itself rate-limited
/// per face) exactly once, not on every subsequent poll.
async fn relay_with_backstop(
    stripped: &mut Box<dyn BidiStream>,
    inner: &mut Box<dyn BidiStream>,
    face: &PerimeterFace,
    counters: &FaceCounters,
) -> io::Result<(u64, u64)> {
    let profile = face.camouflage.session_profile();
    let ceiling = crate::timing::splice_backstop(profile);
    let deadline = tokio::time::Instant::now() + ceiling;
    let ceiling_ms = u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX);

    let copy_fut = tokio::io::copy_bidirectional(&mut **stripped, &mut **inner);
    tokio::pin!(copy_fut);

    let mut backstop_fired = false;
    loop {
        tokio::select! {
            biased;
            result = &mut copy_fut => return result,
            () = tokio::time::sleep_until(deadline), if !backstop_fired => {
                backstop_fired = true;
                counters.note_splice_backstop_observed(face.port, profile.label(), ceiling_ms);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Which channel a face's purpose (and the hello's hint) routes to
    //    (`inward_target`) ──
    //
    // `route_to_inner` itself dials a real `LocalChannel`, so it is not
    // unit-testable without standing up a socket. This is the pure decision
    // it delegates to instead — extracted specifically so the mapping from
    // `(FacePurpose, TargetHint)` to `(LocalChannel, InnerKind)` is provable
    // here, not just read off the source.

    #[test]
    fn legacy_hint_falls_back_to_a_monitor_wire_purpose() {
        let (channel, kind) = inward_target(FacePurpose::MonitorWire, TargetHint::Legacy);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::MonitorWireSplice);
        assert!(matches!(kind, InnerKind::Monitor));
    }

    #[test]
    fn legacy_hint_falls_back_to_a_node_chain_purpose() {
        let (channel, kind) = inward_target(FacePurpose::NodeChain, TargetHint::Legacy);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::NodeChainSplice);
        assert!(matches!(kind, InnerKind::NodeChain));
    }

    #[test]
    fn legacy_hint_falls_back_to_an_edge_entrance_purpose() {
        let (channel, kind) = inward_target(FacePurpose::EdgeEntrance, TargetHint::Legacy);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::EdgeChainSplice);
        assert!(matches!(kind, InnerKind::Edge));
    }

    /// The property the whole staged roll depends on, named directly: a
    /// `Legacy` hint (every hello sent by this codebase today, and every
    /// hello from a peer that predates this byte) must route IDENTICALLY to
    /// how `inward_target` behaved before `TargetHint` existed — on the
    /// face's declared purpose alone, nothing else. Pinned against every
    /// purpose so no direction of the old mapping is disturbed.
    #[test]
    fn legacy_hint_is_a_pure_fallback_to_the_face_purpose_on_every_arm() {
        for purpose in [FacePurpose::MonitorWire, FacePurpose::NodeChain, FacePurpose::EdgeEntrance] {
            let (channel, kind) = inward_target(purpose, TargetHint::Legacy);
            let (expected_channel, expected_kind) = match purpose {
                FacePurpose::MonitorWire => {
                    (mirage_core::local_endpoint::LocalChannel::MonitorWireSplice, InnerKind::Monitor)
                }
                FacePurpose::NodeChain => {
                    (mirage_core::local_endpoint::LocalChannel::NodeChainSplice, InnerKind::NodeChain)
                }
                FacePurpose::EdgeEntrance => {
                    (mirage_core::local_endpoint::LocalChannel::EdgeChainSplice, InnerKind::Edge)
                }
            };
            assert_eq!(channel, expected_channel, "purpose={purpose:?}");
            assert_eq!(kind, expected_kind, "purpose={purpose:?}");
        }
    }

    /// The other half of Stage 2's contract: a hint that names a destination
    /// wins over the face's own declared purpose — tested on the
    /// DISAGREEING arm for both hints, since an override that only happens
    /// to match the face's purpose would prove nothing about precedence.
    #[test]
    fn a_monitor_hint_overrides_a_node_chain_face_purpose() {
        let (channel, kind) = inward_target(FacePurpose::NodeChain, TargetHint::Monitor);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::MonitorWireSplice);
        assert!(matches!(kind, InnerKind::Monitor));
    }

    #[test]
    fn a_node_hint_overrides_a_monitor_wire_face_purpose() {
        let (channel, kind) = inward_target(FacePurpose::MonitorWire, TargetHint::Node);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::NodeChainSplice);
        assert!(matches!(kind, InnerKind::NodeChain));
    }

    #[test]
    fn a_monitor_hint_overrides_an_edge_entrance_face_purpose() {
        let (channel, kind) = inward_target(FacePurpose::EdgeEntrance, TargetHint::Monitor);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::MonitorWireSplice);
        assert!(matches!(kind, InnerKind::Monitor));
    }

    #[test]
    fn a_node_hint_overrides_an_edge_entrance_face_purpose() {
        let (channel, kind) = inward_target(FacePurpose::EdgeEntrance, TargetHint::Node);
        assert_eq!(channel, mirage_core::local_endpoint::LocalChannel::NodeChainSplice);
        assert!(matches!(kind, InnerKind::NodeChain));
    }

    /// Every `(FacePurpose, TargetHint)` combination that can reach
    /// `inward_target` — 3 purposes × 3 hints — resolves to a channel this
    /// test names explicitly, so a future variant added to either enum
    /// without a matching arm here is a compile error in THIS test, not a
    /// silently-passing gap in coverage.
    #[test]
    fn every_purpose_and_hint_combination_resolves_to_a_named_channel() {
        use mirage_core::local_endpoint::LocalChannel;

        for purpose in [FacePurpose::MonitorWire, FacePurpose::NodeChain, FacePurpose::EdgeEntrance] {
            for hint in [TargetHint::Legacy, TargetHint::Monitor, TargetHint::Node] {
                let (channel, kind) = inward_target(purpose, hint);
                let expected_channel = match hint {
                    TargetHint::Monitor => LocalChannel::MonitorWireSplice,
                    TargetHint::Node => LocalChannel::NodeChainSplice,
                    TargetHint::Legacy => match purpose {
                        FacePurpose::MonitorWire => LocalChannel::MonitorWireSplice,
                        FacePurpose::NodeChain => LocalChannel::NodeChainSplice,
                        FacePurpose::EdgeEntrance => LocalChannel::EdgeChainSplice,
                    },
                };
                assert_eq!(channel, expected_channel, "purpose={purpose:?} hint={hint:?}");
                assert_eq!(
                    matches!(kind, InnerKind::Monitor),
                    channel == LocalChannel::MonitorWireSplice,
                    "InnerKind and LocalChannel must agree on the destination"
                );
            }
        }
    }

    // ── Permanent vs transient bind failures (`classify_bind_error`) ──
    //
    // Exactly the split this module's doc and `BindFailureKind` describe:
    // `EADDRINUSE` (another daemon mid-handover) must keep retrying forever,
    // while `EADDRNOTAVAIL`/`EAFNOSUPPORT` (no IPv6 stack on this host) must
    // stop after one attempt. None of this touches a socket — every case
    // here is a constructed `io::Error`.

    #[test]
    fn address_in_use_is_transient() {
        // The mshd/`:22` handover case `bind_with_retry` was built for —
        // must keep retrying, never give up on its own.
        let e = io::Error::from(io::ErrorKind::AddrInUse);
        assert_eq!(classify_bind_error(&e), BindFailureKind::Transient);
    }

    #[test]
    fn address_not_available_is_permanent() {
        // `EADDRNOTAVAIL` / `WSAEADDRNOTAVAIL` both decode to this stable
        // `ErrorKind` — the family exists but this host has nothing to bind
        // to in it.
        let e = io::Error::from(io::ErrorKind::AddrNotAvailable);
        assert_eq!(classify_bind_error(&e), BindFailureKind::Permanent);
    }

    #[test]
    #[cfg(unix)]
    fn address_family_not_supported_is_permanent_on_unix() {
        // EAFNOSUPPORT has no stable `ErrorKind` of its own — this is the
        // raw-errno fallback `classify_bind_error` needs for it, exercised
        // directly rather than trusting `.kind()` to name it.
        let e = io::Error::from_raw_os_error(97);
        assert_eq!(classify_bind_error(&e), BindFailureKind::Permanent);
    }

    #[test]
    #[cfg(windows)]
    fn address_family_not_supported_is_permanent_on_windows() {
        let e = io::Error::from_raw_os_error(10047);
        assert_eq!(classify_bind_error(&e), BindFailureKind::Permanent);
    }

    #[test]
    fn an_unrelated_raw_errno_is_not_misclassified_as_permanent() {
        // A raw OS error that happens to be neither `AddrNotAvailable` nor
        // the platform's `EAFNOSUPPORT`/`WSAEAFNOSUPPORT` number must fall
        // through to `Transient` — `classify_bind_error` must not treat an
        // unrecognised code as evidence of a durable condition.
        let e = io::Error::from_raw_os_error(9999);
        assert_eq!(classify_bind_error(&e), BindFailureKind::Transient);
    }

    #[test]
    fn other_error_kinds_stay_transient() {
        // Anything this function does not specifically recognise as
        // permanent must default to retrying — `Transient` is the safe
        // default, since retrying a condition that turns out to be durable
        // only costs log lines, while treating a transient one as permanent
        // would take a face down for good over a passing contention.
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::Other,
        ] {
            let e = io::Error::from(kind);
            assert_eq!(
                classify_bind_error(&e),
                BindFailureKind::Transient,
                "{kind:?} must not be misclassified as permanent"
            );
        }
    }

    // ── The invariant `bind_v6_only` exists to guarantee ──
    //
    // Not the plumbing (that a `TcpListener` comes back) — the actual fact:
    // a v6-only socket and a v4 wildcard socket can hold the SAME port at
    // once in this process. Measured on the live fleet, `bindv6only=0`
    // means a plain `[::]` bind claims the v4 wildcard too, so this is the
    // one test that would fail if `set_only_v6(true)` were ever dropped or
    // silently miscompiled away.
    //
    // Binding on port 0 twice (once per family) would NOT prove this: two
    // independent ephemeral ports never contend regardless of
    // `IPV6_V6ONLY`. This binds v6-only on an OS-assigned port first and
    // keeps that socket OPEN, then reuses its exact port for the v4 bind —
    // the only way to force both binds onto the identical port without a
    // race against another process for a fixed one.
    //
    // `#[ignore]` and NOT run by a plain `cargo test`. It is the only test in
    // this crate that binds a WILDCARD address, and the dev box that runs
    // `cargo test` is the operator box: nothing mirage-shaped may open a
    // public listener there, however briefly, and a test is not an exception
    // to that — it is the most likely way to breach it by accident. The
    // behaviour under test is Linux `bindv6only` semantics, which the Windows
    // host cannot exhibit at all, so running it here would prove nothing even
    // if it were allowed. Run it in the musl build container, where the
    // kernel is the one the fleet actually runs:
    //
    // ```text
    // cargo test -p mirage-perimeter --target x86_64-unknown-linux-musl     //     -- --ignored a_v6_only_socket_and_a_v4_wildcard_can_share_one_port
    // ```
    #[ignore = "binds wildcard addresses — container only, never the operator box"]
    #[tokio::test]
    async fn a_v6_only_socket_and_a_v4_wildcard_can_share_one_port() {
        let v6_addr: SocketAddr = "[::]:0".parse().expect("valid v6 unspecified addr");
        let v6 = bind_v6_only(v6_addr).expect("v6-only bind must succeed");
        let port = v6.local_addr().expect("v6 listener has a local addr").port();

        let v4_addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid v4 addr");
        let v4 = tokio::net::TcpListener::bind(v4_addr).await;

        // `v6` is still open and listening at this point — if `set_only_v6`
        // had no effect (or `bindv6only=0` leaked through), this second
        // bind would fail with `EADDRINUSE` because `v6` would already own
        // the v4 wildcard on this exact port.
        assert!(
            v4.is_ok(),
            "a v4 wildcard bind on the same port as an open v6-only socket must succeed: {:?}",
            v4.err()
        );

        // Keep both alive until here so neither can be optimised away
        // before the assertion runs.
        drop(v6);
        drop(v4);
    }

    // ── The stop mechanism `crate::run::Surface` relies on for retirement ──
    //
    // `accept_loop` itself does not care which address it was bound to —
    // unlike `run_face`/`bind_and_serve`, it is not the function that picks
    // `0.0.0.0`/`[::]`. That means the REAL production accept loop can be
    // exercised here on loopback only, never a wildcard address, which is
    // what this crate's own rule for tests on this box requires (see the
    // ignored test just above). This is deliberately not a smaller
    // hand-rolled stand-in: it is the exact function `bind_and_serve` calls.

    /// Build a minimal [`FaceRuntime`] for exercising [`accept_loop`]
    /// directly, without any of `run_face`'s bind machinery. `port` is
    /// whatever `listener` actually bound to — callers read that off
    /// `TcpListener::local_addr` themselves, since it is an OS-assigned
    /// ephemeral port in every test that uses this.
    fn test_runtime(port: u16, cancel: CancellationToken) -> Arc<FaceRuntime> {
        let face = PerimeterFace {
            port,
            camouflage: mirage_core::mirage::wire::camouflage::TransportCamouflage::None,
            label: format!("test:{port}"),
            purpose: FacePurpose::MonitorWire,
        };
        Arc::new(FaceRuntime {
            face: Arc::new(ArcSwap::from_pointee(face)),
            config: Arc::new(PerimeterConfig::baseline()),
            keypair: Arc::new(ArcSwap::from_pointee(KeyPair::generate())),
            counters: Arc::new(FaceCounters::default()),
            rate_limit: Arc::new(SourceRateLimit::new(1_000.0, 1_000.0)),
            sink: crate::observe::SecdSink::spawn(),
            semaphore: Arc::new(Semaphore::new(4)),
            jail_budget: Arc::new(crate::jail::FaceJail::new(4)),
            disposition: crate::jail::Disposition::default(),
            port,
            cancel,
        })
    }

    /// The proof the brief this change came from demands by name: cancelling
    /// the token must not merely end the task, it must release the OS
    /// socket. A leaked listener still holding the port would reproduce the
    /// exact defect this mechanism exists to fix while looking fixed —
    /// `accept_loop` returning is not enough evidence on its own, so this
    /// rebinds the EXACT same address afterwards and requires that to
    /// succeed.
    #[tokio::test]
    async fn cancelling_the_token_stops_accepting_and_releases_the_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind must succeed");
        let addr = listener.local_addr().expect("listener has a local addr");

        let cancel = CancellationToken::new();
        let runtime = test_runtime(addr.port(), cancel.clone());

        let task = tokio::spawn(accept_loop(listener, AddressFamily::V4, runtime));

        // Give the loop a real chance to start polling `listener.accept()`
        // before cancelling it — otherwise this would only prove that a
        // task which never ran can be joined, not that a genuinely
        // accepting loop stops and lets go of its socket.
        tokio::task::yield_now().await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("accept_loop must return once cancelled, not hang forever")
            .expect("accept_loop task must not panic");

        let rebound = tokio::net::TcpListener::bind(addr).await;
        assert!(
            rebound.is_ok(),
            "the port must be free once the accept loop stops — a listener that merely \
             forgot its task would still hold it and fail this exact rebind: {:?}",
            rebound.err()
        );
    }

    // ── The splice backstop (`relay_with_backstop`) — OBSERVE-ONLY ──
    //
    // `relay_with_backstop`'s own doc names the property: the deadline
    // firing must report and must NEVER drop or cancel the underlying
    // `copy_bidirectional` future. This is the one place in this crate that
    // proves it end to end, on real loopback sockets, without waiting on the
    // ceiling's real (minutes-to-hours) duration — `start_paused` virtual
    // time plus `tokio::time::advance` fires the deadline deterministically,
    // the same technique `mirage-protocol/src/driver.rs`'s own
    // `tcp_connect_bounded` timeout test already uses for an identical
    // reason.

    /// Two loopback `TcpStream`s already connected to each other — a real
    /// socket pair, standing in for one leg of a splice
    /// (`stripped`/`inner`). Returns `(near, far)`; `far` is handed back to
    /// the caller only so it can be kept alive for the test's duration —
    /// dropping it would close `near` too, which would let
    /// `copy_bidirectional` complete on its own and prove nothing about the
    /// backstop.
    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind must succeed");
        let addr = listener.local_addr().expect("listener has a local addr");
        let (connect_result, accept_result) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let far = connect_result.expect("loopback connect must succeed");
        let (near, _peer_addr) = accept_result.expect("loopback accept must succeed");
        (near, far)
    }

    /// The property `relay_with_backstop`'s own doc claims, proven rather
    /// than merely read off the source: crossing the (jittered) ceiling
    /// reports exactly once via [`FaceCounters::splice_backstop_observed`]
    /// and the relay task is STILL RUNNING afterward — the backstop never
    /// dropped or cancelled the underlying `copy_bidirectional` future.
    ///
    /// Both loopback pairs are left open and silent for this test's whole
    /// life, so `copy_bidirectional` genuinely blocks forever on its own —
    /// the only thing that could ever end the relay task is this wrap
    /// cutting it, which it must not do.
    #[tokio::test(start_paused = true)]
    async fn the_backstop_observes_and_reports_without_ending_the_relay() {
        let (stripped_near, stripped_far) = loopback_pair().await;
        let (inner_near, inner_far) = loopback_pair().await;

        let counters = Arc::new(FaceCounters::default());
        let face = Arc::new(PerimeterFace {
            port: 4443,
            // `Bursty` — the shorter of the two ceilings, so this test's one
            // `advance()` below only ever has to clear
            // `BURSTY_SPLICE_BACKSTOP_MS`, not the `Sustained` one.
            camouflage: mirage_core::mirage::wire::camouflage::TransportCamouflage::TlsReal {
                sni: "example.com".into(),
                alpn: vec![],
            },
            label: "tls_real:4443".into(),
            purpose: FacePurpose::MonitorWire,
        });

        let task_counters = Arc::clone(&counters);
        let task_face = Arc::clone(&face);
        let relay_task = tokio::spawn(async move {
            let mut stripped: Box<dyn BidiStream> = Box::new(stripped_near);
            let mut inner: Box<dyn BidiStream> = Box::new(inner_near);
            relay_with_backstop(&mut stripped, &mut inner, &task_face, &task_counters).await
        });

        // Let the spawned task actually run far enough to register both its
        // pending socket read and the backstop's own sleep with the (paused)
        // reactor before virtual time moves — otherwise `advance` below
        // could race ahead of a task that has not even started polling yet.
        tokio::task::yield_now().await;

        // Comfortably past even the high end of `Bursty`'s jitter band
        // (`base + base/5`, i.e. at most 120% of `BURSTY_SPLICE_BACKSTOP_MS`)
        // — this guarantees the deadline fired regardless of which jittered
        // value this run happened to draw.
        let past_every_possible_bursty_ceiling =
            Duration::from_millis(crate::timing::BURSTY_SPLICE_BACKSTOP_MS) * 2;
        tokio::time::advance(past_every_possible_bursty_ceiling).await;
        tokio::task::yield_now().await;

        assert_eq!(
            counters.splice_backstop_observed.load(Ordering::Relaxed),
            1,
            "the observer must have fired exactly once once the ceiling was crossed"
        );
        assert!(
            !relay_task.is_finished(),
            "the backstop must only observe and report — the relay task must still be running, \
             proving the underlying copy_bidirectional was never dropped or cancelled"
        );

        // The guard on the backstop's own select arm (`if !backstop_fired`)
        // must stop it firing again on every subsequent poll — advance far
        // past the ceiling a second time and confirm the counter does not
        // move again.
        tokio::time::advance(past_every_possible_bursty_ceiling).await;
        tokio::task::yield_now().await;
        assert_eq!(
            counters.splice_backstop_observed.load(Ordering::Relaxed),
            1,
            "the backstop must report a given connection's crossing at most once, not on every poll"
        );

        // Cleanup: this relay task blocks forever by construction (neither
        // loopback peer ever sends or closes), so it never finishes on its
        // own — abort it now that the property above is proven, and keep
        // the `_far` ends alive until here so neither pair closes early.
        relay_task.abort();
        drop(stripped_far);
        drop(inner_far);
    }

    /// The companion case: cancelling BEFORE the loop ever gets to accept
    /// anything must still return promptly and release the port, not wait
    /// for a first connection that may never come.
    #[tokio::test]
    async fn cancelling_before_any_accept_still_releases_the_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind must succeed");
        let addr = listener.local_addr().expect("listener has a local addr");

        let cancel = CancellationToken::new();
        cancel.cancel();
        let runtime = test_runtime(addr.port(), cancel);

        tokio::time::timeout(Duration::from_secs(5), accept_loop(listener, AddressFamily::V4, runtime))
            .await
            .expect("accept_loop must return immediately on an already-cancelled token");

        let rebound = tokio::net::TcpListener::bind(addr).await;
        assert!(rebound.is_ok(), "the port must be free: {:?}", rebound.err());
    }
}
