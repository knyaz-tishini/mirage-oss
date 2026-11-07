//! The jail — what the front door does with a touch that is not ours.
//!
//! # A drop is not a jail
//!
//! Until this module, every failed touch was closed immediately: the stream
//! went out of scope and the socket died. That is cheap and it is also a
//! signature. A real web server whose TLS session has just completed does not
//! tear it down a millisecond later, and it does not do so identically on
//! every port of every machine. An instant, uniform close is a fingerprint in
//! the shape of an absence.
//!
//! The jail holds instead: accept it, read whatever it sends, answer nothing,
//! release it on a timer. The prober spends a socket and a timeout; the box
//! spends one bounded slot.
//!
//! # Two axes, and this module is axis one
//!
//! **Axis 1 — what happens to this connection**, configured PER FACE, because
//! camouflage is not wanted everywhere: some deployments want an iron firewall
//! and no pretence at all.
//!
//! - [`Disposition::Jail`] — hold, return nothing, release on a timer.
//! - [`Disposition::HardCut`] — close now. Cheapest, and honest about being a
//!   wall.
//!
//! **Axis 2 — what happens to the SOURCE** (count offences, ban the repeat
//! offender in the kernel) is deliberately NOT here. This process holds
//! `CAP_NET_BIND_SERVICE` and `CAP_DAC_READ_SEARCH` under
//! `SecureBits=keep-caps-locked` — it cannot touch nftables, and giving the
//! box's only internet-facing process the power to rewrite the box's firewall
//! is the wrong direction on purpose. Enforcement belongs to the arbiter
//! (`mirage-secd`), which this crate reports to and does not depend on — see
//! `crate::sink`'s module doc. The jail is what makes that affordable in the
//! meantime: a held connection costs a slot, not a decision.
//!
//! # Why the socket is duplicated before the camouflage strip
//!
//! `strip_tcp_server` takes the `TcpStream` by value and drops it when the
//! strip fails, which closes the socket before anything here could hold it —
//! so seam A (the camouflage strip) would be un-jailable without a change to
//! shared wire code that every camouflage rides on. Instead the face hands the
//! strip a DUPLICATE of the socket and keeps the original: dropping one dup
//! does not close the socket while the other lives. On a successful strip the
//! spare is dropped immediately, so a carrying connection pays one `dup(2)` and
//! nothing else.
//!
//! # The cap is not optional
//!
//! Holding costs a file descriptor and a task for the hold duration, on boxes
//! with one vCPU and ~460 MB. Without a ceiling the jail is a way to take the
//! box down: open sockets until the process runs out. Each face therefore has
//! its own hold budget, and a face at capacity degrades to a hard cut rather
//! than queueing — a jail that makes the box unreachable has protected nothing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// What a face does with a connection that is not ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disposition {
    /// Hold it, return nothing, release on a timer.
    #[default]
    Jail,
    /// Close it immediately.
    HardCut,
}

impl Disposition {
    /// Parse the capsule's spelling. Anything unrecognised is `Jail`, because
    /// the safe default when a config cannot be understood is the one that
    /// gives an observer less, not more.
    pub fn from_tag(tag: &str) -> Self {
        match tag.trim().to_ascii_lowercase().as_str() {
            "hard_cut" | "hardcut" | "cut" => Self::HardCut,
            _ => Self::Jail,
        }
    }

    pub fn as_tag(self) -> &'static str {
        match self {
            Self::Jail => "jail",
            Self::HardCut => "hard_cut",
        }
    }
}

/// How long a held connection is kept before it is released.
///
/// Long enough that a scanner's own timeout fires first — the point is that
/// the port never answers the question "is something here" — and short enough
/// that the per-face budget recycles under a sweep.
pub const DEFAULT_HOLD_MS: u64 = 30_000;

/// Concurrently held connections allowed per face.
///
/// Deliberately far below `max_inflight` (256): a held connection is doing no
/// work and must never be able to crowd out a carrying one.
pub const DEFAULT_MAX_HELD_PER_FACE: usize = 64;

/// Resolved jail settings for one boot.
#[derive(Debug, Clone)]
pub struct JailConfig {
    /// Applied to any face without its own entry.
    pub default_disposition: Disposition,
    /// Per-face override, keyed by port.
    pub per_face: HashMap<u16, Disposition>,
    pub hold_ms: u64,
    pub max_held_per_face: usize,
}

impl Default for JailConfig {
    fn default() -> Self {
        Self {
            default_disposition: Disposition::Jail,
            per_face: HashMap::new(),
            hold_ms: DEFAULT_HOLD_MS,
            max_held_per_face: DEFAULT_MAX_HELD_PER_FACE,
        }
    }
}

impl JailConfig {
    pub fn disposition_for(&self, port: u16) -> Disposition {
        self.per_face.get(&port).copied().unwrap_or(self.default_disposition)
    }
}

/// What the jail did, so the caller can count it without re-deriving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailOutcome {
    /// Held for the configured duration (or until the peer gave up first).
    Held,
    /// Closed immediately because this face is configured `HardCut`.
    Cut,
    /// Closed immediately because the face's hold budget was full. Its own
    /// outcome, never folded into `Cut`: one is a policy and the other is
    /// pressure, and only the second is a reason to look at the box.
    AtCapacity,
}

/// One face's hold budget.
///
/// Only the budget. The counters live in `crate::stats::FaceCounters` beside
/// every other per-face number the operator reads — a second place to look for
/// "how many did we hold" is a second place for the two to disagree.
#[derive(Debug)]
pub struct FaceJail {
    permits: Arc<Semaphore>,
}

impl FaceJail {
    pub fn new(max_held: usize) -> Self {
        Self { permits: Arc::new(Semaphore::new(max_held.max(1))) }
    }

    /// Slots free right now — used by tests to prove a hard cut spends none.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

/// Apply this face's disposition to one rejected connection.
///
/// Takes the socket by value: whatever happens, this function owns the end of
/// its life. Returns what it did so the caller counts one outcome rather than
/// guessing from the disposition (a `Jail` face at capacity really did cut).
///
/// **It never writes.** Not a byte, not a reset, not a protocol-level "no".
/// The only thing a prober may learn is that the connection went nowhere
/// slowly, which is what an overloaded or uninterested server looks like.
pub async fn dispose(
    stream: TcpStream,
    disposition: Disposition,
    face: &FaceJail,
    holding_now: &AtomicU64,
    hold_ms: u64,
) -> JailOutcome {
    if disposition == Disposition::HardCut {
        drop(stream);
        return JailOutcome::Cut;
    }

    // `try_acquire` and not `acquire`: waiting for a slot would queue probers
    // behind each other and turn a flood into unbounded task growth, which is
    // the failure this budget exists to prevent.
    let Ok(permit) = Arc::clone(&face.permits).try_acquire_owned() else {
        drop(stream);
        return JailOutcome::AtCapacity;
    };

    holding_now.fetch_add(1, Ordering::Relaxed);
    hold(stream, hold_ms).await;
    holding_now.fetch_sub(1, Ordering::Relaxed);
    drop(permit);
    JailOutcome::Held
}

/// Duplicate the socket so the jail keeps a handle the camouflage strip cannot
/// take with it.
///
/// `strip_tcp_server` consumes the `TcpStream` and drops it when the strip
/// fails, which closes the connection before anything here could hold it. A
/// `dup(2)` gives two handles to ONE socket: dropping the strip's copy leaves
/// the peer connected while this one lives, so seam A becomes jailable without
/// changing shared wire code that every camouflage rides on.
///
/// Returns `(original, spare)`. `spare` is `None` when the duplication failed
/// — the connection then behaves exactly as it did before this module existed
/// (closed on rejection), which is a degradation, never a broken connection.
pub fn duplicate(stream: TcpStream) -> (TcpStream, Option<TcpStream>) {
    let Ok(std_stream) = stream.into_std() else {
        // Cannot happen for a freshly accepted stream with no I/O in flight,
        // and if it ever does, the caller still has to get a stream back.
        return (
            TcpStream::from_std(unreachable_placeholder()).expect("placeholder"),
            None,
        );
    };
    let spare = std_stream
        .try_clone()
        .ok()
        // The clone shares the open file description, so it is already
        // non-blocking; tokio only needs that guarantee, not a fresh setting.
        .and_then(|c| TcpStream::from_std(c).ok());
    match TcpStream::from_std(std_stream) {
        Ok(original) => (original, spare),
        // Re-wrapping our own std stream cannot fail in practice; if it did,
        // the spare (if any) is the only live handle and the caller gets it
        // back as the original so nothing is silently leaked.
        Err(_) => match spare {
            Some(s) => (s, None),
            None => (
                TcpStream::from_std(unreachable_placeholder()).expect("placeholder"),
                None,
            ),
        },
    }
}

/// Only reachable if `into_std` fails on a fresh accept, which it does not.
/// Kept as a named function so the impossible branch above is obvious rather
/// than hidden behind an `unwrap` that a reader has to reason about.
fn unreachable_placeholder() -> std::net::TcpStream {
    unreachable!("a freshly accepted TcpStream always converts to std")
}

/// Read and discard until the peer gives up or the timer fires. Never writes.
async fn hold(mut stream: TcpStream, hold_ms: u64) {
    let _ = tokio::time::timeout(Duration::from_millis(hold_ms), async {
        // Small buffer on purpose: this path exists to consume, and a large
        // per-connection buffer multiplied by the hold budget is memory spent
        // on somebody else's scan.
        let mut scratch = [0u8; 512];
        loop {
            match stream.read(&mut scratch).await {
                // Peer closed — nothing left to hold.
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connected_pair() -> (tokio::net::TcpListener, TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dialer = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (accepted, _) = listener.accept().await.unwrap();
        let client = dialer.await.unwrap();
        (listener, accepted, client)
    }

    /// The default has to be the jail. A setting that cannot be understood must
    /// fall to the disposition that tells an observer less, not more.
    #[test]
    fn an_unknown_tag_falls_to_the_jail() {
        assert_eq!(Disposition::from_tag("jail"), Disposition::Jail);
        assert_eq!(Disposition::from_tag("HARD_CUT"), Disposition::HardCut);
        assert_eq!(Disposition::from_tag("hardcut"), Disposition::HardCut);
        assert_eq!(Disposition::from_tag("nonsense"), Disposition::Jail);
        assert_eq!(Disposition::from_tag(""), Disposition::Jail);
        assert_eq!(Disposition::default(), Disposition::Jail);
    }

    /// The mode is per FACE: one box legitimately wants to look like a website
    /// on 443 and be a plain wall on a service port.
    #[test]
    fn a_face_may_differ_from_the_box_default() {
        let mut cfg = JailConfig::default();
        cfg.per_face.insert(8443, Disposition::HardCut);
        assert_eq!(cfg.disposition_for(443), Disposition::Jail);
        assert_eq!(cfg.disposition_for(8443), Disposition::HardCut);
    }

    /// A hard-cut face never consumes a hold slot — otherwise configuring a
    /// face as a wall would still let a flood exhaust the budget.
    #[ignore = "opens a socket — container only, never the operator box"]
    #[tokio::test]
    async fn a_hard_cut_face_spends_no_hold_budget() {
        let jail = FaceJail::new(1);
        let gauge = AtomicU64::new(0);
        let (_l, accepted, _client) = connected_pair().await;
        let out = dispose(accepted, Disposition::HardCut, &jail, &gauge, 10_000).await;
        assert_eq!(out, JailOutcome::Cut);
        assert_eq!(jail.available(), 1, "no slot was taken");
        assert_eq!(gauge.load(Ordering::Relaxed), 0);
    }

    /// A face at capacity degrades to a cut rather than queueing. An unbounded
    /// jail is a way to take the box down, and a queued prober is a task we pay
    /// for.
    #[ignore = "opens a socket — container only, never the operator box"]
    #[tokio::test]
    async fn a_full_face_cuts_instead_of_queueing() {
        let jail = Arc::new(FaceJail::new(1));
        let gauge = Arc::new(AtomicU64::new(0));
        let (listener, a1, _c1) = connected_pair().await;
        let addr = listener.local_addr().unwrap();

        let bg = {
            let j = Arc::clone(&jail);
            let g = Arc::clone(&gauge);
            tokio::spawn(async move { dispose(a1, Disposition::Jail, &j, &g, 60_000).await })
        };
        for _ in 0..200 {
            if gauge.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(gauge.load(Ordering::Relaxed), 1, "the only slot must be taken");

        let d2 = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (a2, _) = listener.accept().await.unwrap();
        let _c2 = d2.await.unwrap();
        let out = dispose(a2, Disposition::Jail, &jail, &gauge, 60_000).await;
        assert_eq!(out, JailOutcome::AtCapacity);
        bg.abort();
    }

    /// The whole promise: a held connection gets ZERO bytes back. A prober that
    /// receives anything at all has learned the port is inhabited.
    #[ignore = "opens a socket — container only, never the operator box"]
    #[tokio::test]
    async fn a_held_connection_is_answered_with_nothing() {
        let jail = FaceJail::new(4);
        let gauge = AtomicU64::new(0);
        let (_l, accepted, mut client) = connected_pair().await;
        let prober = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            client.write_all(b"GET / HTTP/1.1").await.unwrap();
            let mut buf = [0u8; 64];
            client.read(&mut buf).await.unwrap_or(0)
        });
        let out = dispose(accepted, Disposition::Jail, &jail, &gauge, 150).await;
        assert_eq!(out, JailOutcome::Held);
        assert_eq!(prober.await.unwrap(), 0, "the jail must never write a byte");
        assert_eq!(gauge.load(Ordering::Relaxed), 0, "the slot is returned");
    }

    /// A peer that hangs up early releases its slot at once rather than pinning
    /// it for the whole hold — otherwise the budget is sized by the timer
    /// instead of by real pressure.
    #[tokio::test]
    async fn a_peer_that_leaves_frees_its_slot_at_once() {
        let jail = FaceJail::new(1);
        let gauge = AtomicU64::new(0);
        let (_l, accepted, client) = connected_pair().await;
        drop(client);
        let started = std::time::Instant::now();
        let out = dispose(accepted, Disposition::Jail, &jail, &gauge, 60_000).await;
        assert_eq!(out, JailOutcome::Held);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "an EOF must release the slot, not wait out the timer"
        );
        assert_eq!(jail.available(), 1);
    }

    /// The duplicate is what makes seam A jailable at all: the camouflage strip
    /// takes one handle and drops it, and the connection has to survive that.
    #[tokio::test]
    async fn a_duplicated_socket_survives_its_twin_being_dropped() {
        let (_l, accepted, mut client) = connected_pair().await;
        let (original, spare) = duplicate(accepted);
        let mut spare = spare.expect("dup must succeed on a fresh accept");
        drop(original); // exactly what a failed camouflage strip does.

        use tokio::io::AsyncWriteExt;
        client.write_all(b"still here").await.expect("the peer is still connected");
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_millis(500), spare.read(&mut buf))
            .await
            .expect("the surviving handle must still be readable")
            .unwrap_or(0);
        assert_eq!(n, 10, "the surviving handle reads what the peer sent");
    }
}
