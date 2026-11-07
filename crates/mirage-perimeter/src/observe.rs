//! The perimeter's side of the observation channel — the implementation of
//! [`crate::sink::ObservationSink`] that this crate deliberately did not have.
//!
//! # What it is
//!
//! A unix-socket client. The face handlers hand it a
//! [`PerimeterObservation`]; it hands that to the arbiter (`mirage-secd`)
//! listening on [`LOCAL_EVENT_SOCKET_PATH`], one newline-terminated JSON row
//! per observation. That is the whole contract. This crate still does not
//! depend on `mirage-secd`, still computes no reputation, still owns no list,
//! and still decides nothing about a source address — it reports.
//!
//! # Why it cannot block, and what it does instead
//!
//! [`ObservationSink::report`] is called INLINE on a per-connection handler,
//! at the exact moment the perimeter has decided a touch is not wire. A sink
//! that did a synchronous write there would put the arbiter's scheduling —
//! or the arbiter's absence — directly in the accept path's way, and the
//! first consequence of a wedged secd would be a perimeter that stops
//! answering. So:
//!
//! * `report` does a `try_send` on a BOUNDED channel and returns. It never
//!   awaits, never allocates a task, and never fails the caller.
//! * A full channel DROPS the observation and counts it. Losing observations
//!   under load is correct: they are a sample of hostile traffic, and the
//!   thing they feed is a threshold. Losing the accept loop is not correct.
//! * A single drain task owns the socket. It connects lazily, reconnects with
//!   a bounded backoff, and buffers nothing across a failure — an arbiter
//!   that was not listening simply did not hear that minute.
//!
//! Every one of those loss paths is COUNTED and readable
//! ([`ObservationChannelStats`]), because a reporting channel that silently
//! reports nothing is indistinguishable from a quiet internet, and this
//! codebase has already paid for that shape more than once.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[cfg(unix)]
use mirage_core::local_security_event::LOCAL_EVENT_SOCKET_PATH;
use mirage_core::local_security_event::{InwardDest, LocalSecurityEvent};
use mirage_core::perimeter_observation::PerimeterObservation;
use tokio::sync::mpsc;

use crate::sink::ObservationSink;

/// Bounded queue depth between the face handlers and the drain task.
///
/// Sized for a burst, not for a backlog: a scanner sweeping every face of a
/// box produces observations far faster than a threshold needs them, so the
/// right behaviour past this depth is to drop and count, not to grow.
const CHANNEL_DEPTH: usize = 1024;

/// Backoff between reconnect attempts when the arbiter is not listening.
#[cfg(unix)]
const RECONNECT_BACKOFF_MS: u64 = 2_000;

/// Counters for everything that can happen to an observation after a face
/// hands it over. `queued + dropped_full` is every observation ever reported;
/// `sent + dropped_io + dropped_permission` is every one the drain task took
/// off the queue.
#[derive(Debug, Default)]
pub struct ObservationChannelStats {
    /// Accepted onto the queue.
    pub queued: AtomicU64,
    /// Refused because the queue was full — the load-shed path.
    pub dropped_full: AtomicU64,
    /// Written to the arbiter's socket.
    pub sent: AtomicU64,
    /// Taken off the queue but lost to a socket error or a missing arbiter.
    pub dropped_io: AtomicU64,
    /// Taken off the queue but lost because connecting to
    /// [`LOCAL_EVENT_SOCKET_PATH`] was refused by file permissions
    /// (`EACCES`), not because nobody is listening. A distinct counter from
    /// `dropped_io` on purpose: the socket is deliberately root-only at rest
    /// (`mirage-secd/src/perimeter_intake.rs`'s own doc — "a local
    /// unprivileged process that could write here could ban the operator"),
    /// so this climbs on EVERY attempt, forever, the moment this process
    /// runs as anything other than the identity that socket is scoped to —
    /// waiting for secd to "come up" will never clear it, unlike an ordinary
    /// `dropped_io` — same "distinct counter for a distinct fact" reasoning
    /// `crate::stats::FaceCounters` applies elsewhere.
    ///
    /// **It counts the wrong MOMENT, and that limit is worth knowing before
    /// reading a zero here as "no permission problem".** This process
    /// connects once and holds the socket (`connects: 1` is the healthy
    /// steady state), so a permission fault can only appear here at connect
    /// time. A mode that changes under a live fd is invisible to it — the
    /// kernel checks permission at `connect()`, not per write.
    ///
    /// A zero therefore means "no permission problem WHEN WE LAST DIALLED",
    /// which on a long-lived process can be hours or a boot ago.
    pub dropped_permission: AtomicU64,
    /// Times the drain task (re)connected to the arbiter.
    pub connects: AtomicU64,
}

/// How many source addresses the local touch ledger may hold before idle
/// entries are swept. Same shape and same reason as
/// [`crate::ratelimit::SourceRateLimit`]'s bound: an address-spray flood
/// mints a new key per packet, and an unbounded map is the whole attack.
const MAX_TRACKED_SOURCES: usize = 8192;

/// A source untouched for this long is dropped by the sweep.
const IDLE_EVICT_SECS: u64 = 300;

/// The perimeter's OWN count of how often it has seen an address — the
/// `perimeter_touch_count` field, and nothing more.
///
/// It is not the arbiter's offense counter and must never be confused with
/// one: the arbiter derives its own count independently, from the
/// observations it actually received, which is a different number the moment
/// one is shed. This one exists so the confidence bucket has a repeat signal
/// to scale on, and so the field is not a constant `1` pretending to be a
/// count.
#[derive(Debug, Default)]
struct TouchLedger {
    seen: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
}

impl TouchLedger {
    fn bump(&self, ip: std::net::IpAddr) -> u32 {
        let now = std::time::Instant::now();
        let mut map = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() > MAX_TRACKED_SOURCES {
            map.retain(|_, (_, last)| now.duration_since(*last).as_secs() < IDLE_EVICT_SECS);
        }
        let entry = map.entry(ip).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = now;
        entry.0
    }
}

/// The live sink handed to the face handlers.
pub struct SecdSink {
    tx: mpsc::Sender<LocalSecurityEvent>,
    stats: Arc<ObservationChannelStats>,
    ledger: TouchLedger,
}

impl SecdSink {
    /// Build the sink and spawn its drain task.
    ///
    /// Never fails and never blocks on the arbiter: if nothing is listening
    /// on [`LOCAL_EVENT_SOCKET_PATH`], the drain task retries in the
    /// background and the counters say so. A perimeter whose boot depended on
    /// secd being up would have made the box's front door hostage to a
    /// daemon behind it.
    #[must_use]
    pub fn spawn() -> Arc<Self> {
        let (tx, rx) = mpsc::channel(CHANNEL_DEPTH);
        let stats = Arc::new(ObservationChannelStats::default());
        tokio::spawn(drain(rx, Arc::clone(&stats)));
        Arc::new(Self {
            tx,
            stats,
            ledger: TouchLedger::default(),
        })
    }

    /// Read-only handle on the channel counters (for `/stats`).
    #[must_use]
    pub fn stats(&self) -> Arc<ObservationChannelStats> {
        Arc::clone(&self.stats)
    }

    /// Build and report one observation: bump the local ledger, classify the
    /// confidence from `(signal, count)`, hand it to the queue.
    ///
    /// This is the ONLY entry point the faces use, so a face cannot invent a
    /// confidence of its own — the classifier is shared with the arbiter
    /// (`mirage_core::perimeter_observation::confidence_bucket`) precisely so
    /// the two planes never score the same touch differently.
    pub fn observe(
        &self,
        ip: std::net::IpAddr,
        port: u16,
        signal_type: mirage_core::fact_signing::AttackerSignalType,
    ) {
        let perimeter_touch_count = self.ledger.bump(ip);
        let ts_ms = now_ms();
        self.report(PerimeterObservation {
            ip: ip.to_string(),
            port,
            ts_ms,
            signal_type,
            perimeter_touch_count,
            confidence: mirage_core::perimeter_observation::confidence_bucket(
                signal_type,
                perimeter_touch_count,
            ),
        });
    }
}

impl SecdSink {
    /// Queue one already-built event. Shared by every producer path so the
    /// shed accounting is in exactly one place.
    fn send(&self, event: LocalSecurityEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {
                self.stats.queued.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.stats.dropped_full.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Report that a connection from `client_ip` was ADMITTED and routed
    /// inward — through which public face, to which destination.
    ///
    /// It proves nothing about the peer: routing is decided on the opening
    /// bytes, so anything that sends `SSH-2.0-` or a well-shaped V9 hello
    /// produces one of these. What it is, is the WAF's record of who was let
    /// in and what they were reaching for.
    ///
    /// It used to carry the loopback dial's ephemeral port, as half of a join
    /// secd completed against the destination's authentication report. The
    /// address now travels WITH the connection
    /// (`mirage_core::perimeter_preamble`), so the destination reports an
    /// address it was told rather than one a third daemon reconstructed —
    /// and this report is free to say the thing that is actually useful,
    /// which face carried the peer.
    pub fn routed_inward(&self, client_ip: std::net::IpAddr, face_port: u16, dest: InwardDest) {
        self.send(LocalSecurityEvent::RoutedInward {
            client_ip: client_ip.to_string(),
            face_port,
            dest,
            ts_ms: now_ms(),
        });
    }
}

impl ObservationSink for SecdSink {
    fn report(&self, observation: PerimeterObservation) {
        self.send(LocalSecurityEvent::Observation(observation));
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Drain loop: own the socket, write lines, reconnect on failure.
#[cfg(unix)]
async fn drain(mut rx: mpsc::Receiver<LocalSecurityEvent>, stats: Arc<ObservationChannelStats>) {
    use std::io::ErrorKind;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let mut sock: Option<UnixStream> = None;
    while let Some(event) = rx.recv().await {
        let Ok(mut line) = serde_json::to_vec(&event) else {
            stats.dropped_io.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        line.push(b'\n');

        if sock.is_none() {
            match UnixStream::connect(LOCAL_EVENT_SOCKET_PATH).await {
                Ok(s) => {
                    stats.connects.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(
                        path = LOCAL_EVENT_SOCKET_PATH,
                        "[perimeter/observe] connected to the arbiter"
                    );
                    sock = Some(s);
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    // Distinct from every other connect failure: a durable
                    // ownership fact, not "secd has not booted yet". WARN,
                    // not DEBUG, because retrying can never clear this one —
                    // see `ObservationChannelStats::dropped_permission`'s
                    // doc.
                    stats.dropped_permission.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        path = LOCAL_EVENT_SOCKET_PATH,
                        error = %e,
                        "[perimeter/observe] permission denied connecting to the arbiter socket \
                         — this will not clear by waiting; check the socket's owner against this \
                         process's user"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(RECONNECT_BACKOFF_MS))
                        .await;
                    continue;
                }
                Err(e) => {
                    stats.dropped_io.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        path = LOCAL_EVENT_SOCKET_PATH,
                        error = %e,
                        "[perimeter/observe] arbiter not listening — observation dropped"
                    );
                    // Back off WITHOUT draining the queue: the next
                    // observation to arrive gets the next connect attempt.
                    tokio::time::sleep(std::time::Duration::from_millis(RECONNECT_BACKOFF_MS))
                        .await;
                    continue;
                }
            }
        }

        let s = sock.as_mut().expect("socket present on this branch");
        if let Err(e) = s.write_all(&line).await {
            stats.dropped_io.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(error = %e, "[perimeter/observe] write failed — reconnecting");
            sock = None;
            continue;
        }
        stats.sent.fetch_add(1, Ordering::Relaxed);
    }
}

/// Non-unix builds have no arbiter socket. The queue still exists and the
/// counters still move, so the perimeter's own code path is identical on the
/// dev box; only the far end is missing.
#[cfg(not(unix))]
async fn drain(mut rx: mpsc::Receiver<LocalSecurityEvent>, stats: Arc<ObservationChannelStats>) {
    while rx.recv().await.is_some() {
        stats.dropped_io.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::fact_signing::AttackerSignalType;

    fn observation(ip: &str) -> PerimeterObservation {
        PerimeterObservation {
            ip: ip.to_string(),
            port: 443,
            ts_ms: 1,
            signal_type: AttackerSignalType::PerimeterCamoFailed,
            perimeter_touch_count: 1,
            confidence: 28,
        }
    }

    #[tokio::test]
    async fn a_full_queue_drops_and_counts_instead_of_blocking() {
        // No drain task at all — the channel fills and every further report
        // must return immediately rather than wedge the caller.
        let (tx, _rx) = mpsc::channel(2);
        let sink = SecdSink {
            tx,
            stats: Arc::new(ObservationChannelStats::default()),
            ledger: TouchLedger::default(),
        };
        for _ in 0..10 {
            sink.report(observation("198.51.100.7"));
        }
        assert_eq!(sink.stats.queued.load(Ordering::Relaxed), 2, "queue depth is the bound");
        assert_eq!(
            sink.stats.dropped_full.load(Ordering::Relaxed),
            8,
            "everything past the bound must be counted as shed, not lost silently"
        );
    }

    #[tokio::test]
    async fn a_reported_observation_reaches_the_queue_intact() {
        let (tx, mut rx) = mpsc::channel(4);
        let sink = SecdSink {
            tx,
            stats: Arc::new(ObservationChannelStats::default()),
            ledger: TouchLedger::default(),
        };
        sink.report(observation("203.0.113.4"));
        let got = expect_observation(rx.recv().await.expect("one observation queued"));
        assert_eq!(got.ip, "203.0.113.4");
        assert_eq!(got.signal_type, AttackerSignalType::PerimeterCamoFailed);
    }

    #[tokio::test]
    async fn a_routed_ssh_connection_reports_the_address_and_the_face_that_carried_it() {
        // The WAF's record of an admitted touch: the real address and the
        // public port it arrived on. It asserts nothing about identity.
        let (tx, mut rx) = mpsc::channel(4);
        let sink = SecdSink {
            tx,
            stats: Arc::new(ObservationChannelStats::default()),
            ledger: TouchLedger::default(),
        };
        sink.routed_inward("203.0.113.44".parse().unwrap(), 22, InwardDest::Mshd);
        match rx.recv().await.expect("one event queued") {
            LocalSecurityEvent::RoutedInward { client_ip, face_port, dest, .. } => {
                assert_eq!(client_ip, "203.0.113.44");
                assert_eq!(face_port, 22, "which face, not which ephemeral port");
                assert_eq!(dest, InwardDest::Mshd);
            }
            other => panic!("expected RoutedInward, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_routed_report_never_carries_an_authentication_claim() {
        // Guards the property the design rests on: the perimeter cannot
        // assert that a peer is the operator, because routing is decided on
        // the opening bytes and anything can send `SSH-2.0-`.
        let (tx, mut rx) = mpsc::channel(4);
        let sink = SecdSink {
            tx,
            stats: Arc::new(ObservationChannelStats::default()),
            ledger: TouchLedger::default(),
        };
        sink.routed_inward("203.0.113.44".parse().unwrap(), 443, InwardDest::Monitor);
        let got = rx.recv().await.expect("queued");
        assert!(
            !matches!(got, LocalSecurityEvent::OperatorAuthenticated { .. }),
            "the perimeter must never be able to emit the trusted half"
        );
    }

    fn expect_observation(e: LocalSecurityEvent) -> PerimeterObservation {
        match e {
            LocalSecurityEvent::Observation(o) => o,
            other => panic!("expected an Observation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_touch_count_climbs_per_source_and_lifts_the_confidence() {
        // The field is named "count" and has to be one: a constant 1 would
        // flatten the confidence curve the arbiter reads.
        let (tx, mut rx) = mpsc::channel(8);
        let sink = SecdSink {
            tx,
            stats: Arc::new(ObservationChannelStats::default()),
            ledger: TouchLedger::default(),
        };
        let src: std::net::IpAddr = "198.51.100.9".parse().unwrap();
        let other: std::net::IpAddr = "198.51.100.10".parse().unwrap();
        sink.observe(src, 80, AttackerSignalType::PerimeterCamoFailed);
        sink.observe(src, 443, AttackerSignalType::PerimeterCamoFailed);
        sink.observe(other, 80, AttackerSignalType::PerimeterCamoFailed);

        let first = expect_observation(rx.recv().await.expect("first"));
        let second = expect_observation(rx.recv().await.expect("second"));
        let third = expect_observation(rx.recv().await.expect("third"));
        assert_eq!(first.perimeter_touch_count, 1);
        assert_eq!(second.perimeter_touch_count, 2, "same source across faces is one ledger");
        assert_eq!(third.perimeter_touch_count, 1, "a different source starts at one");
        assert!(second.confidence > first.confidence, "a repeat toucher scores higher");
    }
}
