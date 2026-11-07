//! D0 — sentry live box inventory typed data model (arc3 Foundation, see
//! `docs/mirage/plans/arc3-foundation-d0-sentry-d1-prober-2026-07-24.md`
//! §1.2).
//!
//! Two families, mirroring the `box_profile` (1-row/machine LWW) vs
//! `kernel_security_event` (append-only per-machine ring) split already
//! established in `fact_signing.rs`:
//!
//! - [`BoxInventorySnapshotRow`] — "what's running RIGHT NOW", re-emitted on
//!   a slow content-hash-gated cadence (sentry-side `box_inventory.rs`).
//! - [`BoxInventoryTransitionRow`] — one state-CHANGE observation, appended
//!   on transition only into a bounded per-machine ring.
//!
//! Row/fact types live here; the canonical signing-bytes functions + their
//! `verify_*` counterparts live in `fact_signing.rs` alongside every other
//! fact's byte layout. No `serde_json::Value` appears anywhere in this
//! family — every field is typed.
//!
//! `sig_hex` / `originator_self_id` are plain (non-`Option`) `String`
//! fields, matching `BoxProfileRow`/`KernelSecurityEventRow`'s convention —
//! but unlike those two (which are ALWAYS mandatory-signed, no legacy path),
//! the monitor-side ingest handlers for this family grace-accept an EMPTY
//! `sig_hex`/`originator_self_id` pair when
//! `MIRAGE_MONITOR_REQUIRE_SIGNED_FACTS` is unset/off (verifier-first
//! rollout doctrine, `auth::require_signed_facts()`), verifying whenever the
//! pair is non-empty either way. See `sentries_api.rs`'s handlers for this
//! family.

use serde::{Deserialize, Serialize};

// ── 1-row-per-machine LWW snapshot ("what's running RIGHT NOW") ────────────

/// Live inventory summary + full lists, re-emitted on a slow cadence,
/// content-hash gated exactly like `BoxProfileRow`. LWW key = `machine_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxInventorySnapshotRow {
    /// LWW key: the canonical machine identifier (e.g. `ru-hostkey-203.0.113.10`).
    pub machine_id: String,
    /// Originator-stamped UNIX millisecond timestamp. Receivers skip the
    /// row when their local `updated_at_ms >= incoming`.
    pub updated_at_ms: u64,

    pub process_count: u32,
    pub foreign_process_count: u32,
    pub listening_port_count: u32,
    pub foreign_listening_port_count: u32,
    pub established_outbound_count: u32,

    pub processes: Vec<BoxProcessFact>,
    pub listeners: Vec<BoxListenerFact>,
    pub outbound: Vec<BoxOutboundConnFact>,
    pub log_levels: Vec<BoxUnitLogLevelFact>,

    /// Sentry's `DeclaredIdentity.self_id`. Empty when submitted unsigned
    /// (grace-accept path — see module doc).
    pub originator_self_id: String,
    /// Hex Ed25519 signature over
    /// [`crate::fact_signing::box_inventory_snapshot_signing_bytes`]. Empty
    /// when submitted unsigned.
    pub sig_hex: String,
}

/// One enumerated `/proc/[pid]` process observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxProcessFact {
    pub pid: u32,
    /// `/proc/[pid]/comm`, world-readable, kernel-truncated to 15 bytes.
    pub comm: String,
    /// `/proc/[pid]/exe` readlink target — empty when unresolvable (EACCES
    /// cross-UID without `CAP_SYS_PTRACE`, or the process is a kernel
    /// thread with no `exe` link).
    pub exe_path: String,
    pub uid: u32,
    /// `/proc/[pid]/status` `VmRSS`, world-readable, in KiB.
    pub rss_kb: u64,
    /// CPU busy percent over the collector's own two-sample window.
    pub cpu_pct: f32,
    pub uptime_secs: u64,
    /// [`BoxProcessClass`] discriminant.
    pub classification: u8,
}

/// Closed classification set for one enumerated process (D0 plan §1.2).
/// Encoded as a fixed enum byte in [`BoxProcessFact::classification`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxProcessClass {
    /// PID resolved to a known mirage systemd unit's `MainPID`
    /// (`mirage_core::mirage_units::MIRAGE_UNITS`).
    ExpectedMirage = 0,
    /// Not resolved to any known unit.
    Foreign = 1,
    /// Resolution attempted, ambiguous (race: unit restarted mid-scan).
    Unknown = 2,
}

impl BoxProcessClass {
    /// Map a raw discriminant byte back to the typed variant. Unknown
    /// discriminants collapse to `Unknown` (forward-compat, mirrors
    /// `KernelSecurityEventKind::from_u8`'s discipline).
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::ExpectedMirage,
            1 => Self::Foreign,
            _ => Self::Unknown,
        }
    }
}

/// One listening TCP/UDP socket, with best-effort owner attribution via the
/// `/proc/[pid]/fd` inode→pid join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxListenerFact {
    /// e.g. `"0.0.0.0:22"` / `"127.0.0.1:19446"`.
    pub bind_addr: String,
    /// `0` = tcp, `1` = udp.
    pub proto: u8,
    /// `0` if inode→pid resolution failed.
    pub owner_pid: u32,
    pub owner_comm: String,
    /// [`BindScope`] discriminant.
    pub bind_scope: u8,
    /// [`ListenerTag`] discriminant.
    pub tag: u8,
}

/// Closed bind-scope classification for [`BoxListenerFact::bind_scope`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindScope {
    Loopback = 0,
    Wildcard = 1,
    SpecificAddr = 2,
}

impl BindScope {
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Loopback,
            1 => Self::Wildcard,
            _ => Self::SpecificAddr,
        }
    }
}

/// Closed listener-ownership tag for [`BoxListenerFact::tag`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerTag {
    MirageService = 0,
    /// Reserved for a future deliberate decoy-listener feature — never
    /// emitted by the D0 collector.
    MirageDecoy = 1,
    Foreign = 2,
    /// The socket's owning process could not be resolved at all, so the
    /// collector knows nothing about who holds it — **not** a claim that it
    /// is foreign.
    ///
    /// Added 2026-08-04 after measuring that every Mirage listener on every
    /// Tier2-enforcing box was being reported as [`Self::Foreign`]. The
    /// collector attributes a socket by walking `/proc/<pid>/fd/*`, and
    /// Tier2's memory-read policy denies `readlink` on those entries for
    /// exactly the mirage daemons — `read_dir` succeeds, every `read_link`
    /// comes back empty, so the inode→pid map is empty and every port the
    /// box itself opened looked like somebody else's. Measured the same day:
    /// 11/11 and 13/13 listeners tagged foreign on the six enforcing boxes
    /// against 5/13 on the three that (wrongly) had no `lsm=bpf`.
    ///
    /// The consequence was not a cosmetic counter: the
    /// `UnexpectedPublicListenerOpened` transition fires on a wildcard
    /// [`Self::Foreign`] listener, so it fired on Mirage's own 443/80/8080/
    /// 3000/19444 at every service restart — and a genuinely foreign public
    /// listener (an open recursive `unbound` on one box) sat inside that
    /// noise for a week.
    ///
    /// A box under its own kernel policy therefore cannot tell its own port
    /// from an implant's. The operator can: it holds the signed face list.
    /// So the collector reports the honest third state and the ours/foreign
    /// judgement moves to the reader that has the declaration.
    Unattributed = 3,
}

impl ListenerTag {
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::MirageService,
            1 => Self::MirageDecoy,
            3 => Self::Unattributed,
            // Unknown discriminants collapse to `Foreign`, the loud side: a
            // reader older than the producer sees `Unattributed` as
            // `Foreign`, which is exactly what it used to be told anyway.
            _ => Self::Foreign,
        }
    }
}

/// One established outbound TCP connection, with best-effort owner
/// attribution — the phone-home detection surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxOutboundConnFact {
    pub local_addr: String,
    /// `"<ip>:<port>"` — the phone-home detection target.
    pub remote_addr: String,
    /// `0` = tcp, `1` = udp.
    pub proto: u8,
    pub owner_pid: u32,
    pub owner_comm: String,
    /// [`BoxProcessClass`] discriminant — inherited from `owner_pid`
    /// resolution.
    pub classification: u8,
}

/// One mirage unit's `RUST_LOG` environment reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxUnitLogLevelFact {
    /// e.g. `"mirage2monitor-v2.service"`.
    pub unit_name: String,
    /// Raw `RUST_LOG` value from `systemctl show -p Environment`, empty if
    /// unset.
    pub rust_log: String,
    pub is_debug_or_trace: bool,
}

// ── append-only, bounded-ring, per-machine transition journal ──────────────

/// One state-CHANGE observation — append on transition only, mirrors
/// `KernelSecurityEventRow`'s shape exactly (append-only stream, not LWW).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxInventoryTransitionRow {
    pub machine_id: String,
    pub ts_ms: u64,
    /// [`BoxTransitionKind`] discriminant.
    pub kind: u8,
    /// Human string, e.g. `"pid=1234 comm=czy_agent exe=/opt/czy/agent"`.
    pub detail: String,
    /// `0` when not process-scoped (e.g. a mem-threshold cross).
    pub subject_pid: u32,
    /// Empty when not port/conn-scoped.
    pub subject_addr: String,
    /// Empty when submitted unsigned (grace-accept path — see module doc).
    pub originator_self_id: String,
    /// Hex Ed25519 signature over
    /// [`crate::fact_signing::box_inventory_transition_signing_bytes`].
    /// Empty when submitted unsigned.
    pub sig_hex: String,
}

/// Closed set of box-inventory transition classes (D0 plan §1.2).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxTransitionKind {
    Other = 0x00,
    ProcessAppeared = 0x01,
    ProcessVanished = 0x02,
    /// Subset of `ProcessAppeared`, called out for alerting.
    ForeignProcessAppeared = 0x03,
    ListenerOpened = 0x04,
    ListenerClosed = 0x05,
    /// Subset of `ListenerOpened`: wildcard-bound + foreign.
    UnexpectedPublicListenerOpened = 0x06,
    /// A foreign process opened its first `ESTABLISHED` outbound conn.
    OutboundPhoneHomeStarted = 0x07,
    /// `mem_used_pct` crossed a configured band.
    MemThresholdCrossed = 0x08,
    /// New OOM line since last scan (already collected by
    /// `mirage2sentry::machine_state`, wired into this diff loop only).
    OomEventObserved = 0x09,
    /// A unit's `RUST_LOG` flipped (e.g. into debug/trace).
    LogLevelChanged = 0x0a,
    /// systemd reported a unit failing, exiting non-zero, or being
    /// restarted after a failure — read from the box's own journal.
    ///
    /// Appended 2026-08-29. Nothing on a box read the journal's CONTENT
    /// until then: the only reader was `mirage-hostsec::journal`, scoped to
    /// sshd auth failures for the ban engine, and `machine_state::journal_mb`,
    /// which reads its DISK USAGE. "0 failed units" was established by hand,
    /// per box, every time anyone wanted to know.
    JournalUnitFailed = 0x0b,
    /// A unit is emitting sustained warnings or errors into the journal.
    ///
    /// This is the class the whole instrument-truth arc opened on.
    /// `mirage-perimeter` on `tr-hostkey-203.0.113.14` logged
    /// `bind failed — this face is DARK ... attempt=9973` once a minute for
    /// days. The fact was correct, current, and exactly what an operator
    /// needed; it went to the journal and nowhere else, while every fleet
    /// instrument read green. A daemon's WARN is not a fact until it leaves
    /// the box as one.
    JournalServiceComplaint = 0x0c,
    /// A new persistence point appeared: a systemd unit became enabled, or a
    /// cron file was created.
    ///
    /// Appended 2026-08-29. Nothing on a mirage box has ever inventoried
    /// what will run at the NEXT boot. Every other transition in this list
    /// is about what is running now, which is the half an attacker cleans up
    /// after; the half they leave behind is a unit file and a crontab line.
    PersistenceAdded = 0x0d,
    /// An existing persistence point changed what it runs -- a unit's
    /// `ExecStart`, or a cron file's content.
    PersistenceModified = 0x0e,
    /// A persistence point went away. Reported for symmetry, and because a
    /// unit that quietly stops being enabled is how a box drifts off its own
    /// deployment.
    PersistenceRemoved = 0x0f,
    /// A binary was seen running on this box for the FIRST time — first on
    /// the box, not first since this daemon restarted: the registry behind
    /// it survives reboots.
    ///
    /// Appended 2026-08-29. `mirage-warden` hashes the `ExecStart` of every
    /// unit IT spawned and flags a replacement within one boot; nothing
    /// covered a foreign binary, across a reboot, or a process no supervisor
    /// started — which is every binary an intruder would actually run.
    ExeFirstSeen = 0x10,
    /// A path this box has seen before is now different bytes. A package
    /// upgrade produces this too, and that is correct: a binary changing
    /// under a running fleet is worth one line whoever changed it.
    ExeHashChanged = 0x11,
    /// A process is running from a directory nothing legitimate runs from
    /// (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`). Needs no history and
    /// fires on the first tick.
    ExeUntrustedPath = 0x12,
    /// One observation of a foreign process holding an outbound connection,
    /// emitted on every inventory tick the connection is still there — not
    /// once when it appears.
    ///
    /// [`Self::OutboundPhoneHomeStarted`] is an EDGE: it fires when a
    /// foreign pid opens its first outbound connection and never again. That
    /// answers "did something start talking outward" and cannot answer "how
    /// often", because one row carries no interval. Periodicity is the whole
    /// question a beacon poses, and it needs a SERIES.
    ///
    /// So this kind is deliberately repetitive where the rest of this enum is
    /// deliberately not. It is `Info` by construction and aggregates into one
    /// finding per `(machine, subject)` like every other kind, so the ring
    /// and the alert table see one row per endpoint however long the
    /// conversation lasts — the timestamps that make it a series live in
    /// `screen_events`, which is what the analysis reads.
    ///
    /// Appended 2026-08-31. What it is NOT: a record of every connection a
    /// box makes. Mirage's own wire between boxes is classified
    /// `ExpectedMirage` and never reaches here, and an accepted INBOUND
    /// session is excluded by the direction test that closed C25 — 968
    /// stored rows that were the internet dialling us, filed as us dialling
    /// out.
    OutboundConnObserved = 0x13,
}

impl BoxTransitionKind {
    /// Map a raw signed discriminant byte back to the typed variant.
    /// Unknown discriminants collapse to `Other` (forward-compat).
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::ProcessAppeared,
            0x02 => Self::ProcessVanished,
            0x03 => Self::ForeignProcessAppeared,
            0x04 => Self::ListenerOpened,
            0x05 => Self::ListenerClosed,
            0x06 => Self::UnexpectedPublicListenerOpened,
            0x07 => Self::OutboundPhoneHomeStarted,
            0x08 => Self::MemThresholdCrossed,
            0x09 => Self::OomEventObserved,
            0x0a => Self::LogLevelChanged,
            0x0b => Self::JournalUnitFailed,
            0x0c => Self::JournalServiceComplaint,
            0x0d => Self::PersistenceAdded,
            0x0e => Self::PersistenceModified,
            0x0f => Self::PersistenceRemoved,
            0x10 => Self::ExeFirstSeen,
            0x11 => Self::ExeHashChanged,
            0x12 => Self::ExeUntrustedPath,
            0x13 => Self::OutboundConnObserved,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_process_class_roundtrips_u8() {
        for c in [
            BoxProcessClass::ExpectedMirage,
            BoxProcessClass::Foreign,
            BoxProcessClass::Unknown,
        ] {
            assert_eq!(BoxProcessClass::from_u8(c as u8), c);
        }
    }

    #[test]
    fn box_process_class_unknown_discriminant_collapses() {
        assert_eq!(BoxProcessClass::from_u8(0xff), BoxProcessClass::Unknown);
    }

    #[test]
    fn bind_scope_roundtrips_u8() {
        for s in [BindScope::Loopback, BindScope::Wildcard, BindScope::SpecificAddr] {
            assert_eq!(BindScope::from_u8(s as u8), s);
        }
    }

    #[test]
    fn listener_tag_roundtrips_u8() {
        for t in [
            ListenerTag::MirageService,
            ListenerTag::MirageDecoy,
            ListenerTag::Foreign,
            ListenerTag::Unattributed,
        ] {
            assert_eq!(ListenerTag::from_u8(t as u8), t);
        }
    }

    #[test]
    fn listener_tag_unknown_discriminant_collapses_to_foreign() {
        assert_eq!(ListenerTag::from_u8(0xff), ListenerTag::Foreign);
    }

    #[test]
    fn box_transition_kind_roundtrips_u8() {
        for k in [
            BoxTransitionKind::Other,
            BoxTransitionKind::ProcessAppeared,
            BoxTransitionKind::ProcessVanished,
            BoxTransitionKind::ForeignProcessAppeared,
            BoxTransitionKind::ListenerOpened,
            BoxTransitionKind::ListenerClosed,
            BoxTransitionKind::UnexpectedPublicListenerOpened,
            BoxTransitionKind::OutboundPhoneHomeStarted,
            BoxTransitionKind::MemThresholdCrossed,
            BoxTransitionKind::OomEventObserved,
            BoxTransitionKind::LogLevelChanged,
        ] {
            assert_eq!(BoxTransitionKind::from_u8(k as u8), k);
        }
    }

    #[test]
    fn box_transition_kind_unknown_discriminant_collapses() {
        assert_eq!(BoxTransitionKind::from_u8(0xff), BoxTransitionKind::Other);
    }
}
