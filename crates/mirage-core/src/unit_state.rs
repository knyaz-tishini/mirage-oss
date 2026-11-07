//! What the supervisor knows about the units it started, as a typed report.
//!
//! # Why this exists
//!
//! Until 2026-08-28 nothing on a box published unit identity. Every consumer
//! that wanted "which binary is running, since when" went and scraped for it:
//! `mirage-sentry` walked `/proc/<pid>/fd/*` (denied by our own Tier-2 for
//! every protected daemon — ~1700 kernel deny events per 30 s scan, and an
//! empty result), `mirage-secd` counted ports with no owner, and the operator
//! had no per-service version readout at all beyond the monitor
//! (`GET /fleet/versions` returns `service: monitor` and nothing else).
//!
//! The information was never hard to get. It was being asked of the wrong
//! party. `mirage-warden` STARTED these processes: it knows the unit, it can
//! ask systemd for the pid and the start timestamp, and it can hash the file
//! on disk — none of which touches `/proc/<pid>/` and none of which is
//! ptrace-gated. This module is the shape of that answer.
//!
//! See `docs/mirage/plans/instrument-truth-arc-2026-08-28.md`, "Resolved
//! design — collection is distributed, the model is one".
//!
//! # Why the hash can be legitimately absent
//!
//! [`ExecHash::DeniedByOwnPolicy`] is not an error path. Tier-2's `file_open`
//! hook denies opening the protected binary from any cgroup that is ITSELF in
//! the protected set (axis I, `BpfFileDeny`), and the warden's own cgroup is
//! in that set. So a running warden cannot read `/usr/local/bin/mirage-warden`
//! — measured 2026-08-28: `dd: failed to open ...: Operation not permitted`.
//! The warden therefore hashes its own image once at startup, BEFORE it arms
//! Tier-2, and reports that value with [`ExecHash::HashedAtBoot`]; every other
//! unit is re-hashed live. A report that could not say which of those two it
//! is would be worth less than no report.

use serde::{Deserialize, Serialize};

/// How the `exec_sha256` field came to be — or why it is absent.
///
/// Absence is never rendered as a plain `None` the reader has to interpret:
/// "we could not look", "we looked and it is gone", and "our own kernel
/// policy forbids looking" are three different facts about the box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecHash {
    /// Hashed from disk on this observation.
    Hashed { sha256: String },
    /// Hashed once at supervisor startup, before Tier-2 was armed, because
    /// the running supervisor is forbidden to open this path afterwards.
    /// Applies to the supervisor's own image. See this module's doc.
    HashedAtBoot { sha256: String },
    /// Our own `file_open` deny refused the read. Carries the errno text.
    DeniedByOwnPolicy { detail: String },
    /// The `ExecStart` path does not exist on disk.
    Missing,
    /// Anything else — carries the reason rather than collapsing to `None`.
    Unreadable { detail: String },
}

impl ExecHash {
    /// The hex digest if one is known, whichever way it was obtained.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        match self {
            ExecHash::Hashed { sha256 } | ExecHash::HashedAtBoot { sha256 } => Some(sha256),
            _ => None,
        }
    }

    /// Short stable token for logs and tables.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            ExecHash::Hashed { .. } => "hashed",
            ExecHash::HashedAtBoot { .. } => "hashed-at-boot",
            ExecHash::DeniedByOwnPolicy { .. } => "denied-by-own-policy",
            ExecHash::Missing => "missing",
            ExecHash::Unreadable { .. } => "unreadable",
        }
    }
}

/// What systemd answered about a unit's main process.
///
/// Mirrors `mirage_secd::hardening::UnitPid`'s three-way discipline: "systemd
/// did not answer" must never render as "the unit is not running". That
/// conflation restart-stormed three boxes on 2026-07-28.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnitPidState {
    /// systemd named a live main process.
    Running { pid: u32 },
    /// systemd answered, and the unit has no main process.
    NotRunning,
    /// systemd did not answer. Carries why.
    Unknown { detail: String },
}

/// One unit's state as the supervisor knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStateRow {
    /// systemd unit name, e.g. `"mirage-secd.service"`.
    pub unit: String,
    /// The declared `ExecStart` path this supervisor expects to run.
    pub exec_path: String,
    pub pid: UnitPidState,
    /// Kernel cgroup id of the unit's cgroup, low 32 bits — the SAME space
    /// Tier-2's `PROTECTED_CGROUP_MAP` keys on, so a reader can join this
    /// report against a kernel deny event's `offender_cgroup_id` without
    /// guessing. `None` when the unit is not running.
    pub cgroup_id: Option<u64>,
    pub exec_size: Option<u64>,
    /// `ExecStart` file mtime, ms since epoch — deploy time, not start time.
    pub exec_mtime_ms: Option<u64>,
    pub exec_hash: ExecHash,
    /// `ExecMainStartTimestamp`, ms since epoch.
    pub started_at_ms: Option<u64>,
    /// The supervisor observed this unit's image hash CHANGE since it first
    /// recorded one this boot. `screen`'s `exe_replaced`, locally detected: a
    /// replaced binary under a running supervisor is a fact worth carrying
    /// even when the mesh is down.
    pub exec_replaced_since_boot: bool,
    /// How many live processes inside this unit's own cgroup this supervisor
    /// most recently counted as matching its main binary's exe path. Only
    /// ever checked for a unit in `mirage_secd::surface_denylist::
    /// MANAGED_RESTART_TARGETS` (`mirage-warden::instance_guard`, a separate
    /// crate, is the one that counts) — `0` for every other unit, and for a
    /// checked unit this supervisor has not observed running yet this boot.
    /// `#[serde(default)]` so a report from a warden that predates this field
    /// still parses in full.
    #[serde(default)]
    pub instances: u32,
    /// This unit's current duplicate-instance verdict, if this box checks
    /// for one. See [`DuplicateInstanceState`]. `#[serde(default)]` for the
    /// same reason as `instances`.
    #[serde(default)]
    pub duplicate_state: DuplicateInstanceState,
    /// Which signal most recently identified this unit's matched processes —
    /// `Exe` when `/proc/<pid>/exe` was readable, `Comm` when it was denied
    /// (Tier2's `file_open`/readlink deny reaches the warden's own reads too,
    /// not only a protected peer's) and the guard fell back to
    /// `/proc/<pid>/comm`. `None` for a unit this box does not
    /// duplicate-check, one it has not observed running yet this boot, or a
    /// report from a warden that predates this field.
    ///
    /// This field exists so a report can never again look healthy while
    /// blind: `tr-hostkey-203.0.113.14` (2026-09-23) read `instances: 0` for
    /// three running units because every `/proc/<pid>/exe` readlink was
    /// denied by Tier2 and nothing else was tried — the guard could not see
    /// a duplicate even where one existed. `#[serde(default)]` for the same
    /// reason as `instances`: a report missing this field must read as "we
    /// don't know," never as a silent claim that exe resolution works.
    #[serde(default)]
    pub match_by: Option<MatchSignal>,
}

/// The report-facing shape of `mirage-warden::instance_guard::InstanceState`
/// for one managed unit — minus the unit name, which the [`UnitStateRow`]
/// this rides in already carries.
///
/// The DEFAULT is [`DuplicateInstanceState::Healthy`], deliberately the same
/// value a genuinely single-instance unit reports: an older warden's report
/// (predates this field) and a checked-and-healthy unit must read alike,
/// never as "duplicated" by omission.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DuplicateInstanceState {
    /// Zero or one matching process, or this unit is not one this box
    /// duplicate-checks.
    #[default]
    Healthy,
    /// More than one live process inside this unit's own cgroup resolves to
    /// the SAME main binary. `pids` names every one of them; `main_pid` is
    /// whichever one systemd currently calls MainPID, when known.
    Duplicate {
        pids: Vec<u32>,
        main_pid: Option<u32>,
        /// The healer already tried a full-unit kill and the duplicate came
        /// back without this unit ever being observed healthy for a
        /// sustained period — automatic healing is suspended for this unit
        /// until it is next observed healthy. `#[serde(default)]` (`false`)
        /// so a report from a warden that predates this field still parses,
        /// reading as "still trying," never as a silent, invisible give-up.
        #[serde(default)]
        heal_gave_up: bool,
    },
    /// systemd reports this unit's main process running, but the warden
    /// could resolve NEITHER `/proc/<pid>/exe` NOR `/proc/<pid>/comm` to the
    /// unit's main binary for any process in its own cgroup this tick — see
    /// `mirage-warden::instance_guard::InstanceState::IdentityUnresolvable`.
    /// A named state, never collapsed into [`DuplicateInstanceState::Healthy`]:
    /// "0 instances, all healthy" for a unit systemd itself calls alive is
    /// exactly the blind spot Tier2's own `/proc/<pid>/exe` denial created —
    /// measured on `tr-hostkey-203.0.113.14`, 2026-09-23. Never healed; a
    /// full-unit kill needs to know it is acting on a genuine duplicate, and
    /// this state means the guard cannot tell.
    IdentityUnresolvable { main_pid: Option<u32> },
}

/// Which signal identified a process as a live copy of a managed unit's main
/// binary, for [`UnitStateRow::match_by`].
///
/// `/proc/<pid>/exe` is the preferred signal whenever the kernel lets it be
/// read — an exact path match. `/proc/<pid>/comm` is the fallback: the
/// kernel task comm, at most 15 bytes (`TASK_COMM_LEN - 1`), read as a plain
/// procfs stat field rather than through `access_remote_vm` the way
/// `/proc/<pid>/cmdline` is — the same memory-read path Tier2's own deny
/// hook covers. A box where Tier2 denies `/proc/<pid>/exe` even to the
/// warden itself (measured `tr-hostkey-203.0.113.14`, 2026-09-23) still
/// answers `comm`, which is why this fallback exists at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchSignal {
    Exe,
    Comm,
}

/// What the perimeter said about its own faces, or why it did not say.
///
/// Three states, not two, mirroring
/// `mirage_secd::perimeter_admission::PerimeterAdmission`: collapsing
/// `NotServing` into `Unreadable` loses the difference between the ordinary
/// state before the perimeter starts and something actually being wrong.
///
/// This rides in the supervisor's report because the perimeter is the ONLY
/// party that knows whether its own `bind` succeeded, and until 2026-08-28
/// that knowledge left the box nowhere: `tr-hostkey-203.0.113.14` retried
/// `:22` every minute to attempt 9973 against an OS `sshd` that had taken
/// the port, wrote one WARN a minute about it, and read green in every
/// fleet instrument the operator had.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FaceReport {
    /// This supervisor does not publish a face report at all — it predates
    /// the field. The DEFAULT, and deliberately not `NotServing`: a warden
    /// too old to ask must never read as a perimeter that is down. During
    /// any roll the fleet holds both, and the difference between "we did
    /// not ask" and "the front door is dark" is the entire point of this
    /// type.
    #[default]
    NotReported,
    /// The perimeter answered with its configured face list.
    Faces { faces: Vec<crate::perimeter_query::FaceState> },
    /// Nobody holds the query channel — the perimeter has not bound this
    /// boot, or is between processes.
    NotServing,
    /// The channel is held but the list could not be read. A fault.
    Unreadable { detail: String },
}

impl FaceReport {
    /// Faces that are configured but NOT bound right now — the ones a
    /// reader has to look at. Empty when the perimeter did not answer,
    /// which is why callers must check the variant too and never read an
    /// empty list as "all faces healthy".
    #[must_use]
    pub fn dark(&self) -> Vec<&crate::perimeter_query::FaceState> {
        match self {
            FaceReport::Faces { faces } => faces.iter().filter(|f| !f.bound).collect(),
            _ => Vec::new(),
        }
    }
}

/// The whole report, one per box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitStateReport {
    pub observed_at_ms: u64,
    /// Wall-clock ms at which the supervisor process itself started, so a
    /// reader can tell "no replacement seen" from "this supervisor has only
    /// been watching for nine seconds".
    pub supervisor_started_at_ms: u64,
    pub units: Vec<UnitStateRow>,
    /// The box's front door, as the only process that can know it sees it.
    /// See [`FaceReport`]. `#[serde(default)]` so a report from a warden
    /// that predates this field still parses in full — dropping the WHOLE
    /// report because one field is absent is worse than the missing field
    /// it was meant to catch.
    #[serde(default)]
    pub faces: FaceReport,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_hash_states_are_distinguishable() {
        assert_eq!(ExecHash::Missing.token(), "missing");
        assert_eq!(
            ExecHash::DeniedByOwnPolicy { detail: "EPERM".into() }.token(),
            "denied-by-own-policy"
        );
        assert!(ExecHash::Missing.sha256().is_none());
        assert!(ExecHash::DeniedByOwnPolicy { detail: "x".into() }.sha256().is_none());
    }

    #[test]
    fn boot_hash_still_reads_as_a_digest() {
        let h = ExecHash::HashedAtBoot { sha256: "abc".into() };
        assert_eq!(h.sha256(), Some("abc"));
        assert_eq!(h.token(), "hashed-at-boot");
    }

    #[test]
    fn report_round_trips_as_json() {
        let r = UnitStateReport {
            observed_at_ms: 1,
            supervisor_started_at_ms: 0,
            units: vec![UnitStateRow {
                unit: "mirage-secd.service".into(),
                exec_path: "/usr/local/bin/mirage-secd".into(),
                pid: UnitPidState::Running { pid: 7 },
                cgroup_id: Some(3910),
                exec_size: Some(10),
                exec_mtime_ms: Some(2),
                exec_hash: ExecHash::Hashed { sha256: "ff".into() },
                started_at_ms: Some(3),
                exec_replaced_since_boot: false,
                instances: 1,
                duplicate_state: DuplicateInstanceState::Healthy,
                match_by: Some(MatchSignal::Exe),
            }],
            faces: FaceReport::NotServing,
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: UnitStateReport = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r, back);
    }

    /// A duplicate verdict round-trips with every pid preserved, not just
    /// the count.
    #[test]
    fn a_duplicate_state_round_trips_with_its_pids() {
        let r = UnitStateReport {
            observed_at_ms: 1,
            supervisor_started_at_ms: 0,
            units: vec![UnitStateRow {
                unit: "mirage-node-v2.service".into(),
                exec_path: "/usr/local/bin/mirage-node-v2".into(),
                pid: UnitPidState::Running { pid: 501 },
                cgroup_id: Some(4200),
                exec_size: Some(10),
                exec_mtime_ms: Some(2),
                exec_hash: ExecHash::Hashed { sha256: "ff".into() },
                started_at_ms: Some(3),
                exec_replaced_since_boot: false,
                instances: 2,
                duplicate_state: DuplicateInstanceState::Duplicate {
                    pids: vec![409, 501],
                    main_pid: Some(501),
                    heal_gave_up: true,
                },
                match_by: Some(MatchSignal::Comm),
            }],
            faces: FaceReport::NotServing,
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: UnitStateReport = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r, back);
    }

    /// An `IdentityUnresolvable` verdict round-trips, and a report missing
    /// `match_by` entirely (a warden that predates this field) still parses,
    /// reading as "we don't know" rather than failing the whole report.
    #[test]
    fn identity_unresolvable_round_trips_and_match_by_defaults_to_unknown() {
        let r = UnitStateReport {
            observed_at_ms: 1,
            supervisor_started_at_ms: 0,
            units: vec![UnitStateRow {
                unit: "mirage-db-worker.service".into(),
                exec_path: "/usr/local/bin/mirage-db-worker".into(),
                pid: UnitPidState::Running { pid: 701 },
                cgroup_id: Some(4300),
                exec_size: Some(10),
                exec_mtime_ms: Some(2),
                exec_hash: ExecHash::Hashed { sha256: "ff".into() },
                started_at_ms: Some(3),
                exec_replaced_since_boot: false,
                instances: 0,
                duplicate_state: DuplicateInstanceState::IdentityUnresolvable { main_pid: Some(701) },
                match_by: None,
            }],
            faces: FaceReport::NotServing,
        };
        let s = serde_json::to_string(&r).expect("serialize");
        let back: UnitStateReport = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r, back);

        let legacy = r#"{"unit":"x","exec_path":"/x","pid":{"kind":"running","pid":1},
            "cgroup_id":null,"exec_size":null,"exec_mtime_ms":null,
            "exec_hash":{"kind":"missing"},"started_at_ms":null,
            "exec_replaced_since_boot":false}"#;
        let row: UnitStateRow = serde_json::from_str(legacy).expect("legacy row parses");
        assert_eq!(row.match_by, None);
    }

    /// A duplicate-state JSON blob from a warden that predates
    /// `heal_gave_up` still parses, reading as "still trying" (`false`) —
    /// never a hard deserialize failure, and never a silent "gave up" that
    /// nobody wrote.
    #[test]
    fn a_duplicate_state_without_heal_gave_up_parses_as_still_trying() {
        let legacy = r#"{"kind":"duplicate","pids":[409,501],"main_pid":501}"#;
        let back: DuplicateInstanceState =
            serde_json::from_str(legacy).expect("legacy duplicate state parses");
        assert_eq!(
            back,
            DuplicateInstanceState::Duplicate {
                pids: vec![409, 501],
                main_pid: Some(501),
                heal_gave_up: false,
            }
        );
    }

    /// A face list that could not be read must never render as "no dark
    /// faces". `dark()` returns empty for BOTH, so the variant is the only
    /// thing that separates them and a caller has to see it.
    #[test]
    fn an_unread_face_list_is_not_an_empty_one() {
        assert!(FaceReport::NotServing.dark().is_empty());
        assert!(FaceReport::Unreadable { detail: "x".into() }.dark().is_empty());
        assert!(FaceReport::Faces { faces: vec![] }.dark().is_empty());
        assert!(FaceReport::NotReported.dark().is_empty());
        assert_ne!(FaceReport::NotServing, FaceReport::Faces { faces: vec![] });
        // The one that matters during a roll: a supervisor too old to ask
        // must not read as a perimeter that is down.
        assert_ne!(FaceReport::NotReported, FaceReport::NotServing);
    }

    /// A report from a warden that predates the face field parses in full,
    /// and says so, rather than failing and taking the unit rows with it.
    #[test]
    fn an_older_wardens_report_still_parses_and_says_it_did_not_ask() {
        let legacy = r#"{"observed_at_ms":5,"supervisor_started_at_ms":1,"units":[]}"#;
        let r: UnitStateReport = serde_json::from_str(legacy).expect("legacy report parses");
        assert_eq!(r.faces, FaceReport::NotReported);
        assert_eq!(r.observed_at_ms, 5);
    }

    /// `Unknown` must not be mistakable for `NotRunning` after a round trip —
    /// the distinction is the one that matters and it travels by tag.
    #[test]
    fn unknown_pid_is_not_not_running() {
        let u = UnitPidState::Unknown { detail: "systemctl exited 1".into() };
        let s = serde_json::to_string(&u).expect("serialize");
        assert!(s.contains("unknown"), "{s}");
        let back: UnitPidState = serde_json::from_str(&s).expect("deserialize");
        assert_ne!(back, UnitPidState::NotRunning);
    }
}
