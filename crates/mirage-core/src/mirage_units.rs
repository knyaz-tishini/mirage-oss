//! Flat exe_path + systemd unit_name allowlist for every mirage-shipped
//! binary, shared between two independent consumers with different needs:
//!
//! - `mirage-secd::protected_units::PROTECTED_BINARIES` (root-privileged,
//!   kill/scrape enforcement) sources its `exe_path` list from
//!   [`MIRAGE_UNITS`] here so the two allowlists can never drift apart.
//! - `mirage2sentry::box_inventory` (de-root, D0 arc3 Foundation plan §1.3)
//!   uses the `unit_name` field to classify a running PID as
//!   `BoxProcessClass::ExpectedMirage` via `systemctl show <unit_name> -p
//!   MainPID --value` — a classification path that does NOT depend on
//!   `/proc/[pid]/exe` (and therefore does not need `CAP_SYS_PTRACE`), unlike
//!   secd's own exact-`ExecStart`-path resolution.
//!
//! This module carries only what both consumers need in common: the exact
//! binary path (kept 1:1 with `PROTECTED_BINARIES`, informational for
//! sentry's classifier — see D0 plan §1.4) plus the systemd unit name. The
//! `kind: ProtectedUnitKind` kill-vs-scrape split stays local to
//! `mirage-secd::protected_units` — that distinction is secd's own concern,
//! irrelevant to sentry's read-only classifier.
//!
//! # A third consumer, added 2026-08-19: the box's own role set
//!
//! [`MirageUnit::role`] answers the question `mirage-warden`'s self-issued
//! identity mechanism needs — "which [`crate::identity::ServiceRole`] does
//! this unit correspond to" — from the table this workspace already
//! maintains, rather than a second, drifting one invented for that purpose.
//! `mirage-warden::derive_self_issue_roles` walks [`MIRAGE_UNITS`] and
//! includes a unit's role in the box's self-issued set exactly when that
//! unit's systemd file is present on disk — the one artefact
//! `mirage2operator`'s provisioning (`mint.rs`, `deploy_apply.rs`) actually
//! writes to express a per-box role decision; there is no separate roles
//! manifest anywhere in that pipeline.

use crate::identity::ServiceRole;
use crate::ids::NodeEpoch;

/// One mirage-shipped binary: its exact absolute on-disk path (mirrors
/// `mirage-secd::protected_units::ProtectedBinary::exe_path` exactly), the
/// systemd unit name that resolves it via `systemctl show`, and which
/// [`ServiceRole`] (if any) running this unit means the box performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirageUnit {
    /// Exact absolute `ExecStart` binary path — informational for sentry's
    /// classifier (see module doc); the security-boundary use of this exact
    /// string lives in `mirage-secd::protected_units::PROTECTED_BINARIES`.
    pub exe_path: &'static str,
    /// systemd unit name (with `.service` suffix), e.g.
    /// `"mirage2monitor-v2.service"`.
    pub unit_name: &'static str,
    /// The [`ServiceRole`] this unit corresponds to, or `None` when it
    /// deliberately has none — see [`STANDALONE_NODE`]'s own doc for the
    /// one case that applies to today. `None` here is a fact about the
    /// unit, stated explicitly, never an omission a reader has to notice by
    /// its absence from a separate mapping.
    pub role: Option<ServiceRole>,
}

pub const MONITOR: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage2monitor-v2",
    unit_name: "mirage2monitor-v2.service",
    role: Some(ServiceRole::Monitor),
};
pub const NODE: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-node-v2",
    unit_name: "mirage-node-v2.service",
    role: Some(ServiceRole::Node { epoch: NodeEpoch::V2 }),
};
pub const DB_WORKER: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-db-worker",
    unit_name: "mirage-db-worker.service",
    role: Some(ServiceRole::DbWorker),
};
pub const SECD: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-secd",
    unit_name: "mirage-secd.service",
    role: Some(ServiceRole::Secd),
};
pub const WARDEN: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-warden",
    unit_name: "mirage-warden.service",
    role: Some(ServiceRole::Warden),
};
pub const SENTRY: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-sentry",
    unit_name: "mirage-sentry.service",
    role: Some(ServiceRole::Sentry),
};
pub const MSHD: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-mshd",
    unit_name: "mirage-mshd.service",
    role: Some(ServiceRole::Mshd),
};
/// NOTE (grounding deviation, D0): `protected_units::PROTECTED_BINARIES`
/// carries `exe_path = "/usr/local/bin/standalone-node"` (no `-v2` suffix),
/// while `mirage2operator/crates/operator-box/src/deploy_spec.rs` renders
/// the REAL deployed binary/unit as `standalone-node-v2`
/// (`/usr/local/bin/standalone-node-v2`, unit `standalone-node-v2.service`).
/// This module mirrors `PROTECTED_BINARIES`'s exe_path 1:1 (read-only
/// refactor, no behavior change) rather than silently fixing that
/// pre-existing drift — flagged here, not corrected, since correcting it is
/// secd's allowlist to own and is out of scope for this D0 task.
///
/// `role: None` — the AWG standalone-node stack is a foreign-wire product
/// outside the native Mirage identity system entirely: it has no
/// `ServiceRole` variant, no `DeclaredIdentity`, and no machine-capsule
/// slice, so there is nothing here to map it to. Stated explicitly rather
/// than left to default, per this field's own doc.
pub const STANDALONE_NODE: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/standalone-node",
    unit_name: "standalone-node.service",
    role: None,
};
/// The perimeter daemon (`ServiceRole::Perimeter`) — added 2026-08-02, arc3
/// core/periphery split. NOT yet mirrored into
/// `mirage-secd::protected_units::PROTECTED_BINARIES`: that allowlist is
/// secd's own and out of scope for this crate to edit unilaterally (see
/// this module's own doc — sentry's classifier use of this list is
/// informational, it does not itself grant Tier2 protection). Until secd's
/// list is updated to match, the perimeter binary is NOT covered by Tier2
/// kill/memory-read protection the way every other listed unit is — flagged
/// here, not silently assumed fixed.
pub const PERIMETER: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-perimeter",
    unit_name: "mirage-perimeter.service",
    role: Some(ServiceRole::Perimeter),
};

/// The edge box's client-facing unit (edge-as-entry, 2026-09-24): it
/// terminates the customer's client behind the perimeter's EdgeEntrance faces
/// and carries the customer's streams into the mesh as the owner of its own
/// chains. It supersedes cli2's `mirage-chain-supervisor`, which never runs on
/// a box any more. `role: Some(ServiceRole::Edge)`: the unit's presence is
/// exactly what makes a box an edge.
pub const EDGE: MirageUnit = MirageUnit {
    exe_path: "/usr/local/bin/mirage-edge",
    unit_name: "mirage-edge.service",
    role: Some(ServiceRole::Edge),
};

/// The full mirage-binary allowlist. Historically 1:1 with
/// `mirage-secd::protected_units::PROTECTED_BINARIES` (same entries, same
/// order) minus the kill-vs-scrape `kind` split — as of [`PERIMETER`]'s
/// addition that parity is broken on purpose (see its own doc) until
/// secd's allowlist is updated to match. [`EDGE`] is mirrored into
/// `PROTECTED_BINARIES` as `ScrapeOnly`.
pub const MIRAGE_UNITS: &[MirageUnit] = &[
    MONITOR,
    NODE,
    DB_WORKER,
    SECD,
    WARDEN,
    SENTRY,
    MSHD,
    STANDALONE_NODE,
    PERIMETER,
    EDGE,
];

/// Exact match of `path` against [`MIRAGE_UNITS`] — mirrors
/// `protected_units::kind_of_exe`'s discipline (never a prefix/glob match).
#[must_use]
pub fn unit_name_for_exe(path: &str) -> Option<&'static str> {
    MIRAGE_UNITS.iter().find(|u| u.exe_path == path).map(|u| u.unit_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_non_empty() {
        assert!(!MIRAGE_UNITS.is_empty());
    }

    #[test]
    fn allowlist_has_ten_entries() {
        // 8 historically 1:1 with mirage-secd::protected_units::
        // PROTECTED_BINARIES, plus PERIMETER and EDGE.
        assert_eq!(MIRAGE_UNITS.len(), 10);
    }

    #[test]
    fn every_exe_path_is_absolute_and_unique() {
        let mut paths: Vec<&str> = MIRAGE_UNITS.iter().map(|u| u.exe_path).collect();
        for p in &paths {
            assert!(p.starts_with('/'), "exe_path must be absolute: {p}");
        }
        paths.sort_unstable();
        let mut deduped = paths.clone();
        deduped.dedup();
        assert_eq!(paths, deduped, "MIRAGE_UNITS exe_path entries must be unique");
    }

    #[test]
    fn every_unit_name_ends_with_dot_service() {
        for u in MIRAGE_UNITS {
            assert!(u.unit_name.ends_with(".service"), "{} must end with .service", u.unit_name);
        }
    }

    #[test]
    fn unit_name_for_exe_hits_and_misses() {
        assert_eq!(
            unit_name_for_exe("/usr/local/bin/mirage-db-worker"),
            Some("mirage-db-worker.service")
        );
        assert_eq!(
            unit_name_for_exe("/usr/local/bin/mirage2monitor-v2"),
            Some("mirage2monitor-v2.service")
        );
        assert_eq!(unit_name_for_exe("/tmp/mirage-db-worker"), None);
        assert_eq!(unit_name_for_exe(""), None);
    }

    /// Exactly one unit has no `ServiceRole` today, named explicitly rather
    /// than merely absent from some other mapping — see [`STANDALONE_NODE`]'s
    /// own doc for why the AWG stack has none.
    #[test]
    fn exactly_standalone_node_has_no_service_role() {
        let roleless: Vec<&str> =
            MIRAGE_UNITS.iter().filter(|u| u.role.is_none()).map(|u| u.unit_name).collect();
        assert_eq!(roleless, vec!["standalone-node.service"]);
    }

    /// Every OTHER unit names a role, and no two units claim the same one —
    /// a role appearing twice would make "which unit file proves this role
    /// is present" ambiguous for `mirage-warden`'s derivation.
    #[test]
    fn every_named_role_is_claimed_by_exactly_one_unit() {
        let roles: Vec<ServiceRole> = MIRAGE_UNITS.iter().filter_map(|u| u.role).collect();
        let mut deduped = roles.clone();
        deduped.dedup();
        let mut sorted = roles.clone();
        sorted.sort_by_key(|r| r.to_string());
        let mut sorted_deduped = sorted.clone();
        sorted_deduped.dedup();
        assert_eq!(sorted.len(), sorted_deduped.len(), "a role must not be claimed by two units");
        assert_eq!(
            roles.len(),
            MIRAGE_UNITS.len() - 1,
            "exactly one unit (standalone-node) has none"
        );
    }

    #[test]
    fn node_carries_the_v2_epoch_matching_its_unit_name() {
        assert_eq!(NODE.unit_name, "mirage-node-v2.service");
        assert_eq!(NODE.role, Some(ServiceRole::Node { epoch: NodeEpoch::V2 }));
    }

    #[test]
    fn perimeter_role_matches_the_unit_the_module_doc_names() {
        assert_eq!(PERIMETER.role, Some(ServiceRole::Perimeter));
    }
}
