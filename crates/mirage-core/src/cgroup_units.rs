//! Which systemd unit owns which cgroup id — read from the cgroup
//! filesystem, which is world-readable and not ptrace-gated.
//!
//! # Why this exists
//!
//! [`crate::sock_diag`] answers "which cgroup owns this socket" without
//! touching `/proc`. That answer is an integer. This module is what turns it
//! into a unit name, using the same identity the kernel itself uses: a
//! cgroup's id is its kernfs node id, which is the **inode number of its
//! directory** under `/sys/fs/cgroup`.
//!
//! Verified on the canary 2026-08-29 in both directions — the unknown
//! offender cgroup 448 in the kernel-security-event stream resolved to
//! `/sys/fs/cgroup/system.slice/systemd-journald.service` by inode, and the
//! sockets on `:22`/`:80`/`:443` resolved to 3112,
//! `mirage-perimeter.service`.
//!
//! This is the same id space Tier-2's `PROTECTED_CGROUP_MAP` keys on and the
//! same one the warden publishes per unit in its `UnitStateReport`, so a
//! deny event, a listening socket and a supervisor's unit row can all be
//! joined without a single privileged read.
//!
//! # Rebuilt every pass, never cached across one
//!
//! cgroup ids are inode numbers: they change when a unit restarts and again
//! on every boot. A map held across scans would silently attribute one
//! unit's socket to whatever previously occupied its id — the same class of
//! error as treating a pid as an identity. It is cheap to rebuild: a few
//! dozen `stat` calls on a directory tree already in the page cache.

use std::collections::HashMap;

/// Where the unified cgroup hierarchy is mounted on every fleet box.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How deep to walk below [`CGROUP_ROOT`].
///
/// Units live at `system.slice/<unit>` (depth 2) and, for templated or
/// nested units, at `system.slice/system-<x>.slice/<unit>` (depth 3). User
/// sessions add `user.slice/user-N.slice/session-N.scope` at the same depth.
/// Four is comfortably past both without walking a box's entire container
/// tree on a box that runs containers.
const MAX_DEPTH: usize = 4;

/// `cgroup id -> unit name`, e.g. `3112 -> "mirage-perimeter.service"`.
pub type CgroupUnits = HashMap<u64, String>;

/// Build the map by walking the cgroup filesystem.
///
/// Every entry that names a systemd unit is included — services, sockets,
/// scopes and slices alike — because the question a caller asks is "who owns
/// this socket", and the honest answer for a session-scoped process is its
/// scope, not nothing.
///
/// Unreadable subtrees are skipped rather than failing the whole map: a
/// container's nested hierarchy that this process cannot traverse costs
/// those entries, and the map stays correct for everything above it.
#[cfg(target_os = "linux")]
#[must_use]
pub fn read_map() -> CgroupUnits {
    let mut out = HashMap::new();
    walk(std::path::Path::new(CGROUP_ROOT), 0, &mut out);
    out
}

#[cfg(target_os = "linux")]
fn walk(dir: &std::path::Path, depth: usize, out: &mut CgroupUnits) {
    use std::os::unix::fs::MetadataExt;

    if depth > MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        // `file_type` avoids following symlinks into another subtree.
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let Ok(md) = std::fs::metadata(&path) else { continue };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_unit_name(name) {
            // The cgroup id IS the directory's inode number. Insert rather
            // than overwrite: two paths cannot share an inode here, and a
            // first-wins rule keeps the shallowest name.
            out.entry(md.ino()).or_insert_with(|| name.to_string());
        }
        walk(&path, depth + 1, out);
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn read_map() -> CgroupUnits {
    CgroupUnits::new()
}

/// Does this directory name a systemd unit?
///
/// The four suffixes systemd gives cgroup directories. `.slice` is included
/// deliberately: a process directly in a slice is owned by that slice, and
/// reporting it as unattributed would recreate the blindness this replaces
/// one level up.
#[must_use]
pub fn is_unit_name(name: &str) -> bool {
    name.ends_with(".service")
        || name.ends_with(".scope")
        || name.ends_with(".socket")
        || name.ends_with(".slice")
}

/// Is this unit one of the mirage daemons?
#[must_use]
pub fn is_mirage_unit(unit: &str) -> bool {
    crate::mirage_units::MIRAGE_UNITS.iter().any(|u| u.unit_name == unit)
}

/// Name the owner of a socket, given its cgroup id.
///
/// Three answers, not two. `None` means the cgroup id resolved to no unit
/// this box can name — a container's own hierarchy, a cgroup that went away
/// between the socket dump and this walk — and a caller must render that as
/// "unattributed", never as "not one of ours". Calling an unresolvable
/// cgroup foreign would turn a race into an alert.
#[must_use]
pub fn owner_of(map: &CgroupUnits, cgroup_id: u64) -> Option<&str> {
    map.get(&cgroup_id).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_systemd_cgroup_suffixes_are_units() {
        assert!(is_unit_name("mirage-perimeter.service"));
        assert!(is_unit_name("ssh.socket"));
        assert!(is_unit_name("session-3.scope"));
        assert!(is_unit_name("system.slice"));
        assert!(!is_unit_name("cgroup.procs"));
        assert!(!is_unit_name("init"));
        assert!(!is_unit_name(""));
    }

    #[test]
    fn mirage_units_are_recognised_and_others_are_not() {
        assert!(is_mirage_unit("mirage-secd.service"));
        assert!(is_mirage_unit("mirage-perimeter.service"));
        // The two that mattered on 2026-08-29: an OS logger and an
        // unmanaged SSH daemon are both NOT ours.
        assert!(!is_mirage_unit("systemd-journald.service"));
        assert!(!is_mirage_unit("ssh.service"));
    }

    /// An id nothing resolves must be `None`, so a caller cannot mistake a
    /// race for a foreign process.
    #[test]
    fn an_unresolvable_cgroup_is_unattributed_not_foreign() {
        let mut m = CgroupUnits::new();
        m.insert(3112, "mirage-perimeter.service".to_string());
        assert_eq!(owner_of(&m, 3112), Some("mirage-perimeter.service"));
        assert_eq!(owner_of(&m, 999_999), None);
    }
}
