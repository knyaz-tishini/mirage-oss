//! `harden_sandbox` — axis S self-sandbox (secd master plan §10, `frameworks §5`).
//!
//! Each root daemon that opts in calls [`harden_sandbox`] once at boot, AFTER
//! its own listener sockets/DB file handles are open and BEFORE it starts
//! processing any network input — Landlock's filesystem/network restriction
//! is irrevocable for the calling process once applied (structurally
//! self-only, per `frameworks §5`), so the caller must open everything it
//! will ever need first.
//!
//! # Two independent layers
//!
//! - **Seccomp** (`seccompiler`): a deny-list BPF filter. A tight *allow-list*
//!   is not attempted here — a root daemon's actual syscall surface (tokio's
//!   epoll/io_uring/futex/mmap mix) is too wide to enumerate safely without
//!   risking a self-lockout; instead this denies the specific syscalls a
//!   code-exec exploit inside the daemon would want (`ptrace`,
//!   `process_vm_readv`/`process_vm_writev`, `kexec_load`/`kexec_file_load`,
//!   `init_module`/`finit_module`/`delete_module`, `bpf`) and allows
//!   everything else. Denied calls return `EPERM` (not `KillProcess`) so a
//!   legitimate-but-unexpected call degrades to a visible error instead of an
//!   instant crash-loop.
//! - **Landlock** (`landlock` crate, ABI-gated): self-restricts the calling
//!   process's filesystem view to an explicit allow-list of paths (typically
//!   the daemon's own config/socket/DB directories) via
//!   [`SandboxProfile::fs_read_write`] / [`SandboxProfile::fs_read_only`],
//!   plus — on kernels new enough to expose Landlock ABI v4
//!   (`AccessNet::BindTcp`/`ConnectTcp`) — TCP bind/connect port scoping via
//!   [`SandboxProfile::tcp_bind_ports`] / [`SandboxProfile::tcp_connect_ports`].
//!   `BestEffort` compatibility mode (the crate default): on a kernel with a
//!   lower/no Landlock ABI, the ruleset degrades to whatever subset that
//!   kernel supports rather than failing outright — this is the ABI-gating
//!   the plan calls for, handled by the crate itself.
//!
//! Never panics, never returns `Err` — every knob that doesn't take is
//! recorded as a note in the returned [`SandboxReport`], mirroring
//! [`crate::HardeningReport`]'s existing contract.

use serde::Serialize;

/// Caller-supplied self-sandbox request. Every field is additive — an empty
/// profile (`SandboxProfile::default()`) still installs the seccomp deny-list
/// (which needs no caller input) but skips Landlock (which needs at least one
/// path to be meaningful).
#[derive(Debug, Clone, Default)]
pub struct SandboxProfile {
    /// Filesystem paths the daemon needs read+write access to (its own
    /// working/data/socket directories). Must already exist — Landlock rules
    /// are resolved against open file descriptors at ruleset-build time.
    pub fs_read_write: Vec<std::path::PathBuf>,
    /// Filesystem paths the daemon needs read-only access to (e.g. its own
    /// binary path, a shared config directory).
    pub fs_read_only: Vec<std::path::PathBuf>,
    /// TCP ports the daemon needs to `bind()` (server sockets). Empty = no
    /// restriction is requested for bind (Landlock only restricts what is
    /// explicitly listed as a scope with `handle_access`; skipping this list
    /// entirely, rather than requesting an empty-but-enforced scope, keeps
    /// this profile purely additive for a caller that doesn't care about
    /// port scoping).
    pub tcp_bind_ports: Vec<u16>,
    /// TCP ports the daemon needs to `connect()` out to.
    pub tcp_connect_ports: Vec<u16>,
}

/// Outcome of [`harden_sandbox`].
#[derive(Debug, Clone, Serialize, Default)]
pub struct SandboxReport {
    /// Seccomp deny-list filter installed successfully.
    pub seccomp_applied: bool,
    /// Landlock filesystem/network self-restriction was applied (to any
    /// degree — see `landlock_abi` for how much of the requested ruleset the
    /// running kernel actually enforced).
    pub landlock_applied: bool,
    /// The Landlock ABI level the running kernel actually supports (`0` if
    /// Landlock is entirely unavailable). Sourced from the crate's own
    /// `RestrictionStatus` report — never guessed.
    pub landlock_abi: u8,
    /// Why a given knob didn't take (unsupported kernel, wrong platform, …).
    pub notes: Vec<String>,
}

/// Apply the self-sandbox: seccomp deny-list + Landlock self-restriction
/// (ABI-gated to the richest ruleset the running kernel's Landlock ABI
/// level supports). Best-effort; never panics, never returns `Err`.
///
/// Call ONCE at daemon boot, after every socket/file the daemon will ever
/// need is already open (Landlock's `restrict_self()` is irrevocable for the
/// calling process — a path or port not listed here becomes permanently
/// unreachable to this process for the rest of its life).
#[cfg(target_os = "linux")]
pub fn harden_sandbox(profile: &SandboxProfile) -> SandboxReport {
    let mut r = SandboxReport::default();
    apply_seccomp(&mut r);
    apply_landlock(profile, &mut r);
    r
}

#[cfg(not(target_os = "linux"))]
pub fn harden_sandbox(_profile: &SandboxProfile) -> SandboxReport {
    let mut r = SandboxReport::default();
    r.notes.push("harden_sandbox: linux-only".into());
    r
}

// ── Seccomp ──────────────────────────────────────────────────────────────────

/// Syscalls denied outright for every daemon that self-sandboxes. Each is a
/// crown-jewel scrape/tamper primitive with no legitimate use inside a
/// Rust-only, non-JIT, non-debugging daemon:
///
/// - `ptrace` / `process_vm_readv` / `process_vm_writev` — the RAM-scrape
///   vector axis K's Tier-2 BPF-LSM deny also targets; denying it in
///   userspace via seccomp gives the SAME defense at Tier 0/1 (no kernel
///   BPF-LSM dependency) for this process's own memory specifically.
/// - `kexec_load` / `kexec_file_load` — kernel-replacement primitive.
/// - `init_module` / `finit_module` / `delete_module` — kernel module
///   load/unload (belt-and-suspenders alongside the `CAP_SYS_MODULE`
///   bounding-set drop — this holds even if the capability somehow leaks).
/// - `bpf` — this daemon never needs to load eBPF itself (secd's own Tier-2
///   loader runs before this filter is armed, if ever co-resident in the
///   same process — see the ordering note in `harden_sandbox`'s doc).
#[cfg(target_os = "linux")]
fn denied_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
    ]
}

#[cfg(target_os = "linux")]
fn apply_seccomp(r: &mut SandboxReport) {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    let arch: TargetArch = match std::env::consts::ARCH.try_into() {
        Ok(a) => a,
        Err(_) => {
            r.notes
                .push(format!("seccomp: unsupported arch '{}'", std::env::consts::ARCH));
            return;
        }
    };

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for syscall in denied_syscalls() {
        // Empty rule vec = "this syscall number always matches" → always
        // takes `match_action` (EPERM) regardless of arguments.
        rules.insert(syscall, vec![]);
    }

    let filter = match SeccompFilter::new(
        rules,
        SeccompAction::Allow,          // mismatch (everything not listed) → allow
        SeccompAction::Errno(libc::EPERM as u32), // match (the denied list) → EPERM, not a kill
        arch,
    ) {
        Ok(f) => f,
        Err(e) => {
            r.notes.push(format!("seccomp: filter build failed: {e}"));
            return;
        }
    };

    let program: BpfProgram = match filter.try_into() {
        Ok(p) => p,
        Err(e) => {
            r.notes.push(format!("seccomp: BPF compile failed: {e}"));
            return;
        }
    };

    match seccompiler::apply_filter(&program) {
        Ok(()) => r.seccomp_applied = true,
        Err(e) => r.notes.push(format!("seccomp: apply_filter failed: {e}")),
    }
}

// ── Landlock ─────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn apply_landlock(profile: &SandboxProfile, r: &mut SandboxReport) {
    use landlock::{
        Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    if profile.fs_read_write.is_empty()
        && profile.fs_read_only.is_empty()
        && profile.tcp_bind_ports.is_empty()
        && profile.tcp_connect_ports.is_empty()
    {
        r.notes
            .push("landlock: empty profile — nothing to restrict, skipped".into());
        return;
    }

    // Richest ABI this crate release knows about; `BestEffort` (the crate
    // default `CompatLevel`) transparently downgrades to whatever the
    // running kernel actually supports — the ABI-gating the plan calls for.
    let abi = ABI::V7;

    // `handle_access`/`add_rule` are CONSUMING builders (take `self` by value,
    // return the new value) — thread the value through each step; on any
    // failure, note it and bail (the value is already moved, so we cannot
    // continue building). Best-effort: never Err upward, never panic.
    let mut ruleset = Ruleset::default();
    match ruleset.handle_access(AccessFs::from_all(abi)) {
        Ok(rs) => ruleset = rs,
        Err(e) => {
            r.notes.push(format!("landlock: handle_access(fs) failed: {e}"));
            return;
        }
    }
    if !profile.tcp_bind_ports.is_empty() {
        match ruleset.handle_access(AccessNet::BindTcp) {
            Ok(rs) => ruleset = rs,
            Err(e) => {
                r.notes.push(format!("landlock: handle_access(net bind) failed: {e}"));
                return;
            }
        }
    }
    if !profile.tcp_connect_ports.is_empty() {
        match ruleset.handle_access(AccessNet::ConnectTcp) {
            Ok(rs) => ruleset = rs,
            Err(e) => {
                r.notes.push(format!("landlock: handle_access(net connect) failed: {e}"));
                return;
            }
        }
    }

    let mut created = match ruleset.create() {
        Ok(c) => c,
        Err(e) => {
            r.notes.push(format!("landlock: ruleset create failed: {e}"));
            return;
        }
    };

    for path in &profile.fs_read_write {
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(e) => {
                r.notes
                    .push(format!("landlock: open path {} failed: {e}", path.display()));
                continue;
            }
        };
        match created.add_rule(PathBeneath::new(fd, AccessFs::from_all(abi))) {
            Ok(c) => created = c,
            Err(e) => {
                r.notes
                    .push(format!("landlock: add_rule(rw {}) failed: {e}", path.display()));
                return;
            }
        }
    }

    for path in &profile.fs_read_only {
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(e) => {
                r.notes
                    .push(format!("landlock: open path {} failed: {e}", path.display()));
                continue;
            }
        };
        match created.add_rule(PathBeneath::new(fd, AccessFs::from_read(abi))) {
            Ok(c) => created = c,
            Err(e) => {
                r.notes
                    .push(format!("landlock: add_rule(ro {}) failed: {e}", path.display()));
                return;
            }
        }
    }

    for &port in &profile.tcp_bind_ports {
        match created.add_rule(NetPort::new(port, AccessNet::BindTcp)) {
            Ok(c) => created = c,
            Err(e) => {
                r.notes.push(format!("landlock: add_rule(bind {port}) failed: {e}"));
                return;
            }
        }
    }

    for &port in &profile.tcp_connect_ports {
        match created.add_rule(NetPort::new(port, AccessNet::ConnectTcp)) {
            Ok(c) => created = c,
            Err(e) => {
                r.notes.push(format!("landlock: add_rule(connect {port}) failed: {e}"));
                return;
            }
        }
    }

    match created.restrict_self() {
        Ok(status) => {
            r.landlock_abi = landlock_abi_number(&status);
            r.landlock_applied = status.ruleset != RulesetStatus::NotEnforced;
            if !status.no_new_privs {
                r.notes
                    .push("landlock: kernel did not set no_new_privs alongside the restriction".into());
            }
            if status.ruleset == RulesetStatus::PartiallyEnforced {
                r.notes
                    .push("landlock: kernel enforced only a subset of the requested ruleset".into());
            }
        }
        Err(e) => r.notes.push(format!("landlock: restrict_self failed: {e}")),
    }
}

/// Extract a plain numeric Landlock ABI level from the crate's
/// `RestrictionStatus.landlock` report, for the `SandboxReport` field —
/// never guessed, always the kernel's own reported value (or `0` if
/// Landlock is unavailable/not implemented).
#[cfg(target_os = "linux")]
fn landlock_abi_number(status: &landlock::RestrictionStatus) -> u8 {
    use landlock::{LandlockStatus, ABI};

    match status.landlock {
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => 0,
        LandlockStatus::Available { effective_abi, .. } => match effective_abi {
            ABI::Unsupported => 0,
            ABI::V1 => 1,
            ABI::V2 => 2,
            ABI::V3 => 3,
            ABI::V4 => 4,
            ABI::V5 => 5,
            ABI::V6 => 6,
            ABI::V7 => 7,
            // `ABI` is #[non_exhaustive]: a landlock-crate/kernel newer than
            // this build knows about — report the highest level we enumerate
            // (a newer ABI is a strict superset, so >=7 is honest-conservative).
            _ => 7,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_profile_never_panics() {
        let r = harden_sandbox(&SandboxProfile::default());
        // On non-Linux or with an empty profile this must be a documented
        // no-op, never a panic.
        let _ = r.seccomp_applied;
        let _ = r.landlock_applied;
    }

    #[test]
    fn report_serializes_to_json() {
        let r = SandboxReport::default();
        let v = serde_json::to_value(&r).expect("serialize");
        assert_eq!(v["seccomp_applied"], false);
        assert_eq!(v["landlock_applied"], false);
        assert!(v["notes"].is_array());
    }
}
