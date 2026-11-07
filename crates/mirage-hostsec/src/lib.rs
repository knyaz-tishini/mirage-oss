//! `mirage-hostsec` — mirage-local host-security recipes for the L2/L3
//! security vertical.
//!
//! Pattern COPIED from `servertoolkit-hardening` (one-directional
//! mirage <- stk; never a path-dep on stk — substrate master plan §5/§6).
//! This is the home for the host-security stack as it lands:
//!
//! - **now**: `harden_process()` — process-level lockdowns at daemon boot.
//! - **next (mirage-fw)**: nftables base policy (`inet fw`) + `mirage_banned`
//!   timed set + connection-rate meter, driven off the live listener
//!   inventory allowlist.
//! - **next (secd)**: sshd/posture probes + the sdjournal ban engine +
//!   the trust-tiered friend/foe discriminator.
//!
//! **This is the only mirage crate carrying `unsafe` libc FFI**, kept
//! isolated here exactly as stk isolates `servertoolkit-hardening` — the
//! `prctl(2)` / `mlockall(2)` / `setrlimit(2)` knobs are not exposed
//! through std, and confining the `unsafe` to one tiny crate makes review
//! trivial.
//!
//! ## Threat model
//!
//! Best-effort lockdowns that shrink what a hostile host root can scrape
//! from a running mirage daemon (monitor / node / sentry / secd / opbox).
//! Each function returns a [`HardeningReport`] of which knobs took — it
//! never panics and never returns `Err`, because on an unprivileged
//! process most of these are advisory ("the kernel refuses if it can't").
//!
//! ## Usage
//!
//! ```ignore
//! let report = mirage_hostsec::harden_process();
//! tracing::info!(?report, "host hardening applied");
//! ```
//!
//! Call ONCE at daemon boot, BEFORE any DB unseal or secret load, so a
//! later SIGSEGV cannot drop a core file with key material and a hostile
//! local process cannot `ptrace(PTRACE_ATTACH)` us.

pub mod journal;
pub mod nft;
pub mod sandbox;

use serde::Serialize;

/// Outcome of [`harden_process`]: which lockdowns took, plus free-form
/// notes for any that didn't (shown in logs so operators understand why).
#[derive(Debug, Clone, Serialize, Default)]
pub struct HardeningReport {
    /// `prctl(PR_SET_DUMPABLE, 0)` (Linux) / `setrlimit(RLIMIT_CORE, 0)` (macOS).
    pub no_core_dump: bool,
    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)` (Linux only).
    pub no_new_privs: bool,
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` — pages can't swap to disk.
    pub mlock_pages: bool,
    /// `/proc/self/coredump_filter` zeroed (Linux only) — belt-and-suspenders.
    pub coredump_filter_zeroed: bool,
    /// Why a given knob didn't take (unprivileged, wrong platform, …).
    pub notes: Vec<String>,
}

impl HardeningReport {
    /// `true` iff every applicable knob was set. Reporting only — do NOT
    /// gate behaviour on this (an operator may run without CAP_IPC_LOCK
    /// and that is still a valid deployment).
    pub fn all_applied(&self) -> bool {
        self.no_core_dump && self.no_new_privs && self.mlock_pages && self.coredump_filter_zeroed
    }
}

/// Apply every safe hardening knob. Best-effort; logs notes for any that
/// don't take. Never panics, never returns `Err`.
pub fn harden_process() -> HardeningReport {
    let mut r = HardeningReport::default();
    disable_core_dumps(&mut r);
    set_no_new_privs(&mut r);
    lock_pages(&mut r);
    zero_coredump_filter(&mut r);
    r
}

#[cfg(target_os = "linux")]
fn disable_core_dumps(r: &mut HardeningReport) {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) is well-defined + async-signal-safe.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_u64, 0_u64, 0_u64, 0_u64) };
    if rc == 0 {
        r.no_core_dump = true;
    } else {
        r.notes
            .push(format!("PR_SET_DUMPABLE failed (errno={})", errno_now()));
    }
}

#[cfg(target_os = "macos")]
fn disable_core_dumps(r: &mut HardeningReport) {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit with a valid rlimit pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if rc == 0 {
        r.no_core_dump = true;
    } else {
        r.notes.push(format!(
            "setrlimit(RLIMIT_CORE,0) failed (errno={})",
            errno_now()
        ));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn disable_core_dumps(r: &mut HardeningReport) {
    r.notes
        .push("disable_core_dumps: unsupported on this platform".into());
}

#[cfg(target_os = "linux")]
fn set_no_new_privs(r: &mut HardeningReport) {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1) — well-defined, no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1_u64, 0_u64, 0_u64, 0_u64) };
    if rc == 0 {
        r.no_new_privs = true;
    } else {
        r.notes
            .push(format!("PR_SET_NO_NEW_PRIVS failed (errno={})", errno_now()));
    }
}

#[cfg(not(target_os = "linux"))]
fn set_no_new_privs(r: &mut HardeningReport) {
    r.notes.push("set_no_new_privs: linux-only knob".into());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lock_pages(r: &mut HardeningReport) {
    // MCL_CURRENT | MCL_FUTURE — pin current + all future allocations.
    // Needs CAP_IPC_LOCK (or generous RLIMIT_MEMLOCK); on EPERM we log
    // and move on (deployment choice, not a failure).
    // SAFETY: mlockall with valid flags.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        r.mlock_pages = true;
    } else {
        r.notes.push(format!(
            "mlockall failed (errno={} — needs CAP_IPC_LOCK or generous RLIMIT_MEMLOCK)",
            errno_now()
        ));
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn lock_pages(r: &mut HardeningReport) {
    r.notes
        .push("lock_pages: unsupported on this platform".into());
}

#[cfg(target_os = "linux")]
fn zero_coredump_filter(r: &mut HardeningReport) {
    match std::fs::write("/proc/self/coredump_filter", b"00000000") {
        Ok(_) => r.coredump_filter_zeroed = true,
        Err(e) => r.notes.push(format!("write coredump_filter failed: {e}")),
    }
}

#[cfg(not(target_os = "linux"))]
fn zero_coredump_filter(r: &mut HardeningReport) {
    r.notes.push("zero_coredump_filter: linux-only".into());
}

#[cfg(unix)]
fn errno_now() -> i32 {
    // SAFETY: __errno_location returns a valid per-thread errno pointer.
    unsafe { *libc::__errno_location() }
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn errno_now() -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_returns_a_report_without_panic() {
        // On Linux as a normal user: no_core_dump + no_new_privs OK,
        // mlock typically fails (no caps), coredump_filter OK. On Windows
        // everything is a no-op. We only assert no panic + notes exists.
        let r = harden_process();
        let _ = r.all_applied();
        let _ = r.notes.len();
    }

    #[test]
    fn report_serializes_to_json() {
        let r = HardeningReport::default();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["no_core_dump"], false);
        assert!(v["notes"].is_array());
    }
}
