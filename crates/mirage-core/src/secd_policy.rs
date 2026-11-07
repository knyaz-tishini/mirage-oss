//! `secd`'s typed operating point — orthogonal, capability-gated defense axes.
//!
//! Per the secd master development plan (`docs/mirage/plans/secd-master-development-plan-2026-07-06.md`
//! §2): secd's operating point is not one scalar tier. It is a typed
//! [`SecdPolicy`] of **independent axes**, each selected per-box (≤ the
//! ceiling sentry detected for that box — see the extended
//! [`crate::fact_signing::BoxProfileRow`] ceiling fields), each honestly
//! reported as *achieved* in the signed `SecurityPostureRow` (extended in
//! `mirage2monitor::store`; the signing-byte layout lives in
//! [`crate::fact_signing::security_posture_signing_bytes`]).
//!
//! Every axis is a closed, `#[repr(u8)]` enum — no stringly config, matching
//! the `AttackerSignalType` / `FwAction` precedent in this crate. Discriminant
//! values are chosen to match the ladder order given in plan §2 (`0` = the
//! weakest/most-conservative point on each ladder) so a numeric comparison
//! (`achieved as u8 >= requested as u8`) is a meaningful "at least as strong"
//! check wherever a caller needs one.

use serde::{Deserialize, Serialize};

/// secd's full typed operating point — one independent selection per axis.
///
/// Carried as the payload of `SecdDirectiveBody::SetPolicy` (see
/// [`crate::secd_directive::SecdDirectiveBody::SetPolicy`]) and re-derived
/// (not cached-and-trusted) into the per-axis *achieved* fields of the
/// extended `SecurityPostureRow` on every posture tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecdPolicy {
    /// axis K — kernel hardening ladder (plan §5).
    pub kernel_tier: KernelTier,
    /// axis D — DK-storage backend (plan §6).
    pub dk_backend: DkBackend,
    /// axis C — confidential compute / attestation, Tier-3 (plan §7).
    pub confidential: ConfMode,
    /// axis E — egress perimeter (plan §8).
    pub egress: EgressMode,
    /// axis I — binary/FS integrity (plan §9).
    pub integrity: IntegrityMode,
    /// axis S — self-sandbox (plan §10).
    pub self_sandbox: SandboxMode,
    /// axis M — enforce-mode safety valve, cross-cuts every deny axis (plan §11).
    pub enforce_mode: EnforceMode,
    /// axis N — detection-everywhere sensor (plan §12).
    pub detection: DetectionMode,
    /// axis P — automated kernel/security package patching.
    pub patch_mode: PatchMode,
    /// axis F — attack-surface minimization / least-functionality (arc2.8 §1).
    ///
    /// `#[serde(default)]`: forward-compat for a `SecdPolicy` blob persisted
    /// before axis F existed (pre-arc2.8) — the field is simply absent in
    /// the old JSON, and defaults to `SurfaceMode::Off` (the same
    /// "audit-only, touch nothing" no-op every fresh box already starts at).
    /// This only lets the OLD blob PARSE; its operator signature was
    /// computed over the pre-arc2.8 byte layout and will still fail
    /// re-verification — that rejection is expected and handled by the
    /// boot-seed caller, not by this default.
    #[serde(default)]
    pub surface: SurfaceMode,
}

/// axis R — the fleet reputation ladder.
///
/// Deliberately NOT a field of [`SecdPolicy`], and the reason is worth
/// keeping: `encode_secd_policy` writes one byte per axis in field order into
/// the operator-signed preimage of a `SetPolicy` directive. An eleventh byte
/// changes that preimage for EVERY `SetPolicy`, in both directions — a new
/// secd verifying an old opbox's directive fails, and an old secd verifying a
/// new one fails too, so there is no roll order that avoids a window. Worse,
/// the durably stored `set_policy` row would stop re-verifying at boot and a
/// rebooted box would fall back to the default operating point, which is
/// `KernelTier::Tier0` — a silent kernel-hardening downgrade bought with a
/// knob. Carried instead by its own directive variant
/// (`SecdDirectiveBody::SetReputationMode`, tag `0x0E`), which is purely
/// additive: no existing signature preimage moves.
///
/// The gossiped `attacker_intel` table already carries every box's
/// observations to every monitor. This axis says what THIS box's secd is
/// allowed to do with the part of it that came from somebody else.
///
/// Ordered weakest-first like every other axis here, so `achieved as u8 >=
/// requested as u8` keeps meaning "at least as strong".
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ReputationMode {
    /// Read nothing, act on nothing. What every box did before the axis
    /// existed, and the default a box falls to when the field is absent.
    #[default]
    Off = 0,
    /// Read the fleet table and account for what WOULD have been banned,
    /// without touching the firewall. The honest canary rung: it produces
    /// the numbers that say whether the corroboration threshold is right on
    /// real traffic, and a mistake here costs a counter rather than the
    /// mesh.
    Observe = 1,
    /// Ban a source this box has not seen, once enough OTHER boxes have.
    /// Bounded by the exempt set, a per-tick ceiling, and a TTL — never a
    /// permanent ban from another box's word alone.
    Corroborated = 2,
}

/// axis K — kernel-hardening ladder (plan §5, generalizes the prior
/// `secd-tier-engine-impl` single `DefenseTier` scalar).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelTier {
    /// Cap-bounding-set drop, `NoNewPrivileges`, seccomp self-filter, W^X
    /// systemd battery. Free, every box including containers.
    Tier0 = 0,
    /// + `ptrace_scope=3`, `lockdown=integrity`, sysctl hardening battery.
    /// Needs KVM, no reboot.
    Tier1 = 1,
    /// + aya BPF-LSM crown jewels (ptrace/file_open/task_kill/bpf-lock/
    /// file_mprotect denies). Needs `bpf` live in `lsm=` (grub-canary reboot).
    Tier2 = 2,
}

/// axis D — DK-storage backend (plan §6, `keyram §7`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DkBackend {
    /// `mlock` + `DUMPABLE=0`. Baseline only — root ptrace/proc-mem/kcore/
    /// dev-mem all still reach it.
    Mlock = 0,
    /// `memfd_secret(2)` — pages removed from the kernel direct-map and
    /// GUP-refused. Default: near-free, works every tier.
    MemfdSecret = 1,
    /// Kernel keyring `trusted`/`encrypted`. Kept in the enum only for
    /// completeness — REJECTED as a DK backend (root `keyctl link` still
    /// reaches any keyring); auto-select never picks it.
    KeyringTpm = 2,
    /// DK lives in SEV-SNP/TDX-encrypted guest RAM (axis C). The only
    /// backend that closes hypervisor RAM read.
    AttestedCvm = 3,
}

/// axis C — confidential compute / attestation, Tier-3 (plan §7, `cc §X`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfMode {
    /// No confidential-compute capability on this box (honest — the current
    /// fleet reports this).
    None = 0,
    /// A signed attestation report is produced and gossiped on a capable box.
    ReportEmit = 1,
    /// The `KeyRelease` protocol gates DK delivery on a verified attestation
    /// with the expected measurement.
    AttestationGatedRelease = 2,
}

/// axis E — egress perimeter (plan §8, `frameworks §7`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressMode {
    /// nft ruleset observes only — no default-deny.
    MonitorOnly = 0,
    /// Default-deny egress + allowlist of the live mesh peer set + monitor +
    /// DNS + NTP. Works at every tier including container.
    DefaultDenyAllowlist = 1,
}

/// axis I — binary/FS integrity (plan §9, `frameworks §3`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityMode {
    /// No integrity enforcement.
    None = 0,
    /// BPF-LSM `file_open`/`path_*` write-deny on the daemon binary path
    /// (Tier2, cgroup-scoped).
    BpfFileDeny = 1,
    /// Per-file Merkle-tree read-time integrity. Realistic default where
    /// supported.
    FsVerity = 2,
    /// Signed `security.ima` xattr, `ima_appraise=enforce`.
    ImaAppraise = 3,
    /// Read-only dm-verity rootfs + IPE LSM exec-allowlist. Needs kernel
    /// ≥6.12 — not on the current fleet (6.8/5.15/5.10); kept in the enum
    /// so it activates on a future kernel bump.
    DmVerityIpe = 4,
}

/// axis S — self-sandbox (plan §10, `frameworks §5`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    /// No self-restriction.
    Off = 0,
    /// Tight seccomp allowlist + Landlock self-restriction (ABI-gated by
    /// kernel — richest ruleset the box's Landlock ABI level supports).
    SeccompLandlock = 1,
}

/// axis M — enforce-mode, the cross-cutting safety valve applied uniformly
/// to every *deny* axis (plan §11, Tetragon monitor→enforce precedent).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforceMode {
    /// Programs loaded/attached, violations logged, nothing denied. The
    /// mandatory first state for any new deny rule on any box.
    Observe = 0,
    /// Log + emit a high-signal fact, still allow.
    Warn = 1,
    /// Actually deny.
    Enforce = 2,
}

/// axis N — detection-everywhere sensor (plan §12, `frameworks §6` + `harness §4`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMode {
    /// No portable detection sensor active.
    Off = 0,
    /// Lightweight eBPF observability (kprobe/tracepoint/fentry, not
    /// BPF-LSM) — portable to kernels lacking `CONFIG_BPF_LSM`.
    KprobeSensor = 1,
}

/// axis P — automated kernel/security package patching.
///
/// Ladder is by blast-radius, not by mechanism: `SecurityOnly` touches only
/// the distro's `-security` apt pocket (a narrow, vetted stream — the safe
/// autonomous default); `Full` additionally pulls ordinary package updates
/// and kernel images from the full archive. Neither variant ever reboots —
/// a kernel/systemd-core update that needs a reboot to take effect is
/// surfaced as `reboot_pending` in the patch report and left for an
/// operator-gated `Reboot` directive (secd never restarts its own box
/// unprompted).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchMode {
    /// No automated patching — current/legacy behaviour.
    Off = 0,
    /// Only the `${dist}-security` apt pocket. Safe autonomous default.
    SecurityOnly = 1,
    /// Full `apt-get dist-upgrade`, including kernel package updates.
    Full = 2,
}

/// axis F — attack-surface minimization (least-functionality, NIST CM-7).
/// Staged ladder, `0` = weakest (audit-only), matching every other axis's
/// "0 = most-conservative" convention (arc2.8 §1.1).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceMode {
    /// Audit/detect only. secd computes the "would-mask"/"would-blacklist"
    /// diff against the denylist and reports it in posture/directive-result
    /// detail; touches NOTHING on disk. Mandatory first state for any new
    /// box, mirrors axis M's `Observe` mandatory-first-state contract.
    Off = 0,
    /// Reversible baseline: mask the vetted service denylist (`systemctl
    /// mask`, package left installed) + modprobe blacklist drop-in +
    /// sysctl network-hardening drop-in + sshd baseline reuse (existing
    /// `sshd.rs` machinery, unchanged). Nothing here survives a manual
    /// `systemctl unmask` + `apt purge` being reversed by the operator —
    /// every mutation is drop-in-based and fully undoable.
    MaskBaseline = 1,
    /// systemd unit-confinement (additive hardening drop-in) for the
    /// de-privileged KEPT/must-run daemons this box already runs
    /// unprivileged (`mirage-db-worker`, `mirage2monitor-v2`,
    /// `mirage-node-v2` — `User=mirage`, zero caps) + the broader module
    /// blacklist (extended list, e.g. cifs/afs/ceph/exfat/gfs2/smbfs).
    /// Still 100% reversible (delete the drop-in file). Distinct from the
    /// Mirage honeypot/`mirage2sandbox` (arc3 attacker-trap) — the name
    /// `sandbox` is reserved for that trap, so this ladder rung is named
    /// `UnitConfined` instead. secd's OWN root daemons (secd/sentry/mshd)
    /// and `sshd` are never confined — see `surface_denylist::
    /// UNIT_CONFINE_TARGETS`/`NEVER_TOUCH_UNITS` and `unit_confine.rs`.
    UnitConfined = 2,
    /// Opt-in aggressive tier: `apt purge` the vetted purge-worthy set +
    /// `kernel.modules_disabled=1` (irreversible until reboot). Only
    /// reachable if the operator explicitly requests it; auto-policy never
    /// self-promotes into this tier.
    PurgeAggressive = 3,
}

impl Default for SurfaceMode {
    /// Audit-only, touches nothing — the mandatory first state for any new
    /// box (see the variant's own doc) and the correct fill-in for a
    /// pre-arc2.8 `SecdPolicy` blob that predates this axis entirely.
    fn default() -> Self {
        SurfaceMode::Off
    }
}

/// axis F configuration payload — carried alongside `SecdPolicy.surface`
/// (the ladder position) as a SEPARATE directive body, same split pattern
/// axis P already uses (`PatchMode` ladder in `SecdPolicy` vs the richer
/// `PatchSchedule` cadence/target carried by its own directive). Rationale:
/// the denylist/override set is data (variable-length, operator-tunable),
/// not a ladder position — folding it into `SecdPolicy`'s fixed-width
/// per-axis-discriminant signing-bytes encoding would break that encoding's
/// "one byte per axis" invariant (arc2.8 §1.1). Not `Copy` (carries `Vec`s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceConfig {
    /// Ladder position (mirrors `PatchSchedule.mode` vs `SecdPolicy.patch_mode`).
    pub mode: SurfaceMode,
    /// Additional services to mask/purge beyond the built-in default
    /// denylist (systemd unit names, e.g. `"snmpd.service"`).
    pub extra_denylist: Vec<String>,
    /// Services in the built-in default denylist the operator wants
    /// EXCLUDED (kept running) for this specific box — e.g. a box that
    /// legitimately runs `postfix` unbound, or an NFS server box.
    pub allow_services: Vec<String>,
    /// Additional kernel modules to blacklist beyond the built-in default
    /// set.
    pub extra_module_blacklist: Vec<String>,
    /// Modules in the built-in default blacklist to EXCLUDE (e.g. a box
    /// that still runs snapd — keep `squashfs` off the blacklist).
    pub allow_modules: Vec<String>,
}

/// axis P schedule — cadence + kernel-line target for the autonomous apt
/// cycle. Separate from [`SecdPolicy`] (secd master plan §1 addendum,
/// `docs/mirage/plans/secd-update-control-system-2026-07-07.md`): edited
/// independently, carried by its own directive
/// (`SecdDirectiveBody::SetPatchSchedule`), never folded into `SecdPolicy`'s
/// nine hardening axes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchSchedule {
    /// Which apt scope the scheduler runs when due. `Off` disables the
    /// autonomous cycle entirely (mirrors `PatchMode::Off` semantics —
    /// `mirage-secd::patch::maybe_run_scheduled` still no-ops on `Off`
    /// exactly as before this schedule type existed).
    pub mode: PatchMode,
    /// Minimum seconds between scheduled patch cycles. Replaces the
    /// hardcoded `SCHEDULE_INTERVAL` (was 24*3600) that used to live in
    /// `mirage-secd::patch`. Operator-editable floor — NOT validated
    /// against a minimum here (wire crate does no business-rule
    /// validation); opbox's PUT handler enforces a sane floor.
    pub interval_secs: u64,
    /// Width of the deterministic per-box jitter window. Replaces the
    /// hardcoded `JITTER_WINDOW` (was 3600). `0` = no jitter (every box
    /// fires exactly at `interval_secs`).
    pub jitter_secs: u64,
    /// Target kernel line this box should converge on.
    pub kernel_track: KernelTrack,
    /// Auto-reboot arm state (arc2.8 §2.1). NEW field (append). Default
    /// `RebootPolicy::Off` preserves every existing `PatchSchedule` call
    /// site's behavior byte-for-byte (secd never reboots on its own today).
    ///
    /// `#[serde(default)]`: a `PatchSchedule` blob persisted before this
    /// field existed (pre-arc2.8) simply lacks the key — defaults to `Off`,
    /// letting the old blob PARSE. Its operator signature still won't
    /// re-verify against the new byte layout — expected, handled by the
    /// boot-seed caller's per-directive verify step, not by this default.
    #[serde(default)]
    pub reboot: RebootPolicy,
    /// Auto-reboot maintenance window (arc2.8 §2.1). NEW field (append).
    ///
    /// `#[serde(default)]`: same forward-compat rationale as `reboot` above.
    #[serde(default)]
    pub reboot_window: RebootWindow,
}

/// Auto-reboot ladder — `0` = Off, matching every axis's convention even
/// though this isn't formally one of the `SecdPolicy` axes (it lives on
/// `PatchSchedule`, axis P's sibling config, same non-`SecdPolicy`
/// placement `KernelTrack` already uses).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebootPolicy {
    /// Never auto-reboot. `reboot_pending` still surfaces in `PatchReport`/
    /// posture as today; acting on it stays a distinct operator-issued
    /// `Reboot` directive. DEFAULT — every box, prod-safe out of the box.
    Off = 0,
    /// Armed: reboot when `reboot_pending` is true AND the current time
    /// (box-local) falls in `reboot_window` AND per-box jitter + rolling-
    /// fleet discipline clears.
    Armed = 1,
}

impl Default for RebootPolicy {
    /// Never auto-reboot — the prod-safe, byte-for-byte-preserving fill-in
    /// for a pre-arc2.8 `PatchSchedule` blob that predates this field.
    fn default() -> Self {
        RebootPolicy::Off
    }
}

/// Reboot maintenance window — box-local clock time, HH:MM, mirrors
/// `unattended-upgrades`' `Automatic-Reboot-Time` "HH:MM" form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootWindow {
    /// 0-23, box-local wall-clock hour the window OPENS.
    pub start_hour: u8,
    /// 0-59.
    pub start_minute: u8,
    /// Width of the window in minutes — the per-box jitter is drawn from
    /// `[0, window_minutes)`, so "02:00 window_minutes=120" means every box
    /// in the fleet reboots somewhere in [02:00, 04:00) local,
    /// deterministically spread by `blake3(machine_id)`.
    pub window_minutes: u16,
}

impl Default for RebootWindow {
    /// `02:00, 120min` — matches the doc comment's own worked example and
    /// is inert regardless (only consulted when `reboot == Armed`, which
    /// itself defaults to `Off`).
    fn default() -> Self {
        RebootWindow {
            start_hour: 2,
            start_minute: 0,
            window_minutes: 120,
        }
    }
}

/// axis P kernel-line target. Orthogonal to axis K's [`KernelTier`]
/// (hardening ladder) — this selects WHICH kernel package line apt should
/// converge on, not how hardened the running kernel is.
///
/// No `#[repr(u8)]`: `Pinned` carries a `String` payload, so this enum
/// follows the `FwAction`/`DetailKind` precedent in `secd_directive.rs`
/// (plain enum + a match-based tag fn used only by the signing-bytes
/// encoder) rather than `PatchMode`'s bare-discriminant shape (which only
/// suits payload-free enums).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelTrack {
    /// No kernel-line steering — apt upgrades whatever kernel package the
    /// normal patch cycle (`SecurityOnly`/`Full`) already pulls, same as
    /// the pre-schedule behaviour with no axis-P kernel logic at all.
    Hold,
    /// Ensure `linux-generic-hwe-<release>` (HWE 6.8 stack on 22.04) is
    /// installed and is the boot default. The only non-`Hold` variant
    /// implemented by `mirage-secd::patch`'s executor in this cut.
    Hwe,
    /// Pin a specific kernel meta-package/version string (e.g.
    /// `"5.15.0-119-generic"`). **Formally unsupported** — owner-scoped-out,
    /// not a "coming later" gap: Tier2 is kernel-agnostic (the aya-kfunc
    /// cgroup walk + BTF offset table are resolved per-kernel at runtime),
    /// so pinning one specific version buys nothing and only narrows the
    /// fleet's patch surface. `mirage-secd::patch`'s executor
    /// (`ensure_pinned_kernel`) intentionally always returns a named error
    /// for this variant. Kept in the enum wire-reserved-only, for wire
    /// compat with any already-issued directive that carries it — never
    /// remove the variant, but do not implement it either.
    Pinned(String),
}

// THROWAWAY — delete at Stage I
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_tier_discriminants_match_plan_ladder() {
        assert_eq!(KernelTier::Tier0 as u8, 0);
        assert_eq!(KernelTier::Tier1 as u8, 1);
        assert_eq!(KernelTier::Tier2 as u8, 2);
    }

    #[test]
    fn dk_backend_discriminants_match_plan_ladder() {
        assert_eq!(DkBackend::Mlock as u8, 0);
        assert_eq!(DkBackend::MemfdSecret as u8, 1);
        assert_eq!(DkBackend::KeyringTpm as u8, 2);
        assert_eq!(DkBackend::AttestedCvm as u8, 3);
    }

    #[test]
    fn conf_mode_discriminants_match_plan_ladder() {
        assert_eq!(ConfMode::None as u8, 0);
        assert_eq!(ConfMode::ReportEmit as u8, 1);
        assert_eq!(ConfMode::AttestationGatedRelease as u8, 2);
    }

    #[test]
    fn egress_mode_discriminants_match_plan_ladder() {
        assert_eq!(EgressMode::MonitorOnly as u8, 0);
        assert_eq!(EgressMode::DefaultDenyAllowlist as u8, 1);
    }

    #[test]
    fn integrity_mode_discriminants_match_plan_ladder() {
        assert_eq!(IntegrityMode::None as u8, 0);
        assert_eq!(IntegrityMode::BpfFileDeny as u8, 1);
        assert_eq!(IntegrityMode::FsVerity as u8, 2);
        assert_eq!(IntegrityMode::ImaAppraise as u8, 3);
        assert_eq!(IntegrityMode::DmVerityIpe as u8, 4);
    }

    #[test]
    fn sandbox_mode_discriminants_match_plan_ladder() {
        assert_eq!(SandboxMode::Off as u8, 0);
        assert_eq!(SandboxMode::SeccompLandlock as u8, 1);
    }

    #[test]
    fn enforce_mode_discriminants_match_plan_ladder() {
        assert_eq!(EnforceMode::Observe as u8, 0);
        assert_eq!(EnforceMode::Warn as u8, 1);
        assert_eq!(EnforceMode::Enforce as u8, 2);
    }

    #[test]
    fn detection_mode_discriminants_match_plan_ladder() {
        assert_eq!(DetectionMode::Off as u8, 0);
        assert_eq!(DetectionMode::KprobeSensor as u8, 1);
    }

    #[test]
    fn patch_mode_discriminants_match_plan_ladder() {
        assert_eq!(PatchMode::Off as u8, 0);
        assert_eq!(PatchMode::SecurityOnly as u8, 1);
        assert_eq!(PatchMode::Full as u8, 2);
    }

    // THROWAWAY (arc2.8 axis F / auto-reboot) — delete at Stage I
    #[test]
    fn surface_mode_discriminants_match_plan_ladder() {
        assert_eq!(SurfaceMode::Off as u8, 0);
        assert_eq!(SurfaceMode::MaskBaseline as u8, 1);
        assert_eq!(SurfaceMode::UnitConfined as u8, 2);
        assert_eq!(SurfaceMode::PurgeAggressive as u8, 3);
    }

    #[test]
    fn reboot_policy_discriminants_match_plan_ladder() {
        assert_eq!(RebootPolicy::Off as u8, 0);
        assert_eq!(RebootPolicy::Armed as u8, 1);
    }

    #[test]
    fn surface_config_json_roundtrips() {
        let config = SurfaceConfig {
            mode: SurfaceMode::MaskBaseline,
            extra_denylist: vec!["snmpd.service".to_string()],
            allow_services: vec!["postfix.service".to_string()],
            extra_module_blacklist: vec!["cifs".to_string()],
            allow_modules: vec!["squashfs".to_string()],
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let back: SurfaceConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, back, "SurfaceConfig must round-trip through JSON");
    }

    #[test]
    fn reboot_window_json_roundtrips() {
        let window = RebootWindow {
            start_hour: 2,
            start_minute: 0,
            window_minutes: 120,
        };
        let json = serde_json::to_string(&window).expect("serialize");
        let back: RebootWindow = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(window, back, "RebootWindow must round-trip through JSON");
    }

    #[test]
    fn secd_policy_json_roundtrips() {
        let policy = SecdPolicy {
            kernel_tier: KernelTier::Tier1,
            dk_backend: DkBackend::MemfdSecret,
            confidential: ConfMode::None,
            egress: EgressMode::DefaultDenyAllowlist,
            integrity: IntegrityMode::FsVerity,
            self_sandbox: SandboxMode::SeccompLandlock,
            enforce_mode: EnforceMode::Observe,
            detection: DetectionMode::KprobeSensor,
            patch_mode: PatchMode::SecurityOnly,
            surface: SurfaceMode::Off,
        };
        let json = serde_json::to_string(&policy).expect("serialize");
        let back: SecdPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, back, "SecdPolicy must round-trip through JSON");
    }

    // ── PatchSchedule / KernelTrack (SUCS) ────────────────────────────────

    #[test]
    fn patch_schedule_json_roundtrips() {
        let schedule = PatchSchedule {
            mode: PatchMode::SecurityOnly,
            interval_secs: 24 * 60 * 60,
            jitter_secs: 60 * 60,
            kernel_track: KernelTrack::Hwe,
            reboot: RebootPolicy::Off,
            reboot_window: RebootWindow { start_hour: 2, start_minute: 0, window_minutes: 120 },
        };
        let json = serde_json::to_string(&schedule).expect("serialize");
        let back: PatchSchedule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schedule, back, "PatchSchedule must round-trip through JSON");
    }

    #[test]
    fn patch_schedule_pinned_kernel_track_json_roundtrips() {
        let schedule = PatchSchedule {
            mode: PatchMode::Full,
            interval_secs: 3600,
            jitter_secs: 0,
            kernel_track: KernelTrack::Pinned("5.15.0-119-generic".to_string()),
            reboot: RebootPolicy::Armed,
            reboot_window: RebootWindow { start_hour: 3, start_minute: 30, window_minutes: 90 },
        };
        let json = serde_json::to_string(&schedule).expect("serialize");
        let back: PatchSchedule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schedule, back, "Pinned KernelTrack must round-trip through JSON");
    }

    // THROWAWAY (boot-seed forward-compat fix) — delete at Stage I
    #[test]
    fn patch_schedule_pre_arc28_json_parses_with_defaults() {
        // Layout as persisted BEFORE `reboot`/`reboot_window` existed —
        // exactly what a stale db-worker row looks like on a box that was
        // last rerolled pre-arc2.8.
        let old_json = r#"{
            "mode": "SecurityOnly",
            "interval_secs": 86400,
            "jitter_secs": 3600,
            "kernel_track": "Hwe"
        }"#;
        let parsed: PatchSchedule =
            serde_json::from_str(old_json).expect("pre-arc2.8 PatchSchedule must still parse");
        assert_eq!(parsed.reboot, RebootPolicy::Off);
        assert_eq!(parsed.reboot_window, RebootWindow::default());
    }

    // THROWAWAY (boot-seed forward-compat fix) — delete at Stage I
    #[test]
    fn secd_policy_pre_arc28_json_parses_with_default_surface() {
        // Layout as persisted BEFORE axis F (`surface`) existed.
        let old_json = r#"{
            "kernel_tier": "Tier1",
            "dk_backend": "MemfdSecret",
            "confidential": "None",
            "egress": "DefaultDenyAllowlist",
            "integrity": "FsVerity",
            "self_sandbox": "SeccompLandlock",
            "enforce_mode": "Observe",
            "detection": "KprobeSensor",
            "patch_mode": "SecurityOnly"
        }"#;
        let parsed: SecdPolicy =
            serde_json::from_str(old_json).expect("pre-arc2.8 SecdPolicy must still parse");
        assert_eq!(parsed.surface, SurfaceMode::Off);
    }

    #[test]
    fn kernel_track_hold_json_roundtrips() {
        let json = serde_json::to_string(&KernelTrack::Hold).expect("serialize");
        let back: KernelTrack = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(KernelTrack::Hold, back);
    }

    #[test]
    fn kernel_track_hwe_json_roundtrips() {
        let json = serde_json::to_string(&KernelTrack::Hwe).expect("serialize");
        let back: KernelTrack = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(KernelTrack::Hwe, back);
    }

    #[test]
    fn kernel_track_pinned_json_roundtrips() {
        let track = KernelTrack::Pinned("6.8.0-generic".to_string());
        let json = serde_json::to_string(&track).expect("serialize");
        let back: KernelTrack = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(track, back);
    }

    #[test]
    fn kernel_track_variants_are_distinguishable() {
        assert_ne!(KernelTrack::Hold, KernelTrack::Hwe);
        assert_ne!(KernelTrack::Hwe, KernelTrack::Pinned("x".to_string()));
        assert_ne!(
            KernelTrack::Pinned("a".to_string()),
            KernelTrack::Pinned("b".to_string())
        );
    }
}
