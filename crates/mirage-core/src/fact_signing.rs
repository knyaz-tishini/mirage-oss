//! Canonical signing-byte layout for gossiped facts.
//!
//! Both the signer (sentry, slice 1B) and the verifier (monitor, this slice)
//! call these helpers to compute an identical byte string that is then signed
//! or verified with an Ed25519 key.
//!
//! `BoxProfileRow` additionally keeps its full row type + a typed
//! `verify_box_profile` helper directly in this crate (unlike the other
//! facts here, whose row types live in `mirage2monitor::store`), because the
//! capability-profile fact is consumed by more than one server-side crate
//! (monitor + secd) and this is the shared contract module both depend on.
//!
//! # Design goals
//!
//! - **Deterministic**: no floating-point formatting, no locale-dependent
//!   output, no map iteration order. Every encoding is fixed-width or
//!   NUL-terminated.
//! - **Domain-separated**: a version-tagged prefix makes cross-fact
//!   confusion impossible even if field layouts accidentally collide.
//! - **100% typed**: only structured fields are covered. Free-form JSON
//!   blobs are never part of the signed input — they cannot be
//!   canonically reproduced across serialisation implementations.
//!
//! # Option fields
//!
//! Fields that are `Option<_>` in `MachineStateRow` (`load_one`, `load_five`,
//! `load_fifteen`, `disk_total_bytes`, `disk_used_bytes`, `sqlite_bytes`,
//! `cpu_pct`) are encoded with a one-byte presence flag followed by the
//! value or nothing:
//!
//! - `None`   → `0x00` (1 byte)
//! - `Some(v)` → `0x01` followed by the big-endian encoding of `v`
//!
//! This is stable across code upgrades: adding a new optional field always
//! appends to the layout, and old verifiers see a truncated input that
//! produces a different digest — the signature will fail, which is the
//! correct and safe behaviour.

use serde::{Deserialize, Serialize};

use crate::box_inventory::{
    BoxInventorySnapshotRow, BoxInventoryTransitionRow, BoxListenerFact, BoxOutboundConnFact,
    BoxProcessFact, BoxUnitLogLevelFact,
};

/// Domain prefix for `machine_state` facts.
const DOMAIN_MACHINE_STATE: &[u8] = b"mirage-fact-machine-state-v1\0";

/// Domain prefix for `node_metrics` facts.
const DOMAIN_NODE_METRICS: &[u8] = b"mirage-fact-node-metrics-v1\0";

/// Domain prefix for `node_egress` facts.
const DOMAIN_NODE_EGRESS: &[u8] = b"mirage-fact-node-egress-v1\0";

/// Domain prefix for `listener_state` facts.
const DOMAIN_LISTENER_STATE: &[u8] = b"mirage-fact-listener-state-v1\0";

/// Domain prefix for `security_posture` facts (secd-originated).
///
/// Stays `-v1` across the 2026-06-28 enrichment append and the 2026-07-06
/// secd-arc2 per-axis-achieved append (this module): the established
/// convention for this fact (see the 2026-06-28 enrichment block below) is
/// append-only field growth under one domain string, not a version bump per
/// append — an old verifier still rejects (shorter buffer → signature
/// mismatch), which is the same safety property a version bump would give,
/// without perpetually renaming the domain. A domain bump is reserved for a
/// breaking reorder/removal, which this plan explicitly forbids (append-only).
const DOMAIN_SECURITY_POSTURE: &[u8] = b"mirage-fact-security-posture-v1\0";

/// Domain prefix for `attacker_intel` facts (secd-originated, tier-0).
const DOMAIN_ATTACKER_INTEL: &[u8] = b"mirage-fact-attacker-intel-v1\0";

/// Domain prefix for `box_profile` facts (secd-originated capability profile).
const DOMAIN_BOX_PROFILE: &[u8] = b"mirage-fact-box-profile-v1\0";

/// Domain prefix for `attestation_report` facts (axis C, sentry-originated).
const DOMAIN_ATTESTATION_REPORT: &[u8] = b"mirage-fact-attestation-report-v1\0";

/// Domain prefix for `kernel_security_event` facts (axis N/K, secd-originated).
const DOMAIN_KERNEL_SECURITY_EVENT: &[u8] = b"mirage-fact-security-kernel-event-v1\0";

/// Domain prefix for `scrape_test_result` facts (validation harness).
const DOMAIN_SCRAPE_TEST_RESULT: &[u8] = b"mirage-fact-scrape-test-result-v1\0";

/// Domain prefix for `box_inventory_snapshot` facts (D0 arc3 Foundation,
/// sentry-originated live process/listener/outbound/log-level snapshot).
const DOMAIN_BOX_INVENTORY_SNAPSHOT: &[u8] = b"mirage-fact-box-inventory-snapshot-v1\0";

/// Domain prefix for `box_inventory_transition` facts (D0 arc3 Foundation,
/// sentry-originated append-only state-change journal).
const DOMAIN_BOX_INVENTORY_TRANSITION: &[u8] = b"mirage-fact-box-inventory-transition-v1\0";

/// Signal class for an `attacker_intel` observation (tier-0 active defense).
///
/// The discriminant byte is exactly what `attacker_intel_signing_bytes` signs
/// — a closed set, domain-versioned with the fact (`-v1`). Extend by appending
/// variants and rolling the verifier to every monitor FIRST, identical to the
/// signing-bytes layout contract. Encoded as a fixed enum byte (not a
/// free-string) matching the `SecdDirectiveBody` body-tag precedent.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackerSignalType {
    /// Unclassified / fallback.
    Other = 0x00,
    /// Touched a zero-parse decoy tripwire port.
    Decoy = 0x01,
    /// SSH brute-force / credential-stuffing attempt.
    SshBrute = 0x02,
    /// Connected to a listener not in the expected allow-list.
    UnexpectedListener = 0x03,
    /// Held in a tier-2 tarpit.
    Tarpit = 0x04,
    /// Subjected to a tier-2 junk-flood.
    Flood = 0x05,
    /// Served a tier-2 send-first decompression bomb.
    Bomb = 0x06,
    /// Interacted with the tier-3 sandboxed honeypot.
    Honeypot = 0x07,
    /// A BPF-LSM `ptrace_access_check`/`task_kill` deny fired against a
    /// protected cgroup (axis K Tier-2 / axis N, Wave-2 Stage G) — routes
    /// the SAME unambiguous-foe signal path every other zero-parse signal
    /// here already uses (master plan §12: "add ONE new `AttackerSignalType`
    /// variant, not a new pipeline"). NOTE: unlike every other variant in
    /// this enum, the kernel-event sensor's natural key is a PID/cgroup id,
    /// not an IP address — `IntelState::observe` is IP-keyed
    /// (`(machine_id, ip)`), so routing an in-box kernel-level ptrace deny
    /// through THIS specific accumulator needs an IP-shaped key that a
    /// local kernel event does not have. This variant exists (as explicitly
    /// requested) for the discriminant to be available/typed; the actual
    /// sensor→intel wiring is left as a named gap — see
    /// `mirage-secd/src/bpf_lsm/sensor.rs` doc for the honest boundary
    /// (the sensor emits its own dedicated `KernelSecurityEventRow` fact
    /// instead, which is NOT IP-keyed).
    KernelPtraceDeny = 0x08,
    /// Failed the perimeter's camouflage strip on a published face (seam A).
    /// Weak evidence on its own — a plain HTTP client that does not know a
    /// websocket face's path lands here, and so does a crawler. It is the
    /// REPEAT that carries the signal, which is why
    /// [`crate::perimeter_observation::confidence_bucket`] scales this one
    /// with the touch count instead of returning a constant.
    PerimeterCamoFailed = 0x09,
    /// Passed the perimeter's camouflage strip and then failed the inner
    /// classification — not a V9 hello, not an SSH banner (seam B). Strictly
    /// more deliberate than seam A: the peer spoke the outer protocol
    /// correctly and still was not one of the two things the face carries.
    PerimeterNotWire = 0x0a,
}

impl AttackerSignalType {
    /// Map a raw signed discriminant byte back to the typed variant.
    /// Unknown discriminants collapse to `Other` (forward-compat: a newer
    /// producer's variant a shorter-lived reader doesn't know yet reads as
    /// `Other` rather than panicking).
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Decoy,
            0x02 => Self::SshBrute,
            0x03 => Self::UnexpectedListener,
            0x04 => Self::Tarpit,
            0x05 => Self::Flood,
            0x06 => Self::Bomb,
            0x07 => Self::Honeypot,
            0x08 => Self::KernelPtraceDeny,
            0x09 => Self::PerimeterCamoFailed,
            0x0a => Self::PerimeterNotWire,
            _ => Self::Other,
        }
    }
}

/// Build the canonical byte string that covers one `machine_state` snapshot.
///
/// All parameters are typed — no free-form JSON is included. The signer
/// (sentry) and the verifier (monitor) both call this function with the same
/// typed values extracted from the heartbeat body, producing byte-identical
/// output without any JSON round-trip.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                    28 bytes + NUL = 29 bytes
/// machine_id UTF-8          variable
/// 0x00                      1 byte separator
/// updated_at_ms             8 bytes big-endian u64
/// load_one flag+value       1 or 9 bytes  (Option<f64> via f64::to_bits BE)
/// load_five flag+value      1 or 9 bytes
/// load_fifteen flag+value   1 or 9 bytes
/// disk_total_bytes flag+val 1 or 9 bytes  (Option<i64> as u64 BE)
/// disk_used_bytes flag+val  1 or 9 bytes
/// sqlite_bytes flag+val     1 or 9 bytes
/// -- CPU utilisation, appended 2026-07-31 --
/// cpu_pct flag+value        1 or 9 bytes  (Option<f64> via f64::to_bits BE)
/// ```
///
/// The `cpu_pct` append is a **dual-accept**, not a "roll every verifier
/// first" change like `security_posture` / `box_profile` above: a monitor
/// that only accepted this exact layout would reject every heartbeat from
/// a sentry that hasn't shipped the matching signer change yet, and this
/// fact already lost a month of `/fleet/health` to exactly that failure
/// mode once. The verifier-side fix lives in [`verify_machine_state_signature`]
/// — it tries this layout first, then falls back to
/// [`machine_state_signing_bytes_legacy`] (the frozen pre-append layout) so
/// a box mid-roll is never rejected. See that function's doc for the
/// removal condition on the legacy branch.
#[allow(clippy::too_many_arguments)]
/// The exact bit patterns of every `f64` a `machine_state` signature commits
/// to, carried on the wire beside the human-readable float fields.
///
/// # Why a signature must not depend on a reparsed decimal
///
/// [`machine_state_signing_bytes`] commits to `f64::to_bits`, so signer and
/// verifier agree only if they hold the *same* `f64`. The float reaches the
/// verifier as decimal text inside the heartbeat body, and the round trip
/// through that text is not guaranteed to return the bits that went in.
///
/// Measured on the live fleet 2026-08-10 and it is not a hypothetical: for one
/// heartbeat (sig prefix `5c07a95a…`, `updated_at_ms` 1786330266359) the
/// signer's preimage ended `…402af9e2e53866a3` and the verifier's
/// `…402af9e2e53866a2` — **one ULP**, in the last byte, with the other 118 of
/// 119 bytes identical. Every sentry heartbeat on every box had been rejected
/// that way for days. The three load averages survived only because they
/// happened to be short decimals; that is luck about the values, not a
/// property of the path.
///
/// So the exact bits travel explicitly. The verifier reconstructs each float
/// with [`f64::from_bits`] and uses it for BOTH the signature check and the
/// stored row — correcting the value at ingest, once, so everything
/// downstream (the row, its gossip, any later re-verification) holds what was
/// actually signed rather than a value one bit away from it.
///
/// `Option` on the whole struct at the call site, not here: a producer that
/// has not rolled yet simply omits the field and the verifier falls back to
/// the reparsed floats, i.e. to exactly today's behaviour. That is what lets
/// the verifier roll BEFORE the signer, which is the standing rule for any
/// change touching signed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MachineStateFloatBits {
    pub load_one: u64,
    pub load_five: u64,
    pub load_fifteen: u64,
    /// `None` mirrors `cpu_pct: None` — "not measured", never a fabricated 0.
    #[serde(default)]
    pub cpu_pct: Option<u64>,
}

impl MachineStateFloatBits {
    /// Capture the bits of the floats about to be signed.
    pub fn capture(
        load_one: f64,
        load_five: f64,
        load_fifteen: f64,
        cpu_pct: Option<f64>,
    ) -> Self {
        Self {
            load_one: load_one.to_bits(),
            load_five: load_five.to_bits(),
            load_fifteen: load_fifteen.to_bits(),
            cpu_pct: cpu_pct.map(f64::to_bits),
        }
    }

    /// The four floats exactly as the signer held them.
    pub fn floats(&self) -> (f64, f64, f64, Option<f64>) {
        (
            f64::from_bits(self.load_one),
            f64::from_bits(self.load_five),
            f64::from_bits(self.load_fifteen),
            self.cpu_pct.map(f64::from_bits),
        )
    }
}

pub fn machine_state_signing_bytes(
    machine_id: &str,
    updated_at_ms: u64,
    load_one: Option<f64>,
    load_five: Option<f64>,
    load_fifteen: Option<f64>,
    disk_total_bytes: Option<i64>,
    disk_used_bytes: Option<i64>,
    sqlite_bytes: Option<i64>,
    cpu_pct: Option<f64>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_MACHINE_STATE.len()
            + machine_id.len()
            + 1   // separator
            + 8   // updated_at_ms
            + 3 * 9  // three optional f64s (worst case)
            + 3 * 9  // three optional i64s (worst case)
            + 9,  // cpu_pct (worst case)
    );

    // Domain prefix.
    out.extend_from_slice(DOMAIN_MACHINE_STATE);

    // machine_id, NUL-terminated.
    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    // Timestamp.
    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    // Optional f64 fields: load averages.
    encode_opt_f64(&mut out, load_one);
    encode_opt_f64(&mut out, load_five);
    encode_opt_f64(&mut out, load_fifteen);

    // Optional i64 fields: disk counters.
    encode_opt_i64(&mut out, disk_total_bytes);
    encode_opt_i64(&mut out, disk_used_bytes);
    encode_opt_i64(&mut out, sqlite_bytes);

    // CPU utilisation percentage (appended 2026-07-31).
    encode_opt_f64(&mut out, cpu_pct);

    out
}

/// The `machine_state` signing-bytes layout as it existed before the
/// 2026-07-31 `cpu_pct` append — i.e. [`machine_state_signing_bytes`] minus
/// its trailing `cpu_pct` field and parameter, byte-for-byte identical to
/// what every sentry in the fleet signs today (Phase 2, which switches
/// sentries to the new layout, has not shipped yet).
///
/// # Why this exists
///
/// `MachineStateRow` is a signed fact (see the module doc's "Option fields"
/// section): appending a field to the canonical layout means a signer still
/// on the old layout and a verifier that only accepts the new layout compute
/// different byte strings, and every signature mismatches. Unlike
/// `security_posture` / `box_profile` above — where the convention is
/// "roll the verifier to every monitor, then flip the signer" with no
/// overlap window — this fact needs the two to coexist while sentries roll
/// out independently over time, so the monitor accepts either layout
/// instead. [`verify_machine_state_signature`] is the only caller: it tries
/// [`machine_state_signing_bytes`] first, then this frozen layout.
///
/// # Removal condition
///
/// Delete this function AND the fallback branch in
/// `verify_machine_state_signature` that calls it once every sentry in the
/// fleet has shipped Phase 2 (signs the layout with `cpu_pct` included). At
/// that point every signature the monitor ever sees verifies against
/// [`machine_state_signing_bytes`] on the first attempt, this branch never
/// matches, and it is dead weight kept alive only by caution. A reviewer
/// checking whether that day has come should look at whether
/// `MachineStateSigLayout::Legacy` is still being observed anywhere in the
/// fleet's logs (see `verify_machine_state_signature`'s return value).
#[allow(clippy::too_many_arguments)]
pub fn machine_state_signing_bytes_legacy(
    machine_id: &str,
    updated_at_ms: u64,
    load_one: Option<f64>,
    load_five: Option<f64>,
    load_fifteen: Option<f64>,
    disk_total_bytes: Option<i64>,
    disk_used_bytes: Option<i64>,
    sqlite_bytes: Option<i64>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_MACHINE_STATE.len()
            + machine_id.len()
            + 1   // separator
            + 8   // updated_at_ms
            + 3 * 9  // three optional f64s (worst case)
            + 3 * 9, // three optional i64s (worst case)
    );

    out.extend_from_slice(DOMAIN_MACHINE_STATE);
    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    encode_opt_f64(&mut out, load_one);
    encode_opt_f64(&mut out, load_five);
    encode_opt_f64(&mut out, load_fifteen);

    encode_opt_i64(&mut out, disk_total_bytes);
    encode_opt_i64(&mut out, disk_used_bytes);
    encode_opt_i64(&mut out, sqlite_bytes);

    out
}

/// Which `machine_state` signing-bytes layout a signature matched in
/// [`verify_machine_state_signature`]. Surfaced (rather than collapsed to a
/// bool) so a caller can log/count observations of `Legacy` — that count
/// hitting zero fleet-wide is the removal condition documented on
/// [`machine_state_signing_bytes_legacy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineStateSigLayout {
    /// Verified against the current layout (`cpu_pct` included).
    Current,
    /// Verified against the pre-2026-07-31 legacy layout (no `cpu_pct`) —
    /// this box hasn't shipped Phase 2 yet.
    Legacy,
}

/// Verify a `machine_state` signature against either signing-bytes layout,
/// so a monitor running this Phase-1 change never rejects a heartbeat from
/// a sentry that hasn't shipped the matching Phase-2 signer change.
///
/// Tries [`machine_state_signing_bytes`] (current layout) first — the
/// common case once the fleet has rolled — then falls back to
/// [`machine_state_signing_bytes_legacy`]. Returns which layout matched, or
/// `None` if the signature is invalid against both.
///
/// This is the single place both call sites in `mirage2monitor`
/// (`sentries_api.rs`'s direct-heartbeat verify and `api.rs`'s
/// gossip-received-fact verify) call into, so the dual-accept logic exists
/// exactly once rather than being copy-pasted at each verifier.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_machine_state_signature(
    machine_id: &str,
    updated_at_ms: u64,
    load_one: Option<f64>,
    load_five: Option<f64>,
    load_fifteen: Option<f64>,
    disk_total_bytes: Option<i64>,
    disk_used_bytes: Option<i64>,
    sqlite_bytes: Option<i64>,
    cpu_pct: Option<f64>,
    sig: &ed25519_dalek::Signature,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> Option<MachineStateSigLayout> {
    use ed25519_dalek::Verifier as _;

    let current_bytes = machine_state_signing_bytes(
        machine_id,
        updated_at_ms,
        load_one,
        load_five,
        load_fifteen,
        disk_total_bytes,
        disk_used_bytes,
        sqlite_bytes,
        cpu_pct,
    );
    if pubkey.verify(&current_bytes, sig).is_ok() {
        return Some(MachineStateSigLayout::Current);
    }

    // Migration path — see `machine_state_signing_bytes_legacy`'s doc for
    // the removal condition.
    let legacy_bytes = machine_state_signing_bytes_legacy(
        machine_id,
        updated_at_ms,
        load_one,
        load_five,
        load_fifteen,
        disk_total_bytes,
        disk_used_bytes,
        sqlite_bytes,
    );
    if pubkey.verify(&legacy_bytes, sig).is_ok() {
        return Some(MachineStateSigLayout::Legacy);
    }

    None
}

/// Build the canonical byte string that covers one `security_posture` fact.
///
/// Originated and signed by `mirage-secd` (one box), verified by every
/// monitor before the fact is applied to the L1 plane. All parameters are
/// typed — no free-form JSON — so signer and verifier produce byte-identical
/// input. A compromised relay cannot forge "I'm compliant" (hide an attacker)
/// or "this peer is hostile" (DoS a peer via the fleet blocklist).
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                       31 bytes + NUL = 32 bytes
/// machine_id UTF-8             variable
/// 0x00                         1 byte separator
/// updated_at_ms                8 bytes big-endian u64
/// posture_ok                   1 byte (0x00 / 0x01)
/// fw_active                    1 byte (0x00 / 0x01)
/// ban_count                    4 bytes big-endian u32
/// attacker_observations        4 bytes big-endian u32
/// -- enrichment appended 2026-06-28 (verifier-first rolled) --
/// password_auth_disabled       1 byte (0x00 / 0x01)
/// root_login_disabled          1 byte (0x00 / 0x01)
/// listener_count               4 bytes big-endian u32
/// unexpected_listener_count    4 bytes big-endian u32
/// trusted_count                4 bytes big-endian u32
/// recent_auth_failures         4 bytes big-endian u32
/// recent_auth_successes        4 bytes big-endian u32
/// -- secd arc2 per-axis achieved, appended 2026-07-06 (verifier-first rolled) --
/// kernel_tier_achieved         1 byte (KernelTier discriminant)
/// dk_backend_achieved          1 byte (DkBackend discriminant)
/// conf_mode_achieved           1 byte (ConfMode discriminant)
/// egress_achieved              1 byte (EgressMode discriminant)
/// integrity_achieved           1 byte (IntegrityMode discriminant)
/// sandbox_achieved             1 byte (SandboxMode discriminant)
/// enforce_mode                 1 byte (EnforceMode discriminant)
/// detection_achieved           1 byte (DetectionMode discriminant)
/// tier2_bpf_lsm_live           1 byte (0x00 / 0x01)
/// -- arc2.8 axis F, appended 2026-07-09 (verifier-first rolled) --
/// surface_achieved             1 byte (SurfaceMode discriminant)
/// ```
///
/// Appended fields extend the canonical layout (old verifiers compute a
/// shorter buffer → signature mismatch → drop; hence the verifier rolls to
/// every monitor BEFORE secd signs the new layout). The arc2 block carries
/// achieved-per-axis as raw `u8` discriminants (not the `mirage_core::secd_policy`
/// enums directly) so this crate's byte layout has no dependency edge onto
/// the enum's `#[repr(u8)]` guarantee changing shape independently of the
/// signing contract — callers pass `achieved as u8`.
#[allow(clippy::too_many_arguments)]
pub fn security_posture_signing_bytes(
    machine_id: &str,
    updated_at_ms: u64,
    posture_ok: bool,
    fw_active: bool,
    ban_count: u32,
    attacker_observations: u32,
    password_auth_disabled: bool,
    root_login_disabled: bool,
    listener_count: u32,
    unexpected_listener_count: u32,
    trusted_count: u32,
    recent_auth_failures: u32,
    recent_auth_successes: u32,
    kernel_tier_achieved: u8,
    dk_backend_achieved: u8,
    conf_mode_achieved: u8,
    egress_achieved: u8,
    integrity_achieved: u8,
    sandbox_achieved: u8,
    enforce_mode: u8,
    detection_achieved: u8,
    tier2_bpf_lsm_live: bool,
    surface_achieved: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_SECURITY_POSTURE.len()
            + machine_id.len()
            + 1  // separator
            + 8  // updated_at_ms
            + 1  // posture_ok
            + 1  // fw_active
            + 4  // ban_count
            + 4  // attacker_observations
            + 1  // password_auth_disabled
            + 1  // root_login_disabled
            + 4  // listener_count
            + 4  // unexpected_listener_count
            + 4  // trusted_count
            + 4  // recent_auth_failures
            + 4  // recent_auth_successes
            + 1  // kernel_tier_achieved
            + 1  // dk_backend_achieved
            + 1  // conf_mode_achieved
            + 1  // egress_achieved
            + 1  // integrity_achieved
            + 1  // sandbox_achieved
            + 1  // enforce_mode
            + 1  // detection_achieved
            + 1  // tier2_bpf_lsm_live
            + 1, // surface_achieved
    );

    // Domain prefix.
    out.extend_from_slice(DOMAIN_SECURITY_POSTURE);

    // machine_id, NUL-terminated.
    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    // Timestamp (originator-stamped, preserved verbatim by verifiers).
    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    // Booleans as single bytes.
    out.push(u8::from(posture_ok));
    out.push(u8::from(fw_active));

    // Counters.
    out.extend_from_slice(&ban_count.to_be_bytes());
    out.extend_from_slice(&attacker_observations.to_be_bytes());

    // --- enrichment (appended 2026-06-28) ---
    out.push(u8::from(password_auth_disabled));
    out.push(u8::from(root_login_disabled));
    out.extend_from_slice(&listener_count.to_be_bytes());
    out.extend_from_slice(&unexpected_listener_count.to_be_bytes());
    out.extend_from_slice(&trusted_count.to_be_bytes());
    out.extend_from_slice(&recent_auth_failures.to_be_bytes());
    out.extend_from_slice(&recent_auth_successes.to_be_bytes());

    // --- secd arc2 per-axis achieved (appended 2026-07-06) ---
    out.push(kernel_tier_achieved);
    out.push(dk_backend_achieved);
    out.push(conf_mode_achieved);
    out.push(egress_achieved);
    out.push(integrity_achieved);
    out.push(sandbox_achieved);
    out.push(enforce_mode);
    out.push(detection_achieved);
    out.push(u8::from(tier2_bpf_lsm_live));

    // --- arc2.8 axis F achieved (appended 2026-07-09) ---
    out.push(surface_achieved);

    out
}

/// One box's signed static hardware/OS/capability profile, originated and
/// signed by `mirage-secd`, verified by every monitor before the fact is
/// applied to the L1 plane — same trust model as `SecurityPostureRow`.
///
/// Unlike `security_posture` (whose row type lives in
/// `mirage2monitor::store`), `BoxProfileRow` lives here in `mirage-core`
/// because the capability profile is a cross-crate contract type consumed
/// directly by more than one server-side component.
///
/// Field order matches the signing order in [`box_profile_signing_bytes`] —
/// do not reorder without also updating that function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxProfileRow {
    /// LWW key: the canonical machine identifier (e.g. `ru-hostkey-203.0.113.10`).
    pub machine_id: String,
    /// Originator-stamped UNIX millisecond timestamp. Receivers skip the
    /// row when their local `updated_at_ms >= incoming`.
    pub updated_at_ms: u64,
    // --- static hardware ---
    /// CPU model string (e.g. `"Intel(R) Xeon(R) Gold 6248R"`).
    pub cpu_model: String,
    /// CPU architecture (`"x86_64"` / `"aarch64"`).
    pub cpu_arch: String,
    /// Physical CPU core count.
    pub cpu_cores_physical: u32,
    /// Logical thread count (physical cores × SMT factor).
    pub cpu_threads: u32,
    /// Sorted, comma-joined CPU feature flags (deterministic) —
    /// e.g. `"aes,avx2,rdrand"`.
    pub cpu_flags: String,
    /// Total RAM in megabytes.
    pub ram_total_mb: u32,
    /// Total disk capacity in gigabytes.
    pub disk_total_gb: u32,
    /// Root filesystem type (e.g. `"ext4"`, `"xfs"`, `"zfs"`).
    pub rootfs_type: String,
    /// DMI system vendor string.
    pub dmi_sys_vendor: String,
    /// DMI product name string.
    pub dmi_product_name: String,
    /// DMI board name string.
    pub dmi_board: String,
    // --- static OS/kernel ---
    /// Distro id (e.g. `"ubuntu"`).
    pub distro: String,
    /// Distro version string.
    pub distro_version: String,
    /// Kernel release (`uname -r`).
    pub kernel_version: String,
    /// systemd version string.
    pub systemd_version: String,
    /// Unix-ms boot time of the box.
    pub boot_time_ms: u64,
    // --- capability profile (the arc2-critical block) ---
    /// `systemd-detect-virt` token: `"kvm"` / `"lxc"` / `"openvz"` /
    /// `"none"` / ...
    pub virt_type: String,
    /// Whether the box is a full hardware-virtualised VM (vs. container /
    /// bare metal).
    pub is_full_vm: bool,
    /// Sorted, comma-joined active LSMs from `/sys/kernel/security/lsm`.
    pub active_lsms: String,
    /// Whether the BPF LSM is active at runtime.
    pub has_bpf_lsm_active: bool,
    /// Whether `CONFIG_BPF_LSM` was compiled into the running kernel.
    pub config_bpf_lsm_compiled: bool,
    /// `/proc/sys/kernel/yama/ptrace_scope` value (0..3).
    pub ptrace_scope: u8,
    /// Kernel lockdown state: `"none"` / `"integrity"` / `"confidentiality"`.
    pub lockdown_state: String,
    /// Whether `bpffs` is mounted.
    pub bpffs_mounted: bool,
    /// Whether kernel module loading has been permanently disabled.
    pub modules_disabled: bool,
    /// Derived maximum defense tier this box can run (0/1/2).
    pub max_defense_tier: u8,
    // --- secd arc2 per-axis capability ceilings (plan §3, appended 2026-07-06) ---
    /// Confidential-compute platform this box exposes: `0` none, `1`
    /// SEV-SNP, `2` TDX, ... (axis C ceiling source).
    pub cc_platform: u8,
    /// Whether `memfd_secret(2)` is available (axis D ceiling source).
    pub secretmem_enabled: bool,
    /// Whether a vTPM device (`/dev/tpmrm0`) is present (axis D ceiling source).
    pub vtpm_present: bool,
    /// Whether the filesystem supports fs-verity (axis I ceiling source).
    pub fsverity_supported: bool,
    /// Whether IMA (`/sys/kernel/security/ima`) is available (axis I ceiling source).
    pub ima_present: bool,
    /// Whether the IPE LSM is present (kernel ≥6.12; axis I ceiling source).
    pub ipe_present: bool,
    /// Whether dm-verity is available (axis I ceiling source).
    pub dmverity_supported: bool,
    /// Landlock ABI level (`0` = unavailable; axis S ceiling source).
    pub landlock_abi: u8,
    /// Derived ceiling: the highest [`crate::secd_policy::DkBackend`]
    /// discriminant this box can reach.
    pub dk_backend_ceiling: u8,
    /// Derived ceiling: the highest [`crate::secd_policy::ConfMode`]
    /// discriminant this box can reach.
    pub conf_mode_ceiling: u8,
    /// Derived ceiling: the highest [`crate::secd_policy::IntegrityMode`]
    /// discriminant this box can reach.
    pub integrity_ceiling: u8,
    /// Derived ceiling: the highest [`crate::secd_policy::SandboxMode`]
    /// discriminant this box can reach.
    pub sandbox_ceiling: u8,
    // --- provenance ---
    /// secd's `DeclaredIdentity.self_id` (UUID string). Required — the
    /// verifier resolves the Ed25519 pubkey via
    /// `declared_identities WHERE self_id = originator_self_id`.
    pub originator_self_id: String,
    /// Hex Ed25519 signature over [`box_profile_signing_bytes`].
    pub sig_hex: String,
}

/// Build the canonical byte string that covers one `box_profile` fact.
///
/// Originated and signed by `mirage-secd` (one box), verified by every
/// monitor before the fact is applied to the L1 plane. All parameters are
/// typed — no free-form JSON — so signer and verifier produce byte-identical
/// input. `originator_self_id` and `sig_hex` are NOT part of the signed
/// bytes (same convention as `security_posture_signing_bytes`): they are
/// provenance/verification metadata carried alongside the row, not data the
/// signature covers.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                        27 bytes + NUL = 28 bytes
/// machine_id UTF-8              variable
/// 0x00                          1 byte separator
/// updated_at_ms                 8 bytes big-endian u64
/// cpu_model UTF-8               variable
/// 0x00                          1 byte separator
/// cpu_arch UTF-8                variable
/// 0x00                          1 byte separator
/// cpu_cores_physical            4 bytes big-endian u32
/// cpu_threads                   4 bytes big-endian u32
/// cpu_flags UTF-8                variable
/// 0x00                          1 byte separator
/// ram_total_mb                  4 bytes big-endian u32
/// disk_total_gb                 4 bytes big-endian u32
/// rootfs_type UTF-8              variable
/// 0x00                          1 byte separator
/// dmi_sys_vendor UTF-8           variable
/// 0x00                          1 byte separator
/// dmi_product_name UTF-8         variable
/// 0x00                          1 byte separator
/// dmi_board UTF-8                variable
/// 0x00                          1 byte separator
/// distro UTF-8                   variable
/// 0x00                          1 byte separator
/// distro_version UTF-8           variable
/// 0x00                          1 byte separator
/// kernel_version UTF-8           variable
/// 0x00                          1 byte separator
/// systemd_version UTF-8          variable
/// 0x00                          1 byte separator
/// boot_time_ms                  8 bytes big-endian u64
/// virt_type UTF-8                 variable
/// 0x00                          1 byte separator
/// is_full_vm                    1 byte (0x00 / 0x01)
/// active_lsms UTF-8               variable
/// 0x00                          1 byte separator
/// has_bpf_lsm_active             1 byte (0x00 / 0x01)
/// config_bpf_lsm_compiled        1 byte (0x00 / 0x01)
/// ptrace_scope                   1 byte
/// lockdown_state UTF-8            variable
/// 0x00                          1 byte separator
/// bpffs_mounted                  1 byte (0x00 / 0x01)
/// modules_disabled               1 byte (0x00 / 0x01)
/// max_defense_tier               1 byte
/// -- secd arc2 per-axis ceilings, appended 2026-07-06 (verifier-first rolled) --
/// cc_platform                    1 byte
/// secretmem_enabled              1 byte (0x00 / 0x01)
/// vtpm_present                   1 byte (0x00 / 0x01)
/// fsverity_supported             1 byte (0x00 / 0x01)
/// ima_present                    1 byte (0x00 / 0x01)
/// ipe_present                    1 byte (0x00 / 0x01)
/// dmverity_supported             1 byte (0x00 / 0x01)
/// landlock_abi                   1 byte
/// dk_backend_ceiling             1 byte
/// conf_mode_ceiling              1 byte
/// integrity_ceiling              1 byte
/// sandbox_ceiling                1 byte
/// ```
#[allow(clippy::too_many_arguments)]
pub fn box_profile_signing_bytes(
    machine_id: &str,
    updated_at_ms: u64,
    cpu_model: &str,
    cpu_arch: &str,
    cpu_cores_physical: u32,
    cpu_threads: u32,
    cpu_flags: &str,
    ram_total_mb: u32,
    disk_total_gb: u32,
    rootfs_type: &str,
    dmi_sys_vendor: &str,
    dmi_product_name: &str,
    dmi_board: &str,
    distro: &str,
    distro_version: &str,
    kernel_version: &str,
    systemd_version: &str,
    boot_time_ms: u64,
    virt_type: &str,
    is_full_vm: bool,
    active_lsms: &str,
    has_bpf_lsm_active: bool,
    config_bpf_lsm_compiled: bool,
    ptrace_scope: u8,
    lockdown_state: &str,
    bpffs_mounted: bool,
    modules_disabled: bool,
    max_defense_tier: u8,
    cc_platform: u8,
    secretmem_enabled: bool,
    vtpm_present: bool,
    fsverity_supported: bool,
    ima_present: bool,
    ipe_present: bool,
    dmverity_supported: bool,
    landlock_abi: u8,
    dk_backend_ceiling: u8,
    conf_mode_ceiling: u8,
    integrity_ceiling: u8,
    sandbox_ceiling: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_BOX_PROFILE.len()
            + machine_id.len() + 1
            + 8 // updated_at_ms
            + cpu_model.len() + 1
            + cpu_arch.len() + 1
            + 4 // cpu_cores_physical
            + 4 // cpu_threads
            + cpu_flags.len() + 1
            + 4 // ram_total_mb
            + 4 // disk_total_gb
            + rootfs_type.len() + 1
            + dmi_sys_vendor.len() + 1
            + dmi_product_name.len() + 1
            + dmi_board.len() + 1
            + distro.len() + 1
            + distro_version.len() + 1
            + kernel_version.len() + 1
            + systemd_version.len() + 1
            + 8 // boot_time_ms
            + virt_type.len() + 1
            + 1 // is_full_vm
            + active_lsms.len() + 1
            + 1 // has_bpf_lsm_active
            + 1 // config_bpf_lsm_compiled
            + 1 // ptrace_scope
            + lockdown_state.len() + 1
            + 1 // bpffs_mounted
            + 1 // modules_disabled
            + 1 // max_defense_tier
            + 1 // cc_platform
            + 1 // secretmem_enabled
            + 1 // vtpm_present
            + 1 // fsverity_supported
            + 1 // ima_present
            + 1 // ipe_present
            + 1 // dmverity_supported
            + 1 // landlock_abi
            + 1 // dk_backend_ceiling
            + 1 // conf_mode_ceiling
            + 1 // integrity_ceiling
            + 1, // sandbox_ceiling
    );

    // Domain prefix.
    out.extend_from_slice(DOMAIN_BOX_PROFILE);

    // machine_id, NUL-terminated.
    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    // Timestamp (originator-stamped, preserved verbatim by verifiers).
    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    // --- static hardware ---
    out.extend_from_slice(cpu_model.as_bytes());
    out.push(0u8);
    out.extend_from_slice(cpu_arch.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&cpu_cores_physical.to_be_bytes());
    out.extend_from_slice(&cpu_threads.to_be_bytes());
    out.extend_from_slice(cpu_flags.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&ram_total_mb.to_be_bytes());
    out.extend_from_slice(&disk_total_gb.to_be_bytes());
    out.extend_from_slice(rootfs_type.as_bytes());
    out.push(0u8);
    out.extend_from_slice(dmi_sys_vendor.as_bytes());
    out.push(0u8);
    out.extend_from_slice(dmi_product_name.as_bytes());
    out.push(0u8);
    out.extend_from_slice(dmi_board.as_bytes());
    out.push(0u8);

    // --- static OS/kernel ---
    out.extend_from_slice(distro.as_bytes());
    out.push(0u8);
    out.extend_from_slice(distro_version.as_bytes());
    out.push(0u8);
    out.extend_from_slice(kernel_version.as_bytes());
    out.push(0u8);
    out.extend_from_slice(systemd_version.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&boot_time_ms.to_be_bytes());

    // --- capability profile ---
    out.extend_from_slice(virt_type.as_bytes());
    out.push(0u8);
    out.push(u8::from(is_full_vm));
    out.extend_from_slice(active_lsms.as_bytes());
    out.push(0u8);
    out.push(u8::from(has_bpf_lsm_active));
    out.push(u8::from(config_bpf_lsm_compiled));
    out.push(ptrace_scope);
    out.extend_from_slice(lockdown_state.as_bytes());
    out.push(0u8);
    out.push(u8::from(bpffs_mounted));
    out.push(u8::from(modules_disabled));
    out.push(max_defense_tier);

    // --- secd arc2 per-axis ceilings (appended 2026-07-06) ---
    out.push(cc_platform);
    out.push(u8::from(secretmem_enabled));
    out.push(u8::from(vtpm_present));
    out.push(u8::from(fsverity_supported));
    out.push(u8::from(ima_present));
    out.push(u8::from(ipe_present));
    out.push(u8::from(dmverity_supported));
    out.push(landlock_abi);
    out.push(dk_backend_ceiling);
    out.push(conf_mode_ceiling);
    out.push(integrity_ceiling);
    out.push(sandbox_ceiling);

    out
}

/// Verify a [`BoxProfileRow`]'s `sig_hex` against the given Ed25519
/// verifying key, recomputing [`box_profile_signing_bytes`] from the row's
/// typed fields (never trusting a serialised blob).
///
/// Mirrors how `security_posture` verification is done inline at the
/// `secd_posture` call site in `mirage2monitor`, but packaged as a reusable
/// helper here since `BoxProfileRow` itself lives in this crate.
///
/// Returns `false` on any decoding failure (malformed hex, wrong signature
/// length) or a genuine signature mismatch — callers only need a boolean
/// accept/reject, never a reason.
#[must_use]
pub fn verify_box_profile(row: &BoxProfileRow, pubkey: &ed25519_dalek::VerifyingKey) -> bool {
    use ed25519_dalek::Verifier as _;

    let Ok(sig_bytes) = hex::decode(&row.sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let bytes = box_profile_signing_bytes(
        &row.machine_id,
        row.updated_at_ms,
        &row.cpu_model,
        &row.cpu_arch,
        row.cpu_cores_physical,
        row.cpu_threads,
        &row.cpu_flags,
        row.ram_total_mb,
        row.disk_total_gb,
        &row.rootfs_type,
        &row.dmi_sys_vendor,
        &row.dmi_product_name,
        &row.dmi_board,
        &row.distro,
        &row.distro_version,
        &row.kernel_version,
        &row.systemd_version,
        row.boot_time_ms,
        &row.virt_type,
        row.is_full_vm,
        &row.active_lsms,
        row.has_bpf_lsm_active,
        row.config_bpf_lsm_compiled,
        row.ptrace_scope,
        &row.lockdown_state,
        row.bpffs_mounted,
        row.modules_disabled,
        row.max_defense_tier,
        row.cc_platform,
        row.secretmem_enabled,
        row.vtpm_present,
        row.fsverity_supported,
        row.ima_present,
        row.ipe_present,
        row.dmverity_supported,
        row.landlock_abi,
        row.dk_backend_ceiling,
        row.conf_mode_ceiling,
        row.integrity_ceiling,
        row.sandbox_ceiling,
    );

    pubkey.verify(&bytes, &sig).is_ok()
}

/// The platform-identifying subset of a [`BoxProfileRow`] — cpu model,
/// arch, and DMI vendor/product/board strings.
///
/// Used to compare a value a box PRESENTS at ask-time
/// (`crate::identity_boot::BootAnnounce::platform`) against the last signed
/// [`BoxProfileRow`] a monitor holds for it — admission gate 4, "platform
/// facts match the last box_profile". Deliberately narrower than the full
/// `BoxProfileRow`, which also carries fields that legitimately change on
/// every report (`updated_at_ms`) or carry no platform information at all
/// (`sig_hex`, `originator_self_id`). Comparing the full row would refuse
/// every re-admission on the timestamp alone, which is not what this gate
/// is for — it exists to notice a DIFFERENT machine answering under the
/// same name, not a machine that filed a fresh report since the last one.
///
/// Carries `Serialize`/`Deserialize` so it can ride inside a signed,
/// wire-carried `BootAnnounce` — this is what replaces
/// `mirage2monitor::admission::PlatformFingerprint`, a structurally
/// identical local type with no serde derives that could not ride a wire
/// request for exactly that reason. The two operands of gate 4's
/// comparison — what a box presents, and what a monitor has stored — must
/// share one shape, or the comparison itself is meaningless.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformFingerprint {
    pub cpu_model: String,
    pub cpu_arch: String,
    pub dmi_sys_vendor: String,
    pub dmi_product_name: String,
    pub dmi_board: String,
}

impl BoxProfileRow {
    /// Project this row down to its platform-identifying subset, for a
    /// direct comparison against what a `BootAnnounce` presents. The whole
    /// point of gate 4 is comparing a presented claim to a stored signed
    /// one, and two independently-shaped views of "the same five facts"
    /// would make that comparison meaningless.
    #[must_use]
    pub fn platform_fingerprint(&self) -> PlatformFingerprint {
        PlatformFingerprint {
            cpu_model: self.cpu_model.clone(),
            cpu_arch: self.cpu_arch.clone(),
            dmi_sys_vendor: self.dmi_sys_vendor.clone(),
            dmi_product_name: self.dmi_product_name.clone(),
            dmi_board: self.dmi_board.clone(),
        }
    }
}

/// Build the canonical byte string that covers one `attacker_intel`
/// observation (tier-0 active defense).
///
/// Originated and signed by one box's `mirage-secd`, verified by every monitor
/// before the fact is applied to the L1 plane. Each fact is a single box's
/// self-contained assertion — "I, `machine_id`, observed `ip` `touch_count`
/// times since `first_seen_ms`". A signature can only bind what one signer
/// asserts, so `(machine_id, ip)` is the LWW key and fleet-wide reputation
/// ("how many boxes saw this IP") is recovered at READ time via aggregation,
/// never a write-time CRDT merge. A compromised relay can therefore forge only
/// its OWN observations (its key binds its own `machine_id`), never a peer's —
/// the same guarantee `security_posture` has, now enforced fleet-wide.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                        29 bytes + NUL = 30 bytes
/// machine_id UTF-8              variable
/// 0x00                          1 byte separator
/// ip UTF-8                      variable
/// 0x00                          1 byte separator
/// updated_at_ms                 8 bytes big-endian u64  (== last-seen)
/// first_seen_ms                 8 bytes big-endian u64
/// touch_count                   4 bytes big-endian u32
/// signal_type                   1 byte (AttackerSignalType discriminant)
/// confidence                    1 byte (0-100 bucket, u8 not f32 — determinism)
/// ban_active                    1 byte (0x00 / 0x01)
/// ```
///
/// Appended fields extend the canonical layout (old verifiers compute a
/// shorter buffer → signature mismatch → drop); roll the verifier to every
/// monitor BEFORE secd signs a new layout — the same rolling-upgrade contract
/// as `security_posture`.
pub fn attacker_intel_signing_bytes(
    machine_id: &str,
    ip: &str,
    updated_at_ms: u64,
    first_seen_ms: u64,
    touch_count: u32,
    signal_type: u8,
    confidence: u8,
    ban_active: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_ATTACKER_INTEL.len()
            + machine_id.len()
            + 1  // separator
            + ip.len()
            + 1  // separator
            + 8  // updated_at_ms
            + 8  // first_seen_ms
            + 4  // touch_count
            + 1  // signal_type
            + 1  // confidence
            + 1, // ban_active
    );

    // Domain prefix.
    out.extend_from_slice(DOMAIN_ATTACKER_INTEL);

    // Key: (machine_id, ip), each NUL-terminated.
    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);
    out.extend_from_slice(ip.as_bytes());
    out.push(0u8);

    // Timestamps (originator-stamped, preserved verbatim by verifiers).
    out.extend_from_slice(&updated_at_ms.to_be_bytes());
    out.extend_from_slice(&first_seen_ms.to_be_bytes());

    // Per-box counter + closed-set discriminant + bounded confidence + local ban.
    out.extend_from_slice(&touch_count.to_be_bytes());
    out.push(signal_type);
    out.push(confidence);
    out.push(u8::from(ban_active));

    out
}

/// Build the canonical byte string that covers one `node_metrics` snapshot.
///
/// All parameters are typed — no free-form JSON is included.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                    28 bytes + NUL = 29 bytes
/// node_id UTF-8             variable
/// 0x00                      1 byte separator
/// updated_at_ms             8 bytes big-endian u64
/// cpu_pct                   4 bytes (f32::to_bits BE)
/// mem_total_mb              4 bytes big-endian u32
/// mem_used_mb               4 bytes big-endian u32
/// mem_used_pct              4 bytes (f32::to_bits BE)
/// load_avg_1m               4 bytes (f32::to_bits BE)
/// num_cpus                  4 bytes big-endian u32
/// sampled_at_ms             8 bytes big-endian u64
/// ```
#[allow(clippy::too_many_arguments)]
pub fn node_metrics_signing_bytes(
    node_id: &str,
    updated_at_ms: u64,
    cpu_pct: f32,
    mem_total_mb: u32,
    mem_used_mb: u32,
    mem_used_pct: f32,
    load_avg_1m: f32,
    num_cpus: u32,
    sampled_at_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_NODE_METRICS.len()
            + node_id.len()
            + 1   // NUL separator
            + 8   // updated_at_ms
            + 4   // cpu_pct
            + 4   // mem_total_mb
            + 4   // mem_used_mb
            + 4   // mem_used_pct
            + 4   // load_avg_1m
            + 4   // num_cpus
            + 8,  // sampled_at_ms
    );

    out.extend_from_slice(DOMAIN_NODE_METRICS);

    out.extend_from_slice(node_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&updated_at_ms.to_be_bytes());
    out.extend_from_slice(&cpu_pct.to_bits().to_be_bytes());
    out.extend_from_slice(&mem_total_mb.to_be_bytes());
    out.extend_from_slice(&mem_used_mb.to_be_bytes());
    out.extend_from_slice(&mem_used_pct.to_bits().to_be_bytes());
    out.extend_from_slice(&load_avg_1m.to_bits().to_be_bytes());
    out.extend_from_slice(&num_cpus.to_be_bytes());
    out.extend_from_slice(&sampled_at_ms.to_be_bytes());

    out
}

/// Build the canonical byte string that covers one `node_egress` observation.
///
/// All parameters are typed — no free-form JSON is included. The `status`
/// string is encoded as UTF-8 followed by a NUL terminator so distinct status
/// strings always produce distinct byte sequences.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                    26 bytes + NUL = 27 bytes
/// from_node_id UTF-8        variable
/// 0x00                      1 byte separator
/// to_node_id UTF-8          variable
/// 0x00                      1 byte separator
/// updated_at_ms             8 bytes big-endian u64
/// status UTF-8              variable
/// 0x00                      1 byte separator
/// rtt_ms flag+value         1 or 5 bytes  (Option<u32> BE)
/// consecutive_fails         4 bytes big-endian u32
/// last_probe_ms             8 bytes big-endian u64
/// ```
#[allow(clippy::too_many_arguments)]
pub fn node_egress_signing_bytes(
    from_node_id: &str,
    to_node_id: &str,
    updated_at_ms: u64,
    status: &str,
    rtt_ms: Option<u32>,
    consecutive_fails: u32,
    last_probe_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_NODE_EGRESS.len()
            + from_node_id.len()
            + 1   // NUL separator
            + to_node_id.len()
            + 1   // NUL separator
            + 8   // updated_at_ms
            + status.len()
            + 1   // NUL separator
            + 5   // rtt_ms (worst case: flag + u32)
            + 4   // consecutive_fails
            + 8,  // last_probe_ms
    );

    out.extend_from_slice(DOMAIN_NODE_EGRESS);

    out.extend_from_slice(from_node_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(to_node_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    out.extend_from_slice(status.as_bytes());
    out.push(0u8);

    encode_opt_u32(&mut out, rtt_ms);

    out.extend_from_slice(&consecutive_fails.to_be_bytes());
    out.extend_from_slice(&last_probe_ms.to_be_bytes());

    out
}

/// Build the canonical byte string that covers one `listener_state` snapshot.
///
/// `listener_state` is the only gossiped fact originated by a **node**
/// (every other signed fact comes from a sentry). The node signs over the
/// fields it asserts in a single `ListenerBound` / `ListenerError` /
/// `ListenerSnapshot`-entry frame; the receiving monitor stamps
/// `originator_self_id = <node self_id>` and forwards `sig_hex` into the
/// gossiped `ListenerStateUpsert`, and every sibling monitor recomputes
/// these bytes from the gossiped event to verify before applying.
///
/// All parameters are typed — no free-form JSON. The two string fields
/// (`bound_addr`, `last_error`) are `Option`; each is encoded with a
/// one-byte presence flag and a NUL terminator so that distinct strings —
/// and `None` vs `Some("")` — always produce distinct byte sequences.
///
/// `updated_at_ms` is **node-stamped** (originator-stamped, L1.2): the node
/// sets it at emit time and the monitor preserves it verbatim for signed
/// facts. Including it in the signature binds the timestamp, closing the
/// rollback window where a captured signed fact is replayed with a fresher
/// timestamp to win LWW.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                    29 bytes + NUL = 30 bytes
/// node_id UTF-8             variable
/// 0x00                      1 byte separator
/// listener_id UTF-8         variable
/// 0x00                      1 byte separator
/// state UTF-8               variable
/// 0x00                      1 byte separator
/// updated_at_ms             8 bytes big-endian u64
/// bound_addr flag+value     1 byte, or 1 + len + NUL  (Option<&str>)
/// bind_port flag+value      1 or 3 bytes             (Option<u16> BE)
/// last_error flag+value     1 byte, or 1 + len + NUL  (Option<&str>)
/// bytes_in                  8 bytes big-endian u64
/// bytes_out                 8 bytes big-endian u64
/// active_conns              4 bytes big-endian u32
/// ```
#[allow(clippy::too_many_arguments)]
pub fn listener_state_signing_bytes(
    node_id: &str,
    listener_id: &str,
    state: &str,
    updated_at_ms: u64,
    bound_addr: Option<&str>,
    bind_port: Option<u16>,
    last_error: Option<&str>,
    bytes_in: u64,
    bytes_out: u64,
    active_conns: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_LISTENER_STATE.len()
            + node_id.len()
            + 1
            + listener_id.len()
            + 1
            + state.len()
            + 1
            + 8   // updated_at_ms
            + 1 + bound_addr.map(|s| s.len() + 1).unwrap_or(0)
            + 3   // bind_port (worst case)
            + 1 + last_error.map(|s| s.len() + 1).unwrap_or(0)
            + 8   // bytes_in
            + 8   // bytes_out
            + 4,  // active_conns
    );

    out.extend_from_slice(DOMAIN_LISTENER_STATE);

    out.extend_from_slice(node_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(listener_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(state.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    encode_opt_str(&mut out, bound_addr);
    encode_opt_u16(&mut out, bind_port);
    encode_opt_str(&mut out, last_error);

    out.extend_from_slice(&bytes_in.to_be_bytes());
    out.extend_from_slice(&bytes_out.to_be_bytes());
    out.extend_from_slice(&active_conns.to_be_bytes());

    out
}

// -- Private helpers ----------------------------------------------------------

#[inline]
fn encode_opt_f64(out: &mut Vec<u8>, v: Option<f64>) {
    match v {
        None => out.push(0x00),
        Some(f) => {
            out.push(0x01);
            out.extend_from_slice(&f.to_bits().to_be_bytes());
        }
    }
}

#[inline]
fn encode_opt_i64(out: &mut Vec<u8>, v: Option<i64>) {
    match v {
        None => out.push(0x00),
        Some(i) => {
            out.push(0x01);
            // Reinterpret as u64 for a stable big-endian bit pattern.
            out.extend_from_slice(&(i as u64).to_be_bytes());
        }
    }
}

#[inline]
fn encode_opt_u32(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => out.push(0x00),
        Some(n) => {
            out.push(0x01);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

#[inline]
fn encode_opt_u16(out: &mut Vec<u8>, v: Option<u16>) {
    match v {
        None => out.push(0x00),
        Some(n) => {
            out.push(0x01);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Encode an `Option<&str>` as a presence flag plus, when present, the UTF-8
/// bytes followed by a NUL terminator. The terminator makes the boundary
/// unambiguous against the following field and keeps `Some("")` distinct
/// from `None` (`0x01 0x00` vs `0x00`).
#[inline]
fn encode_opt_str(out: &mut Vec<u8>, v: Option<&str>) {
    match v {
        None => out.push(0x00),
        Some(s) => {
            out.push(0x01);
            out.extend_from_slice(s.as_bytes());
            out.push(0u8);
        }
    }
}

// ── secd arc2 — new signed-fact types (2026-07-06) ──────────────────────────
//
// Each follows the exact `BoxProfileRow` pattern: a domain-separated
// `..._signing_bytes` builder + a `verify_...` helper living directly in this
// crate (not `mirage2monitor::store`), because these facts are consumed by
// more than one server-side crate (monitor + secd + operator-box harness).

/// One box's signed confidential-compute attestation report (axis C, plan
/// §7). Originated by sentry once it detects `ConfMode` capability, verified
/// by every monitor before the fact is applied to the L1 plane.
///
/// Inert on the current fleet (`cc_platform == 0`, empty measurement) —
/// activates automatically the moment a box reports capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReportRow {
    /// LWW key: the canonical machine identifier (e.g. `ru-hostkey-203.0.113.10`).
    pub machine_id: String,
    /// Originator-stamped UNIX millisecond timestamp. Receivers skip the
    /// row when their local `updated_at_ms >= incoming`.
    pub updated_at_ms: u64,
    /// Confidential-compute platform: `0` none, `1` SEV-SNP, `2` TDX, ...
    /// (same scale as `BoxProfileRow::cc_platform`).
    pub cc_platform: u8,
    /// The attestation measurement (hex-encoded hash of the guest's
    /// launch/runtime state — e.g. SNP `MEASUREMENT` or TDX `MRTD`).
    pub measurement_hex: String,
    /// Report-data field bound into the attestation request (hex-encoded) —
    /// e.g. a nonce or a hash of the DK-release request being gated.
    pub report_data_hex: String,
    /// The raw attestation blob (hex-encoded) — e.g. the full SNP
    /// `SNP_GET_REPORT` structure or TDX quote, for offline re-verification
    /// against the AMD KDS / Intel DCAP chain. Variable length, so it rides
    /// the signed bytes as a length-prefixed field like every other string.
    pub attestation_blob_hex: String,
    /// secd's `DeclaredIdentity.self_id` (UUID string). Required — the
    /// verifier resolves the Ed25519 pubkey via
    /// `declared_identities WHERE self_id = originator_self_id`.
    pub originator_self_id: String,
    /// Hex Ed25519 signature over [`attestation_report_signing_bytes`].
    pub sig_hex: String,
}

/// Build the canonical byte string that covers one `attestation_report` fact.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                        33 bytes + NUL = 34 bytes
/// machine_id UTF-8 + NUL        variable
/// updated_at_ms                 8 bytes big-endian u64
/// cc_platform                   1 byte
/// measurement_hex UTF-8 + NUL   variable
/// report_data_hex UTF-8 + NUL   variable
/// attestation_blob_hex + NUL    variable
/// ```
pub fn attestation_report_signing_bytes(
    machine_id: &str,
    updated_at_ms: u64,
    cc_platform: u8,
    measurement_hex: &str,
    report_data_hex: &str,
    attestation_blob_hex: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_ATTESTATION_REPORT.len()
            + machine_id.len() + 1
            + 8 // updated_at_ms
            + 1 // cc_platform
            + measurement_hex.len() + 1
            + report_data_hex.len() + 1
            + attestation_blob_hex.len() + 1,
    );

    out.extend_from_slice(DOMAIN_ATTESTATION_REPORT);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    out.push(cc_platform);

    out.extend_from_slice(measurement_hex.as_bytes());
    out.push(0u8);

    out.extend_from_slice(report_data_hex.as_bytes());
    out.push(0u8);

    out.extend_from_slice(attestation_blob_hex.as_bytes());
    out.push(0u8);

    out
}

/// Verify an [`AttestationReportRow`]'s `sig_hex` against the given Ed25519
/// verifying key, recomputing [`attestation_report_signing_bytes`] from the
/// row's typed fields.
#[must_use]
pub fn verify_attestation_report(
    row: &AttestationReportRow,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier as _;

    let Ok(sig_bytes) = hex::decode(&row.sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let bytes = attestation_report_signing_bytes(
        &row.machine_id,
        row.updated_at_ms,
        row.cc_platform,
        &row.measurement_hex,
        &row.report_data_hex,
        &row.attestation_blob_hex,
    );

    pubkey.verify(&bytes, &sig).is_ok()
}

/// One kernel-security-event observation (axis N/K, plan §12/§5) — a
/// portable-detection or Tier-2-enforcement sensor firing on a single box.
/// Unlike `security_posture` / `box_profile` (bounded 1-row/machine LWW),
/// this is an append-only signed event stream — each row is one occurrence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelSecurityEventRow {
    /// The observing box's canonical machine identifier.
    pub machine_id: String,
    /// Originator-stamped UNIX millisecond timestamp of the event.
    pub ts_ms: u64,
    /// Event class discriminant — see [`KernelSecurityEventKind`].
    pub event_kind: u8,
    /// The cgroup id the sensor was scoped to protect (e.g. the DK-holder's
    /// cgroup), empty string if not cgroup-scoped.
    pub protected_cgroup_id: String,
    /// PID of the process that triggered the event.
    pub offender_pid: u32,
    /// cgroup id of the offending process, empty string if unknown.
    pub offender_cgroup_id: String,
    /// Free-form human-readable detail (e.g. syscall args, file path).
    pub detail: String,
    /// secd's/sentry's `DeclaredIdentity.self_id` (UUID string).
    pub originator_self_id: String,
    /// Hex Ed25519 signature over [`kernel_security_event_signing_bytes`].
    pub sig_hex: String,
}

/// Closed set of kernel-security-event classes (plan §12/§5). Encoded as a
/// fixed enum byte — same precedent as [`AttackerSignalType`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelSecurityEventKind {
    /// Unclassified / fallback.
    Other = 0x00,
    /// BPF-LSM `ptrace_access_check` deny fired.
    PtraceDenied = 0x01,
    /// BPF-LSM `file_open` deny fired (e.g. `/dev/mem`, `/proc/kcore`).
    FileOpenDenied = 0x02,
    /// BPF-LSM `task_kill` deny fired.
    TaskKillDenied = 0x03,
    /// BPF-LSM `bpf` (lock-the-door) deny fired.
    BpfLoadDenied = 0x04,
    /// A kernel module was loaded.
    ModuleLoad = 0x05,
    /// A `kexec_load`/`kexec_file_load` attempt was observed.
    KexecAttempt = 0x06,
    /// `/dev/mem` (or `/proc/kcore`) was opened outside the deny path
    /// (e.g. axis N observing on a box that can't yet deny).
    DevMemOpen = 0x07,
    /// `file_mprotect` W^X deny fired.
    MprotectDenied = 0x08,
}

impl KernelSecurityEventKind {
    /// Map a raw signed discriminant byte back to the typed variant.
    /// Unknown discriminants collapse to `Other` (forward-compat).
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::PtraceDenied,
            0x02 => Self::FileOpenDenied,
            0x03 => Self::TaskKillDenied,
            0x04 => Self::BpfLoadDenied,
            0x05 => Self::ModuleLoad,
            0x06 => Self::KexecAttempt,
            0x07 => Self::DevMemOpen,
            0x08 => Self::MprotectDenied,
            _ => Self::Other,
        }
    }
}

/// Build the canonical byte string that covers one `kernel_security_event`
/// fact.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                          37 bytes + NUL = 38 bytes
/// machine_id UTF-8 + NUL          variable
/// ts_ms                           8 bytes big-endian u64
/// event_kind                      1 byte (KernelSecurityEventKind discriminant)
/// protected_cgroup_id UTF-8 + NUL variable
/// offender_pid                    4 bytes big-endian u32
/// offender_cgroup_id UTF-8 + NUL  variable
/// detail UTF-8 + NUL              variable
/// ```
pub fn kernel_security_event_signing_bytes(
    machine_id: &str,
    ts_ms: u64,
    event_kind: u8,
    protected_cgroup_id: &str,
    offender_pid: u32,
    offender_cgroup_id: &str,
    detail: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_KERNEL_SECURITY_EVENT.len()
            + machine_id.len() + 1
            + 8 // ts_ms
            + 1 // event_kind
            + protected_cgroup_id.len() + 1
            + 4 // offender_pid
            + offender_cgroup_id.len() + 1
            + detail.len() + 1,
    );

    out.extend_from_slice(DOMAIN_KERNEL_SECURITY_EVENT);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&ts_ms.to_be_bytes());

    out.push(event_kind);

    out.extend_from_slice(protected_cgroup_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&offender_pid.to_be_bytes());

    out.extend_from_slice(offender_cgroup_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(detail.as_bytes());
    out.push(0u8);

    out
}

/// Verify a [`KernelSecurityEventRow`]'s `sig_hex` against the given Ed25519
/// verifying key, recomputing [`kernel_security_event_signing_bytes`] from
/// the row's typed fields.
#[must_use]
pub fn verify_kernel_security_event(
    row: &KernelSecurityEventRow,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier as _;

    let Ok(sig_bytes) = hex::decode(&row.sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let bytes = kernel_security_event_signing_bytes(
        &row.machine_id,
        row.ts_ms,
        row.event_kind,
        &row.protected_cgroup_id,
        row.offender_pid,
        &row.offender_cgroup_id,
        &row.detail,
    );

    pubkey.verify(&bytes, &sig).is_ok()
}

// ── box_inventory_snapshot / box_inventory_transition (D0 arc3 Foundation) ──

/// Build the canonical byte string that covers one `box_inventory_snapshot`
/// fact.
///
/// Sentry-originated, verified by every monitor before the fact is applied
/// (mirrors `box_profile_signing_bytes`'s trust model). Each `Vec<Fact>` is
/// encoded in a STABLE sort order (processes by `pid`, listeners by
/// `bind_addr`, outbound by `(local_addr, remote_addr)`, log_levels by
/// `unit_name`) — callers (the sentry collector) are expected to have
/// already sorted their input this way, but this function re-sorts
/// defensively so signer and verifier always agree regardless of collection
/// order. Each vec is length-prefixed as a big-endian `u32`, then each item
/// is NUL-terminated per string field and big-endian-encoded per integer
/// field, matching the existing convention at
/// [`kernel_security_event_signing_bytes`].
///
/// `originator_self_id` / `sig_hex` are NOT part of the signed bytes — same
/// convention as every other fact here.
#[allow(clippy::too_many_arguments)]
pub fn box_inventory_snapshot_signing_bytes(
    machine_id: &str,
    updated_at_ms: u64,
    process_count: u32,
    foreign_process_count: u32,
    listening_port_count: u32,
    foreign_listening_port_count: u32,
    established_outbound_count: u32,
    processes: &[BoxProcessFact],
    listeners: &[BoxListenerFact],
    outbound: &[BoxOutboundConnFact],
    log_levels: &[BoxUnitLogLevelFact],
) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(DOMAIN_BOX_INVENTORY_SNAPSHOT);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&updated_at_ms.to_be_bytes());

    out.extend_from_slice(&process_count.to_be_bytes());
    out.extend_from_slice(&foreign_process_count.to_be_bytes());
    out.extend_from_slice(&listening_port_count.to_be_bytes());
    out.extend_from_slice(&foreign_listening_port_count.to_be_bytes());
    out.extend_from_slice(&established_outbound_count.to_be_bytes());

    let mut sorted_processes: Vec<&BoxProcessFact> = processes.iter().collect();
    sorted_processes.sort_by_key(|p| p.pid);
    out.extend_from_slice(&(sorted_processes.len() as u32).to_be_bytes());
    for p in sorted_processes {
        out.extend_from_slice(&p.pid.to_be_bytes());
        out.extend_from_slice(p.comm.as_bytes());
        out.push(0u8);
        out.extend_from_slice(p.exe_path.as_bytes());
        out.push(0u8);
        out.extend_from_slice(&p.uid.to_be_bytes());
        out.extend_from_slice(&p.rss_kb.to_be_bytes());
        out.extend_from_slice(&p.cpu_pct.to_bits().to_be_bytes());
        out.extend_from_slice(&p.uptime_secs.to_be_bytes());
        out.push(p.classification);
    }

    let mut sorted_listeners: Vec<&BoxListenerFact> = listeners.iter().collect();
    sorted_listeners.sort_by(|a, b| a.bind_addr.cmp(&b.bind_addr));
    out.extend_from_slice(&(sorted_listeners.len() as u32).to_be_bytes());
    for l in sorted_listeners {
        out.extend_from_slice(l.bind_addr.as_bytes());
        out.push(0u8);
        out.push(l.proto);
        out.extend_from_slice(&l.owner_pid.to_be_bytes());
        out.extend_from_slice(l.owner_comm.as_bytes());
        out.push(0u8);
        out.push(l.bind_scope);
        out.push(l.tag);
    }

    let mut sorted_outbound: Vec<&BoxOutboundConnFact> = outbound.iter().collect();
    sorted_outbound.sort_by(|a, b| {
        (a.local_addr.as_str(), a.remote_addr.as_str())
            .cmp(&(b.local_addr.as_str(), b.remote_addr.as_str()))
    });
    out.extend_from_slice(&(sorted_outbound.len() as u32).to_be_bytes());
    for o in sorted_outbound {
        out.extend_from_slice(o.local_addr.as_bytes());
        out.push(0u8);
        out.extend_from_slice(o.remote_addr.as_bytes());
        out.push(0u8);
        out.push(o.proto);
        out.extend_from_slice(&o.owner_pid.to_be_bytes());
        out.extend_from_slice(o.owner_comm.as_bytes());
        out.push(0u8);
        out.push(o.classification);
    }

    let mut sorted_logs: Vec<&BoxUnitLogLevelFact> = log_levels.iter().collect();
    sorted_logs.sort_by(|a, b| a.unit_name.cmp(&b.unit_name));
    out.extend_from_slice(&(sorted_logs.len() as u32).to_be_bytes());
    for lg in sorted_logs {
        out.extend_from_slice(lg.unit_name.as_bytes());
        out.push(0u8);
        out.extend_from_slice(lg.rust_log.as_bytes());
        out.push(0u8);
        out.push(u8::from(lg.is_debug_or_trace));
    }

    out
}

/// Verify a [`BoxInventorySnapshotRow`]'s `sig_hex` against the given
/// Ed25519 verifying key, recomputing
/// [`box_inventory_snapshot_signing_bytes`] from the row's typed fields.
///
/// Returns `false` on any decoding failure (malformed hex, wrong signature
/// length) or a genuine signature mismatch. Callers gate on
/// `row.sig_hex`/`row.originator_self_id` being non-empty first (grace-
/// accept-unsigned path — see `box_inventory` module doc); this function
/// itself performs no such gate, matching every other `verify_*` helper
/// here.
#[must_use]
pub fn verify_box_inventory_snapshot(
    row: &BoxInventorySnapshotRow,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier as _;

    let Ok(sig_bytes) = hex::decode(&row.sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let bytes = box_inventory_snapshot_signing_bytes(
        &row.machine_id,
        row.updated_at_ms,
        row.process_count,
        row.foreign_process_count,
        row.listening_port_count,
        row.foreign_listening_port_count,
        row.established_outbound_count,
        &row.processes,
        &row.listeners,
        &row.outbound,
        &row.log_levels,
    );

    pubkey.verify(&bytes, &sig).is_ok()
}

/// Build the canonical byte string that covers one `box_inventory_transition`
/// fact — same shape as [`kernel_security_event_signing_bytes`] (a single-
/// occurrence row: machine_id, ts_ms, one kind byte, one detail string, two
/// subject fields), different field names.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                          variable + NUL
/// machine_id UTF-8 + NUL          variable
/// ts_ms                           8 bytes big-endian u64
/// kind                            1 byte (BoxTransitionKind discriminant)
/// detail UTF-8 + NUL              variable
/// subject_pid                     4 bytes big-endian u32
/// subject_addr UTF-8 + NUL        variable
/// ```
pub fn box_inventory_transition_signing_bytes(
    machine_id: &str,
    ts_ms: u64,
    kind: u8,
    detail: &str,
    subject_pid: u32,
    subject_addr: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_BOX_INVENTORY_TRANSITION.len()
            + machine_id.len() + 1
            + 8 // ts_ms
            + 1 // kind
            + detail.len() + 1
            + 4 // subject_pid
            + subject_addr.len() + 1,
    );

    out.extend_from_slice(DOMAIN_BOX_INVENTORY_TRANSITION);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&ts_ms.to_be_bytes());

    out.push(kind);

    out.extend_from_slice(detail.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&subject_pid.to_be_bytes());

    out.extend_from_slice(subject_addr.as_bytes());
    out.push(0u8);

    out
}

/// Verify a [`BoxInventoryTransitionRow`]'s `sig_hex` against the given
/// Ed25519 verifying key, recomputing
/// [`box_inventory_transition_signing_bytes`] from the row's typed fields.
#[must_use]
pub fn verify_box_inventory_transition(
    row: &BoxInventoryTransitionRow,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier as _;

    let Ok(sig_bytes) = hex::decode(&row.sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let bytes = box_inventory_transition_signing_bytes(
        &row.machine_id,
        row.ts_ms,
        row.kind,
        &row.detail,
        row.subject_pid,
        &row.subject_addr,
    );

    pubkey.verify(&bytes, &sig).is_ok()
}

/// One typed, signed validation-harness result (plan §13) — proves "threat
/// present? / defense holds?" for one box, one axis, one test run. Runs
/// against a disposable TEST-key fixture, never the real DK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrapeTestResultRow {
    /// The tested box's canonical machine identifier.
    pub machine_id: String,
    /// Originator-stamped UNIX millisecond timestamp of the test run.
    pub ts_ms: u64,
    /// Which vantage ran the test — `0` = Vantage A (in-guest proxy), `1` =
    /// Vantage B (provider snapshot, operator-driven).
    pub vantage: u8,
    /// The axis under test — the discriminant of whichever axis enum in
    /// [`crate::secd_policy`] applies (e.g. a `KernelTier` or `DkBackend`
    /// value), interpreted alongside `vantage`/`detail`.
    pub axis_under_test: u8,
    /// Whether the scrape attempt (ptrace/`process_vm_readv`/`/proc/pid/mem`
    /// read, etc.) was actually attempted this run.
    pub threat_present: bool,
    /// Whether the targeted defense actually blocked the scrape.
    pub defense_holds: bool,
    /// Whether the box's claimed posture (e.g. `kernel_tier_achieved` in
    /// `SecurityPostureRow`) matches the observed kernel-reality outcome of
    /// this test — catches a box claiming Tier-2 whose ptrace deny doesn't
    /// actually fire.
    pub tier_claim_verified: bool,
    /// Free-form human-readable detail (test fixture id, error text, etc).
    pub detail: String,
    /// secd's `DeclaredIdentity.self_id` (UUID string).
    pub originator_self_id: String,
    /// Hex Ed25519 signature over [`scrape_test_result_signing_bytes`].
    pub sig_hex: String,
}

/// Build the canonical byte string that covers one `scrape_test_result`
/// fact.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                       32 bytes + NUL = 33 bytes
/// machine_id UTF-8 + NUL       variable
/// ts_ms                        8 bytes big-endian u64
/// vantage                      1 byte
/// axis_under_test              1 byte
/// threat_present               1 byte (0x00 / 0x01)
/// defense_holds                1 byte (0x00 / 0x01)
/// tier_claim_verified          1 byte (0x00 / 0x01)
/// detail UTF-8 + NUL           variable
/// ```
pub fn scrape_test_result_signing_bytes(
    machine_id: &str,
    ts_ms: u64,
    vantage: u8,
    axis_under_test: u8,
    threat_present: bool,
    defense_holds: bool,
    tier_claim_verified: bool,
    detail: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_SCRAPE_TEST_RESULT.len()
            + machine_id.len() + 1
            + 8 // ts_ms
            + 1 // vantage
            + 1 // axis_under_test
            + 1 // threat_present
            + 1 // defense_holds
            + 1 // tier_claim_verified
            + detail.len() + 1,
    );

    out.extend_from_slice(DOMAIN_SCRAPE_TEST_RESULT);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&ts_ms.to_be_bytes());

    out.push(vantage);
    out.push(axis_under_test);
    out.push(u8::from(threat_present));
    out.push(u8::from(defense_holds));
    out.push(u8::from(tier_claim_verified));

    out.extend_from_slice(detail.as_bytes());
    out.push(0u8);

    out
}

/// Verify a [`ScrapeTestResultRow`]'s `sig_hex` against the given Ed25519
/// verifying key, recomputing [`scrape_test_result_signing_bytes`] from the
/// row's typed fields.
#[must_use]
pub fn verify_scrape_test_result(
    row: &ScrapeTestResultRow,
    pubkey: &ed25519_dalek::VerifyingKey,
) -> bool {
    use ed25519_dalek::Verifier as _;

    let Ok(sig_bytes) = hex::decode(&row.sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let bytes = scrape_test_result_signing_bytes(
        &row.machine_id,
        row.ts_ms,
        row.vantage,
        row.axis_under_test,
        row.threat_present,
        row.defense_holds,
        row.tier_claim_verified,
        &row.detail,
    );

    pubkey.verify(&bytes, &sig).is_ok()
}

// -- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::box_inventory::{BindScope, BoxProcessClass, BoxTransitionKind, ListenerTag};
    use crate::box_signing::BoxSigningKey;
    use ed25519_dalek::Verifier;
    use uuid::Uuid;

    fn tmp_key_path(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mirage-core-fact-signing-{label}-{}-{}.raw",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        p
    }

    fn sample_bytes() -> Vec<u8> {
        machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            Some(37.5_f64),
        )
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let path = tmp_key_path("roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_bytes();
        let sig_hex = key.sign(&bytes);

        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("signature must verify with matching bytes");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tamper_machine_id_fails_verify() {
        let path = tmp_key_path("tamper-id");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            Some(37.5_f64),
        );
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Tamper: different machine_id.
        let tampered = machine_state_signing_bytes(
            "nl-example-203.0.113.12",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            Some(37.5_f64),
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered machine_id must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tamper_timestamp_fails_verify() {
        let path = tmp_key_path("tamper-ts");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.1_f64),
            Some(0.1_f64),
            Some(0.1_f64),
            None,
            None,
            None,
            None,
        );
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_001u64, // one millisecond off
            Some(0.1_f64),
            Some(0.1_f64),
            Some(0.1_f64),
            None,
            None,
            None,
            None,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered timestamp must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn none_vs_some_differs() {
        // Encoding for None must differ from Some(0.0) so a downgrade
        // attack (strip a field to None) produces a different digest.
        let with_none = machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let with_zeros = machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.0_f64),
            Some(0.0_f64),
            Some(0.0_f64),
            Some(0_i64),
            Some(0_i64),
            Some(0_i64),
            Some(0.0_f64),
        );
        assert_ne!(with_none, with_zeros, "None and Some(0) must produce different bytes");
    }

    // ── machine_state dual-accept (Phase 1) tests ──────────────────────────────

    /// A sentry that hasn't shipped Phase 2 yet signs the legacy (no
    /// `cpu_pct`) layout. The monitor's dual-accept verify must still
    /// accept it — this is the whole point of Phase 1.
    #[test]
    fn legacy_layout_signature_still_verifies() {
        let path = tmp_key_path("legacy-verify");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let legacy_bytes = machine_state_signing_bytes_legacy(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
        );
        let sig_hex = key.sign(&legacy_bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // The verifier is called with whatever cpu_pct the monitor read
        // from the heartbeat -- here None, since a legacy sentry never
        // sent it. The dual-accept path must still find the legacy match.
        let layout = verify_machine_state_signature(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            None,
            &sig,
            &vk,
        );
        assert_eq!(layout, Some(MachineStateSigLayout::Legacy));

        let _ = std::fs::remove_file(&path);
    }

    /// A sentry that has shipped Phase 2 signs the current (`cpu_pct`
    /// included) layout. The monitor's dual-accept verify must match it on
    /// the first attempt.
    #[test]
    fn current_layout_signature_verifies() {
        let path = tmp_key_path("current-verify");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let current_bytes = machine_state_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            Some(37.5_f64),
        );
        let sig_hex = key.sign(&current_bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let layout = verify_machine_state_signature(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            Some(37.5_f64),
            &sig,
            &vk,
        );
        assert_eq!(layout, Some(MachineStateSigLayout::Current));

        let _ = std::fs::remove_file(&path);
    }

    /// Neither layout matches a signature over unrelated bytes -- the
    /// dual-accept path must not accept garbage just because it tries twice.
    #[test]
    fn garbage_signature_matches_neither_layout() {
        let path = tmp_key_path("garbage-verify");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let sig_hex = key.sign(b"not a machine_state fact at all");
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let layout = verify_machine_state_signature(
            "ru-hostkey-203.0.113.10",
            1_700_000_000_000u64,
            Some(0.42_f64),
            Some(0.55_f64),
            Some(0.61_f64),
            Some(50_000_000_000_i64),
            Some(20_000_000_000_i64),
            Some(1_024_000_i64),
            Some(37.5_f64),
            &sig,
            &vk,
        );
        assert_eq!(layout, None);

        let _ = std::fs::remove_file(&path);
    }

    // ── attacker_intel tests ──────────────────────────────────────────────────

    fn sample_attacker_intel_bytes() -> Vec<u8> {
        attacker_intel_signing_bytes(
            "ru-hostkey-203.0.113.10",
            "203.0.113.7",
            1_700_000_002_000u64,
            1_700_000_000_000u64,
            42u32,
            AttackerSignalType::Tarpit as u8,
            80u8,
            true,
        )
    }

    #[test]
    fn attacker_intel_sign_then_verify_roundtrip() {
        let path = tmp_key_path("ai-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let bytes = sample_attacker_intel_bytes();
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn attacker_intel_tamper_ip_fails_verify() {
        let path = tmp_key_path("ai-tamper-ip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let original = sample_attacker_intel_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Tamper: a relay swaps the observed IP (DoS-a-peer attempt).
        let tampered = attacker_intel_signing_bytes(
            "ru-hostkey-203.0.113.10",
            "203.0.113.8", // one octet off
            1_700_000_002_000u64,
            1_700_000_000_000u64,
            42u32,
            AttackerSignalType::Tarpit as u8,
            80u8,
            true,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered ip must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn attacker_intel_tamper_touch_count_fails_verify() {
        let path = tmp_key_path("ai-tamper-count");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let original = sample_attacker_intel_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Tamper: inflate the per-box touch counter to fake corroboration weight.
        let tampered = attacker_intel_signing_bytes(
            "ru-hostkey-203.0.113.10",
            "203.0.113.7",
            1_700_000_002_000u64,
            1_700_000_000_000u64,
            9_999u32,
            AttackerSignalType::Tarpit as u8,
            80u8,
            true,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered touch_count must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn attacker_signal_type_roundtrips_u8() {
        for st in [
            AttackerSignalType::Other,
            AttackerSignalType::Decoy,
            AttackerSignalType::SshBrute,
            AttackerSignalType::UnexpectedListener,
            AttackerSignalType::Tarpit,
            AttackerSignalType::Flood,
            AttackerSignalType::Bomb,
            AttackerSignalType::Honeypot,
            AttackerSignalType::KernelPtraceDeny,
        ] {
            assert_eq!(AttackerSignalType::from_u8(st as u8), st);
        }
    }

    #[test]
    fn attacker_intel_ban_active_flag_is_covered() {
        // ban_active must be part of the signed bytes — a relay flipping it
        // (fake "already banned" / "all clear") must break verification.
        let banned = attacker_intel_signing_bytes(
            "ru-hostkey-203.0.113.10",
            "203.0.113.7",
            1_700_000_002_000u64,
            1_700_000_000_000u64,
            42u32,
            AttackerSignalType::Tarpit as u8,
            80u8,
            true,
        );
        let not_banned = attacker_intel_signing_bytes(
            "ru-hostkey-203.0.113.10",
            "203.0.113.7",
            1_700_000_002_000u64,
            1_700_000_000_000u64,
            42u32,
            AttackerSignalType::Tarpit as u8,
            80u8,
            false,
        );
        assert_ne!(banned, not_banned, "ban_active must change the signed bytes");
    }

    // ── node_metrics tests ────────────────────────────────────────────────────

    fn sample_node_metrics_bytes() -> Vec<u8> {
        node_metrics_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            1_700_000_001_000u64,
            12.5_f32,
            4096_u32,
            2048_u32,
            50.0_f32,
            0.75_f32,
            4_u32,
            1_700_000_000_500u64,
        )
    }

    #[test]
    fn node_metrics_roundtrip() {
        let path = tmp_key_path("nm-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_node_metrics_bytes();
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("node_metrics signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_metrics_tamper_node_id_fails() {
        let path = tmp_key_path("nm-tamper-id");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_node_metrics_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = node_metrics_signing_bytes(
            "v2-nl-example-203.0.113.12", // different node_id
            1_700_000_001_000u64,
            12.5_f32,
            4096_u32,
            2048_u32,
            50.0_f32,
            0.75_f32,
            4_u32,
            1_700_000_000_500u64,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered node_id must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_metrics_tamper_cpu_pct_fails() {
        let path = tmp_key_path("nm-tamper-cpu");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_node_metrics_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = node_metrics_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            1_700_000_001_000u64,
            99.9_f32, // different cpu_pct
            4096_u32,
            2048_u32,
            50.0_f32,
            0.75_f32,
            4_u32,
            1_700_000_000_500u64,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered cpu_pct must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── node_egress tests ─────────────────────────────────────────────────────

    fn sample_node_egress_bytes() -> Vec<u8> {
        node_egress_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "v2-nl-example-203.0.113.12",
            1_700_000_002_000u64,
            "ok",
            Some(42_u32),
            0_u32,
            1_700_000_001_800u64,
        )
    }

    #[test]
    fn node_egress_roundtrip() {
        let path = tmp_key_path("ne-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_node_egress_bytes();
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("node_egress signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_egress_tamper_status_fails() {
        let path = tmp_key_path("ne-tamper-status");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_node_egress_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = node_egress_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "v2-nl-example-203.0.113.12",
            1_700_000_002_000u64,
            "timeout", // different status
            Some(42_u32),
            0_u32,
            1_700_000_001_800u64,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered status must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_egress_tamper_rtt_none_vs_some_fails() {
        let path = tmp_key_path("ne-tamper-rtt");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = node_egress_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "v2-nl-example-203.0.113.12",
            1_700_000_002_000u64,
            "ok",
            None, // no rtt
            0_u32,
            1_700_000_001_800u64,
        );
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = node_egress_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "v2-nl-example-203.0.113.12",
            1_700_000_002_000u64,
            "ok",
            Some(0_u32), // injected rtt
            0_u32,
            1_700_000_001_800u64,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "None rtt vs Some(0) rtt must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn node_egress_tamper_to_node_id_fails() {
        let path = tmp_key_path("ne-tamper-toid");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_node_egress_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = node_egress_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "v2-tr-example-203.0.113.75", // different to_node_id
            1_700_000_002_000u64,
            "ok",
            Some(42_u32),
            0_u32,
            1_700_000_001_800u64,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered to_node_id must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── listener_state tests ──────────────────────────────────────────────────

    fn sample_listener_state_bytes() -> Vec<u8> {
        listener_state_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "mirage-node-v2-ru-hostkey-203.0.113.10-0",
            "bound",
            1_700_000_003_000u64,
            Some("0.0.0.0:4700"),
            Some(4700u16),
            None,
            123u64,
            456u64,
            7u32,
        )
    }

    #[test]
    fn listener_state_roundtrip() {
        let path = tmp_key_path("ls-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_listener_state_bytes();
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("listener_state signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listener_state_tamper_state_fails() {
        let path = tmp_key_path("ls-tamper-state");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_listener_state_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Rollback attack: re-assert "bound" as "failed" (or vice-versa).
        let tampered = listener_state_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "mirage-node-v2-ru-hostkey-203.0.113.10-0",
            "failed", // different state
            1_700_000_003_000u64,
            Some("0.0.0.0:4700"),
            Some(4700u16),
            None,
            123u64,
            456u64,
            7u32,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered state must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listener_state_tamper_bound_addr_fails() {
        let path = tmp_key_path("ls-tamper-addr");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_listener_state_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = listener_state_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "mirage-node-v2-ru-hostkey-203.0.113.10-0",
            "bound",
            1_700_000_003_000u64,
            Some("10.0.0.9:4700"), // attacker-controlled addr
            Some(4700u16),
            None,
            123u64,
            456u64,
            7u32,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered bound_addr must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listener_state_tamper_timestamp_fails() {
        let path = tmp_key_path("ls-tamper-ts");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_listener_state_bytes();
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        let tampered = listener_state_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "mirage-node-v2-ru-hostkey-203.0.113.10-0",
            "bound",
            1_700_000_003_001u64, // one ms off — LWW rollback
            Some("0.0.0.0:4700"),
            Some(4700u16),
            None,
            123u64,
            456u64,
            7u32,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered timestamp must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn listener_state_none_vs_some_empty_str_differs() {
        // last_error None must differ from Some("") so a strip-to-None
        // downgrade produces a different digest.
        let with_none = listener_state_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "L",
            "failed",
            1_700_000_003_000u64,
            None,
            None,
            None,
            0,
            0,
            0,
        );
        let with_empty = listener_state_signing_bytes(
            "v2-ru-hostkey-203.0.113.10",
            "L",
            "failed",
            1_700_000_003_000u64,
            None,
            None,
            Some(""),
            0,
            0,
            0,
        );
        assert_ne!(
            with_none, with_empty,
            "None and Some(\"\") must produce different bytes"
        );
    }

    // ── box_profile tests ─────────────────────────────────────────────────────

    fn sample_box_profile_row(sig_hex: String) -> BoxProfileRow {
        BoxProfileRow {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            updated_at_ms: 1_700_000_004_000u64,
            cpu_model: "Intel(R) Xeon(R) Gold 6248R".to_string(),
            cpu_arch: "x86_64".to_string(),
            cpu_cores_physical: 8,
            cpu_threads: 16,
            cpu_flags: "aes,avx2,rdrand".to_string(),
            ram_total_mb: 16384,
            disk_total_gb: 200,
            rootfs_type: "ext4".to_string(),
            dmi_sys_vendor: "DigitalOcean".to_string(),
            dmi_product_name: "Droplet".to_string(),
            dmi_board: "Standard PC".to_string(),
            distro: "ubuntu".to_string(),
            distro_version: "22.04".to_string(),
            kernel_version: "5.15.0-105-generic".to_string(),
            systemd_version: "249.11".to_string(),
            boot_time_ms: 1_700_000_000_000u64,
            virt_type: "kvm".to_string(),
            is_full_vm: true,
            active_lsms: "capability,apparmor".to_string(),
            has_bpf_lsm_active: false,
            config_bpf_lsm_compiled: true,
            ptrace_scope: 1,
            lockdown_state: "none".to_string(),
            bpffs_mounted: true,
            modules_disabled: false,
            max_defense_tier: 2,
            cc_platform: 0,
            secretmem_enabled: true,
            vtpm_present: false,
            fsverity_supported: true,
            ima_present: false,
            ipe_present: false,
            dmverity_supported: false,
            landlock_abi: 4,
            dk_backend_ceiling: 1,
            conf_mode_ceiling: 0,
            integrity_ceiling: 2,
            sandbox_ceiling: 1,
            originator_self_id: "3fae1e2a-4b3e-4b7a-9c1a-000000000001".to_string(),
            sig_hex,
        }
    }

    fn sample_box_profile_bytes() -> Vec<u8> {
        box_profile_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_004_000u64,
            "Intel(R) Xeon(R) Gold 6248R",
            "x86_64",
            8,
            16,
            "aes,avx2,rdrand",
            16384,
            200,
            "ext4",
            "DigitalOcean",
            "Droplet",
            "Standard PC",
            "ubuntu",
            "22.04",
            "5.15.0-105-generic",
            "249.11",
            1_700_000_000_000u64,
            "kvm",
            true,
            "capability,apparmor",
            false,
            true,
            1u8,
            "none",
            true,
            false,
            2u8,
            0u8,
            true,
            false,
            true,
            false,
            false,
            false,
            4u8,
            1u8,
            0u8,
            2u8,
            1u8,
        )
    }

    #[test]
    fn box_profile_sign_then_verify_roundtrip() {
        let path = tmp_key_path("bp-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_profile_bytes();
        let sig_hex = key.sign(&bytes);
        let row = sample_box_profile_row(sig_hex.0.clone());

        assert!(
            verify_box_profile(&row, &key.verifying_key()),
            "box_profile signature must verify with matching row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_profile_tamper_ptrace_scope_fails_verify() {
        let path = tmp_key_path("bp-tamper-ptrace");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_profile_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_profile_row(sig_hex.0.clone());

        // Flip ptrace_scope AFTER signing — a relay trying to hide a
        // weakened ptrace restriction must not slip past verification.
        row.ptrace_scope = 0;

        assert!(
            !verify_box_profile(&row, &key.verifying_key()),
            "tampered ptrace_scope must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_profile_tamper_max_defense_tier_fails_verify() {
        let path = tmp_key_path("bp-tamper-tier");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_profile_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_profile_row(sig_hex.0.clone());

        // Sample row was signed with max_defense_tier == 2; downgrade it
        // after signing (a relay hiding a weaker isolation posture).
        row.max_defense_tier = 0;

        assert!(
            !verify_box_profile(&row, &key.verifying_key()),
            "tampered max_defense_tier must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_profile_bad_sig_hex_fails_verify() {
        let key = BoxSigningKey::load_or_generate(&tmp_key_path("bp-bad-hex"))
            .expect("generate key");
        let row = sample_box_profile_row("not-valid-hex".to_string());
        assert!(
            !verify_box_profile(&row, &key.verifying_key()),
            "malformed sig_hex must not verify"
        );
    }

    #[test]
    fn box_profile_signing_bytes_stable_per_field() {
        // Deterministic input -> deterministic bytes (byte-layout stability).
        let a = sample_box_profile_bytes();
        let b = sample_box_profile_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn box_profile_tamper_cpu_flags_fails_verify() {
        let path = tmp_key_path("bp-tamper-flags");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_profile_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_profile_row(sig_hex.0.clone());

        // Strip a claimed CPU feature after signing (e.g. hide the absence
        // of hardware RNG support).
        row.cpu_flags = "aes,avx2".to_string();

        assert!(
            !verify_box_profile(&row, &key.verifying_key()),
            "tampered cpu_flags must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── secd arc2 additions — THROWAWAY, delete at Stage I ────────────────────
    //
    // Coverage for the 2026-07-06 appends: box_profile per-axis ceilings +
    // security_posture per-axis achieved fields. Determinism, sign→verify,
    // tamper-detection, and "every new field actually moves the bytes".

    #[test]
    fn box_profile_ceiling_fields_are_covered_by_signature() {
        let path = tmp_key_path("bp-ceiling-coverage");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_profile_bytes();
        let sig_hex = key.sign(&bytes);
        let base_row = sample_box_profile_row(sig_hex.0.clone());

        // Flip every new ceiling field one at a time after signing — each
        // must independently break verification (proves none was silently
        // omitted from the signed-bytes layout).
        let mutations: Vec<(&str, Box<dyn Fn(&mut BoxProfileRow)>)> = vec![
            ("cc_platform", Box::new(|r: &mut BoxProfileRow| r.cc_platform = 1)),
            (
                "secretmem_enabled",
                Box::new(|r: &mut BoxProfileRow| r.secretmem_enabled = false),
            ),
            ("vtpm_present", Box::new(|r: &mut BoxProfileRow| r.vtpm_present = true)),
            (
                "fsverity_supported",
                Box::new(|r: &mut BoxProfileRow| r.fsverity_supported = false),
            ),
            ("ima_present", Box::new(|r: &mut BoxProfileRow| r.ima_present = true)),
            ("ipe_present", Box::new(|r: &mut BoxProfileRow| r.ipe_present = true)),
            (
                "dmverity_supported",
                Box::new(|r: &mut BoxProfileRow| r.dmverity_supported = true),
            ),
            ("landlock_abi", Box::new(|r: &mut BoxProfileRow| r.landlock_abi = 1)),
            (
                "dk_backend_ceiling",
                Box::new(|r: &mut BoxProfileRow| r.dk_backend_ceiling = 3),
            ),
            (
                "conf_mode_ceiling",
                Box::new(|r: &mut BoxProfileRow| r.conf_mode_ceiling = 2),
            ),
            (
                "integrity_ceiling",
                Box::new(|r: &mut BoxProfileRow| r.integrity_ceiling = 4),
            ),
            (
                "sandbox_ceiling",
                Box::new(|r: &mut BoxProfileRow| r.sandbox_ceiling = 0),
            ),
        ];

        for (name, mutate) in mutations {
            let mut row = base_row.clone();
            mutate(&mut row);
            assert!(
                !verify_box_profile(&row, &key.verifying_key()),
                "tampered {name} must not verify"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_profile_ceiling_bytes_deterministic() {
        let a = sample_box_profile_bytes();
        let b = sample_box_profile_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    /// `platform_fingerprint()` must carry over exactly the five identifying
    /// fields, and nothing about the projection may depend on the fields it
    /// deliberately drops (`updated_at_ms`, `sig_hex`, `originator_self_id`)
    /// — two rows that differ ONLY in those must project identically.
    #[test]
    fn platform_fingerprint_projects_the_identifying_fields_only() {
        let row_a = sample_box_profile_row("aa".to_string());
        let mut row_b = sample_box_profile_row("bb".to_string());
        row_b.updated_at_ms += 1;
        row_b.originator_self_id = "3fae1e2a-4b3e-4b7a-9c1a-000000000002".to_string();

        let fp = row_a.platform_fingerprint();
        assert_eq!(fp.cpu_model, row_a.cpu_model);
        assert_eq!(fp.cpu_arch, row_a.cpu_arch);
        assert_eq!(fp.dmi_sys_vendor, row_a.dmi_sys_vendor);
        assert_eq!(fp.dmi_product_name, row_a.dmi_product_name);
        assert_eq!(fp.dmi_board, row_a.dmi_board);

        assert_eq!(
            row_a.platform_fingerprint(),
            row_b.platform_fingerprint(),
            "sig_hex/updated_at_ms/originator_self_id must not affect the projection"
        );
    }

    fn sample_security_posture_bytes(
        kernel_tier_achieved: u8,
        tier2_bpf_lsm_live: bool,
    ) -> Vec<u8> {
        security_posture_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_005_000u64,
            true,
            true,
            2u32,
            5u32,
            true,
            true,
            10u32,
            0u32,
            3u32,
            1u32,
            42u32,
            kernel_tier_achieved,
            1u8, // dk_backend_achieved
            0u8, // conf_mode_achieved
            1u8, // egress_achieved
            2u8, // integrity_achieved
            1u8, // sandbox_achieved
            0u8, // enforce_mode
            1u8, // detection_achieved
            tier2_bpf_lsm_live,
            1u8, // surface_achieved
        )
    }

    #[test]
    fn security_posture_signing_bytes_deterministic() {
        let a = sample_security_posture_bytes(1, false);
        let b = sample_security_posture_bytes(1, false);
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn security_posture_sign_then_verify_roundtrip() {
        let path = tmp_key_path("sp-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_security_posture_bytes(2, true);
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("security_posture signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn security_posture_tamper_kernel_tier_achieved_fails() {
        let path = tmp_key_path("sp-tamper-kernel-tier");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_security_posture_bytes(1, false);
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Relay hides a downgrade from Tier2 (2) to Tier0 (0) after signing.
        let tampered = sample_security_posture_bytes(0, false);
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered kernel_tier_achieved must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn security_posture_tamper_tier2_bpf_lsm_live_fails() {
        let path = tmp_key_path("sp-tamper-bpf-lsm-live");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = sample_security_posture_bytes(2, true);
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Relay falsely claims the BPF-LSM ringbuf enforcement sensor is
        // live when it is not (posture-fact-vs-kernel-reality mismatch).
        let tampered = sample_security_posture_bytes(2, false);
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered tier2_bpf_lsm_live must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    // THROWAWAY (arc2.8 axis F) — delete at Stage I
    #[test]
    fn security_posture_tamper_surface_achieved_fails() {
        let path = tmp_key_path("sp-tamper-surface-achieved");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = security_posture_signing_bytes(
            "ru-hostkey-203.0.113.10", 1_700_000_005_000u64, true, true, 2, 5, true, true, 10, 0, 3, 1,
            42, 1, 1, 0, 1, 2, 1, 0, 1, false, 1,
        );
        let sig_hex = key.sign(&original);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();

        // Relay hides a surface-minimization downgrade (MaskBaseline=1 ->
        // Off=0) after signing.
        let tampered = security_posture_signing_bytes(
            "ru-hostkey-203.0.113.10", 1_700_000_005_000u64, true, true, 2, 5, true, true, 10, 0, 3, 1,
            42, 1, 1, 0, 1, 2, 1, 0, 1, false, 0,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered surface_achieved must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn security_posture_every_new_axis_field_moves_bytes() {
        // Base with every new field at a fixed value; flip one at a time —
        // each must independently move the signed bytes.
        let base = security_posture_signing_bytes(
            "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 0,
        );
        let variants: Vec<Vec<u8>> = vec![
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, false, 0,
            ),
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true, 0,
            ),
            // THROWAWAY (arc2.8 axis F) — delete at Stage I
            security_posture_signing_bytes(
                "m", 1, true, true, 0, 0, true, true, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, 1,
            ),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(v, &base, "new axis field index {i} must alter the signed bytes");
        }
    }

    // ── attestation_report tests (axis C) ─────────────────────────────────────

    fn sample_attestation_report_row(sig_hex: String) -> AttestationReportRow {
        AttestationReportRow {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            updated_at_ms: 1_700_000_006_000u64,
            cc_platform: 1,
            measurement_hex: "aa".repeat(48),
            report_data_hex: "bb".repeat(64),
            attestation_blob_hex: "cc".repeat(128),
            originator_self_id: "3fae1e2a-4b3e-4b7a-9c1a-000000000002".to_string(),
            sig_hex,
        }
    }

    fn sample_attestation_report_bytes() -> Vec<u8> {
        attestation_report_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_006_000u64,
            1,
            &"aa".repeat(48),
            &"bb".repeat(64),
            &"cc".repeat(128),
        )
    }

    #[test]
    fn attestation_report_signing_bytes_deterministic() {
        let a = sample_attestation_report_bytes();
        let b = sample_attestation_report_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn attestation_report_sign_then_verify_roundtrip() {
        let path = tmp_key_path("ar-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_attestation_report_bytes();
        let sig_hex = key.sign(&bytes);
        let row = sample_attestation_report_row(sig_hex.0.clone());

        assert!(
            verify_attestation_report(&row, &key.verifying_key()),
            "attestation_report signature must verify with matching row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn attestation_report_tamper_measurement_fails_verify() {
        let path = tmp_key_path("ar-tamper-measurement");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_attestation_report_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_attestation_report_row(sig_hex.0.clone());

        // Swap the measurement after signing — a relay hiding the real
        // measurement (wrong-VM substitution) must not slip past verification.
        row.measurement_hex = "ff".repeat(48);

        assert!(
            !verify_attestation_report(&row, &key.verifying_key()),
            "tampered measurement_hex must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn attestation_report_tamper_cc_platform_fails_verify() {
        let path = tmp_key_path("ar-tamper-platform");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_attestation_report_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_attestation_report_row(sig_hex.0.clone());

        row.cc_platform = 0;

        assert!(
            !verify_attestation_report(&row, &key.verifying_key()),
            "tampered cc_platform must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn attestation_report_bad_sig_hex_fails_verify() {
        let key = BoxSigningKey::load_or_generate(&tmp_key_path("ar-bad-hex"))
            .expect("generate key");
        let row = sample_attestation_report_row("not-valid-hex".to_string());
        assert!(
            !verify_attestation_report(&row, &key.verifying_key()),
            "malformed sig_hex must not verify"
        );
    }

    // ── kernel_security_event tests (axis N/K) ────────────────────────────────

    fn sample_kernel_security_event_row(sig_hex: String) -> KernelSecurityEventRow {
        KernelSecurityEventRow {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            ts_ms: 1_700_000_007_000u64,
            event_kind: KernelSecurityEventKind::PtraceDenied as u8,
            protected_cgroup_id: "/sys/fs/cgroup/db-worker.slice".to_string(),
            offender_pid: 4242,
            offender_cgroup_id: "/sys/fs/cgroup/user.slice".to_string(),
            detail: "ptrace_access_check denied: PTRACE_ATTACH".to_string(),
            originator_self_id: "3fae1e2a-4b3e-4b7a-9c1a-000000000003".to_string(),
            sig_hex,
        }
    }

    fn sample_kernel_security_event_bytes() -> Vec<u8> {
        kernel_security_event_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_007_000u64,
            KernelSecurityEventKind::PtraceDenied as u8,
            "/sys/fs/cgroup/db-worker.slice",
            4242,
            "/sys/fs/cgroup/user.slice",
            "ptrace_access_check denied: PTRACE_ATTACH",
        )
    }

    #[test]
    fn kernel_security_event_signing_bytes_deterministic() {
        let a = sample_kernel_security_event_bytes();
        let b = sample_kernel_security_event_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn kernel_security_event_sign_then_verify_roundtrip() {
        let path = tmp_key_path("kse-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_kernel_security_event_bytes();
        let sig_hex = key.sign(&bytes);
        let row = sample_kernel_security_event_row(sig_hex.0.clone());

        assert!(
            verify_kernel_security_event(&row, &key.verifying_key()),
            "kernel_security_event signature must verify with matching row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kernel_security_event_tamper_offender_pid_fails_verify() {
        let path = tmp_key_path("kse-tamper-pid");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_kernel_security_event_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_kernel_security_event_row(sig_hex.0.clone());

        row.offender_pid = 1; // relay re-attributes the event to PID 1

        assert!(
            !verify_kernel_security_event(&row, &key.verifying_key()),
            "tampered offender_pid must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kernel_security_event_tamper_event_kind_fails_verify() {
        let path = tmp_key_path("kse-tamper-kind");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_kernel_security_event_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_kernel_security_event_row(sig_hex.0.clone());

        // Downgrade a denied-ptrace event to an innocuous "module load" class.
        row.event_kind = KernelSecurityEventKind::ModuleLoad as u8;

        assert!(
            !verify_kernel_security_event(&row, &key.verifying_key()),
            "tampered event_kind must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kernel_security_event_kind_roundtrips_u8() {
        for k in [
            KernelSecurityEventKind::Other,
            KernelSecurityEventKind::PtraceDenied,
            KernelSecurityEventKind::FileOpenDenied,
            KernelSecurityEventKind::TaskKillDenied,
            KernelSecurityEventKind::BpfLoadDenied,
            KernelSecurityEventKind::ModuleLoad,
            KernelSecurityEventKind::KexecAttempt,
            KernelSecurityEventKind::DevMemOpen,
            KernelSecurityEventKind::MprotectDenied,
        ] {
            assert_eq!(KernelSecurityEventKind::from_u8(k as u8), k);
        }
    }

    #[test]
    fn kernel_security_event_bad_sig_hex_fails_verify() {
        let key = BoxSigningKey::load_or_generate(&tmp_key_path("kse-bad-hex"))
            .expect("generate key");
        let row = sample_kernel_security_event_row("not-valid-hex".to_string());
        assert!(
            !verify_kernel_security_event(&row, &key.verifying_key()),
            "malformed sig_hex must not verify"
        );
    }

    // ── box_inventory_snapshot / box_inventory_transition tests (D0) ──────────

    fn sample_box_inventory_snapshot_row(sig_hex: String) -> BoxInventorySnapshotRow {
        BoxInventorySnapshotRow {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            updated_at_ms: 1_700_000_008_000u64,
            process_count: 2,
            foreign_process_count: 1,
            listening_port_count: 1,
            foreign_listening_port_count: 0,
            established_outbound_count: 1,
            processes: vec![
                BoxProcessFact {
                    pid: 100,
                    comm: "mirage2monitor".to_string(),
                    exe_path: "/usr/local/bin/mirage2monitor-v2".to_string(),
                    uid: 0,
                    rss_kb: 20_480,
                    cpu_pct: 1.5,
                    uptime_secs: 3600,
                    classification: BoxProcessClass::ExpectedMirage as u8,
                },
                BoxProcessFact {
                    pid: 4242,
                    comm: "czy_agent".to_string(),
                    exe_path: "/opt/czy/agent".to_string(),
                    uid: 1000,
                    rss_kb: 4096,
                    cpu_pct: 0.2,
                    uptime_secs: 60,
                    classification: BoxProcessClass::Foreign as u8,
                },
            ],
            listeners: vec![BoxListenerFact {
                bind_addr: "0.0.0.0:19444".to_string(),
                proto: 0,
                owner_pid: 100,
                owner_comm: "mirage2monitor".to_string(),
                bind_scope: BindScope::Wildcard as u8,
                tag: ListenerTag::MirageService as u8,
            }],
            outbound: vec![BoxOutboundConnFact {
                local_addr: "10.0.0.5:51000".to_string(),
                remote_addr: "203.0.113.9:443".to_string(),
                proto: 0,
                owner_pid: 4242,
                owner_comm: "czy_agent".to_string(),
                classification: BoxProcessClass::Foreign as u8,
            }],
            log_levels: vec![BoxUnitLogLevelFact {
                unit_name: "mirage2monitor-v2.service".to_string(),
                rust_log: "info".to_string(),
                is_debug_or_trace: false,
            }],
            originator_self_id: "3fae1e2a-4b3e-4b7a-9c1a-000000000004".to_string(),
            sig_hex,
        }
    }

    fn sample_box_inventory_snapshot_bytes() -> Vec<u8> {
        let row = sample_box_inventory_snapshot_row(String::new());
        box_inventory_snapshot_signing_bytes(
            &row.machine_id,
            row.updated_at_ms,
            row.process_count,
            row.foreign_process_count,
            row.listening_port_count,
            row.foreign_listening_port_count,
            row.established_outbound_count,
            &row.processes,
            &row.listeners,
            &row.outbound,
            &row.log_levels,
        )
    }

    #[test]
    fn box_inventory_snapshot_signing_bytes_deterministic() {
        let a = sample_box_inventory_snapshot_bytes();
        let b = sample_box_inventory_snapshot_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn box_inventory_snapshot_signing_bytes_order_independent() {
        // Sorting inside the signing-bytes fn means feeding the same facts
        // in a DIFFERENT order still produces identical bytes -- signer and
        // verifier don't need to agree on collection order.
        let row = sample_box_inventory_snapshot_row(String::new());
        let mut reversed = row.clone();
        reversed.processes.reverse();
        reversed.listeners.reverse();
        reversed.outbound.reverse();
        reversed.log_levels.reverse();

        let a = box_inventory_snapshot_signing_bytes(
            &row.machine_id, row.updated_at_ms, row.process_count, row.foreign_process_count,
            row.listening_port_count, row.foreign_listening_port_count,
            row.established_outbound_count, &row.processes, &row.listeners, &row.outbound,
            &row.log_levels,
        );
        let b = box_inventory_snapshot_signing_bytes(
            &reversed.machine_id, reversed.updated_at_ms, reversed.process_count,
            reversed.foreign_process_count, reversed.listening_port_count,
            reversed.foreign_listening_port_count, reversed.established_outbound_count,
            &reversed.processes, &reversed.listeners, &reversed.outbound, &reversed.log_levels,
        );
        assert_eq!(a, b, "collection order must not affect signed bytes");
    }

    #[test]
    fn box_inventory_snapshot_sign_then_verify_roundtrip() {
        let path = tmp_key_path("bis-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_inventory_snapshot_bytes();
        let sig_hex = key.sign(&bytes);
        let row = sample_box_inventory_snapshot_row(sig_hex.0.clone());

        assert!(
            verify_box_inventory_snapshot(&row, &key.verifying_key()),
            "box_inventory_snapshot signature must verify with matching row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_inventory_snapshot_tamper_process_count_fails_verify() {
        let path = tmp_key_path("bis-tamper-count");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_inventory_snapshot_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_inventory_snapshot_row(sig_hex.0.clone());

        row.foreign_process_count = 0; // hide the foreign process from the summary

        assert!(
            !verify_box_inventory_snapshot(&row, &key.verifying_key()),
            "tampered foreign_process_count must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_inventory_snapshot_tamper_process_classification_fails_verify() {
        let path = tmp_key_path("bis-tamper-class");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_inventory_snapshot_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_inventory_snapshot_row(sig_hex.0.clone());

        // Re-attribute the foreign process as expected-mirage.
        row.processes[1].classification = BoxProcessClass::ExpectedMirage as u8;

        assert!(
            !verify_box_inventory_snapshot(&row, &key.verifying_key()),
            "tampered process classification must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_inventory_snapshot_bad_sig_hex_fails_verify() {
        let key = BoxSigningKey::load_or_generate(&tmp_key_path("bis-bad-hex"))
            .expect("generate key");
        let row = sample_box_inventory_snapshot_row("not-valid-hex".to_string());
        assert!(
            !verify_box_inventory_snapshot(&row, &key.verifying_key()),
            "malformed sig_hex must not verify"
        );
    }

    fn sample_box_inventory_transition_row(sig_hex: String) -> BoxInventoryTransitionRow {
        BoxInventoryTransitionRow {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            ts_ms: 1_700_000_009_000u64,
            kind: BoxTransitionKind::ForeignProcessAppeared as u8,
            detail: "pid=4242 comm=czy_agent exe=/opt/czy/agent".to_string(),
            subject_pid: 4242,
            subject_addr: String::new(),
            originator_self_id: "3fae1e2a-4b3e-4b7a-9c1a-000000000005".to_string(),
            sig_hex,
        }
    }

    fn sample_box_inventory_transition_bytes() -> Vec<u8> {
        box_inventory_transition_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_009_000u64,
            BoxTransitionKind::ForeignProcessAppeared as u8,
            "pid=4242 comm=czy_agent exe=/opt/czy/agent",
            4242,
            "",
        )
    }

    #[test]
    fn box_inventory_transition_signing_bytes_deterministic() {
        let a = sample_box_inventory_transition_bytes();
        let b = sample_box_inventory_transition_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn box_inventory_transition_sign_then_verify_roundtrip() {
        let path = tmp_key_path("bit-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_inventory_transition_bytes();
        let sig_hex = key.sign(&bytes);
        let row = sample_box_inventory_transition_row(sig_hex.0.clone());

        assert!(
            verify_box_inventory_transition(&row, &key.verifying_key()),
            "box_inventory_transition signature must verify with matching row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_inventory_transition_tamper_subject_pid_fails_verify() {
        let path = tmp_key_path("bit-tamper-pid");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_inventory_transition_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_inventory_transition_row(sig_hex.0.clone());

        row.subject_pid = 1; // relay re-attributes the transition to PID 1

        assert!(
            !verify_box_inventory_transition(&row, &key.verifying_key()),
            "tampered subject_pid must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_inventory_transition_tamper_kind_fails_verify() {
        let path = tmp_key_path("bit-tamper-kind");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_box_inventory_transition_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_box_inventory_transition_row(sig_hex.0.clone());

        // Downgrade a foreign-process-appeared alert to the innocuous
        // generic ProcessAppeared class.
        row.kind = BoxTransitionKind::ProcessAppeared as u8;

        assert!(
            !verify_box_inventory_transition(&row, &key.verifying_key()),
            "tampered kind must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn box_inventory_transition_bad_sig_hex_fails_verify() {
        let key = BoxSigningKey::load_or_generate(&tmp_key_path("bit-bad-hex"))
            .expect("generate key");
        let row = sample_box_inventory_transition_row("not-valid-hex".to_string());
        assert!(
            !verify_box_inventory_transition(&row, &key.verifying_key()),
            "malformed sig_hex must not verify"
        );
    }

    // ── scrape_test_result tests (validation harness) ─────────────────────────

    fn sample_scrape_test_result_row(sig_hex: String) -> ScrapeTestResultRow {
        ScrapeTestResultRow {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            ts_ms: 1_700_000_008_000u64,
            vantage: 0,
            axis_under_test: 1, // e.g. DkBackend::MemfdSecret
            threat_present: true,
            defense_holds: true,
            tier_claim_verified: true,
            detail: "ptrace PTRACE_PEEKDATA against db-worker TEST-key fixture".to_string(),
            originator_self_id: "3fae1e2a-4b3e-4b7a-9c1a-000000000004".to_string(),
            sig_hex,
        }
    }

    fn sample_scrape_test_result_bytes() -> Vec<u8> {
        scrape_test_result_signing_bytes(
            "ru-hostkey-203.0.113.10",
            1_700_000_008_000u64,
            0,
            1,
            true,
            true,
            true,
            "ptrace PTRACE_PEEKDATA against db-worker TEST-key fixture",
        )
    }

    #[test]
    fn scrape_test_result_signing_bytes_deterministic() {
        let a = sample_scrape_test_result_bytes();
        let b = sample_scrape_test_result_bytes();
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn scrape_test_result_sign_then_verify_roundtrip() {
        let path = tmp_key_path("str-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_scrape_test_result_bytes();
        let sig_hex = key.sign(&bytes);
        let row = sample_scrape_test_result_row(sig_hex.0.clone());

        assert!(
            verify_scrape_test_result(&row, &key.verifying_key()),
            "scrape_test_result signature must verify with matching row"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scrape_test_result_tamper_defense_holds_fails_verify() {
        let path = tmp_key_path("str-tamper-defense-holds");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_scrape_test_result_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_scrape_test_result_row(sig_hex.0.clone());

        // Flip a real scrape-succeeded result to a false "defense holds".
        row.defense_holds = false;

        assert!(
            !verify_scrape_test_result(&row, &key.verifying_key()),
            "tampered defense_holds must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scrape_test_result_tamper_tier_claim_verified_fails_verify() {
        let path = tmp_key_path("str-tamper-tier-claim");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_scrape_test_result_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_scrape_test_result_row(sig_hex.0.clone());

        // Hide a posture-fact-vs-kernel-reality mismatch (the headline field
        // this fact exists to catch).
        row.tier_claim_verified = false;

        assert!(
            !verify_scrape_test_result(&row, &key.verifying_key()),
            "tampered tier_claim_verified must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scrape_test_result_tamper_vantage_fails_verify() {
        let path = tmp_key_path("str-tamper-vantage");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = sample_scrape_test_result_bytes();
        let sig_hex = key.sign(&bytes);
        let mut row = sample_scrape_test_result_row(sig_hex.0.clone());

        row.vantage = 1; // relay re-attributes an in-guest result to Vantage B

        assert!(
            !verify_scrape_test_result(&row, &key.verifying_key()),
            "tampered vantage must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scrape_test_result_bad_sig_hex_fails_verify() {
        let key = BoxSigningKey::load_or_generate(&tmp_key_path("str-bad-hex"))
            .expect("generate key");
        let row = sample_scrape_test_result_row("not-valid-hex".to_string());
        assert!(
            !verify_scrape_test_result(&row, &key.verifying_key()),
            "malformed sig_hex must not verify"
        );
    }
}
