//! Typed, operator-signed control directives for `mirage-secd`.
//!
//! # Why a pull channel (not a control WS)
//!
//! secd holds **no inbound listener** and **no persistent control WS** — it is
//! a stateless request/response daemon that dials a fresh V9 tunnel to each
//! monitor on its posture loop. Operator → secd control therefore rides a
//! **durable pull channel** modelled on the mshd blob-delivery API SHAPE: the
//! operator (opbox) stages a signed directive on a monitor; secd pulls pending
//! directives on its loop, verifies the operator Ed25519 signature against its
//! pinned `OPERATOR_PUBKEY_HEX`, applies it, and reports a signed result.
//!
//! # Authenticated, not secret
//!
//! Unlike [`crate::mshd_blob`] (which encrypts an opaque file under the target's
//! X25519 key), directives carry **nothing worth hiding** — "turn root-login
//! off", "ban 1.2.3.4". So this contract **signs (Ed25519) but does not
//! encrypt**. The monitor is a blind relay; it never needs to understand the
//! directive, only route it. secd is the verifier.
//!
//! # 100% typed signing bytes
//!
//! Per the fleet-wide signing doctrine (`fact_signing` + memory
//! `zt_facts_fully_typed_no_freeform_json`): the signed bytes are entirely
//! structured — a domain prefix, NUL-terminated id/machine fields, a big-endian
//! timestamp, then a one-byte **variant tag** selecting the body, then that
//! body's scalar fields in a fixed order. A free-form JSON blob is **never**
//! part of the signed input. Variable-length detail *responses* are bound by a
//! 32-byte BLAKE3 hash field, never embedded raw.
//!
//! Appended body variants / fields extend the layout; an old verifier computes
//! a shorter buffer → signature mismatch → drop.
//!
//! # The pull channel is live delivery; the anchor is durability
//!
//! The pull channel above is how a directive reaches a **running** secd, and
//! for that it needs no fleet-wide verifier roll: the monitor is a blind relay
//! and only secd computes the signing bytes.
//!
//! That is not enough for the directives which have to still be in force after
//! a reboot. Those were echoed into a SQLCipher table whose key the operator
//! delivers, so a box that came back while the operator was away read nothing
//! and fell to its compiled-in defaults — for [`SecdDirectiveBody::
//! SetReputationMode`] that default is `Off`, so the box switched its own
//! reputation enforcement off while the fleet's evidence sat fully gossiped
//! beside it. [`SecdPolicyRecord`] is the fix: the same signed directive,
//! carried as a gossiped anchor instead of a locked row.
//!
//! That does introduce a verifier-roll dependency the live path never had —
//! every monitor now computes these signing bytes, so appending a body variant
//! or a field means rolling the monitors before opbox emits one. The gossip
//! layer's own tolerance covers the transition rather than the contract: an
//! unknown event `kind` is skipped per-element and the batch survives
//! (`monitor::peer_event::decode_peer_event_batch`), and anti-entropy repairs
//! what was skipped once the roll finishes.

use serde::{Deserialize, Serialize};

use crate::secd_policy::{
    KernelTrack, PatchMode, PatchSchedule, ReputationMode, SecdPolicy, SurfaceConfig,
};

/// Domain prefix for operator→secd directive signatures.
const DOMAIN_SECD_DIRECTIVE: &[u8] = b"mirage-secd-directive-v1\0";

/// Domain prefix for secd→operator directive-result signatures.
const DOMAIN_SECD_DIRECTIVE_RESULT: &[u8] = b"mirage-secd-directive-result-v1\0";

/// One operator-issued control directive targeting a single box's secd.
///
/// Carried as JSON on `POST /relay/secd/{id}/directive` (operator→monitor) and
/// returned verbatim on `GET /relay/secd/{id}/directive/pending` (monitor→secd).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecdDirective {
    /// UUID. secd dedups by this — idempotent across re-pulls and delivery
    /// through more than one monitor.
    pub directive_id: String,
    /// Target `machine_id`. secd **refuses** a directive whose `machine_id`
    /// does not equal its own (anti-misroute / anti-cross-box).
    pub machine_id: String,
    /// Operator-stamped issue time (ms since epoch). Bound by the signature so a
    /// captured directive cannot be replayed under a fresh `directive_id`.
    pub issued_at_ms: u64,
    /// The typed command.
    pub body: SecdDirectiveBody,
    /// Operator Ed25519 signature (hex) over [`secd_directive_signing_bytes`].
    pub sig_hex: String,
}

/// The typed command carried by a [`SecdDirective`].
///
/// Externally tagged (serde default) — robust for newtype variants holding
/// other enums; the canonical signed bytes are computed by
/// [`secd_directive_signing_bytes`], independent of the JSON representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecdDirectiveBody {
    /// Edit sshd hardening knobs (drop-in conf → `sshd -t` → reload).
    Sshd {
        /// `Some(policy)` sets `PermitRootLogin`; `None` → leave unchanged.
        /// The tri-state matters: `No` blocks root entirely (locks out
        /// key-based operator management), `ProhibitPassword` keeps key-only
        /// root (the safe hardening for an opbox-russh-managed box).
        permit_root_login: Option<RootLoginPolicy>,
        /// `Some(false)` → `PasswordAuthentication no`; `None` → leave.
        password_auth: Option<bool>,
    },
    /// An nftables action applied via `mirage-nft`.
    Fw(FwAction),
    /// An operator-signed desired baseline. Once set, secd drift-corrects it on
    /// every posture tick (the master-plan continuous-enforcement state).
    Baseline {
        password_auth_off: bool,
        root_login_off: bool,
        fw_enforced: bool,
    },
    /// On-demand deep detail. The variable-length listing rides the **signed
    /// result** payload (bound by BLAKE3), not a gossiped fact.
    Detail(DetailKind),
    /// Emergency: drop all inbound except SSH (22) + Mirage wire.
    Lockdown,
    /// Lift a prior lockdown — re-apply the normal base policy.
    Open,
    /// Tier-1 fleet-collaborative ban. Issued by opbox AFTER its K-of-N
    /// corroboration gate confirms an IP is independently hostile on ≥K boxes
    /// (or a single very-high-confidence signal, or an operator click) — then
    /// fanned to EVERY box's secd (not one target), each applying a local nft
    /// ban with the given TTL. The K-of-N decision lives in opbox's
    /// aggregation layer; by the time secd sees this directive it is a plain
    /// operator-signed "ban this IP locally" command (the monitor stays a blind
    /// relay). `ttl_ms` feeds the nft per-element timeout so escalation
    /// (24h→72h→7d→cap, tier-2) is expressed purely as a longer TTL.
    FleetBan {
        /// The IP to ban fleet-wide.
        ip: String,
        /// nft per-element ban timeout in milliseconds (0 = no timeout / until
        /// reaper). Escalation is expressed by re-issuing with a larger value.
        ttl_ms: u64,
        /// Operator/aggregation reason (e.g. "corroborated on 4 boxes,
        /// signal=ssh_brute"). Covered by the signature; surfaced in audit +
        /// secd's local attacker_intel.
        reason: String,
    },
    /// Set secd's full typed operating point (plan §2/§4 — generalizes the
    /// prior `SetTier` directive into one field of [`SecdPolicy`]). secd
    /// applies whatever runtime-reachable subset it can per axis and never
    /// crash-loops on a failed axis (graceful-degrade contract, plan §4).
    SetPolicy {
        /// The requested operating point. Achieved-vs-requested per axis is
        /// reported in the extended `SecurityPostureRow`, never silently
        /// clamped.
        policy: SecdPolicy,
    },
    /// axis P: immediate one-shot patch run, independent of `SetPolicy`'s
    /// scheduled cadence (an operator-triggered "patch now").
    RunPatch {
        /// Which apt scope to run (`SecurityOnly` or `Full` — `Off` is
        /// rejected by the apply-arm as a no-op request).
        mode: PatchMode,
        /// If the patch run leaves `/var/run/reboot-required` present,
        /// surface that fact in the directive result message. secd NEVER
        /// reboots from this arm regardless of this flag — a reboot is
        /// only ever performed by a separate, operator-issued `Reboot`
        /// directive.
        reboot_if_required: bool,
    },
    /// Operator-gated reboot, `delay_secs` from now (`shutdown -r +N`
    /// equivalent). Never triggered automatically by `RunPatch` or the axis
    /// P scheduler — always a distinct operator decision.
    Reboot {
        /// Delay before the reboot actually fires, in seconds. `0` = as
        /// immediate as the OS reboot mechanism allows.
        delay_secs: u64,
    },
    /// axis P: replace the live schedule the scheduler reads on its next
    /// tick (`mirage-secd::patch::maybe_run_scheduled`). Independent of
    /// `SetPolicy` — see the SUCS plan §1
    /// (`docs/mirage/plans/secd-update-control-system-2026-07-07.md`).
    SetPatchSchedule {
        /// The requested cadence + kernel-line target.
        schedule: PatchSchedule,
    },
    /// axis F: replace the live attack-surface-minimization config the
    /// policy engine reads on its next apply pass (`apply_surface`).
    /// Independent of `SetPolicy` — mirrors `SetPatchSchedule`'s split from
    /// `SecdPolicy` (arc2.8 §1.1/§1.2).
    SetSurfaceConfig {
        /// The requested ladder position + denylist/allowlist overrides.
        config: SurfaceConfig,
    },
    /// Operator-triggered in-place restart of a Tier-2-PROTECTED
    /// de-privileged daemon (`db-worker`/`monitor`/`node`), during a
    /// version-update deploy — opens secd's narrow, time-bounded
    /// managed-restart allow-window (`mirage-secd::managed_restart`) so
    /// `systemctl restart` can deliver its SIGTERM despite the BPF-LSM
    /// `task_kill` deny that otherwise protects that cgroup from every
    /// other caller. secd rejects any `unit` outside its own managed set —
    /// never a blanket "restart anything."
    ManagedRestart {
        /// The systemd unit to restart (e.g. `mirage-db-worker.service`).
        unit: String,
    },
    /// axis R: what this box's secd may do with the fleet's gossiped
    /// attacker reputation — the observations other boxes made at their own
    /// front doors.
    ///
    /// Its own variant rather than a field of [`SecdPolicy`] on purpose: an
    /// extra axis byte inside `encode_secd_policy` would move the signed
    /// preimage of every `SetPolicy` that has ever been issued, in both roll
    /// directions, and would stop the durably stored policy row from
    /// re-verifying at boot — dropping a rebooted box to the default
    /// operating point. A new tag costs nothing anybody already signed. See
    /// [`crate::secd_policy::ReputationMode`].
    SetReputationMode {
        /// The requested rung. `Off` is a legitimate request, not a no-op:
        /// it is how a box that is acting on fleet evidence is told to stop.
        mode: ReputationMode,
    },
}

/// An nftables action (subset of `mirage-nft` ops reachable from the operator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FwAction {
    /// Add `ip` to the banned set.
    Ban { ip: String },
    /// Remove `ip` from the banned set.
    Unban { ip: String },
    /// Add `ip` to the trusted set.
    Trust { ip: String },
    /// Remove `ip` from the trusted set.
    Untrust { ip: String },
    /// Re-assert the full base policy (table/chains/sets/allowlist).
    ReapplyBasePolicy,
    /// Add `port` to the inbound allowlist.
    AllowPort { port: u16 },
}

/// sshd `PermitRootLogin` policy — the three values sshd actually distinguishes.
///
/// `No` blocks ALL root login (even key-based) → locks out an operator that
/// manages the box over root-SSH. `ProhibitPassword` (aka `without-password`)
/// keeps key-based root but forbids password root login — the safe hardening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootLoginPolicy {
    /// `PermitRootLogin yes` — password OR key.
    Yes,
    /// `PermitRootLogin prohibit-password` — key only, no password.
    ProhibitPassword,
    /// `PermitRootLogin no` — no root login at all.
    No,
}

/// Which on-demand detail listing the operator wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetailKind {
    /// Full LISTEN port list with owning process.
    Listeners,
    /// Recent sshd auth event feed (successes + failures).
    AuthFeed,
    /// Current banned IP set.
    BanList,
    /// Current trusted IP set.
    TrustList,
    /// Recent decoy/honeypot touches (peer IP + decoy port + opaque snippet).
    /// A touch of a decoy is an unambiguous-foe signal — this surfaces who hit
    /// the traps without anyone SSHing in.
    DecoyFeed,
}

/// secd's signed reply to one [`SecdDirective`].
///
/// Posted to `POST /relay/secd/{id}/directive/{did}/result`. The operator polls
/// for it via the monitor. `payload_json` (e.g. a listener listing for a
/// [`DetailKind`] request) is **not** in the signed scalar layout — it is bound
/// by `payload_blake3` so a blind relay cannot tamper with it undetectably.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecdDirectiveResult {
    /// The `directive_id` this result answers.
    pub directive_id: String,
    /// The reporting box's `machine_id`.
    pub machine_id: String,
    /// secd-stamped apply time (ms).
    pub applied_at_ms: u64,
    /// Whether the directive applied cleanly.
    pub ok: bool,
    /// Human-readable status / error detail (covered by the signature).
    pub message: String,
    /// Optional variable-length detail payload (JSON). Bound by BLAKE3 in the
    /// signature; `None` for non-detail directives.
    pub payload_json: Option<String>,
    /// secd Ed25519 signature (hex) over [`secd_directive_result_signing_bytes`].
    pub sig_hex: String,
}

// ── Signing-byte builders ────────────────────────────────────────────────────

/// Build the canonical byte string an operator signs to authorise a directive.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                      24 bytes + NUL = 25 bytes
/// directive_id UTF-8 + NUL    variable
/// machine_id  UTF-8 + NUL     variable
/// issued_at_ms                8 bytes big-endian u64
/// body_tag                    1 byte  (0x01..=0x06)
/// <body fields, per variant>  variable
/// ```
///
/// Body tags: `Sshd=0x01 Fw=0x02 Baseline=0x03 Detail=0x04 Lockdown=0x05 Open=0x06
/// FleetBan=0x07 SetPolicy=0x08 RunPatch=0x09 Reboot=0x0A SetPatchSchedule=0x0B
/// SetSurfaceConfig=0x0C ManagedRestart=0x0D SetReputationMode=0x0E`.
/// SetReputationMode body: the `ReputationMode` discriminant (1 byte).
/// FleetBan body: `ip UTF-8 + NUL | ttl_ms 8 bytes BE u64 | reason UTF-8 + NUL`.
/// SetPolicy body: ten axis bytes in `SecdPolicy` field order — `kernel_tier
/// | dk_backend | confidential | egress | integrity | self_sandbox |
/// enforce_mode | detection | patch_mode | surface` (each the enum's
/// `#[repr(u8)]` discriminant).
/// RunPatch body: `mode` discriminant (1 byte) `| reboot_if_required` (1 byte,
/// `0x00`/`0x01`).
/// Reboot body: `delay_secs` (8 bytes BE u64).
/// SetPatchSchedule body — **byte order deliberately differs from the
/// `PatchSchedule` struct field order** (arc2.8 §2.2: the new fixed-width
/// reboot fields are inserted BEFORE the variable-length `kernel_track` tail
/// so that tail stays last in the stream): `schedule.mode` discriminant (1
/// byte) `| interval_secs` (8 bytes BE u64) `| jitter_secs` (8 bytes BE u64)
/// `| reboot` discriminant (1 byte, `Off=0x00 Armed=0x01`) `|
/// reboot_window.start_hour` (1 byte) `| reboot_window.start_minute` (1
/// byte) `| reboot_window.window_minutes` (2 bytes BE u16) `|
/// kernel_track_tag` (1 byte, `Hold=0x01 Hwe=0x02 Pinned=0x03`) `| Pinned
/// only: version UTF-8 + NUL`.
/// SetSurfaceConfig body: `mode` discriminant (1 byte, `Off=0x00
/// MaskBaseline=0x01 UnitConfined=0x02 PurgeAggressive=0x03`) `|` then,
/// for each of `extra_denylist`, `allow_services`, `extra_module_blacklist`,
/// `allow_modules` in that order: a count (2 bytes BE u16) followed by that
/// many UTF-8 + NUL strings.
/// ManagedRestart body: `unit` UTF-8 + NUL.
pub fn secd_directive_signing_bytes(
    directive_id: &str,
    machine_id: &str,
    issued_at_ms: u64,
    body: &SecdDirectiveBody,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_SECD_DIRECTIVE.len() + directive_id.len() + 1 + machine_id.len() + 1 + 8 + 1 + 32,
    );

    out.extend_from_slice(DOMAIN_SECD_DIRECTIVE);

    out.extend_from_slice(directive_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&issued_at_ms.to_be_bytes());

    match body {
        SecdDirectiveBody::Sshd {
            permit_root_login,
            password_auth,
        } => {
            out.push(0x01);
            encode_opt_root_login(&mut out, *permit_root_login);
            encode_opt_bool(&mut out, *password_auth);
        }
        SecdDirectiveBody::Fw(action) => {
            out.push(0x02);
            encode_fw_action(&mut out, action);
        }
        SecdDirectiveBody::Baseline {
            password_auth_off,
            root_login_off,
            fw_enforced,
        } => {
            out.push(0x03);
            out.push(u8::from(*password_auth_off));
            out.push(u8::from(*root_login_off));
            out.push(u8::from(*fw_enforced));
        }
        SecdDirectiveBody::Detail(kind) => {
            out.push(0x04);
            out.push(detail_kind_tag(*kind));
        }
        SecdDirectiveBody::Lockdown => out.push(0x05),
        SecdDirectiveBody::Open => out.push(0x06),
        SecdDirectiveBody::FleetBan { ip, ttl_ms, reason } => {
            out.push(0x07);
            out.extend_from_slice(ip.as_bytes());
            out.push(0u8);
            out.extend_from_slice(&ttl_ms.to_be_bytes());
            out.extend_from_slice(reason.as_bytes());
            out.push(0u8);
        }
        SecdDirectiveBody::SetPolicy { policy } => {
            out.push(0x08);
            encode_secd_policy(&mut out, policy);
        }
        SecdDirectiveBody::RunPatch { mode, reboot_if_required } => {
            out.push(0x09);
            out.push(*mode as u8);
            out.push(u8::from(*reboot_if_required));
        }
        SecdDirectiveBody::Reboot { delay_secs } => {
            out.push(0x0A);
            out.extend_from_slice(&delay_secs.to_be_bytes());
        }
        SecdDirectiveBody::SetPatchSchedule { schedule } => {
            out.push(0x0B);
            encode_patch_schedule(&mut out, schedule);
        }
        SecdDirectiveBody::SetSurfaceConfig { config } => {
            out.push(0x0C);
            encode_surface_config(&mut out, config);
        }
        SecdDirectiveBody::ManagedRestart { unit } => {
            out.push(0x0D);
            out.extend_from_slice(unit.as_bytes());
            out.push(0u8);
        }
        SecdDirectiveBody::SetReputationMode { mode } => {
            out.push(0x0E);
            out.push(*mode as u8);
        }
    }

    out
}

/// Build the canonical byte string secd signs to authenticate a directive result.
///
/// # Field encoding order
///
/// ```text
/// DOMAIN                      31 bytes + NUL = 32 bytes
/// directive_id UTF-8 + NUL    variable
/// machine_id  UTF-8 + NUL     variable
/// applied_at_ms               8 bytes big-endian u64
/// ok                          1 byte (0x00 / 0x01)
/// message UTF-8 + NUL         variable
/// payload_blake3 flag+value   1 byte, or 1 + 32 bytes
/// ```
pub fn secd_directive_result_signing_bytes(
    directive_id: &str,
    machine_id: &str,
    applied_at_ms: u64,
    ok: bool,
    message: &str,
    payload_blake3: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_SECD_DIRECTIVE_RESULT.len()
            + directive_id.len()
            + 1
            + machine_id.len()
            + 1
            + 8
            + 1
            + message.len()
            + 1
            + 1
            + 32,
    );

    out.extend_from_slice(DOMAIN_SECD_DIRECTIVE_RESULT);

    out.extend_from_slice(directive_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(machine_id.as_bytes());
    out.push(0u8);

    out.extend_from_slice(&applied_at_ms.to_be_bytes());

    out.push(u8::from(ok));

    out.extend_from_slice(message.as_bytes());
    out.push(0u8);

    match payload_blake3 {
        None => out.push(0x00),
        Some(h) => {
            out.push(0x01);
            out.extend_from_slice(&h);
        }
    }

    out
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// `None → 0x00`; `Some(false) → 0x01 0x00`; `Some(true) → 0x01 0x01`.
/// Keeps `None` distinct from `Some(false)` so a strip-to-None downgrade
/// produces a different digest.
#[inline]
fn encode_opt_bool(out: &mut Vec<u8>, v: Option<bool>) {
    match v {
        None => out.push(0x00),
        Some(b) => {
            out.push(0x01);
            out.push(u8::from(b));
        }
    }
}

/// `None → 0x00`; `Some(policy) → 0x01 <tag>` where tag is
/// `Yes=0x01 ProhibitPassword=0x02 No=0x03`. Each policy yields a distinct
/// digest so a downgrade (e.g. ProhibitPassword→No, or strip-to-None) is
/// signature-detectable.
#[inline]
fn encode_opt_root_login(out: &mut Vec<u8>, v: Option<RootLoginPolicy>) {
    match v {
        None => out.push(0x00),
        Some(p) => {
            out.push(0x01);
            out.push(match p {
                RootLoginPolicy::Yes => 0x01,
                RootLoginPolicy::ProhibitPassword => 0x02,
                RootLoginPolicy::No => 0x03,
            });
        }
    }
}

/// FwAction op tags: `Ban=0x01 Unban=0x02 Trust=0x03 Untrust=0x04
/// ReapplyBasePolicy=0x05 AllowPort=0x06`.
#[inline]
fn encode_fw_action(out: &mut Vec<u8>, action: &FwAction) {
    match action {
        FwAction::Ban { ip } => {
            out.push(0x01);
            out.extend_from_slice(ip.as_bytes());
            out.push(0u8);
        }
        FwAction::Unban { ip } => {
            out.push(0x02);
            out.extend_from_slice(ip.as_bytes());
            out.push(0u8);
        }
        FwAction::Trust { ip } => {
            out.push(0x03);
            out.extend_from_slice(ip.as_bytes());
            out.push(0u8);
        }
        FwAction::Untrust { ip } => {
            out.push(0x04);
            out.extend_from_slice(ip.as_bytes());
            out.push(0u8);
        }
        FwAction::ReapplyBasePolicy => out.push(0x05),
        FwAction::AllowPort { port } => {
            out.push(0x06);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

#[inline]
fn detail_kind_tag(kind: DetailKind) -> u8 {
    match kind {
        DetailKind::Listeners => 0x01,
        DetailKind::AuthFeed => 0x02,
        DetailKind::BanList => 0x03,
        DetailKind::TrustList => 0x04,
        DetailKind::DecoyFeed => 0x05,
    }
}

/// Encode a [`SecdPolicy`] as ten fixed discriminant bytes, in field order.
/// Each axis enum is `#[repr(u8)]`, so the discriminant IS the wire byte —
/// no separate tag table to keep in sync.
#[inline]
fn encode_secd_policy(out: &mut Vec<u8>, policy: &SecdPolicy) {
    out.push(policy.kernel_tier as u8);
    out.push(policy.dk_backend as u8);
    out.push(policy.confidential as u8);
    out.push(policy.egress as u8);
    out.push(policy.integrity as u8);
    out.push(policy.self_sandbox as u8);
    out.push(policy.enforce_mode as u8);
    out.push(policy.detection as u8);
    out.push(policy.patch_mode as u8);
    out.push(policy.surface as u8);
}

/// `KernelTrack` tags: `Hold=0x01 Hwe=0x02 Pinned=0x03`. `KernelTrack` has no
/// `#[repr(u8)]` (data-carrying `Pinned` variant, see
/// `secd_policy::KernelTrack` doc), so this match-based tag fn mirrors
/// `detail_kind_tag`/`encode_fw_action`'s pattern in this file.
#[inline]
fn kernel_track_tag(track: &KernelTrack) -> u8 {
    match track {
        KernelTrack::Hold => 0x01,
        KernelTrack::Hwe => 0x02,
        KernelTrack::Pinned(_) => 0x03,
    }
}

/// Encode a [`PatchSchedule`] as `mode | interval_secs | jitter_secs |
/// reboot | reboot_window (start_hour + start_minute + window_minutes BE
/// u16) | kernel_track_tag [| Pinned version UTF-8 + NUL]`.
///
/// **Byte order deliberately differs from the struct's field order**
/// (arc2.8 §2.2) — `reboot`/`reboot_window` are appended fields on
/// `PatchSchedule` but are encoded BEFORE `kernel_track_tag` here so the
/// variable-length `Pinned` tail stays last in the signed byte stream.
#[inline]
fn encode_patch_schedule(out: &mut Vec<u8>, schedule: &PatchSchedule) {
    out.push(schedule.mode as u8);
    out.extend_from_slice(&schedule.interval_secs.to_be_bytes());
    out.extend_from_slice(&schedule.jitter_secs.to_be_bytes());
    out.push(schedule.reboot as u8);
    out.push(schedule.reboot_window.start_hour);
    out.push(schedule.reboot_window.start_minute);
    out.extend_from_slice(&schedule.reboot_window.window_minutes.to_be_bytes());
    out.push(kernel_track_tag(&schedule.kernel_track));
    if let KernelTrack::Pinned(version) = &schedule.kernel_track {
        out.extend_from_slice(version.as_bytes());
        out.push(0u8);
    }
}

/// Encode one variable-length string list as `count (2 bytes BE u16) |`
/// each string as `UTF-8 + NUL`, mirroring the `FleetBan`/`Reboot`
/// each-variable-length-field-UTF-8+NUL precedent already used elsewhere in
/// this file. `count` is `u16` — callers never expect a list anywhere near
/// `u16::MAX` entries; a genuinely oversized list truncates the count
/// (`as u16`), which is a wire-contract concern for the caller, not a panic
/// here.
#[inline]
fn encode_string_list(out: &mut Vec<u8>, items: &[String]) {
    out.extend_from_slice(&(items.len() as u16).to_be_bytes());
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0u8);
    }
}

/// Encode a [`SurfaceConfig`] as `mode discriminant (1 byte) |
/// extra_denylist | allow_services | extra_module_blacklist |
/// allow_modules` — each list encoded via [`encode_string_list`], in that
/// fixed field order (arc2.8 §1.2). No JSON in signed bytes.
#[inline]
fn encode_surface_config(out: &mut Vec<u8>, config: &SurfaceConfig) {
    out.push(config.mode as u8);
    encode_string_list(out, &config.extra_denylist);
    encode_string_list(out, &config.allow_services);
    encode_string_list(out, &config.extra_module_blacklist);
    encode_string_list(out, &config.allow_modules);
}

// ── The durable policy anchor ────────────────────────────────────────────────

/// The directive kinds that carry **enduring** state — the ones a box has to
/// still be under after a reboot, as opposed to the one-shot acts (`Fw`,
/// `Detail`, `ManagedRestart`, …) that mean nothing once they have run.
///
/// These four are exactly the kinds the monitor already echoed into the
/// durable `secd_desired_state` table, and the string forms below are the
/// same ones that table has always used as its `kind` column — they are the
/// on-the-wire and on-disk names, so they are pinned here rather than derived
/// from a `Debug` impl.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecdPolicyKind {
    /// [`SecdDirectiveBody::SetPolicy`].
    SetPolicy,
    /// [`SecdDirectiveBody::SetPatchSchedule`].
    SetPatchSchedule,
    /// [`SecdDirectiveBody::SetSurfaceConfig`] (axis F).
    SetSurfaceConfig,
    /// [`SecdDirectiveBody::SetReputationMode`] (axis R).
    SetReputationMode,
}

impl SecdPolicyKind {
    /// The canonical wire/disk name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetPolicy => "set_policy",
            Self::SetPatchSchedule => "set_patch_schedule",
            Self::SetSurfaceConfig => "set_surface_config",
            Self::SetReputationMode => "set_reputation_mode",
        }
    }

    /// Parse a canonical name. `None` for anything else — an unrecognised
    /// kind is skipped, never guessed at.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "set_policy" => Some(Self::SetPolicy),
            "set_patch_schedule" => Some(Self::SetPatchSchedule),
            "set_surface_config" => Some(Self::SetSurfaceConfig),
            "set_reputation_mode" => Some(Self::SetReputationMode),
            _ => None,
        }
    }

    /// Which anchor slot, if any, a directive body belongs in. `None` for
    /// every one-shot body — those are delivered through the pending queue
    /// and never anchored.
    #[must_use]
    pub fn of_body(body: &SecdDirectiveBody) -> Option<Self> {
        match body {
            SecdDirectiveBody::SetPolicy { .. } => Some(Self::SetPolicy),
            SecdDirectiveBody::SetPatchSchedule { .. } => Some(Self::SetPatchSchedule),
            SecdDirectiveBody::SetSurfaceConfig { .. } => Some(Self::SetSurfaceConfig),
            SecdDirectiveBody::SetReputationMode { .. } => Some(Self::SetReputationMode),
            _ => None,
        }
    }

    /// All four, in a fixed order — for callers that materialise every slot.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::SetPolicy,
            Self::SetPatchSchedule,
            Self::SetSurfaceConfig,
            Self::SetReputationMode,
        ]
    }
}

/// One box's durable policy anchor: the latest operator-signed directive of
/// each enduring kind.
///
/// # Why four independent slots and not one row with one clock
///
/// The same reason [`crate::quorum::SubjectRecord`] is shaped this way, and
/// the trap is worth restating because it is a fail-**open** one. A single
/// per-machine sequence number shared by four independent slots means a
/// receiver holding a fresh `set_reputation_mode` would reject an older-stamped
/// `set_policy` it never saw, as "stale" — and would then never converge on it,
/// because its digest keeps mismatching and every repair pull re-fetches
/// exactly what it keeps rejecting. Per-slot LWW loses nothing: an old
/// directive still cannot displace a newer directive of the same kind, and that
/// is the whole job of the clock.
///
/// The clock is the directive's own `issued_at_ms`, which is operator-stamped
/// and inside [`secd_directive_signing_bytes`] — so it cannot be advanced by
/// anyone without the operator's key, and a replayed directive cannot displace
/// its own successor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecdPolicyRecord {
    /// Latest [`SecdDirectiveBody::SetPolicy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_policy: Option<SecdDirective>,
    /// Latest [`SecdDirectiveBody::SetPatchSchedule`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_patch_schedule: Option<SecdDirective>,
    /// Latest [`SecdDirectiveBody::SetSurfaceConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_surface_config: Option<SecdDirective>,
    /// Latest [`SecdDirectiveBody::SetReputationMode`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_reputation_mode: Option<SecdDirective>,
}

impl SecdPolicyRecord {
    /// Read one slot.
    #[must_use]
    pub fn slot(&self, kind: SecdPolicyKind) -> Option<&SecdDirective> {
        match kind {
            SecdPolicyKind::SetPolicy => self.set_policy.as_ref(),
            SecdPolicyKind::SetPatchSchedule => self.set_patch_schedule.as_ref(),
            SecdPolicyKind::SetSurfaceConfig => self.set_surface_config.as_ref(),
            SecdPolicyKind::SetReputationMode => self.set_reputation_mode.as_ref(),
        }
    }

    /// The LWW watermark of one slot — `0` when the slot is empty, so a first
    /// directive is always strictly newer.
    #[must_use]
    pub fn slot_issued_at_ms(&self, kind: SecdPolicyKind) -> u64 {
        self.slot(kind).map_or(0, |d| d.issued_at_ms)
    }

    /// Whether `incoming` would displace what this record holds for its own
    /// kind. Strictly-greater, never greater-or-equal: two directives stamped
    /// the same millisecond are indistinguishable from a replay, and letting a
    /// replay through would let a retired policy displace its successor.
    ///
    /// Returns `false` for a body that is not an anchored kind at all.
    #[must_use]
    pub fn would_accept(&self, incoming: &SecdDirective) -> bool {
        SecdPolicyKind::of_body(&incoming.body)
            .is_some_and(|kind| incoming.issued_at_ms > self.slot_issued_at_ms(kind))
    }

    /// Apply `incoming` if it is strictly newer than the slot it targets.
    /// Returns whether the record changed.
    ///
    /// This performs **no** signature check — every caller must have verified
    /// the operator signature first (see [`verify_secd_directive`]). Keeping
    /// the check out of here is deliberate: a merge function that silently
    /// verified would invite a caller to skip its own verification and then
    /// quietly stop being safe if this one ever changed.
    pub fn apply(&mut self, incoming: SecdDirective) -> bool {
        let Some(kind) = SecdPolicyKind::of_body(&incoming.body) else {
            return false;
        };
        if incoming.issued_at_ms <= self.slot_issued_at_ms(kind) {
            return false;
        }
        match kind {
            SecdPolicyKind::SetPolicy => self.set_policy = Some(incoming),
            SecdPolicyKind::SetPatchSchedule => self.set_patch_schedule = Some(incoming),
            SecdPolicyKind::SetSurfaceConfig => self.set_surface_config = Some(incoming),
            SecdPolicyKind::SetReputationMode => self.set_reputation_mode = Some(incoming),
        }
        true
    }

    /// Whether every slot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set_policy.is_none()
            && self.set_patch_schedule.is_none()
            && self.set_surface_config.is_none()
            && self.set_reputation_mode.is_none()
    }
}

/// Why a directive was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectiveVerifyError {
    /// The pinned operator public key is not decodable hex / not a key.
    BadOperatorKey(String),
    /// `sig_hex` is not decodable as a 64-byte Ed25519 signature.
    BadSignature(String),
    /// The signature does not verify over [`secd_directive_signing_bytes`].
    SignatureMismatch,
    /// `directive_id` or `machine_id` is empty.
    EmptyIdentifier,
    /// The directive targets a different machine than the one it arrived under.
    MachineMismatch {
        /// The machine the caller expected.
        expected: String,
        /// The machine the directive names.
        found: String,
    },
}

impl std::fmt::Display for DirectiveVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadOperatorKey(e) => write!(f, "operator pubkey unusable: {e}"),
            Self::BadSignature(e) => write!(f, "signature not decodable: {e}"),
            Self::SignatureMismatch => write!(f, "operator signature verification failed"),
            Self::EmptyIdentifier => write!(f, "directive_id and machine_id must be non-empty"),
            Self::MachineMismatch { expected, found } => {
                write!(f, "directive targets {found}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for DirectiveVerifyError {}

/// Verify a directive against the pinned operator key, and optionally against
/// the machine it is supposed to be for.
///
/// One function so that every consumer of an anchored directive — the monitor
/// applying a gossiped one, and secd applying what its monitor served — checks
/// the same things in the same order. `expect_machine` is `Some` wherever the
/// caller already knows which box the directive should name, which is the
/// anti-misroute guard secd has always applied to its pull queue and which a
/// gossiped anchor needs for exactly the same reason: the key that signs a
/// directive for one box signs one for every box.
///
/// # Errors
///
/// See [`DirectiveVerifyError`].
pub fn verify_secd_directive(
    directive: &SecdDirective,
    operator_pubkey_hex: &str,
    expect_machine: Option<&str>,
) -> Result<(), DirectiveVerifyError> {
    if directive.directive_id.trim().is_empty() || directive.machine_id.trim().is_empty() {
        return Err(DirectiveVerifyError::EmptyIdentifier);
    }
    if let Some(expected) = expect_machine {
        if directive.machine_id != expected {
            return Err(DirectiveVerifyError::MachineMismatch {
                expected: expected.to_string(),
                found: directive.machine_id.clone(),
            });
        }
    }

    let key_bytes: [u8; 32] = hex::decode(operator_pubkey_hex)
        .map_err(|e| DirectiveVerifyError::BadOperatorKey(e.to_string()))?
        .try_into()
        .map_err(|_| DirectiveVerifyError::BadOperatorKey("not 32 bytes".to_string()))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| DirectiveVerifyError::BadOperatorKey(e.to_string()))?;

    let sig_bytes: [u8; 64] = hex::decode(&directive.sig_hex)
        .map_err(|e| DirectiveVerifyError::BadSignature(e.to_string()))?
        .try_into()
        .map_err(|_| DirectiveVerifyError::BadSignature("not 64 bytes".to_string()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    let bytes = secd_directive_signing_bytes(
        &directive.directive_id,
        &directive.machine_id,
        directive.issued_at_ms,
        &directive.body,
    );
    ed25519_dalek::Verifier::verify(&key, &bytes, &sig)
        .map_err(|_| DirectiveVerifyError::SignatureMismatch)
}

// ── Tests ────────────────────────────────────────────────────────────────────

// THROWAWAY (SetPolicy coverage only) — delete at Stage I
#[cfg(test)]
mod tests {
    use super::*;
    use crate::box_signing::BoxSigningKey;
    use crate::secd_policy::{
        ConfMode, DetectionMode, DkBackend, EgressMode, EnforceMode, IntegrityMode, KernelTier,
        KernelTrack, PatchMode, PatchSchedule, RebootPolicy, RebootWindow, SandboxMode,
        SurfaceMode,
    };
    use ed25519_dalek::Verifier;
    use uuid::Uuid;

    fn tmp_key_path(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mirage-core-secd-directive-{label}-{}-{}.raw",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        p
    }

    fn sshd_root_off() -> SecdDirectiveBody {
        SecdDirectiveBody::Sshd {
            permit_root_login: Some(RootLoginPolicy::No),
            password_auth: None,
        }
    }

    #[test]
    fn directive_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes =
            secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &sshd_root_off());
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("directive signature must verify with matching bytes");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn directive_fleetban_roundtrip_and_ttl_tamper_fails() {
        let path = tmp_key_path("dir-fleetban");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let vk = key.verifying_key();

        let body = SecdDirectiveBody::FleetBan {
            ip: "203.0.113.7".to_string(),
            ttl_ms: 86_400_000, // 24h
            reason: "corroborated on 4 boxes, signal=ssh_brute".to_string(),
        };
        let bytes =
            secd_directive_signing_bytes("d-fb-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode");
        vk.verify(&bytes, &sig)
            .expect("fleet-ban directive must verify with matching bytes");

        // Relay escalates the ban TTL (24h → 7d) without re-signing.
        let tampered = secd_directive_signing_bytes(
            "d-fb-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::FleetBan {
                ip: "203.0.113.7".to_string(),
                ttl_ms: 604_800_000, // 7d
                reason: "corroborated on 4 boxes, signal=ssh_brute".to_string(),
            },
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered fleet-ban ttl_ms must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn directive_tamper_machine_id_fails() {
        let path = tmp_key_path("dir-tamper-machine");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original =
            secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &sshd_root_off());
        let sig = key.sign(&original).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Re-target the directive at a different box.
        let tampered =
            secd_directive_signing_bytes("d-1", "ru-hostkey-203.0.113.10", 1_700_000_000_000, &sshd_root_off());
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "re-targeted machine_id must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn directive_tamper_body_fails() {
        let path = tmp_key_path("dir-tamper-body");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        // Operator authorised "root login no".
        let original =
            secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &sshd_root_off());
        let sig = key.sign(&original).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Relay flips it to "root login YES".
        let tampered = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::Sshd {
                permit_root_login: Some(RootLoginPolicy::Yes),
                password_auth: None,
            },
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "flipped sshd value must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn directive_root_login_states_all_differ() {
        // Every PermitRootLogin state — None (leave), Yes, ProhibitPassword, No —
        // must produce a distinct digest, so a downgrade (ProhibitPassword→No, or
        // strip-to-None) is signature-detectable.
        let mk = |p: Option<RootLoginPolicy>| {
            secd_directive_signing_bytes(
                "d-1",
                "ch-example-203.0.113.40",
                1_700_000_000_000,
                &SecdDirectiveBody::Sshd {
                    permit_root_login: p,
                    password_auth: None,
                },
            )
        };
        let states = [
            mk(None),
            mk(Some(RootLoginPolicy::Yes)),
            mk(Some(RootLoginPolicy::ProhibitPassword)),
            mk(Some(RootLoginPolicy::No)),
        ];
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j], "root-login states {i}/{j} must differ");
            }
        }
    }

    #[test]
    fn directive_distinct_variants_differ() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let ban = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::Fw(FwAction::Ban { ip: "1.2.3.4".into() }),
        );
        let trust = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::Fw(FwAction::Trust { ip: "1.2.3.4".into() }),
        );
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(ban, trust, "ban vs trust over same ip must differ");
        assert_ne!(ban, lockdown, "fw vs lockdown must differ");
    }

    // ── axis P: RunPatch / Reboot ────────────────────────────────────────────

    #[test]
    fn run_patch_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-runpatch-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::RunPatch {
            mode: PatchMode::SecurityOnly,
            reboot_if_required: true,
        };
        let bytes = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("RunPatch signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn run_patch_mode_and_reboot_flag_both_move_the_bytes() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let security_no_reboot = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::RunPatch { mode: PatchMode::SecurityOnly, reboot_if_required: false },
        );
        let full_no_reboot = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::RunPatch { mode: PatchMode::Full, reboot_if_required: false },
        );
        let security_reboot = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::RunPatch { mode: PatchMode::SecurityOnly, reboot_if_required: true },
        );
        assert_ne!(security_no_reboot, full_no_reboot, "mode must move the signed bytes");
        assert_ne!(security_no_reboot, security_reboot, "reboot_if_required must move the signed bytes");
    }

    #[test]
    fn reboot_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-reboot-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::Reboot { delay_secs: 30 };
        let bytes = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("Reboot signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reboot_tamper_delay_secs_fails() {
        let path = tmp_key_path("dir-reboot-tamper-delay");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::Reboot { delay_secs: 30 },
        );
        let sig = key.sign(&original).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Relay tries to shorten the delay to fire the reboot sooner.
        let tampered = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::Reboot { delay_secs: 0 },
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered delay_secs must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn run_patch_and_reboot_distinguishable_from_other_variants() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let run_patch = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::RunPatch { mode: PatchMode::Full, reboot_if_required: false },
        );
        let reboot = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Reboot { delay_secs: 0 });
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(run_patch, reboot, "RunPatch vs Reboot must differ");
        assert_ne!(run_patch, lockdown, "RunPatch vs an unrelated variant must differ");
        assert_ne!(reboot, lockdown, "Reboot vs an unrelated variant must differ");
    }

    #[test]
    fn result_sign_then_verify_roundtrip() {
        let path = tmp_key_path("res-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let bytes = secd_directive_result_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_001_000,
            true,
            "applied",
            None,
        );
        let sig = key.sign(&bytes).to_signature().expect("decode");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("result signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn result_tamper_ok_flag_fails() {
        let path = tmp_key_path("res-tamper-ok");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = secd_directive_result_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_001_000,
            false, // secd reported FAILURE
            "sshd -t rejected config",
            None,
        );
        let sig = key.sign(&original).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Relay flips failure to success.
        let tampered = secd_directive_result_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_001_000,
            true,
            "sshd -t rejected config",
            None,
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "flipped ok flag must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn result_payload_hash_bound() {
        let path = tmp_key_path("res-payload");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let payload_a = blake3::hash(b"listeners: 22,19444").into();
        let original = secd_directive_result_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_001_000,
            true,
            "detail",
            Some(payload_a),
        );
        let sig = key.sign(&original).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Relay swaps the payload (different hash).
        let payload_b: [u8; 32] = blake3::hash(b"listeners: 22,19444,31337").into();
        let tampered = secd_directive_result_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_001_000,
            true,
            "detail",
            Some(payload_b),
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "swapped payload hash must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn directive_json_roundtrips() {
        let d = SecdDirective {
            directive_id: "d-1".into(),
            machine_id: "ch-example-203.0.113.40".into(),
            issued_at_ms: 1_700_000_000_000,
            body: SecdDirectiveBody::Fw(FwAction::AllowPort { port: 8443 }),
            sig_hex: "deadbeef".into(),
        };
        let json = serde_json::to_string(&d).expect("serialize");
        let back: SecdDirective = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, back, "SecdDirective must round-trip through JSON");
    }

    // ── SetPolicy tests ───────────────────────────────────────────────────────

    fn sample_policy() -> SecdPolicy {
        SecdPolicy {
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
        }
    }

    #[test]
    fn set_policy_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-setpolicy-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::SetPolicy {
            policy: sample_policy(),
        };
        let bytes =
            secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig_hex = key.sign(&bytes);
        let sig = sig_hex.to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("SetPolicy signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_policy_determinism() {
        let body = SecdDirectiveBody::SetPolicy {
            policy: sample_policy(),
        };
        let a = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let b = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn set_policy_tamper_kernel_tier_fails() {
        let path = tmp_key_path("dir-setpolicy-tamper-tier");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = SecdDirectiveBody::SetPolicy {
            policy: sample_policy(),
        };
        let bytes =
            secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &original);
        let sig = key.sign(&bytes).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Relay tries to quietly downgrade the requested kernel tier.
        let mut downgraded = sample_policy();
        downgraded.kernel_tier = KernelTier::Tier0;
        let tampered = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPolicy { policy: downgraded },
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered kernel_tier must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_policy_every_axis_change_alters_bytes() {
        // Each of the 10 axes must independently move the signed bytes — a
        // silently-omitted axis in the encoder would make this fail.
        let base = sample_policy();
        let base_bytes = secd_directive_signing_bytes(
            "d-1",
            "m",
            1,
            &SecdDirectiveBody::SetPolicy { policy: base },
        );

        let variants: Vec<SecdPolicy> = vec![
            SecdPolicy { kernel_tier: KernelTier::Tier2, ..base },
            SecdPolicy { dk_backend: DkBackend::AttestedCvm, ..base },
            SecdPolicy { confidential: ConfMode::ReportEmit, ..base },
            SecdPolicy { egress: EgressMode::MonitorOnly, ..base },
            SecdPolicy { integrity: IntegrityMode::ImaAppraise, ..base },
            SecdPolicy { self_sandbox: SandboxMode::Off, ..base },
            SecdPolicy { enforce_mode: EnforceMode::Enforce, ..base },
            SecdPolicy { detection: DetectionMode::Off, ..base },
            SecdPolicy { patch_mode: PatchMode::Full, ..base },
            SecdPolicy { surface: SurfaceMode::MaskBaseline, ..base },
        ];

        for (i, v) in variants.into_iter().enumerate() {
            let bytes = secd_directive_signing_bytes(
                "d-1",
                "m",
                1,
                &SecdDirectiveBody::SetPolicy { policy: v },
            );
            assert_ne!(
                bytes, base_bytes,
                "axis index {i} change must alter the signed bytes"
            );
        }
    }

    #[test]
    fn set_policy_distinguishable_from_other_variants() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let set_policy = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPolicy {
                policy: sample_policy(),
            },
        );
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(
            set_policy, lockdown,
            "SetPolicy body must differ from an unrelated variant"
        );
    }

    // ── axis P: SetPatchSchedule (SUCS) ──────────────────────────────────────

    fn sample_schedule() -> PatchSchedule {
        PatchSchedule {
            mode: PatchMode::SecurityOnly,
            interval_secs: 86_400,
            jitter_secs: 3_600,
            kernel_track: KernelTrack::Hold,
            reboot: RebootPolicy::Off,
            reboot_window: RebootWindow { start_hour: 2, start_minute: 0, window_minutes: 120 },
        }
    }

    #[test]
    fn set_patch_schedule_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-setschedule-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::SetPatchSchedule {
            schedule: sample_schedule(),
        };
        let bytes = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("SetPatchSchedule signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_patch_schedule_determinism() {
        let body = SecdDirectiveBody::SetPatchSchedule {
            schedule: sample_schedule(),
        };
        let a = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let b = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn set_patch_schedule_tamper_each_field_fails() {
        let path = tmp_key_path("dir-setschedule-tamper");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let vk = key.verifying_key();

        let base = sample_schedule();
        let original = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule { schedule: base.clone() },
        );
        let sig = key.sign(&original).to_signature().expect("decode");

        let tampered_mode = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule { mode: PatchMode::Full, ..base.clone() },
            },
        );
        assert!(
            vk.verify(&tampered_mode, &sig).is_err(),
            "tampered mode must not verify"
        );

        let tampered_interval = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule { interval_secs: 3_600, ..base.clone() },
            },
        );
        assert!(
            vk.verify(&tampered_interval, &sig).is_err(),
            "tampered interval_secs must not verify"
        );

        let tampered_jitter = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule { jitter_secs: 0, ..base.clone() },
            },
        );
        assert!(
            vk.verify(&tampered_jitter, &sig).is_err(),
            "tampered jitter_secs must not verify"
        );

        let tampered_track = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule { kernel_track: KernelTrack::Hwe, ..base.clone() },
            },
        );
        assert!(
            vk.verify(&tampered_track, &sig).is_err(),
            "tampered kernel_track must not verify"
        );

        // THROWAWAY (arc2.8 auto-reboot) — delete at Stage I
        let tampered_reboot = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule { reboot: RebootPolicy::Armed, ..base.clone() },
            },
        );
        assert!(
            vk.verify(&tampered_reboot, &sig).is_err(),
            "tampered reboot policy must not verify"
        );

        let tampered_reboot_window = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule {
                    reboot_window: RebootWindow { start_hour: 4, start_minute: 15, window_minutes: 30 },
                    ..base
                },
            },
        );
        assert!(
            vk.verify(&tampered_reboot_window, &sig).is_err(),
            "tampered reboot_window must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_patch_schedule_pinned_kernel_track_moves_bytes() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let hwe = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule { kernel_track: KernelTrack::Hwe, ..sample_schedule() },
            },
        );
        let pinned_a = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule {
                    kernel_track: KernelTrack::Pinned("5.15.0-119-generic".to_string()),
                    ..sample_schedule()
                },
            },
        );
        let pinned_b = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: PatchSchedule {
                    kernel_track: KernelTrack::Pinned("6.8.0-generic".to_string()),
                    ..sample_schedule()
                },
            },
        );
        assert_ne!(hwe, pinned_a, "Hwe vs Pinned must differ");
        assert_ne!(pinned_a, pinned_b, "different Pinned versions must differ");
    }

    #[test]
    fn set_patch_schedule_distinguishable_from_other_variants() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let set_schedule = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: sample_schedule(),
            },
        );
        let set_policy = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPolicy {
                policy: sample_policy(),
            },
        );
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(
            set_schedule, set_policy,
            "SetPatchSchedule must differ from SetPolicy"
        );
        assert_ne!(
            set_schedule, lockdown,
            "SetPatchSchedule must differ from an unrelated variant"
        );
    }

    // ── axis F: SetSurfaceConfig ─────────────────────────────────────────────
    // THROWAWAY — delete at Stage I

    fn sample_surface_config() -> SurfaceConfig {
        SurfaceConfig {
            mode: SurfaceMode::MaskBaseline,
            extra_denylist: vec!["snmpd.service".to_string()],
            allow_services: vec!["postfix.service".to_string()],
            extra_module_blacklist: vec!["cifs".to_string()],
            allow_modules: vec!["squashfs".to_string()],
        }
    }

    #[test]
    fn set_surface_config_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-setsurface-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::SetSurfaceConfig {
            config: sample_surface_config(),
        };
        let bytes = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("SetSurfaceConfig signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_surface_config_determinism() {
        let body = SecdDirectiveBody::SetSurfaceConfig {
            config: sample_surface_config(),
        };
        let a = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let b = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    #[test]
    fn set_surface_config_tamper_each_field_fails() {
        let path = tmp_key_path("dir-setsurface-tamper");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let vk = key.verifying_key();

        let base = sample_surface_config();
        let original = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetSurfaceConfig { config: base.clone() },
        );
        let sig = key.sign(&original).to_signature().expect("decode");

        let tampered_mode = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetSurfaceConfig {
                config: SurfaceConfig { mode: SurfaceMode::PurgeAggressive, ..base.clone() },
            },
        );
        assert!(
            vk.verify(&tampered_mode, &sig).is_err(),
            "tampered mode must not verify"
        );

        let tampered_denylist = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetSurfaceConfig {
                config: SurfaceConfig {
                    extra_denylist: vec!["telnetd.service".to_string()],
                    ..base.clone()
                },
            },
        );
        assert!(
            vk.verify(&tampered_denylist, &sig).is_err(),
            "tampered extra_denylist must not verify"
        );

        let tampered_allow_services = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetSurfaceConfig {
                config: SurfaceConfig {
                    allow_services: vec!["exim4.service".to_string()],
                    ..base.clone()
                },
            },
        );
        assert!(
            vk.verify(&tampered_allow_services, &sig).is_err(),
            "tampered allow_services must not verify"
        );

        let tampered_module_blacklist = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetSurfaceConfig {
                config: SurfaceConfig {
                    extra_module_blacklist: vec!["dccp".to_string()],
                    ..base.clone()
                },
            },
        );
        assert!(
            vk.verify(&tampered_module_blacklist, &sig).is_err(),
            "tampered extra_module_blacklist must not verify"
        );

        let tampered_allow_modules = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetSurfaceConfig {
                config: SurfaceConfig {
                    allow_modules: vec!["udf".to_string()],
                    ..base
                },
            },
        );
        assert!(
            vk.verify(&tampered_allow_modules, &sig).is_err(),
            "tampered allow_modules must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_surface_config_distinguishable_from_other_variants() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let set_surface = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetSurfaceConfig {
                config: sample_surface_config(),
            },
        );
        let set_schedule = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetPatchSchedule {
                schedule: sample_schedule(),
            },
        );
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(
            set_surface, set_schedule,
            "SetSurfaceConfig must differ from SetPatchSchedule"
        );
        assert_ne!(
            set_surface, lockdown,
            "SetSurfaceConfig must differ from an unrelated variant"
        );
    }

    // ── ManagedRestart ────────────────────────────────────────────────────
    // THROWAWAY — delete at Stage I

    #[test]
    fn managed_restart_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-managedrestart-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::ManagedRestart {
            unit: "mirage-db-worker.service".to_string(),
        };
        let bytes = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("ManagedRestart signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn managed_restart_tamper_unit_fails() {
        let path = tmp_key_path("dir-managedrestart-tamper");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let original = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::ManagedRestart {
                unit: "mirage-db-worker.service".to_string(),
            },
        );
        let sig = key.sign(&original).to_signature().expect("decode");
        let vk = key.verifying_key();

        // Relay tries to retarget the restart at a different unit.
        let tampered = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::ManagedRestart {
                unit: "mirage2monitor-v2.service".to_string(),
            },
        );
        assert!(
            vk.verify(&tampered, &sig).is_err(),
            "tampered unit must not verify"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn managed_restart_distinguishable_from_other_variants() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let managed_restart = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::ManagedRestart {
                unit: "mirage-db-worker.service".to_string(),
            },
        );
        let reboot = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Reboot { delay_secs: 0 });
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(
            managed_restart, reboot,
            "ManagedRestart must differ from Reboot"
        );
        assert_ne!(
            managed_restart, lockdown,
            "ManagedRestart must differ from an unrelated variant"
        );
    }

    #[test]
    fn set_reputation_mode_sign_then_verify_roundtrip() {
        let path = tmp_key_path("dir-setreputation-roundtrip");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");

        let body = SecdDirectiveBody::SetReputationMode {
            mode: ReputationMode::Corroborated,
        };
        let bytes = secd_directive_signing_bytes("d-1", "ch-example-203.0.113.40", 1_700_000_000_000, &body);
        let sig = key.sign(&bytes).to_signature().expect("decode signature");
        let vk = key.verifying_key();
        vk.verify(&bytes, &sig)
            .expect("SetReputationMode signature must verify with matching bytes");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn every_reputation_rung_signs_to_different_bytes() {
        // The rung IS the whole body. If two rungs shared a preimage, a
        // signed "stop enforcing" would be replayable as "start enforcing".
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let of = |mode| {
            secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::SetReputationMode { mode })
        };
        let off = of(ReputationMode::Off);
        let observe = of(ReputationMode::Observe);
        let corroborated = of(ReputationMode::Corroborated);
        assert_ne!(off, observe);
        assert_ne!(observe, corroborated);
        assert_ne!(off, corroborated);
    }

    #[test]
    fn adding_axis_r_did_not_move_the_set_policy_preimage() {
        // The reason axis R is its own directive tag and NOT an eleventh
        // byte inside `encode_secd_policy`: every `SetPolicy` ever signed
        // must keep verifying across this change, in both roll directions,
        // and the durable `set_policy` row must still re-verify at boot —
        // otherwise a rebooted box silently falls back to Tier0.
        let bytes = secd_directive_signing_bytes(
            "d-1",
            "ch-example-203.0.113.40",
            1_700_000_000_000,
            &SecdDirectiveBody::SetPolicy { policy: sample_policy() },
        );
        // Tag byte + exactly ten axis bytes, and nothing else.
        let tag_at = bytes.len() - 11;
        assert_eq!(bytes[tag_at], 0x08, "SetPolicy body tag");
        assert_eq!(
            bytes.len() - tag_at - 1,
            10,
            "the SetPolicy body is still ten axis bytes — adding an eleventh \
             would break every signature already issued"
        );
    }

    #[test]
    fn set_reputation_mode_is_distinguishable_from_every_other_variant() {
        let ts = 1_700_000_000_000;
        let m = "ch-example-203.0.113.40";
        let reputation = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::SetReputationMode { mode: ReputationMode::Observe },
        );
        let managed_restart = secd_directive_signing_bytes(
            "d-1",
            m,
            ts,
            &SecdDirectiveBody::ManagedRestart { unit: "mirage-db-worker.service".to_string() },
        );
        let lockdown = secd_directive_signing_bytes("d-1", m, ts, &SecdDirectiveBody::Lockdown);
        assert_ne!(reputation, managed_restart);
        assert_ne!(reputation, lockdown);
    }
}

#[cfg(test)]
mod policy_anchor_tests {
    use super::*;
    use crate::box_signing::BoxSigningKey;
    use crate::secd_policy::{ReputationMode, SurfaceConfig, SurfaceMode};
    use uuid::Uuid;

    fn tmp_key_path(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mirage-core-policy-anchor-{label}-{}-{}.raw",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        p
    }

    /// Sign a directive the way opbox does, so these tests exercise the real
    /// signing bytes rather than a stand-in.
    fn signed(
        key: &BoxSigningKey,
        id: &str,
        machine: &str,
        issued_at_ms: u64,
        body: SecdDirectiveBody,
    ) -> SecdDirective {
        let bytes = secd_directive_signing_bytes(id, machine, issued_at_ms, &body);
        SecdDirective {
            directive_id: id.to_string(),
            machine_id: machine.to_string(),
            issued_at_ms,
            body,
            sig_hex: key.sign(&bytes).0,
        }
    }

    fn reputation(mode: ReputationMode) -> SecdDirectiveBody {
        SecdDirectiveBody::SetReputationMode { mode }
    }

    /// A second anchored kind, used only to prove the slots are independent.
    /// `SurfaceMode::Off` is the no-op rung every fresh box already sits on.
    fn surface_body() -> SecdDirectiveBody {
        SecdDirectiveBody::SetSurfaceConfig {
            config: SurfaceConfig {
                mode: SurfaceMode::Off,
                extra_denylist: Vec::new(),
                allow_services: Vec::new(),
                extra_module_blacklist: Vec::new(),
                allow_modules: Vec::new(),
            },
        }
    }

    #[test]
    fn kind_names_match_the_durable_column_values() {
        // These strings are the `kind` column `secd_desired_state` has always
        // used and the names the wire now carries. Renaming one silently
        // orphans every row already written under the old name.
        assert_eq!(SecdPolicyKind::SetPolicy.as_str(), "set_policy");
        assert_eq!(
            SecdPolicyKind::SetPatchSchedule.as_str(),
            "set_patch_schedule"
        );
        assert_eq!(
            SecdPolicyKind::SetSurfaceConfig.as_str(),
            "set_surface_config"
        );
        assert_eq!(
            SecdPolicyKind::SetReputationMode.as_str(),
            "set_reputation_mode"
        );
        for kind in SecdPolicyKind::all() {
            assert_eq!(SecdPolicyKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(SecdPolicyKind::parse("set_something_else"), None);
    }

    #[test]
    fn one_shot_bodies_are_not_anchored() {
        // A ban, a restart, or a lockdown is an act, not a state. Anchoring
        // one would replay it on every boot.
        assert_eq!(SecdPolicyKind::of_body(&SecdDirectiveBody::Lockdown), None);
        assert_eq!(
            SecdPolicyKind::of_body(&SecdDirectiveBody::ManagedRestart {
                unit: "mirage-secd".to_string()
            }),
            None
        );
        assert_eq!(
            SecdPolicyKind::of_body(&reputation(ReputationMode::Observe)),
            Some(SecdPolicyKind::SetReputationMode)
        );
    }

    #[test]
    fn newer_directive_of_the_same_kind_displaces_the_older() {
        let path = tmp_key_path("lww");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let m = "tr-hostkey-203.0.113.20";
        let mut rec = SecdPolicyRecord::default();

        assert!(rec.apply(signed(&key, "d1", m, 1_000, reputation(ReputationMode::Observe))));
        assert!(rec.apply(signed(
            &key,
            "d2",
            m,
            2_000,
            reputation(ReputationMode::Corroborated)
        )));
        assert_eq!(
            rec.slot(SecdPolicyKind::SetReputationMode)
                .map(|d| d.directive_id.as_str()),
            Some("d2")
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_replay_at_the_same_millisecond_is_refused() {
        // Strictly-greater, not greater-or-equal: a captured directive
        // re-emitted under a fresh id must not displace its own successor.
        let path = tmp_key_path("replay");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let m = "tr-hostkey-203.0.113.20";
        let mut rec = SecdPolicyRecord::default();

        assert!(rec.apply(signed(
            &key,
            "d1",
            m,
            5_000,
            reputation(ReputationMode::Corroborated)
        )));
        assert!(!rec.apply(signed(&key, "d2", m, 5_000, reputation(ReputationMode::Off))));
        assert!(!rec.apply(signed(&key, "d3", m, 4_999, reputation(ReputationMode::Off))));
        assert_eq!(
            rec.slot(SecdPolicyKind::SetReputationMode)
                .map(|d| d.directive_id.as_str()),
            Some("d1")
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn slots_have_independent_clocks() {
        // The fail-open trap this record's shape exists to avoid: a fresh
        // directive of one kind must not make an older-stamped directive of a
        // DIFFERENT kind look stale, because the receiver would then never
        // converge on it and its digest would never stop mismatching.
        let path = tmp_key_path("independent");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let m = "tr-hostkey-203.0.113.20";
        let mut rec = SecdPolicyRecord::default();

        assert!(rec.apply(signed(
            &key,
            "rep",
            m,
            9_000,
            reputation(ReputationMode::Corroborated)
        )));
        assert!(
            rec.apply(signed(&key, "surf", m, 1_000, surface_body())),
            "an older-stamped directive of another kind must still apply"
        );
        assert!(rec.slot(SecdPolicyKind::SetSurfaceConfig).is_some());
        assert!(rec.slot(SecdPolicyKind::SetReputationMode).is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_accepts_a_real_signature_and_rejects_a_tampered_body() {
        let path = tmp_key_path("verify");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let op_hex = key.verifying_key_hex();
        let m = "tr-hostkey-203.0.113.20";

        let d = signed(&key, "d1", m, 1_000, reputation(ReputationMode::Corroborated));
        verify_secd_directive(&d, &op_hex, Some(m)).expect("a genuine directive must verify");

        // Swap the body under the same signature — the rung an attacker would
        // most want to flip.
        let mut tampered = d.clone();
        tampered.body = reputation(ReputationMode::Off);
        assert_eq!(
            verify_secd_directive(&tampered, &op_hex, Some(m)),
            Err(DirectiveVerifyError::SignatureMismatch)
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_rejects_a_directive_addressed_to_another_box() {
        // The key that signs a directive for one box signs one for every box,
        // so the anchor needs the same anti-misroute guard the pull queue has.
        let path = tmp_key_path("misroute");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate key");
        let op_hex = key.verifying_key_hex();

        let d = signed(
            &key,
            "d1",
            "ru-hostkey-203.0.113.10",
            1_000,
            reputation(ReputationMode::Off),
        );
        assert!(matches!(
            verify_secd_directive(&d, &op_hex, Some("tr-hostkey-203.0.113.20")),
            Err(DirectiveVerifyError::MachineMismatch { .. })
        ));
        // Without an expectation the same directive is fine — a caller that
        // does not know which box it is for must not invent one.
        verify_secd_directive(&d, &op_hex, None).expect("no expectation, no mismatch");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_rejects_a_signature_from_a_different_key() {
        let path_a = tmp_key_path("keya");
        let path_b = tmp_key_path("keyb");
        let signer = BoxSigningKey::load_or_generate(&path_a).expect("generate key a");
        let other = BoxSigningKey::load_or_generate(&path_b).expect("generate key b");
        let m = "tr-hostkey-203.0.113.20";

        let d = signed(
            &signer,
            "d1",
            m,
            1_000,
            reputation(ReputationMode::Corroborated),
        );
        assert_eq!(
            verify_secd_directive(&d, &other.verifying_key_hex(), Some(m)),
            Err(DirectiveVerifyError::SignatureMismatch)
        );

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn empty_record_serialises_to_an_empty_object() {
        // The anchor rides the gossip digest; an empty record must not
        // contribute four `null`s of churn to every hash.
        let json = serde_json::to_string(&SecdPolicyRecord::default()).expect("serialise");
        assert_eq!(json, "{}");
        assert!(SecdPolicyRecord::default().is_empty());
    }
}
