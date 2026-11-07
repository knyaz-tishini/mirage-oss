//! Operator-signed command envelope for the arc2.9 graceful-restart control
//! plane, delivered to `mirage-warden` via `mshd` (an UNTRUSTED transport
//! — see `mirage-secd::pair`'s module doc for the full "why the warden
//! verifies the operator signature itself" rationale).
//!
//! Moved here VERBATIM from `mirage-secd::pair` so that platform-neutral
//! consumers (opbox, which runs on the Windows dev box and must not depend
//! on `mirage-secd` — Linux-only: seccomp/eBPF/nft) can build a
//! well-formed, correctly-signed [`OperatorCommand`] without pulling in the
//! Linux-only crate. `mirage-secd::pair` re-exports every item in this
//! module (`pub use mirage_core::operator_cmd::{...}`) so every existing
//! `mirage_secd::pair::*` path keeps resolving unchanged.
//!
//! # Do not change the signing-byte layout
//!
//! [`operator_cmd_signing_bytes`]'s layout is SIGNED bytes — `mshd` relays
//! whatever it is handed, and `mirage-warden` (already deployed) verifies
//! the signature against its own baked `OPERATOR_PUBKEY_HEX`. Any change to
//! the byte layout here silently breaks that already-deployed verifier.
//! [`tests::golden_operator_cmd_signing_bytes`] locks the exact layout with
//! a fixed hex vector precisely so a future edit here fails loudly instead
//! of silently.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// One operator-signed command for the warden, delivered by `mshd` (an
/// UNTRUSTED transport). Never sent over the secd↔warden pair socket —
/// this travels `opbox → monitor-relay → mshd → local loopback →
/// warden` (arc2.9 §0.4), a completely separate delivery path from the
/// pair-socket messages in `mirage-secd::pair`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorCommand {
    pub command: OperatorCmdKind,
    /// Single-use replay guard — the warden's own consumer maintains a
    /// bounded seen-nonce set (age-gated, see `mirage-warden`'s
    /// `operator_cmd` module).
    pub nonce: String,
    pub ts_ms: u64,
    /// Operator Ed25519 signature (hex) over
    /// [`operator_cmd_signing_bytes`]`(&command, &nonce, ts_ms)`.
    pub sig_hex: String,
}

/// The operator commands the warden accepts (arc2.9 §0.4/§0.5).
///
/// Externally tagged (default serde representation) — `RestartUnit` and
/// `RetireUnit` are newtype (tuple) variants wrapping a bare `String`, which
/// serde's internally-tagged representation does not support (only
/// struct/unit variants are; see serde's own enum-representations
/// documentation). On the wire a retire is `{"RetireUnit":"<unit>"}`; a
/// warden built before this variant existed fails to deserialise it and
/// answers `error: malformed OperatorCommand JSON` with no nonce, so roll the
/// warden before issuing the command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorCmdKind {
    /// Open secd's targeted kill-allow-window + `systemctl restart
    /// mirage-secd` (secd update path — secd itself cannot self-restart,
    /// arc2.9 §0.5).
    RestartSecd,
    /// The warden's own graceful self-update path — NOT a `kill`, so it
    /// is never gated by the eBPF `task_kill` hook: `std::process::exit(0)`
    /// on receipt of a validly-signed request, and systemd's
    /// `Restart=always` respawns the freshly-uploaded binary into the SAME
    /// cgroup (arc2.9 §0.5).
    RestartSelf,
    /// Restart one of the warden-supervised mirage units in place
    /// (monitor/node/db-worker, plus cli2's edge-client supervisor since
    /// 2026-09-23 — the same `MANAGED_RESTART_TARGETS` set secd's own
    /// `managed_restart` allowlists, now driven by an operator-signed
    /// command instead of a directive).
    RestartUnit(String),
    /// Read-only: report what the warden knows about the units it started —
    /// unit, declared `ExecStart` path, pid, cgroup id, image size/mtime/
    /// sha256, start time, whether the image was replaced since this
    /// supervisor began watching, and — for every managed-restart target —
    /// how many live instances of its main binary this box currently
    /// carries and its duplicate-instance state, if any
    /// ([`crate::unit_state::UnitStateReport`]).
    ///
    /// Signed like every other command even though it changes nothing: the
    /// answer names every binary path and hash on the box, which is exactly
    /// the reconnaissance an unauthenticated reader should not get for free.
    ReportUnitState,
    /// Ask the keeper's machine-identity store (`mirage-warden::
    /// machine_store`) to open a fresh delivery window RIGHT NOW instead of
    /// waiting for its own renewal schedule (up to the full capsule TTL —
    /// 24h — away). Closes the gap where a warm restart with a valid stored
    /// capsule serves it immediately and opens no window at all, and a
    /// `/persona/apply` re-sign has no way to reach the box before its own
    /// renewal lead time, so opbox can only SEAL a capsule TO an announce
    /// that never comes.
    ///
    /// Idempotent on the warden side: a second call while a window is
    /// already open only re-arms it (a fresh boot nonce + ephemeral key),
    /// the same re-ask the keeper's own periodic renewal already performs —
    /// never a crash, never a second identity mint. Publishes a
    /// `BootAnnounce`, nothing else — it mints no identity and never
    /// touches the capsule already at rest. See `operator-box::
    /// warden_restart`'s module doc for the caller
    /// (`POST /warden/open-window`) and `mirage-warden::operator_cmd`'s
    /// `process_claimed` for the handler.
    OpenDeliveryWindow,
    /// Remove one unit from the box: archive its unit file out of the systemd
    /// load path (which is what ends the warden's supervision of it — the
    /// supervision set is derived from that directory on every poll), stop it
    /// inside a targeted Tier2 allow-window, wait for its pid and cgroup to
    /// be gone, then disable it and reload systemd. Only for units on the
    /// warden's `RETIRABLE_UNITS` allowlist (`mirage-secd::surface_denylist`);
    /// anything else is a named refusal.
    ///
    /// Why a dedicated command and not `systemctl stop` + `disable` from a
    /// shell: on a Tier2 box the kernel hook denies the SIGTERM/SIGKILL of a
    /// protected unit for every sender unless the warden has opened a window
    /// for that cgroup, and the warden restarts any installed-but-dead unit
    /// within one poll. Only a step sequence that lives inside the warden
    /// can order "stop supervising" before "stop the process".
    ///
    /// The answer is a [`crate::unit_retire::RetireReport`] (JSON after the
    /// `ok:`/`error:` prefix of the response message). Idempotent: a unit that
    /// is already gone reports `already_retired` and changes nothing.
    ///
    /// Discriminant `0x06`; the unit name rides in the same signed slot
    /// `RestartUnit` uses, so a `RetireUnit` signature can never be replayed
    /// as a `RestartUnit` for the same unit (the discriminant differs).
    RetireUnit(String),
}

/// Domain prefix for an operator-signed [`OperatorCommand`].
const DOMAIN_OPERATOR_CMD: &[u8] = b"mirage-warden-operator-cmd-v1\0";

/// One-byte discriminant for [`OperatorCmdKind`] — folded into
/// [`operator_cmd_signing_bytes`] so the SIX distinct command meanings can
/// never collide under the same signature (e.g. a `RestartSecd` signature
/// replayed as a `RestartSelf` request, or a `RestartUnit` signature replayed
/// as a `RetireUnit` for the same unit).
fn operator_cmd_discriminant(cmd: &OperatorCmdKind) -> u8 {
    match cmd {
        OperatorCmdKind::RestartSecd => 0x01,
        OperatorCmdKind::RestartSelf => 0x02,
        OperatorCmdKind::RestartUnit(_) => 0x03,
        OperatorCmdKind::ReportUnitState => 0x04,
        OperatorCmdKind::OpenDeliveryWindow => 0x05,
        OperatorCmdKind::RetireUnit(_) => 0x06,
    }
}

/// Deterministic signing bytes for one [`OperatorCommand`].
///
/// ```text
/// DOMAIN                32 bytes (incl. NUL)
/// discriminant            1 byte  (see operator_cmd_discriminant)
/// unit UTF-8 + NUL         variable (empty string + NUL for the commands
///                          that name no unit; the unit name for
///                          RestartUnit and RetireUnit)
/// nonce UTF-8 + NUL        variable
/// ts_ms                    8 bytes big-endian u64
/// ```
#[must_use]
pub fn operator_cmd_signing_bytes(cmd: &OperatorCmdKind, nonce: &str, ts_ms: u64) -> Vec<u8> {
    let unit: &str = match cmd {
        OperatorCmdKind::RestartUnit(u) | OperatorCmdKind::RetireUnit(u) => u.as_str(),
        OperatorCmdKind::RestartSecd
        | OperatorCmdKind::RestartSelf
        | OperatorCmdKind::ReportUnitState
        | OperatorCmdKind::OpenDeliveryWindow => "",
    };
    let mut out = Vec::with_capacity(
        DOMAIN_OPERATOR_CMD.len() + 1 + unit.len() + 1 + nonce.len() + 1 + 8,
    );
    out.extend_from_slice(DOMAIN_OPERATOR_CMD);
    out.push(operator_cmd_discriminant(cmd));
    out.extend_from_slice(unit.as_bytes());
    out.push(0u8);
    out.extend_from_slice(nonce.as_bytes());
    out.push(0u8);
    out.extend_from_slice(&ts_ms.to_be_bytes());
    out
}

/// Sign `msg` with the Ed25519 key derived from `seed`, returning the
/// signature as lowercase hex. `seed` is the 32-byte Ed25519 seed (the same
/// shape as `bootstrap::SECD_SIGNING_PRIVKEY`/`WARDEN_SIGNING_PRIVKEY`) —
/// never the 64-byte expanded keypair.
#[must_use]
pub fn sign_ed25519(seed: &[u8; 32], msg: &[u8]) -> String {
    let signing_key = SigningKey::from_bytes(seed);
    let signature = signing_key.sign(msg);
    hex::encode(signature.to_bytes())
}

/// The warden's answer to one [`OperatorCommand`], written to `cmd.resp`
/// and read back by the caller that wrote the matching `cmd.req` (arc2.9
/// `POST /warden/restart-{secd,self,unit}` — see
/// `operator-box::warden_restart`'s module doc and
/// `mirage-warden::operator_cmd`'s `run` loop).
///
/// Deliberately NOT part of [`operator_cmd_signing_bytes`]'s preimage — the
/// signature protects the operator's AUTHORITY to make the warden act;
/// this struct only lets the reader confirm which request a response
/// belongs to. Signing it would mean rolling the verifier before any caller
/// could rely on it (see this module's own "do not change the signing-byte
/// layout" doc); echoing an already-signed field back unsigned needs no such
/// coordination and carries no new privilege — the trust boundary for
/// `cmd.resp` is "who can write to `/run/mirage/warden/` on this box"
/// (root, already trusted), the same boundary every other file this pair
/// exchanges relies on.
///
/// Fixes the measured 2026-07-31 defect where `cmd.resp` carried no
/// correlation id at all: a response left over from an unrelated command
/// (a slow health-polled restart still in flight, or a second delivery
/// racing the first on the same mailbox) was indistinguishable from a fresh
/// one, so the poll loop on the caller side could read a stale "ok: ..." and
/// report success for a command that was never executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorCommandResponse {
    /// Echoes the [`OperatorCommand::nonce`] of the request this answers.
    /// `None` only when the warden could not even parse a well-formed
    /// envelope out of `cmd.req` (malformed JSON) — there is no nonce to
    /// echo in that case, and the reader must treat an unconfirmed nonce the
    /// same as a mismatched one: never a success.
    pub nonce: Option<String>,
    /// "ok: \<msg\>" on success or "error: \<msg\>" on rejection/failure —
    /// the same format `mirage-warden::operator_cmd::CommandOutcome` has
    /// always produced.
    pub message: String,
}

/// Verify `sig_hex` over `msg` against `pubkey_hex` (a 64-hex-char Ed25519
/// verifying key, the same encoding `SECD_SIGNING_PUBKEY_HEX`/
/// `WARDEN_SIGNING_PUBKEY_HEX` uses). Returns `false` — never panics — on
/// any malformed hex, wrong-length key/signature, or a genuine verification
/// failure; the caller cannot distinguish "malformed" from "forged" from
/// this return value alone, which is the correct posture for an auth check
/// (never leak which failure mode occurred).
#[must_use]
pub fn verify_ed25519(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pk_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key.verify(msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the exact signing-byte layout for
    /// `RestartUnit("mirage2monitor-v2.service")`, nonce `"n-golden"`,
    /// `ts_ms=1_700_000_000_000` — computed once from the current
    /// implementation and pinned here so any future edit to
    /// [`operator_cmd_signing_bytes`] (or its domain/discriminant/field
    /// order) fails this test loudly instead of silently breaking the
    /// already-deployed warden's signature verification.
    ///
    /// **Re-pinned 2026-08-05, deliberately**, by the watchdog→warden hard
    /// cutover: [`DOMAIN_OPERATOR_CMD`] moved from
    /// `mirage-watchdog-operator-cmd-v1` to `mirage-warden-operator-cmd-v1`,
    /// so these bytes changed on purpose and this test caught it, which is
    /// what it is for. The consequence is real and intended: an opbox
    /// signing with the new domain produces a signature the OLD daemon
    /// rejects. That is safe here ONLY because the cutover never delivers a
    /// command to an old daemon — a box is staged and rebooted onto
    /// `mirage-warden`, never told to restart itself across the rename. If
    /// this constant is ever touched again outside such a cutover, roll the
    /// verifier before the producer.
    #[test]
    fn golden_operator_cmd_signing_bytes() {
        let bytes = operator_cmd_signing_bytes(
            &OperatorCmdKind::RestartUnit("mirage2monitor-v2.service".to_string()),
            "n-golden",
            1_700_000_000_000,
        );
        assert_eq!(
            hex::encode(&bytes),
            "6d69726167652d77617264656e2d6f70657261746f722d636d642d763100036d69726167\
65326d6f6e69746f722d76322e73657276696365006e2d676f6c64656e000000018bcfe56800"
        );
    }

    /// Locks the exact signing-byte layout for
    /// `OpenDeliveryWindow`, nonce `"n-golden-open-window"`,
    /// `ts_ms=1_700_000_000_000` — same purpose as
    /// [`golden_operator_cmd_signing_bytes`], pinned separately because
    /// this is a NEW nullary variant added alongside the three existing
    /// ones (`RestartSecd`/`RestartSelf`/`ReportUnitState`), and its own
    /// discriminant byte (`0x05`) is what this test actually protects: any
    /// future edit that reassigns discriminants, changes the domain, or
    /// touches field order fails this loudly instead of silently colliding
    /// with an existing command's preimage.
    #[test]
    fn golden_operator_cmd_signing_bytes_open_delivery_window() {
        let bytes = operator_cmd_signing_bytes(
            &OperatorCmdKind::OpenDeliveryWindow,
            "n-golden-open-window",
            1_700_000_000_000,
        );
        assert_eq!(
            hex::encode(&bytes),
            "6d69726167652d77617264656e2d6f70657261746f722d636d642d76310005006e2d676f6c64656e2d6f70656e2d\
77696e646f77000000018bcfe56800"
        );
    }

    /// Locks the exact signing-byte layout for
    /// `RetireUnit("mirage-node-v2.service")`, nonce `"n-golden-retire"`,
    /// `ts_ms=1_700_000_000_000` — a NEW unit-carrying variant, so its own
    /// discriminant byte (`0x06`) and the unit-name slot it shares with
    /// `RestartUnit` are what this pins. Same rule as the other goldens: an
    /// edit that reassigns a discriminant, changes the domain or moves a
    /// field fails here instead of silently breaking a deployed verifier.
    #[test]
    fn golden_operator_cmd_signing_bytes_retire_unit() {
        let bytes = operator_cmd_signing_bytes(
            &OperatorCmdKind::RetireUnit("mirage-node-v2.service".to_string()),
            "n-golden-retire",
            1_700_000_000_000,
        );
        assert_eq!(
            hex::encode(&bytes),
            "6d69726167652d77617264656e2d6f70657261746f722d636d642d76310006\
6d69726167652d6e6f64652d76322e73657276696365006e2d676f6c64656e2d726574697265\
000000018bcfe56800"
        );
    }

    /// The same unit name and the same nonce/ts under `RestartUnit` and
    /// `RetireUnit` must differ — and differ only in the discriminant byte —
    /// so a captured restart signature is worthless as a retire.
    #[test]
    fn retire_unit_and_restart_unit_preimages_differ_only_in_the_discriminant() {
        let unit = "mirage-node-v2.service".to_string();
        let restart = operator_cmd_signing_bytes(&OperatorCmdKind::RestartUnit(unit.clone()), "n-1", 7);
        let retire = operator_cmd_signing_bytes(&OperatorCmdKind::RetireUnit(unit), "n-1", 7);
        assert_eq!(restart.len(), retire.len());
        let differing: Vec<usize> = restart
            .iter()
            .zip(retire.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(differing, vec![DOMAIN_OPERATOR_CMD.len()], "only the discriminant byte may differ");
        assert_eq!(restart[DOMAIN_OPERATOR_CMD.len()], 0x03);
        assert_eq!(retire[DOMAIN_OPERATOR_CMD.len()], 0x06);
    }

    /// A retire signed with a fixed seed verifies, and changing the unit it
    /// names (the thing an attacker on the untrusted mshd carrier would want
    /// to swap) breaks the signature.
    #[test]
    fn retire_unit_signature_verifies_and_is_bound_to_the_unit_name() {
        let seed = [12u8; 32];
        let pubkey_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let cmd = OperatorCmdKind::RetireUnit("mirage-node-v2.service".to_string());
        let bytes = operator_cmd_signing_bytes(&cmd, "n-2", 1_700_000_000_000);
        let sig_hex = sign_ed25519(&seed, &bytes);
        assert!(verify_ed25519(&pubkey_hex, &bytes, &sig_hex));

        let swapped = operator_cmd_signing_bytes(
            &OperatorCmdKind::RetireUnit("mirage-secd.service".to_string()),
            "n-2",
            1_700_000_000_000,
        );
        assert!(!verify_ed25519(&pubkey_hex, &swapped, &sig_hex));
    }

    /// The JSON the warden reads off `cmd.req` for a retire: externally
    /// tagged, and the whole envelope survives a round trip with the
    /// signature intact.
    #[test]
    fn retire_unit_command_round_trips_through_the_json_the_warden_reads() {
        let seed = [13u8; 32];
        let kind = OperatorCmdKind::RetireUnit("mirage-chain-supervisor.service".to_string());
        let bytes = operator_cmd_signing_bytes(&kind, "n-3", 1_700_000_000_000);
        let command = OperatorCommand {
            command: kind,
            nonce: "n-3".to_string(),
            ts_ms: 1_700_000_000_000,
            sig_hex: sign_ed25519(&seed, &bytes),
        };

        let json = serde_json::to_string(&command).expect("serialise");
        assert!(
            json.contains("\"command\":{\"RetireUnit\":\"mirage-chain-supervisor.service\"}"),
            "wire shape changed: {json}"
        );
        let back: OperatorCommand = serde_json::from_str(&json).expect("deserialise");
        match &back.command {
            OperatorCmdKind::RetireUnit(u) => assert_eq!(u, "mirage-chain-supervisor.service"),
            other => panic!("expected RetireUnit, got {other:?}"),
        }
        let back_bytes = operator_cmd_signing_bytes(&back.command, &back.nonce, back.ts_ms);
        let pubkey_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        assert!(verify_ed25519(&pubkey_hex, &back_bytes, &back.sig_hex));
    }

    #[test]
    fn sign_verify_roundtrips_with_a_fixed_seed() {
        let seed = [11u8; 32];
        let pubkey_hex = hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        let cmd = OperatorCmdKind::RestartSecd;
        let bytes = operator_cmd_signing_bytes(&cmd, "n-1", 1_700_000_000_000);
        let sig_hex = sign_ed25519(&seed, &bytes);
        assert!(verify_ed25519(&pubkey_hex, &bytes, &sig_hex));

        // Flip the last byte of the signed message — verification must fail.
        let mut tampered = bytes.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x01;
        }
        assert!(!verify_ed25519(&pubkey_hex, &tampered, &sig_hex));
    }

    #[test]
    fn operator_command_response_round_trips_with_and_without_a_nonce() {
        let with_nonce = OperatorCommandResponse {
            nonce: Some("n-1".to_string()),
            message: "ok: mirage2monitor-v2.service restarted".to_string(),
        };
        let json = serde_json::to_string(&with_nonce).expect("serialise");
        let back: OperatorCommandResponse = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.nonce.as_deref(), Some("n-1"));
        assert_eq!(back.message, with_nonce.message);

        let without_nonce = OperatorCommandResponse {
            nonce: None,
            message: "error: malformed OperatorCommand JSON".to_string(),
        };
        let json = serde_json::to_string(&without_nonce).expect("serialise");
        let back: OperatorCommandResponse = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back.nonce, None);
    }

    #[test]
    fn operator_cmd_signing_bytes_distinguish_variants_at_the_same_nonce_ts() {
        let nonce = "n-1";
        let ts = 1_700_000_000_000u64;
        let restart_secd = operator_cmd_signing_bytes(&OperatorCmdKind::RestartSecd, nonce, ts);
        let restart_self = operator_cmd_signing_bytes(&OperatorCmdKind::RestartSelf, nonce, ts);
        let restart_unit = operator_cmd_signing_bytes(
            &OperatorCmdKind::RestartUnit("mirage-node-v2.service".to_string()),
            nonce,
            ts,
        );
        let report_unit_state = operator_cmd_signing_bytes(&OperatorCmdKind::ReportUnitState, nonce, ts);
        let open_delivery_window =
            operator_cmd_signing_bytes(&OperatorCmdKind::OpenDeliveryWindow, nonce, ts);
        let retire_unit = operator_cmd_signing_bytes(
            &OperatorCmdKind::RetireUnit("mirage-node-v2.service".to_string()),
            nonce,
            ts,
        );
        assert_ne!(retire_unit, restart_unit);
        assert_ne!(retire_unit, restart_secd);
        assert_ne!(retire_unit, restart_self);
        assert_ne!(retire_unit, report_unit_state);
        assert_ne!(retire_unit, open_delivery_window);
        assert_ne!(restart_secd, restart_self);
        assert_ne!(restart_secd, restart_unit);
        assert_ne!(restart_self, restart_unit);
        assert_ne!(open_delivery_window, restart_secd);
        assert_ne!(open_delivery_window, restart_self);
        assert_ne!(open_delivery_window, restart_unit);
        assert_ne!(open_delivery_window, report_unit_state);
    }
}
