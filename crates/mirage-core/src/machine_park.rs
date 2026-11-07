//! Operator-signed "machine disabled" (parked) state — a fleet-wide,
//! reversible on/off switch for one machine.
//!
//! ## Why this is a SIBLING fact, not a field on `AttestationPubkey`
//!
//! [`crate::attestation::AttestationPubkey`] is an IDENTITY statement: which
//! Ed25519 key speaks for a machine, verified upstream of the mesh's
//! identity system because it is what lets the quorum decide whom to mint an
//! identity for. "Parked" is an ordinary operator POLICY toggle — is this
//! machine currently in service — with its own independent LWW clock that
//! has nothing to do with key rotation. Folding the two together would force
//! every park/unpark to re-sign (and re-transmit) the machine's key
//! material, and would make an identity rotation and a park indistinguishable
//! in the gossip stream. The two facts share the operator-verification
//! model — the operator's pinned key, checked the same way, on every hop —
//! which this module reuses byte-for-byte, never weakened. (Since S5.1 a
//! park fact can also carry a second, independent trust anchor — see below —
//! which is additive to this fact's own model, not a change to how
//! `AttestationPubkey` itself is verified.)
//!
//! ## What "disabled" means
//!
//! `true` shelves the machine out of every dial path
//! (`desired_monitor_peers`, the active liveness prober, anti-entropy pulls,
//! `mesh_receiver::wire_dial_peer`) without touching its inventory row,
//! escrowed identities, or signed `DeclaredIdentity` records — exactly like
//! opbox's own `parked` column (`MachineRow::parked` in `mirage2operator`),
//! which this fact makes visible to the rest of the fleet instead of
//! opbox-local only. `false` (the default — absence of a record already
//! means "in service") reverses it through the same channel, and neither
//! direction revokes anything or re-mints an identity.
//!
//! ## S5.1 — two authorities, one state
//!
//! [`ParkAuthority`] splits WHO signed a fact: the pinned operator key (as
//! before), or the FROST group key named by a charter epoch — the fleet's
//! own corroborated ban, made without the operator. Both write the same
//! `disabled` state; what differs is who may lift or replace it, enforced by
//! [`park_apply_verdict`], not by verification — a valid quorum signature
//! and a valid operator signature are equally "this really is what that
//! authority asserted", and the asymmetry is a policy choice layered on top,
//! not a cryptographic one. See
//! `docs/mirage/plans/quorum-admission-s5-2026-08-06.md` for the design.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// V1 signing-preimage domain label. Distinct from every other label in the
/// tree (see `crate::attestation`'s `ATTEST_SIG_LABEL` / `ENROL_SIG_LABEL`)
/// so a park fact can never be replayed as an enrolment, capsule, charter,
/// quorum-event, or any other signed fact.
const MACHINE_PARK_SIG_LABEL: &[u8] = b"MIRAGE-MACHINE-PARK-V1";

/// V2 signing-preimage domain label — covers `authority` and `reason` in
/// addition to everything [`MACHINE_PARK_SIG_LABEL`] covers. Distinct from
/// V1 so a V2 signature can never be replayed as a V1 verification or vice
/// versa; that non-collision is what makes the narrow V1 fallback in
/// [`MachineParkFact::verify`] safe.
const MACHINE_PARK_SIG_LABEL_V2: &[u8] = b"MIRAGE-MACHINE-PARK-V2";

/// Who signed a [`MachineParkFact`], and therefore who may lift or replace
/// it. See the module doc's "S5.1" section for why this exists and
/// [`park_apply_verdict`] for the applier's asymmetric lift rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkAuthority {
    /// The pinned operator key. Only the operator may lift or replace a
    /// standing row of this authority.
    Operator,
    /// The FROST group key named by the charter at this epoch.
    Quorum { charter_epoch: u64 },
}

impl Default for ParkAuthority {
    /// A legacy row with no `authority` field genuinely IS an operator
    /// row — the quorum-authority path did not exist when it was signed,
    /// so there is no ambiguity to resolve, only a fact to state.
    /// [`MachineParkFact`]'s `#[serde(default)]` on `authority` depends on
    /// this.
    fn default() -> Self {
        Self::Operator
    }
}

/// The operator's or the quorum's current disabled/enabled statement for
/// one machine.
///
/// 1-row/machine LWW on `updated_at_ms`, the same shape as
/// [`crate::attestation::AttestationPubkey`]: a monitor keeps only the most
/// recent record per `machine_id`, and a strictly-newer `updated_at_ms` is
/// required to overwrite it — a replayed stale fact can never roll a later
/// flip back (see the monitor-side `MeshState::apply_machine_park`, and
/// [`park_apply_verdict`] for the fuller rule once `authority` is in play).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineParkFact {
    pub machine_id: String,
    /// `true` = out of service fleet-wide. `false` = back in service.
    pub disabled: bool,
    /// When this state was asserted. LWW key when gossiped, and bound into
    /// the signature so it cannot be stripped or replayed against a later
    /// flip.
    pub updated_at_ms: u64,
    /// Who signed this fact. See the module doc's "S5.1" section.
    ///
    /// `#[serde(default)]` is load-bearing: every fact already gossiped
    /// fleet-wide predates this field, and without a default every one of
    /// those fails to deserialize the moment a monitor rolls this type.
    #[serde(default)]
    pub authority: ParkAuthority,
    /// Freeform human-readable reason (e.g. why the machine was banned).
    /// What lets "banned" be told apart from "parked for maintenance" —
    /// `parked` alone is a blunt instrument, since it currently suppresses
    /// issuance for every role regardless of intent.
    ///
    /// `#[serde(default)]` is load-bearing for the same reason as
    /// `authority`: every fact already gossiped fleet-wide predates this
    /// field, and without a default every one of those fails to
    /// deserialize the moment a monitor rolls this type.
    #[serde(default)]
    pub reason: String,
    /// Signature over the signing preimage, hex — Ed25519 for an
    /// operator-authority fact, or a FROST group aggregate for a
    /// quorum-authority one, which verifies as an ordinary Ed25519
    /// signature over the same preimage (see `SignedQuorumEvent::sig_hex`'s
    /// doc for why no branch is needed for which kind of key produced it).
    /// The field name predates the authority split and is kept as-is for
    /// wire compatibility.
    ///
    /// Without this the record is worthless: a monitor accepting an
    /// unsigned park fact would let anyone who can gossip take any machine
    /// out of service (or silently re-enable a fenced-off one) fleet-wide.
    pub operator_sig_hex: String,
}

impl MachineParkFact {
    /// V1 signing preimage — never a hash of JSON. Kept exactly as before;
    /// legacy rows still in flight were signed against this and must keep
    /// verifying. See [`Self::verify`] for the narrow fallback that uses it.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(MACHINE_PARK_SIG_LABEL.len() + 64);
        p.extend_from_slice(MACHINE_PARK_SIG_LABEL);
        push_lp(&mut p, self.machine_id.as_bytes());
        p.push(u8::from(self.disabled));
        p.extend_from_slice(&self.updated_at_ms.to_le_bytes());
        p
    }

    /// V2 signing preimage: everything [`Self::signing_bytes`] covers, plus
    /// `authority` and `reason`. Written standalone rather than extending
    /// the V1 helper, so the two preimages can never drift into sharing
    /// bytes beyond the point where their domain labels already diverge.
    ///
    /// Authority is encoded as one discriminant byte (`0` = Operator, `1` =
    /// Quorum) followed by `charter_epoch` LE for the Quorum case only — an
    /// Operator-authority fact and a Quorum-authority one can never produce
    /// the same preimage, whatever `charter_epoch` is substituted.
    fn signing_bytes_v2(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(MACHINE_PARK_SIG_LABEL_V2.len() + 96);
        p.extend_from_slice(MACHINE_PARK_SIG_LABEL_V2);
        push_lp(&mut p, self.machine_id.as_bytes());
        p.push(u8::from(self.disabled));
        p.extend_from_slice(&self.updated_at_ms.to_le_bytes());
        match self.authority {
            ParkAuthority::Operator => p.push(0),
            ParkAuthority::Quorum { charter_epoch } => {
                p.push(1);
                p.extend_from_slice(&charter_epoch.to_le_bytes());
            }
        }
        push_lp(&mut p, self.reason.as_bytes());
        p
    }

    /// Assert a machine's disabled/enabled state, signed under the V2
    /// preimage — every freshly-minted fact carries `authority` and
    /// `reason` from construction on; only rows already on the wire before
    /// S5.1 are V1.
    ///
    /// `key` is the operator's key for [`ParkAuthority::Operator`], or the
    /// FROST group's aggregate for [`ParkAuthority::Quorum`] — a threshold
    /// signature verifies as an ordinary Ed25519 signature over this same
    /// preimage, so this function needs no branch for which kind of key it
    /// was handed.
    #[must_use]
    pub fn sign_new(
        machine_id: impl Into<String>,
        disabled: bool,
        updated_at_ms: u64,
        authority: ParkAuthority,
        reason: impl Into<String>,
        key: &SigningKey,
    ) -> Self {
        let mut me = Self {
            machine_id: machine_id.into(),
            disabled,
            updated_at_ms,
            authority,
            reason: reason.into(),
            operator_sig_hex: String::new(),
        };
        let sig = key.sign(&me.signing_bytes_v2());
        me.operator_sig_hex = hex::encode(sig.to_bytes());
        me
    }

    /// Verify this fact's signature against the trust anchor its
    /// `authority` names.
    ///
    /// `operator_pubkey` is the pinned operator key, the sole anchor for
    /// [`ParkAuthority::Operator`]. `group_key_for_epoch` resolves a
    /// charter epoch to that epoch's FROST group verifying key for
    /// [`ParkAuthority::Quorum`]; returning `None` means "no charter held
    /// for that epoch", which is a rejection, never a fallback to the
    /// operator key — silently swapping the trust anchor is how a verifier
    /// stops meaning anything, the same rule `SignedQuorumEvent::verify`
    /// enforces for quorum events. Callers with no charter pass `|_| None`
    /// explicitly rather than reaching for a convenience wrapper, so the
    /// absence of a trust anchor stays visible at the call site.
    ///
    /// Tries the V2 preimage first (covers `authority` and `reason`). Falls
    /// back to the V1 preimage **only** when the fact is byte-identical to
    /// what V1 could ever produce — `authority == Operator` and `reason`
    /// empty. That narrowness is load-bearing: the V1 preimage does not
    /// cover `authority` or `reason` at all, so a fact carrying either could
    /// be relabelled after the fact (a real reason attached, or authority
    /// switched to `Quorum`) without invalidating an old V1 signature if the
    /// fallback were any wider. Legacy rows already in flight are exactly
    /// the byte-identical case, so they keep verifying without a re-sign;
    /// nothing else is let through this door.
    ///
    /// Returns `false` on any decoding failure (malformed hex, wrong
    /// signature length) or a genuine signature mismatch — callers only
    /// need a boolean accept/reject, never a reason.
    #[must_use]
    pub fn verify(
        &self,
        operator_pubkey: &VerifyingKey,
        group_key_for_epoch: impl Fn(u64) -> Option<VerifyingKey>,
    ) -> bool {
        let Ok(raw_sig) = hex::decode(&self.operator_sig_hex) else {
            return false;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(raw_sig) else {
            return false;
        };
        let sig = Signature::from_bytes(&sig_arr);

        let v2_anchor = match self.authority {
            ParkAuthority::Operator => Some(*operator_pubkey),
            ParkAuthority::Quorum { charter_epoch } => group_key_for_epoch(charter_epoch),
        };
        if let Some(key) = v2_anchor {
            if key.verify(&self.signing_bytes_v2(), &sig).is_ok() {
                return true;
            }
        }

        // Narrow V1 fallback — see the doc above for why this exact guard.
        self.authority == ParkAuthority::Operator
            && self.reason.is_empty()
            && operator_pubkey.verify(&self.signing_bytes(), &sig).is_ok()
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The applier's verdict for one incoming [`MachineParkFact`] against
/// whatever a monitor currently holds for the same `machine_id`.
///
/// Pure: no I/O, no clock, no signature check — same shape as
/// `operator-box`'s `quorum_restart_verdict`
/// (`mirage2operator/crates/operator-box/src/warden_restart.rs`), for the
/// same reason: the decision is cheap to test in isolation, and the caller
/// supplies everything it needs. `incoming` must already have passed
/// [`MachineParkFact::verify`] before this is called — this function makes
/// no attempt to authenticate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParkApply {
    /// Store `incoming`, replacing whatever is held (or nothing, if this is
    /// the first record for the machine).
    Accept,
    /// `incoming.updated_at_ms` is not strictly greater than what is held.
    /// Discard it — the ordinary LWW rule.
    RejectStale,
    /// `incoming` is newer but its authority is not allowed to touch what
    /// is held. The `&'static str` names which rule fired, for logging.
    RejectAuthority(&'static str),
}

/// Decide whether `incoming` may replace `current` for one machine.
///
/// Rules, in order:
///
/// 1. **LWW.** `incoming.updated_at_ms <= current.updated_at_ms` →
///    [`ParkApply::RejectStale`]. Strictly-greater, not greater-or-equal —
///    preserves the strict rule already enforced at the monitor
///    (`MeshState::apply_machine_park`): a replay at the same millisecond
///    must never masquerade as the record of record.
/// 2. **A standing operator ban is the operator's alone.** If `current` is
///    an operator ban (`current.disabled && current.authority ==
///    Operator`) and `incoming.authority` is `Quorum { .. }`, reject —
///    regardless of what `incoming.disabled` says.
///
///    This is deliberately BROADER than "a quorum row may not clear an
///    operator row". Narrowing it to `incoming.disabled == false` would
///    leave a laundering path open: the quorum overwrites the operator's
///    ban with a quorum-authority ban (still `disabled == true`, so the
///    overwrite reads as harmless on its own), then lifts its OWN row on a
///    later tick — arriving at "not banned" without any single step ever
///    looking like a quorum row clearing an operator row. Rejecting the
///    overwrite itself, not just the eventual lift, closes that path at its
///    first move.
/// 3. **Otherwise, accept.** The quorum may ban a machine the operator has
///    not banned — including one the operator previously un-banned, which
///    is not a standing operator *ban* and so does not trigger rule 2; the
///    operator may replace or lift anything, including a standing quorum
///    ban; and the quorum may replace its own standing ban.
#[must_use]
pub fn park_apply_verdict(
    current: Option<&MachineParkFact>,
    incoming: &MachineParkFact,
) -> ParkApply {
    if let Some(cur) = current {
        if incoming.updated_at_ms <= cur.updated_at_ms {
            return ParkApply::RejectStale;
        }
        if cur.disabled
            && cur.authority == ParkAuthority::Operator
            && matches!(incoming.authority, ParkAuthority::Quorum { .. })
        {
            return ParkApply::RejectAuthority(
                "a quorum-authority row may not touch a standing operator ban, \
                 not even to replace it with another ban",
            );
        }
    }
    ParkApply::Accept
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const NOW: u64 = 1_800_000_000_000;

    /// A [`MachineParkFact`] with no real signature, for exercising
    /// [`park_apply_verdict`] — which never inspects `operator_sig_hex` —
    /// without the overhead of a real key.
    fn unsigned_fact(disabled: bool, updated_at_ms: u64, authority: ParkAuthority) -> MachineParkFact {
        MachineParkFact {
            machine_id: "ch-example-203.0.113.40".to_string(),
            disabled,
            updated_at_ms,
            authority,
            reason: String::new(),
            operator_sig_hex: String::new(),
        }
    }

    // ── sign / verify (V2) ──────────────────────────────────────────

    #[test]
    fn a_park_fact_verifies_under_the_operator_key() {
        let operator = SigningKey::generate(&mut OsRng);
        let f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "",
            &operator,
        );
        assert!(f.verify(&operator.verifying_key(), |_| None));
    }

    #[test]
    fn v2_round_trip_with_a_reason_verifies() {
        let operator = SigningKey::generate(&mut OsRng);
        let f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "compromised -- see ticket #42",
            &operator,
        );
        assert!(f.verify(&operator.verifying_key(), |_| None));
        assert_eq!(f.reason, "compromised -- see ticket #42");
    }

    #[test]
    fn a_quorum_authority_fact_verifies_against_the_resolved_group_key() {
        let operator = SigningKey::generate(&mut OsRng);
        let group = SigningKey::generate(&mut OsRng);
        let group_pub = group.verifying_key();
        let f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Quorum { charter_epoch: 3 },
            "corroborated by 3+ peers",
            &group,
        );
        assert!(f.verify(&operator.verifying_key(), |epoch| (epoch == 3).then_some(group_pub)));
    }

    /// A verifier with no charter for the claimed epoch must not silently
    /// accept a quorum-authority row -- the whole point of the resolver
    /// returning `Option` instead of the caller supplying a single fixed
    /// key.
    #[test]
    fn a_quorum_authority_fact_fails_when_the_resolver_has_no_charter() {
        let operator = SigningKey::generate(&mut OsRng);
        let group = SigningKey::generate(&mut OsRng);
        let f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Quorum { charter_epoch: 3 },
            "corroborated",
            &group,
        );
        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    /// Distinct from the "no charter" case above: the resolver DOES answer
    /// for this epoch, but with the wrong key. Ordinary signature-mismatch
    /// behaviour, checked explicitly because this anchor used to be a
    /// single fixed key and is now a caller-supplied function.
    #[test]
    fn a_quorum_authority_fact_fails_against_the_wrong_resolved_key() {
        let operator = SigningKey::generate(&mut OsRng);
        let group = SigningKey::generate(&mut OsRng);
        let impostor = SigningKey::generate(&mut OsRng);
        let impostor_pub = impostor.verifying_key();
        let f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Quorum { charter_epoch: 3 },
            "",
            &group,
        );
        assert!(!f.verify(&operator.verifying_key(), |epoch| (epoch == 3).then_some(impostor_pub)));
    }

    // ── V1 legacy fallback ──────────────────────────────────────────

    /// A fact signed before `authority`/`reason` existed -- byte-identical
    /// to what V1 could ever produce (`Operator`, empty `reason`) -- must
    /// keep verifying without a re-sign. Hand-built rather than via
    /// `sign_new` (which always signs V2 now) to reproduce exactly what is
    /// still in flight on the wire.
    #[test]
    fn a_legacy_v1_signed_fact_still_verifies() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let sig = operator.sign(&f.signing_bytes());
        f.operator_sig_hex = hex::encode(sig.to_bytes());

        assert!(f.verify(&operator.verifying_key(), |_| None));
    }

    /// The narrow-fallback guard, part 1: a fact carrying a real reason
    /// must NOT authenticate under a V1 signature -- the V1 preimage does
    /// not cover `reason`, so accepting this would let a reason be attached
    /// to an old signature without invalidating it.
    #[test]
    fn a_reason_attached_to_a_v1_signature_does_not_verify() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let sig = operator.sign(&f.signing_bytes()); // V1 preimage: no reason
        f.operator_sig_hex = hex::encode(sig.to_bytes());
        f.reason = "attached after signing".to_string();

        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    /// The narrow-fallback guard, part 2: relabelling a V1-signed fact as
    /// quorum-authority must not authenticate either -- the V1 preimage
    /// does not cover `authority`, the same laundering attempt as the
    /// reason case above, aimed at the other new field.
    #[test]
    fn quorum_authority_attached_to_a_v1_signature_does_not_verify() {
        let operator = SigningKey::generate(&mut OsRng);
        let group = SigningKey::generate(&mut OsRng);
        let group_pub = group.verifying_key();
        let mut f = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let sig = operator.sign(&f.signing_bytes()); // V1 preimage: no authority
        f.operator_sig_hex = hex::encode(sig.to_bytes());
        f.authority = ParkAuthority::Quorum { charter_epoch: 1 };

        assert!(!f.verify(&operator.verifying_key(), |epoch| (epoch == 1).then_some(group_pub)));
    }

    // ── tampering ────────────────────────────────────────────────────

    /// A park fact a monitor accepts unsigned (or under the wrong key) lets
    /// anyone who can gossip take a machine out of service, or silently
    /// re-enable one the operator fenced off.
    #[test]
    fn a_tampered_disabled_flag_is_refused() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "",
            &operator,
        );
        f.disabled = false; // flip after signing
        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    #[test]
    fn a_foreign_signature_is_refused() {
        let operator = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "",
            &attacker,
        );
        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    #[test]
    fn machine_id_is_bound_into_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "",
            &operator,
        );
        f.machine_id = "ru-hostkey-203.0.113.10".to_string();
        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    #[test]
    fn updated_at_ms_is_bound_into_the_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "",
            &operator,
        );
        f.updated_at_ms = NOW + 1;
        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    #[test]
    fn tampering_with_the_reason_breaks_a_v2_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "original reason",
            &operator,
        );
        f.reason = "different reason".to_string();
        assert!(!f.verify(&operator.verifying_key(), |_| None));
    }

    /// Tampering with `authority` -- e.g. escalating an Operator-signed
    /// fact to Quorum -- must also break the V2 signature; `authority` is
    /// inside the preimage precisely so this cannot happen.
    #[test]
    fn tampering_with_authority_breaks_a_v2_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let mut f = MachineParkFact::sign_new(
            "ch-example-203.0.113.40",
            true,
            NOW,
            ParkAuthority::Operator,
            "",
            &operator,
        );
        let operator_pub = operator.verifying_key();
        f.authority = ParkAuthority::Quorum { charter_epoch: 1 };
        assert!(!f.verify(&operator.verifying_key(), |epoch| (epoch == 1).then_some(operator_pub)));
    }

    // ── park_apply_verdict ──────────────────────────────────────────

    #[test]
    fn park_apply_accepts_the_first_record_for_a_machine() {
        let incoming = unsigned_fact(true, NOW, ParkAuthority::Operator);
        assert_eq!(park_apply_verdict(None, &incoming), ParkApply::Accept);
    }

    #[test]
    fn park_apply_rejects_a_non_newer_update() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let same_ts = unsigned_fact(false, NOW, ParkAuthority::Operator);
        let older = unsigned_fact(false, NOW - 1, ParkAuthority::Operator);
        assert_eq!(
            park_apply_verdict(Some(&current), &same_ts),
            ParkApply::RejectStale
        );
        assert_eq!(
            park_apply_verdict(Some(&current), &older),
            ParkApply::RejectStale
        );
    }

    #[test]
    fn park_apply_accepts_a_strictly_newer_same_authority_update() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let incoming = unsigned_fact(false, NOW + 1, ParkAuthority::Operator);
        assert_eq!(park_apply_verdict(Some(&current), &incoming), ParkApply::Accept);
    }

    /// The rule that matters, part 1: the quorum cannot lift a standing
    /// operator ban.
    #[test]
    fn park_apply_quorum_cannot_lift_a_standing_operator_ban() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let incoming = unsigned_fact(false, NOW + 1, ParkAuthority::Quorum { charter_epoch: 1 });
        assert!(matches!(
            park_apply_verdict(Some(&current), &incoming),
            ParkApply::RejectAuthority(_)
        ));
    }

    /// The rule that matters, part 2: the quorum cannot overwrite a
    /// standing operator ban with a quorum-authority ban either -- the
    /// laundering path this guards against is overwrite-then-self-lift, so
    /// the overwrite itself must already be refused.
    #[test]
    fn park_apply_quorum_cannot_overwrite_a_standing_operator_ban_with_a_quorum_ban() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Operator);
        let incoming = unsigned_fact(true, NOW + 1, ParkAuthority::Quorum { charter_epoch: 1 });
        assert!(matches!(
            park_apply_verdict(Some(&current), &incoming),
            ParkApply::RejectAuthority(_)
        ));
    }

    #[test]
    fn park_apply_quorum_may_ban_a_machine_the_operator_has_not_banned() {
        let current = unsigned_fact(false, NOW, ParkAuthority::Operator);
        let incoming = unsigned_fact(true, NOW + 1, ParkAuthority::Quorum { charter_epoch: 1 });
        assert_eq!(park_apply_verdict(Some(&current), &incoming), ParkApply::Accept);
    }

    #[test]
    fn park_apply_quorum_may_ban_a_machine_with_no_prior_record() {
        let incoming = unsigned_fact(true, NOW, ParkAuthority::Quorum { charter_epoch: 1 });
        assert_eq!(park_apply_verdict(None, &incoming), ParkApply::Accept);
    }

    #[test]
    fn park_apply_operator_may_lift_a_standing_quorum_ban() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Quorum { charter_epoch: 1 });
        let incoming = unsigned_fact(false, NOW + 1, ParkAuthority::Operator);
        assert_eq!(park_apply_verdict(Some(&current), &incoming), ParkApply::Accept);
    }

    #[test]
    fn park_apply_operator_may_replace_a_standing_quorum_ban_with_an_operator_ban() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Quorum { charter_epoch: 1 });
        let incoming = unsigned_fact(true, NOW + 1, ParkAuthority::Operator);
        assert_eq!(park_apply_verdict(Some(&current), &incoming), ParkApply::Accept);
    }

    #[test]
    fn park_apply_quorum_may_replace_its_own_standing_ban() {
        let current = unsigned_fact(true, NOW, ParkAuthority::Quorum { charter_epoch: 1 });
        let incoming = unsigned_fact(false, NOW + 1, ParkAuthority::Quorum { charter_epoch: 2 });
        assert_eq!(park_apply_verdict(Some(&current), &incoming), ParkApply::Accept);
    }

    // ── serde backward-compat ───────────────────────────────────────

    /// The JSON shape every fact already gossiped fleet-wide has -- no
    /// `authority`, no `reason`. This must keep deserializing after the
    /// rollout, with `authority: Operator` and `reason: ""`, or every
    /// monitor holding old gossip fails to load it the moment it rolls.
    #[test]
    fn the_old_four_field_shape_deserializes_with_defaults() {
        let json = r#"{
            "machine_id": "ch-example-203.0.113.40",
            "disabled": true,
            "updated_at_ms": 1800000000000,
            "operator_sig_hex": "aa"
        }"#;
        let f: MachineParkFact =
            serde_json::from_str(json).expect("legacy 4-field shape must still deserialize");
        assert_eq!(f.authority, ParkAuthority::Operator);
        assert_eq!(f.reason, "");
    }
}
