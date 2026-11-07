//! Quorum log — the append-only record of who the mesh has admitted.
//!
//! ## What this is for
//!
//! Under capsule-only, a rebooted box holds nothing at rest and cannot become
//! operational until someone seals it a capsule. Today that someone is opbox,
//! and only opbox: measured on 2026-07-26, four `ssh connect timeout`s to a
//! single box inside 90 minutes plus one dead session that zeroed an entire
//! reconcile sweep. The A-roll's reboot gate passed *because opbox happened to
//! be up*.
//!
//! This module carries the records that let `t`-of-`n` monitors take over that
//! job when the operator is absent. It is deliberately only the **record** —
//! the typed, signed, replay-resistant statements about identity. Producing a
//! threshold signature is a separate concern ([`crate::capsule`] already
//! verifies one), and enforcing rate limits is the applier's job, not the
//! type's.
//!
//! ## Why the events are split by signer
//!
//! Two authorities, and the split is the whole security story:
//!
//! - **The quorum** signs availability: [`IdentityAdmitted`] and
//!   [`IdentityRotated`]. These are what let a box come back without a human.
//!   Their worst failure is admitting something that should not have been
//!   admitted — bounded by the applier's rate limit and by the operator's
//!   ability to tombstone after the fact.
//! - **The operator** signs policy: [`RecoveryForbidden`]. A quorum must never
//!   be able to grant itself permission to recover a box the operator has
//!   fenced off, so this one is verified against the pinned operator key and
//!   nothing else.
//!
//! Membership itself is not an event here. [`crate::capsule::GroupCharter`] is
//! already an operator-signed, epoch-monotonic record of `(group key, threshold,
//! members)`, and duplicating that into a second signed statement would create
//! two sources of truth for the same fact. A membership change *is* a charter
//! with a higher epoch.
//!
//! ## Replay resistance
//!
//! Every event carries a per-subject `seq`, where a subject is
//! `(mesh_id, machine_id)`. An applier accepts an event only if its `seq`
//! is strictly greater than the highest it has accepted for that subject
//! ([`SubjectSeq`]). Per-subject rather than global because gossip gives no
//! total order — a global counter would need consensus on the counter itself,
//! which is the problem this is supposed to solve, not a prerequisite for it.
//!
//! **Machine-keyed, not `(machine, role)`-keyed.** Admission is a property of
//! the box now, not of one service on it — see
//! `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §5. A
//! `Subject` used to carry a `role` and gate 5 counted eight attempts an
//! hour per box by accident; collapsing to one subject per machine is what
//! makes "one admission per machine reset" true at the type level instead of
//! by convention.
//!
//! Signing preimages follow the house rule: a fixed domain label, then
//! length-prefixed fields, never a hash of serialised JSON. Two events that
//! differ in any field must differ in their preimage, and no field boundary may
//! be ambiguous — the same reason
//! [`crate::capsule::GroupCharter`] count-prefixes its member list.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use crate::identity::RolePublicKeys;
use crate::ids::{MachineId, MeshId};

/// Domain label for an admission. Distinct per event type so a signature over
/// one can never be replayed as a signature over another, even if the field
/// layouts were to converge.
const ADMITTED_SIG_LABEL: &[u8] = b"MIRAGE-QUORUM-IDENTITY-ADMITTED-V1";
/// Bumped V1 -> V2 the day `IdentityRotated` stopped carrying two untagged
/// key sets and started carrying one role-tagged set (`new_role_keys`) — a
/// different field layout must sign under a different label, the same rule
/// this constant's own doc states and the one `ATTEST_SIG_LABEL_V3` already
/// follows for the identical reason. No fallback to V1: this label change
/// rides the same hard cutover as the rest of the machine-identity arc (see
/// `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §7).
const ROTATED_SIG_LABEL: &[u8] = b"MIRAGE-QUORUM-IDENTITY-ROTATED-V2";
const FORBIDDEN_SIG_LABEL: &[u8] = b"MIRAGE-OPERATOR-RECOVERY-FORBIDDEN-V1";

#[derive(Debug, Error)]
pub enum QuorumError {
    #[error("malformed quorum event field: {0}")]
    Malformed(String),
    #[error("quorum event signature invalid")]
    SigInvalid,
    #[error("event is quorum-signed but no charter for epoch {0} is held")]
    NoCharter(u64),
    #[error("stale event: seq {got} is not greater than the accepted {have} for this subject")]
    StaleSeq { got: u64, have: u64 },
    #[error("event is for mesh {got}, this mesh is {want}")]
    WrongMesh { got: String, want: String },
    #[error("unattended recovery is forbidden for machine {0}")]
    RecoveryForbidden(String),
    #[error("rotation retires key set [{want}] but the held identity is [{have}]")]
    RotationChain { have: String, want: String },
}

/// The `(mesh, machine)` pair an event speaks about.
///
/// Carried as its own type because it is both the replay-protection key and the
/// natural unit of the operator's `RecoveryForbidden` policy, and because
/// getting the two in the wrong order in a preimage is exactly the class of
/// bug length-prefixing exists to make impossible.
///
/// **No `role`.** Identity belongs to the machine, not to a service on it —
/// see the module doc's "Replay resistance" section. A quorum event now
/// speaks about the whole box.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject {
    pub mesh_id: MeshId,
    pub machine_id: MachineId,
}

impl Subject {
    /// Total order over subjects, for callers that must hash or list a subject
    /// map deterministically. Allocates; the caller is iterating a fleet-sized
    /// map a few times a minute, not a hot path.
    #[must_use]
    pub fn sort_key(&self) -> (String, String) {
        (
            self.mesh_id.as_str().to_string(),
            self.machine_id.as_str().to_string(),
        )
    }

    /// Length-prefixed contribution to any event preimage. Shared by all three
    /// event types so the subject can never be encoded two different ways.
    fn push_into(&self, p: &mut Vec<u8>) {
        push_lp(p, self.mesh_id.as_str().as_bytes());
        push_lp(p, self.machine_id.as_str().as_bytes());
    }
}

/// Highest accepted `seq` per subject — the applier's replay state.
///
/// Deliberately a plain map rather than anything persistent: under capsule-only
/// this is RAM state rebuilt from the gossiped log, exactly like `peer_health`
/// and the other RAM-first tables. Persisting it would put a consensus artefact
/// at rest for no benefit — the log itself is the durable record.
#[derive(Debug, Default)]
pub struct SubjectSeq(HashMap<Subject, u64>);

impl SubjectSeq {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Highest `seq` accepted so far for this subject, or 0 if never seen.
    #[must_use]
    pub fn highest(&self, subject: &Subject) -> u64 {
        self.0.get(subject).copied().unwrap_or(0)
    }

    /// Check-and-record. Returns `Err` without mutating when the event is not
    /// strictly newer, so a caller that ignores the error cannot accidentally
    /// advance the watermark on a rejected event.
    pub fn accept(&mut self, subject: &Subject, seq: u64) -> Result<(), QuorumError> {
        let have = self.highest(subject);
        if seq <= have {
            return Err(QuorumError::StaleSeq { got: seq, have });
        }
        self.0.insert(subject.clone(), seq);
        Ok(())
    }
}

/// A `(machine, role)` admitted to the mesh under a fresh identity.
///
/// Quorum-signed. This is the event that replaces "the operator looked at the
/// escrow and decided": `t`-of-`n` monitors agreed the announce is genuine and
/// minted a name for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAdmitted {
    pub subject: Subject,
    /// The name the mesh now knows this `(machine, role)` by.
    pub self_id: Uuid,
    /// X25519 wire public key, hex.
    pub wire_pubkey_hex: String,
    /// Ed25519 fact-signing public key, hex. `None` for roles that sign no
    /// facts — the same split `RoleSlice::signing_privkey` already makes.
    pub signing_pubkey_hex: Option<String>,
    /// Charter epoch whose group key signed this. The verifier needs it to pick
    /// the right key, and it pins the event to one membership generation.
    pub charter_epoch: u64,
    /// Per-subject monotonic counter. See the module doc.
    pub seq: u64,
    pub issued_at_ms: u64,
}

/// An existing `self_id` continues under new key material.
///
/// The design decision this type encodes: after an unattended reboot the mesh
/// **rotates keys and keeps the name**, rather than reconstructing the old
/// private key. Reconstruction would require secret-sharing every box's
/// long-term key across seven internet-facing machines, so capturing `t` of them
/// would yield the whole fleet's key material — strictly worse than the single
/// escrow it would replace. Rotation shares no long-term secret with anyone.
///
/// Keeping `self_id` stable is what makes it cheap: `self_id` is a UUID, not a
/// secret, and `peer_table` / `peer_registry` / chain bindings are all keyed on
/// it. Only the public keys move.
///
/// **Machine-scoped SET, role-TAGGED.** `Subject` lost `role` in the same
/// stage this type's own fields did — a rotation now names the whole box's
/// slice set at once, never one role's key at a time. The set used to carry
/// no role tag at all (the quorum authorized WHICH keys were now this
/// machine's, but nothing on the wire said which role each belonged to),
/// and that was a specification error, not a simplification: every box in
/// this fleet runs eight roles, so the first unattended rotation of any real
/// machine left `mesh_state::resolved_identity_by_str` unable to tell which
/// of eight untagged keys served the role a peer was trying to dial — an
/// honest miss for every caller, fleet-wide, on the exact class of failure
/// (a peer unable to resolve or dial a rebooted box) this arc exists to
/// remove. Tagging each entry with [`RolePublicKeys`] — the same type
/// [`crate::identity::DeclaredIdentity::role_keys`] already uses for
/// exactly this shape, "one role's wire + signing public keys" — closes
/// that gap at the type level: a resolver asks for a role directly instead
/// of hoping the set happens to hold exactly one key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRotated {
    pub subject: Subject,
    pub self_id: Uuid,
    /// The wire pubkey SET being retired — every slice's own key, from
    /// before this rotation. Carried so an applier can reject a rotation
    /// that does not chain from what it currently holds, which turns a lost
    /// or reordered event into a visible error instead of a silent
    /// overwrite. Order carries no meaning: see [`QuorumEvent::signing_bytes`]
    /// for why the preimage sorts it regardless of how this `Vec` was built.
    ///
    /// **Deliberately left untagged, unlike [`Self::new_role_keys`] below.**
    /// The only question this field ever answers is "was this key set the
    /// previous one" (`QuorumLog::apply_verified`'s chain check, via
    /// `same_pubkey_set` — order-independent SET equality against whatever
    /// the applier currently holds) and "resolve this role's currently
    /// effective key so it can be named here"
    /// (`mirage2monitor::unattended_issuance`, one `resolved_identity_by_str`
    /// call per role, folded into a plain `Vec<String>`). Neither caller
    /// ever needs to know which retired key belonged to which role — chaining
    /// only cares that the SET matches, and the mint path already resolved
    /// each entry's role before flattening it into this field. Tagging it
    /// too would add a field nothing reads.
    pub prev_wire_pubkeys: Vec<String>,
    /// The key material this rotation authorizes — the machine's entire
    /// slice set going forward, one [`RolePublicKeys`] entry per role the
    /// box runs, unordered. Each entry names the role it belongs to, so a
    /// resolver can pick out ONE role's key directly instead of asking
    /// whether the whole set happens to hold exactly one — see this type's
    /// own doc for the fleet-wide resolution failure the untagged shape
    /// caused.
    pub new_role_keys: Vec<RolePublicKeys>,
    pub charter_epoch: u64,
    pub seq: u64,
    pub issued_at_ms: u64,
}

/// Operator policy: this machine may not be recovered without a human.
///
/// **Operator-signed, never quorum-signed.** A quorum that could sign this could
/// also un-sign it, which would make the operator's veto advisory. Verified
/// against the pinned operator key and nothing else — see
/// [`SignedQuorumEvent::verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryForbidden {
    pub subject: Subject,
    /// `true` fences the machine off; `false` lifts it. Both directions are
    /// recorded rather than implying "absence means allowed", so the log states
    /// the policy explicitly at every point in time.
    pub forbidden: bool,
    pub seq: u64,
    pub issued_at_ms: u64,
}

/// Which key signed an event, and therefore which key verifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSigner {
    /// The pinned operator key. The only acceptable signer for policy.
    Operator,
    /// The FROST group key named by the charter at this epoch.
    Quorum { charter_epoch: u64 },
}

/// The payload of a signed log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuorumEvent {
    IdentityAdmitted(IdentityAdmitted),
    IdentityRotated(IdentityRotated),
    RecoveryForbidden(RecoveryForbidden),
}

impl QuorumEvent {
    #[must_use]
    pub fn subject(&self) -> &Subject {
        match self {
            Self::IdentityAdmitted(e) => &e.subject,
            Self::IdentityRotated(e) => &e.subject,
            Self::RecoveryForbidden(e) => &e.subject,
        }
    }

    #[must_use]
    pub fn seq(&self) -> u64 {
        match self {
            Self::IdentityAdmitted(e) => e.seq,
            Self::IdentityRotated(e) => e.seq,
            Self::RecoveryForbidden(e) => e.seq,
        }
    }

    /// When the issuer says it signed this. Signed, so it cannot be edited in
    /// flight — but it is a claim by the issuer, not a mesh-agreed time, and
    /// ordering is [`Self::seq`], never this.
    #[must_use]
    pub fn issued_at_ms(&self) -> u64 {
        match self {
            Self::IdentityAdmitted(e) => e.issued_at_ms,
            Self::IdentityRotated(e) => e.issued_at_ms,
            Self::RecoveryForbidden(e) => e.issued_at_ms,
        }
    }

    /// Who is *allowed* to have signed this event.
    ///
    /// Note this is a property of the event **type**, not of the wire data — an
    /// attacker cannot turn a policy event into a quorum-signable one by
    /// changing a field, because the check in [`SignedQuorumEvent::verify`]
    /// compares the claimed signer against this.
    #[must_use]
    pub fn required_signer_is_operator(&self) -> bool {
        matches!(self, Self::RecoveryForbidden(_))
    }

    /// Fixed, length-prefixed signing preimage. Never a hash of JSON.
    ///
    /// **Public.** An external threshold-signing coordinator (today:
    /// `mirage2monitor`'s event-sign ceremony, `quorum_event_sign_api.rs`)
    /// has to build the exact bytes every FROST member will independently
    /// recompute and compare its own reconstruction against — that member
    /// check is what keeps a coordinator from being able to make members
    /// sign whatever it hands them (see that module's "Why this module
    /// hand-copies a preimage"). Before this was `pub`, the only way to get
    /// those bytes from outside this crate was a hand-copied duplicate of
    /// this exact function, which is a liveness hazard: a drift between the
    /// copy and this one stops the ceremony working (callers still verify
    /// correctly either way, since a member's own accept check re-derives a
    /// signature through the real, public `SignedQuorumEvent::sign` rather
    /// than trusting the copy) but serves no purpose once the real function
    /// can simply be called.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(256);
        match self {
            Self::IdentityAdmitted(e) => {
                p.extend_from_slice(ADMITTED_SIG_LABEL);
                e.subject.push_into(&mut p);
                push_lp(&mut p, e.self_id.as_bytes());
                push_lp(&mut p, e.wire_pubkey_hex.as_bytes());
                // Presence is part of the preimage: a `None` and an empty
                // string must not produce the same bytes, or a signing key
                // could be stripped without breaking the signature.
                push_opt_lp(&mut p, e.signing_pubkey_hex.as_deref());
                p.extend_from_slice(&e.charter_epoch.to_le_bytes());
                p.extend_from_slice(&e.seq.to_le_bytes());
                p.extend_from_slice(&e.issued_at_ms.to_le_bytes());
            }
            Self::IdentityRotated(e) => {
                p.extend_from_slice(ROTATED_SIG_LABEL);
                e.subject.push_into(&mut p);
                push_lp(&mut p, e.self_id.as_bytes());
                push_pubkey_set(&mut p, &e.prev_wire_pubkeys);
                push_role_keys(&mut p, &e.new_role_keys);
                p.extend_from_slice(&e.charter_epoch.to_le_bytes());
                p.extend_from_slice(&e.seq.to_le_bytes());
                p.extend_from_slice(&e.issued_at_ms.to_le_bytes());
            }
            Self::RecoveryForbidden(e) => {
                p.extend_from_slice(FORBIDDEN_SIG_LABEL);
                e.subject.push_into(&mut p);
                p.push(u8::from(e.forbidden));
                p.extend_from_slice(&e.seq.to_le_bytes());
                p.extend_from_slice(&e.issued_at_ms.to_le_bytes());
            }
        }
        p
    }
}

/// A log entry as it travels over gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedQuorumEvent {
    pub event: QuorumEvent,
    pub signer: EventSigner,
    /// Ed25519 signature over [`QuorumEvent::signing_bytes`], hex. A FROST
    /// threshold signature verifies here as an ordinary Ed25519 signature,
    /// which is why this needs no FROST-specific branch.
    pub sig_hex: String,
}

impl SignedQuorumEvent {
    /// Sign with a single key. Used by the operator for policy events, and by
    /// tests; the quorum path aggregates signature shares and constructs this
    /// struct directly.
    #[must_use]
    pub fn sign(event: QuorumEvent, signer: EventSigner, key: &SigningKey) -> Self {
        let sig = key.sign(&event.signing_bytes());
        Self {
            event,
            signer,
            sig_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify signature, signer class, and mesh.
    ///
    /// `charter_group_key` resolves a charter epoch to its group verifying key;
    /// returning `None` means "no charter held for that epoch", which is a
    /// rejection rather than a fallback to the operator key — silently
    /// downgrading to a different trust anchor is how a verifier stops meaning
    /// anything.
    ///
    /// Deliberately does **not** check `seq`: that needs the applier's
    /// [`SubjectSeq`], and folding it in here would let a caller believe a
    /// signature check alone made an event safe to apply.
    pub fn verify(
        &self,
        expected_mesh: &MeshId,
        operator_key: &VerifyingKey,
        charter_group_key: impl Fn(u64) -> Option<VerifyingKey>,
    ) -> Result<(), QuorumError> {
        let subject = self.event.subject();
        if subject.mesh_id.as_str() != expected_mesh.as_str() {
            return Err(QuorumError::WrongMesh {
                got: subject.mesh_id.as_str().to_string(),
                want: expected_mesh.as_str().to_string(),
            });
        }

        // The signer class is fixed by the event type. A quorum cannot sign
        // policy, and the operator signing an availability event is accepted
        // (genesis and manual recovery are still the operator's to perform).
        if self.event.required_signer_is_operator() && self.signer != EventSigner::Operator {
            return Err(QuorumError::Malformed(
                "policy event must be operator-signed".to_string(),
            ));
        }

        let key = match self.signer {
            EventSigner::Operator => *operator_key,
            EventSigner::Quorum { charter_epoch } => {
                charter_group_key(charter_epoch).ok_or(QuorumError::NoCharter(charter_epoch))?
            }
        };

        let raw = hex::decode(&self.sig_hex)
            .map_err(|e| QuorumError::Malformed(format!("sig not hex: {e}")))?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| QuorumError::Malformed("sig is not 64 bytes".to_string()))?;
        key.verify(&self.event.signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| QuorumError::SigInvalid)
    }
}

/// Everything the mesh knows about one subject, as signed evidence.
///
/// **Two anchors, not a history.** Per subject the state is fully described by
/// the latest identity event (which keys are live) and the latest policy event
/// (whether unattended recovery is permitted) — the latter because
/// [`RecoveryForbidden::forbidden`] records both directions explicitly instead
/// of treating absence as permission. Nothing older changes either answer.
///
/// This is deliberately **not** the bounded-ring shape used by the telemetry
/// streams (`kernel_security_events`, `scrape_test_results`). A ring cannot
/// converge on a content hash: two monitors that booted at different times hold
/// different suffixes of the same stream, so their digests differ forever and a
/// pull cannot repair it, since the pulled events are not newer than the
/// receiver's watermark. That is exactly why those tables are excluded from the
/// anti-entropy digest.
///
/// This table cannot afford that exclusion. Missing an [`IdentityRotated`] costs
/// availability — the box waits for the operator. Missing a
/// [`RecoveryForbidden`] costs custody: the monitor fails **open** and will help
/// sign an admission for a machine the operator fenced off. Only the second is
/// unacceptable, so this table must reconverge, so it must be anchor-shaped.
///
/// History is not lost — it is not the monitors' job. Monitors hold derived RAM
/// state; opbox aggregates the event stream and is the durable record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectRecord {
    /// Latest [`IdentityAdmitted`] or [`IdentityRotated`].
    pub identity: Option<SignedQuorumEvent>,
    /// Latest [`RecoveryForbidden`].
    pub policy: Option<SignedQuorumEvent>,
}

impl SubjectRecord {
    /// Replay watermark for the identity anchor.
    #[must_use]
    pub fn identity_seq(&self) -> u64 {
        self.identity.as_ref().map_or(0, |e| e.event.seq())
    }

    /// Replay watermark for the policy anchor.
    #[must_use]
    pub fn policy_seq(&self) -> u64 {
        self.policy.as_ref().map_or(0, |e| e.event.seq())
    }

    /// The newest `seq` this record holds — an audit/display view.
    ///
    /// **Not** the replay gate. The gate is per anchor
    /// ([`Self::identity_seq`] / [`Self::policy_seq`]), because a single
    /// per-subject counter shared by two independent slots is a fail-open hole
    /// on the repair path: a monitor holding an identity event at `seq` 7 that
    /// missed the policy event at `seq` 5 would pull the policy, reject it as
    /// stale against the shared counter, and stay unfenced forever — while its
    /// digest never converged, so it would pull again on every tick.
    ///
    /// Per-anchor gating loses nothing. An old identity event still cannot
    /// replace a newer identity event, an old policy still cannot replace a
    /// newer policy, and those are the two things replay protection is for.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.identity_seq().max(self.policy_seq())
    }

    /// The `self_id` this subject currently answers to, if it has been admitted.
    #[must_use]
    pub fn self_id(&self) -> Option<Uuid> {
        match self.identity.as_ref().map(|e| &e.event) {
            Some(QuorumEvent::IdentityAdmitted(a)) => Some(a.self_id),
            Some(QuorumEvent::IdentityRotated(r)) => Some(r.self_id),
            _ => None,
        }
    }

    /// The live X25519 wire public key SET, hex — one entry per role slice
    /// the machine currently runs. An `IdentityAdmitted` still names a
    /// single key (admission mints one identity at a time); an
    /// `IdentityRotated` names the machine's whole slice set directly,
    /// flattened here from its role-tagged entries. Order carries no
    /// meaning. `None` before any identity event has landed for this
    /// subject. Callers that need to resolve ONE role's key rather than
    /// this flattened set want [`Self::rotated_role_keys`] instead.
    #[must_use]
    pub fn wire_pubkeys(&self) -> Option<Vec<&str>> {
        match self.identity.as_ref().map(|e| &e.event) {
            Some(QuorumEvent::IdentityAdmitted(a)) => Some(vec![a.wire_pubkey_hex.as_str()]),
            Some(QuorumEvent::IdentityRotated(r)) => Some(
                r.new_role_keys
                    .iter()
                    .map(|rk| rk.wire_pubkey_hex.as_str())
                    .collect(),
            ),
            _ => None,
        }
    }

    /// The live Ed25519 fact-signing public key SET, hex, for roles that
    /// sign facts — parallel to [`Self::wire_pubkeys`], and empty rather
    /// than absent when nothing here signs facts.
    #[must_use]
    pub fn signing_pubkeys(&self) -> Option<Vec<&str>> {
        match self.identity.as_ref().map(|e| &e.event) {
            Some(QuorumEvent::IdentityAdmitted(a)) => {
                Some(a.signing_pubkey_hex.as_deref().into_iter().collect())
            }
            Some(QuorumEvent::IdentityRotated(r)) => Some(
                r.new_role_keys
                    .iter()
                    .filter_map(|rk| rk.signing_pubkey_hex.as_deref())
                    .collect(),
            ),
            _ => None,
        }
    }

    /// The live key material, role-TAGGED, when the latest identity event is
    /// an [`IdentityRotated`] — `None` for [`IdentityAdmitted`] (a single,
    /// role-less key — admission mints one identity at a time, before the
    /// box's other roles have anything to rotate) and before any identity
    /// event has landed. This is the accessor that lets a caller resolve
    /// ONE role's key out of a multi-role machine's rotated set directly,
    /// instead of only being able to ask "is this key anywhere in the set"
    /// ([`Self::wire_pubkeys`] / [`Self::signing_pubkeys`] above) — see
    /// [`IdentityRotated::new_role_keys`]'s own doc for the fleet-wide
    /// resolution failure the untagged shape used to cause.
    #[must_use]
    pub fn rotated_role_keys(&self) -> Option<&[RolePublicKeys]> {
        match self.identity.as_ref().map(|e| &e.event) {
            Some(QuorumEvent::IdentityRotated(r)) => Some(&r.new_role_keys),
            _ => None,
        }
    }

    /// Whether the operator has fenced this subject off from unattended
    /// recovery. Absent policy means permitted — the permissive default is
    /// deliberate and is why the fence must be gossiped reliably.
    #[must_use]
    pub fn recovery_forbidden(&self) -> bool {
        match self.policy.as_ref().map(|e| &e.event) {
            Some(QuorumEvent::RecoveryForbidden(p)) => p.forbidden,
            _ => false,
        }
    }

    /// Canonical fingerprint bytes for the anti-entropy digest.
    ///
    /// Hashes the **signed content**, never the signature. A FROST aggregate is
    /// randomised, so the quorum re-signing the same event yields different
    /// signature bytes; fingerprinting the signature would let two monitors
    /// holding the identical event disagree permanently, and no pull could
    /// repair it because the pulled event's `seq` would not exceed the
    /// receiver's watermark.
    #[must_use]
    pub fn digest_bytes(&self, subject: &Subject) -> Vec<u8> {
        let mut p = Vec::with_capacity(320);
        subject.push_into(&mut p);
        push_opt_bytes(&mut p, self.identity.as_ref().map(|e| e.event.signing_bytes()));
        push_opt_bytes(&mut p, self.policy.as_ref().map(|e| e.event.signing_bytes()));
        p
    }
}

/// The applier: replay-gated, anchor-shaped quorum state for a whole mesh.
///
/// The acceptance order from the design — verify signature, then `seq`, then
/// apply — is expressed once here rather than at every call site. There is no
/// separate watermark structure: the anchors **are** the watermark, per anchor,
/// so there is nothing to keep in step and nothing that can drift.
#[derive(Debug, Default)]
pub struct QuorumLog {
    records: HashMap<Subject, SubjectRecord>,
}

impl QuorumLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn record(&self, subject: &Subject) -> Option<&SubjectRecord> {
        self.records.get(subject)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Subject, &SubjectRecord)> {
        self.records.iter()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Apply an event whose signature has **already** been checked with
    /// [`SignedQuorumEvent::verify`].
    ///
    /// The name says `verified` because the type system cannot: an unverified
    /// event and a verified one are the same struct, so the contract has to live
    /// at the call site. Applying an unverified event admits whatever an
    /// attacker cares to gossip.
    pub fn apply_verified(&mut self, ev: SignedQuorumEvent) -> Result<(), QuorumError> {
        let subject = ev.event.subject().clone();

        // Chain check first, so a rotation that does not line up cannot burn the
        // watermark and fence out the legitimate event that follows it.
        //
        // This is a consistency guard against a lost or reordered event, not a
        // defence against forgery — anyone who can produce a valid quorum
        // signature has already won. It is skipped when no identity anchor is
        // held, because a monitor that just pulled from a peer has nothing to
        // chain from and must still be able to bootstrap.
        if let QuorumEvent::IdentityRotated(r) = &ev.event {
            if let Some(have) = self
                .records
                .get(&subject)
                .and_then(SubjectRecord::wire_pubkeys)
            {
                if !same_pubkey_set(&have, &r.prev_wire_pubkeys) {
                    return Err(QuorumError::RotationChain {
                        have: have.join(","),
                        want: r.prev_wire_pubkeys.join(","),
                    });
                }
            }
        }

        // Gate against THIS anchor's watermark, not a shared per-subject one.
        // See `SubjectRecord::seq` for why a shared counter fails open on the
        // repair path.
        let rec = self.records.entry(subject).or_default();
        let have = match &ev.event {
            QuorumEvent::IdentityAdmitted(_) | QuorumEvent::IdentityRotated(_) => rec.identity_seq(),
            QuorumEvent::RecoveryForbidden(_) => rec.policy_seq(),
        };
        let got = ev.event.seq();
        if got <= have {
            return Err(QuorumError::StaleSeq { got, have });
        }

        match &ev.event {
            QuorumEvent::IdentityAdmitted(_) | QuorumEvent::IdentityRotated(_) => {
                rec.identity = Some(ev);
            }
            QuorumEvent::RecoveryForbidden(_) => rec.policy = Some(ev),
        }
        Ok(())
    }

    /// Insert a record wholesale — for rebuilding this log from state that has
    /// already passed through it, such as the monitor's clone-on-write snapshot.
    ///
    /// Not a merge and not safe on untrusted input: it overwrites both anchors
    /// unconditionally, so feeding it a peer's record would let that peer
    /// downgrade a newer anchor. Events arriving from a peer go through
    /// [`Self::apply_verified`] one at a time, which is what enforces the
    /// per-anchor watermark.
    pub fn install_verified(&mut self, subject: Subject, record: SubjectRecord) {
        self.records.insert(subject, record);
    }
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Length-prefix an optional byte string, distinguishing absent from empty —
/// same discriminant rule as [`push_opt_lp`], for the same reason.
fn push_opt_bytes(out: &mut Vec<u8>, v: Option<Vec<u8>>) {
    match v {
        None => out.push(0),
        Some(b) => {
            out.push(1);
            push_lp(out, &b);
        }
    }
}

/// Length-prefix an optional field, distinguishing absent from empty.
///
/// `None` is a single `0` discriminant with no length; `Some("")` is a `1`
/// discriminant followed by a zero length. Without the discriminant those two
/// encode identically and an optional public key could be removed from a signed
/// event without invalidating the signature.
fn push_opt_lp(out: &mut Vec<u8>, v: Option<&str>) {
    match v {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            push_lp(out, s.as_bytes());
        }
    }
}

/// Set-equality for two hex-pubkey collections, order-independent.
///
/// Both sides of the rotation chain check are built independently — one
/// from whatever this applier currently holds, the other from the incoming
/// event's own `prev_wire_pubkeys` — and neither is guaranteed to share
/// insertion order with the other even when they name the identical set.
fn same_pubkey_set(a: &[&str], b: &[String]) -> bool {
    let mut a_sorted: Vec<&str> = a.to_vec();
    a_sorted.sort_unstable();
    let mut b_sorted: Vec<&str> = b.iter().map(String::as_str).collect();
    b_sorted.sort_unstable();
    a_sorted == b_sorted
}

/// Length-prefix a SET of hex pubkeys into the preimage, canonically sorted
/// so two encoders that assemble the same set in different insertion order
/// — say, iterating `MachineCapsule::slices` versus a `HashMap` — sign the
/// identical bytes. Count-prefixed for the same reason
/// [`crate::capsule::GroupCharter::signing_bytes`] count-prefixes its member
/// list: without it, a shorter set and a longer one whose extra entries look
/// like continuation bytes would be indistinguishable from the preimage
/// alone.
fn push_pubkey_set(out: &mut Vec<u8>, keys: &[String]) {
    let mut sorted: Vec<&str> = keys.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for k in sorted {
        push_lp(out, k.as_bytes());
    }
}

/// Length-prefix a SET of per-role key entries into the preimage, each
/// entry itself field-by-field length-prefixed, canonically sorted by role
/// (`Display` form) so two encoders that assemble the same set in different
/// insertion order — say, iterating [`crate::capsule::MachineCapsule::slices`]
/// versus a `HashMap` — sign identical bytes. The same guarantee
/// [`crate::identity::DeclaredIdentity::signing_bytes`] makes for its own
/// `role_keys` field, and the reason [`IdentityRotated::new_role_keys`]
/// reuses that exact [`RolePublicKeys`] type instead of a parallel tuple:
/// one encoding rule for "a set of per-role public keys," not two.
/// Count-prefixed for the same reason [`push_pubkey_set`] is: without it, a
/// shorter set and a longer one whose extra entries look like continuation
/// bytes would be indistinguishable from the preimage alone.
fn push_role_keys(out: &mut Vec<u8>, keys: &[RolePublicKeys]) {
    let mut sorted: Vec<&RolePublicKeys> = keys.iter().collect();
    sorted.sort_by(|a, b| a.role.to_string().cmp(&b.role.to_string()));
    out.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
    for rk in sorted {
        push_lp(out, rk.role.to_string().as_bytes());
        push_lp(out, rk.wire_pubkey_hex.as_bytes());
        // Presence byte first, same discipline [`push_opt_lp`] documents:
        // `None` and `Some("")` must not share a preimage, or a signing key
        // could be stripped from a role's entry without invalidating the
        // rotation's signature.
        push_opt_lp(out, rk.signing_pubkey_hex.as_deref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ServiceRole;
    use rand::rngs::OsRng;

    fn mesh(s: &str) -> MeshId {
        MeshId::new(s).expect("mesh id")
    }

    fn subject() -> Subject {
        Subject {
            mesh_id: mesh("v3-staging"),
            machine_id: MachineId::new("ru-hostkey-203.0.113.10").expect("machine id"),
        }
    }

    fn admitted(seq: u64) -> QuorumEvent {
        QuorumEvent::IdentityAdmitted(IdentityAdmitted {
            subject: subject(),
            self_id: Uuid::nil(),
            wire_pubkey_hex: "aa".repeat(32),
            signing_pubkey_hex: None,
            charter_epoch: 1,
            seq,
            issued_at_ms: 1_700_000_000_000,
        })
    }

    #[test]
    fn a_valid_quorum_event_verifies_against_the_charter_key() {
        let group = SigningKey::generate(&mut OsRng);
        let operator = SigningKey::generate(&mut OsRng);
        let gv = group.verifying_key();
        let ev = SignedQuorumEvent::sign(
            admitted(1),
            EventSigner::Quorum { charter_epoch: 1 },
            &group,
        );
        ev.verify(&mesh("v3-staging"), &operator.verifying_key(), |e| {
            (e == 1).then_some(gv)
        })
        .expect("must verify");
    }

    /// The operator key must not rescue a quorum-signed event whose charter is
    /// unknown — that would silently swap the trust anchor.
    #[test]
    fn an_unknown_charter_epoch_is_a_rejection_not_an_operator_fallback() {
        let group = SigningKey::generate(&mut OsRng);
        let operator = SigningKey::generate(&mut OsRng);
        let ev = SignedQuorumEvent::sign(
            admitted(1),
            EventSigner::Quorum { charter_epoch: 9 },
            &group,
        );
        let err = ev
            .verify(&mesh("v3-staging"), &operator.verifying_key(), |_| None)
            .unwrap_err();
        assert!(matches!(err, QuorumError::NoCharter(9)), "got {err:?}");
    }

    /// The whole point of splitting signers: a quorum must not be able to lift
    /// the operator's fence on a machine.
    #[test]
    fn a_quorum_cannot_sign_recovery_policy() {
        let group = SigningKey::generate(&mut OsRng);
        let operator = SigningKey::generate(&mut OsRng);
        let gv = group.verifying_key();
        let ev = SignedQuorumEvent::sign(
            QuorumEvent::RecoveryForbidden(RecoveryForbidden {
                subject: subject(),
                forbidden: false,
                seq: 2,
                issued_at_ms: 1_700_000_000_000,
            }),
            EventSigner::Quorum { charter_epoch: 1 },
            &group,
        );
        let err = ev
            .verify(&mesh("v3-staging"), &operator.verifying_key(), |e| {
                (e == 1).then_some(gv)
            })
            .unwrap_err();
        assert!(matches!(err, QuorumError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_event_for_another_mesh_is_rejected() {
        let group = SigningKey::generate(&mut OsRng);
        let operator = SigningKey::generate(&mut OsRng);
        let gv = group.verifying_key();
        let ev = SignedQuorumEvent::sign(
            admitted(1),
            EventSigner::Quorum { charter_epoch: 1 },
            &group,
        );
        let err = ev
            .verify(&mesh("v4-prod"), &operator.verifying_key(), |e| {
                (e == 1).then_some(gv)
            })
            .unwrap_err();
        assert!(matches!(err, QuorumError::WrongMesh { .. }), "got {err:?}");
    }

    #[test]
    fn tampering_with_any_signed_field_breaks_the_signature() {
        let group = SigningKey::generate(&mut OsRng);
        let operator = SigningKey::generate(&mut OsRng);
        let gv = group.verifying_key();
        let mut ev = SignedQuorumEvent::sign(
            admitted(1),
            EventSigner::Quorum { charter_epoch: 1 },
            &group,
        );
        if let QuorumEvent::IdentityAdmitted(a) = &mut ev.event {
            a.wire_pubkey_hex = "bb".repeat(32);
        }
        let err = ev
            .verify(&mesh("v3-staging"), &operator.verifying_key(), |e| {
                (e == 1).then_some(gv)
            })
            .unwrap_err();
        assert!(matches!(err, QuorumError::SigInvalid), "got {err:?}");
    }

    /// The role-tagged key SET inside an `IdentityRotated` event is sorted
    /// (by role) before it enters the preimage, so two encoders that
    /// assemble the same set in different insertion order sign identical
    /// bytes — the same property `DeclaredIdentity::signing_bytes`
    /// guarantees for its own per-role `role_keys` set.
    #[test]
    fn the_rotation_role_key_set_preimage_is_order_independent() {
        let role_key = |role: ServiceRole, wire: &str| RolePublicKeys {
            role,
            wire_pubkey_hex: wire.repeat(32),
            signing_pubkey_hex: None,
        };
        let base = IdentityRotated {
            subject: subject(),
            self_id: Uuid::nil(),
            prev_wire_pubkeys: Vec::new(),
            new_role_keys: vec![
                role_key(ServiceRole::Sentry, "aa"),
                role_key(ServiceRole::Monitor, "bb"),
                role_key(ServiceRole::Warden, "cc"),
            ],
            charter_epoch: 1,
            seq: 1,
            issued_at_ms: 1_700_000_000_000,
        };
        let mut reordered = base.clone();
        reordered.new_role_keys.reverse();
        assert_ne!(
            base.new_role_keys, reordered.new_role_keys,
            "precondition: the two orders really differ"
        );

        let a = QuorumEvent::IdentityRotated(base).signing_bytes();
        let b = QuorumEvent::IdentityRotated(reordered).signing_bytes();
        assert_eq!(a, b, "insertion order of the role key set must not affect the preimage");
    }

    /// `None` and `Some("")` must not share a preimage, or an optional signing
    /// key could be stripped from a signed admission.
    #[test]
    fn absent_and_empty_optional_fields_have_distinct_preimages() {
        let mut none = admitted(1);
        let mut empty = admitted(1);
        if let QuorumEvent::IdentityAdmitted(a) = &mut none {
            a.signing_pubkey_hex = None;
        }
        if let QuorumEvent::IdentityAdmitted(a) = &mut empty {
            a.signing_pubkey_hex = Some(String::new());
        }
        assert_ne!(none.signing_bytes(), empty.signing_bytes());
    }

    #[test]
    fn seq_must_strictly_increase_per_subject() {
        let mut seen = SubjectSeq::new();
        let s = subject();
        seen.accept(&s, 1).expect("first");
        assert!(matches!(
            seen.accept(&s, 1).unwrap_err(),
            QuorumError::StaleSeq { got: 1, have: 1 }
        ));
        assert!(matches!(
            seen.accept(&s, 0).unwrap_err(),
            QuorumError::StaleSeq { got: 0, have: 1 }
        ));
        seen.accept(&s, 2).expect("newer");
        assert_eq!(seen.highest(&s), 2);
    }

    /// A rejected event must not advance the watermark, or one replayed event
    /// could fence out the legitimate next one.
    #[test]
    fn a_rejected_seq_does_not_advance_the_watermark() {
        let mut seen = SubjectSeq::new();
        let s = subject();
        seen.accept(&s, 5).expect("first");
        let _ = seen.accept(&s, 3);
        assert_eq!(seen.highest(&s), 5);
        seen.accept(&s, 6).expect("still accepts the real next one");
    }

    /// A single-role rotation naming `new` under `ServiceRole::Sentry` —
    /// these chain/seq/watermark tests care only about the wire key
    /// chaining through `SubjectRecord::wire_pubkeys`, never about which
    /// role it is tagged with, so one fixed role stands in for all of them.
    fn rotated(seq: u64, prev: &str, new: &str) -> QuorumEvent {
        QuorumEvent::IdentityRotated(IdentityRotated {
            subject: subject(),
            self_id: Uuid::nil(),
            prev_wire_pubkeys: vec![prev.to_string()],
            new_role_keys: vec![RolePublicKeys {
                role: ServiceRole::Sentry,
                wire_pubkey_hex: new.to_string(),
                signing_pubkey_hex: None,
            }],
            charter_epoch: 1,
            seq,
            issued_at_ms: 1_700_000_000_000,
        })
    }

    fn forbid(seq: u64, forbidden: bool) -> QuorumEvent {
        QuorumEvent::RecoveryForbidden(RecoveryForbidden {
            subject: subject(),
            forbidden,
            seq,
            issued_at_ms: 1_700_000_000_000,
        })
    }

    fn signed(ev: QuorumEvent, k: &SigningKey) -> SignedQuorumEvent {
        let signer = if ev.required_signer_is_operator() {
            EventSigner::Operator
        } else {
            EventSigner::Quorum { charter_epoch: 1 }
        };
        SignedQuorumEvent::sign(ev, signer, k)
    }

    /// The anchors ARE the watermark, per anchor. Nothing tracks `seq`
    /// alongside them, so there is nothing that can drift out of step.
    #[test]
    fn each_anchor_carries_its_own_watermark() {
        let k = SigningKey::generate(&mut OsRng);
        let mut log = QuorumLog::new();
        log.apply_verified(signed(admitted(1), &k)).expect("admit");
        log.apply_verified(signed(forbid(2, true), &k)).expect("forbid");
        log.apply_verified(signed(rotated(3, &"aa".repeat(32), &"bb".repeat(32)), &k))
            .expect("rotate");

        let rec = log.record(&subject()).expect("record");
        assert_eq!(rec.identity_seq(), 3);
        assert_eq!(rec.policy_seq(), 2);
        assert_eq!(rec.seq(), 3, "the display view is the newer of the two");
    }

    /// **The repair path, and the reason the gate is per anchor.**
    ///
    /// A monitor that holds an identity event at `seq` 7 but missed the policy
    /// event at `seq` 5 is fail-OPEN: it will help sign an admission for a
    /// machine the operator fenced off. Anti-entropy pulls the missing policy
    /// to fix exactly that. Under one shared per-subject counter the pulled
    /// event would be rejected as stale, the monitor would stay unfenced
    /// permanently, and its digest would never converge — so it would pull
    /// again on every tick, forever.
    #[test]
    fn a_pulled_policy_event_repairs_a_monitor_that_is_ahead_on_identity() {
        let k = SigningKey::generate(&mut OsRng);
        let mut behind = QuorumLog::new();
        behind
            .apply_verified(signed(admitted(7), &k))
            .expect("this monitor saw the identity event");

        behind
            .apply_verified(signed(forbid(5, true), &k))
            .expect("the fence it missed must still be applicable");

        assert!(
            behind.record(&subject()).expect("record").recovery_forbidden(),
            "the monitor must end up fenced, or the pull repaired nothing"
        );
    }

    /// Per-anchor gating must not weaken replay protection within an anchor.
    #[test]
    fn an_anchor_still_refuses_an_older_event_of_its_own_kind() {
        let k = SigningKey::generate(&mut OsRng);
        let mut log = QuorumLog::new();
        log.apply_verified(signed(forbid(9, true), &k)).expect("fence");
        let err = log.apply_verified(signed(forbid(4, false), &k)).unwrap_err();
        assert!(
            matches!(err, QuorumError::StaleSeq { got: 4, have: 9 }),
            "a replayed lift must not unfence the machine: {err:?}"
        );
        assert!(log.record(&subject()).expect("record").recovery_forbidden());
    }

    /// A policy anchor sitting below the watermark is not stale — it is policy
    /// that has not changed. Treating it as stale is how the operator's fence
    /// silently lapses.
    #[test]
    fn a_policy_anchor_below_the_watermark_is_still_in_force() {
        let k = SigningKey::generate(&mut OsRng);
        let mut log = QuorumLog::new();
        log.apply_verified(signed(forbid(1, true), &k)).expect("forbid");
        log.apply_verified(signed(admitted(2), &k)).expect("admit");

        let rec = log.record(&subject()).expect("record");
        assert_eq!(rec.seq(), 2, "the identity event is newer");
        assert!(
            rec.recovery_forbidden(),
            "the fence must survive a later identity event"
        );
    }

    #[test]
    fn a_rotation_that_does_not_chain_is_rejected_without_burning_the_watermark() {
        let k = SigningKey::generate(&mut OsRng);
        let mut log = QuorumLog::new();
        log.apply_verified(signed(admitted(1), &k)).expect("admit");

        let bogus = signed(rotated(2, &"cc".repeat(32), &"dd".repeat(32)), &k);
        let err = log.apply_verified(bogus).unwrap_err();
        assert!(matches!(err, QuorumError::RotationChain { .. }), "got {err:?}");

        // The real rotation at the same seq must still be accepted.
        let new_key = "bb".repeat(32);
        log.apply_verified(signed(rotated(2, &"aa".repeat(32), &new_key), &k))
            .expect("the legitimate rotation must not be fenced out");
        assert_eq!(
            log.record(&subject()).and_then(SubjectRecord::wire_pubkeys),
            Some(vec![new_key.as_str()])
        );
    }

    /// A monitor that pulled a snapshot holds no prior key, and must still be
    /// able to adopt the current one.
    #[test]
    fn a_bootstrapping_log_accepts_a_rotation_with_nothing_to_chain_from() {
        let k = SigningKey::generate(&mut OsRng);
        let mut log = QuorumLog::new();
        log.apply_verified(signed(rotated(7, &"aa".repeat(32), &"bb".repeat(32)), &k))
            .expect("nothing held, nothing to contradict");
        assert_eq!(log.record(&subject()).expect("record").seq(), 7);
    }

    /// **The convergence property.** A FROST aggregate is randomised, so the
    /// quorum signing the same event twice yields different signature bytes.
    /// If the digest included the signature, two monitors holding the identical
    /// event would disagree forever and no pull could repair it — the pulled
    /// event's `seq` never exceeds the receiver's watermark.
    #[test]
    fn the_digest_ignores_the_signature_so_a_re_signed_event_cannot_split_the_fleet() {
        let a = SigningKey::generate(&mut OsRng);
        let b = SigningKey::generate(&mut OsRng);
        let mut left = QuorumLog::new();
        let mut right = QuorumLog::new();
        left.apply_verified(signed(admitted(1), &a)).expect("left");
        right.apply_verified(signed(admitted(1), &b)).expect("right");

        let s = subject();
        let dl = left.record(&s).expect("left").digest_bytes(&s);
        let dr = right.record(&s).expect("right").digest_bytes(&s);
        assert_ne!(
            left.record(&s).expect("l").identity.as_ref().expect("l").sig_hex,
            right.record(&s).expect("r").identity.as_ref().expect("r").sig_hex,
            "precondition: the two signatures really do differ"
        );
        assert_eq!(dl, dr, "identical signed content must fingerprint identically");
    }

    /// Absent policy and lifted policy must not fingerprint the same, or a
    /// monitor that never saw the fence would look converged with one that saw
    /// it lifted — and the two disagree about what happens next time.
    #[test]
    fn absent_policy_and_lifted_policy_have_distinct_digests() {
        let k = SigningKey::generate(&mut OsRng);
        let s = subject();
        let mut none = QuorumLog::new();
        none.apply_verified(signed(admitted(1), &k)).expect("admit");
        let mut lifted = QuorumLog::new();
        lifted.apply_verified(signed(admitted(1), &k)).expect("admit");
        lifted.apply_verified(signed(forbid(2, false), &k)).expect("lift");

        assert_ne!(
            none.record(&s).expect("none").digest_bytes(&s),
            lifted.record(&s).expect("lifted").digest_bytes(&s)
        );
    }

    /// A rebuilt log must gate on the record it was rebuilt from, or every
    /// clone-on-write round trip in the monitor would reopen a replay window.
    #[test]
    fn a_rebuilt_log_still_rejects_a_replay_of_what_it_holds() {
        let k = SigningKey::generate(&mut OsRng);
        let s = subject();
        let mut src = QuorumLog::new();
        src.apply_verified(signed(admitted(4), &k)).expect("admit");
        let rec = src.record(&s).expect("record").clone();

        let mut dst = QuorumLog::new();
        dst.install_verified(s.clone(), rec);
        let err = dst.apply_verified(signed(admitted(4), &k)).unwrap_err();
        assert!(matches!(err, QuorumError::StaleSeq { got: 4, have: 4 }), "got {err:?}");
    }

    /// Subjects are independent: two machines must not share a counter, or a
    /// busy machine would fence out a quiet one.
    ///
    /// This used to be two ROLES on one machine — `Subject` carried a `role`
    /// and gate 5 counted per `(machine, role)`. That is gone on purpose (see
    /// the module doc): admission is machine-keyed now, so the property left
    /// to prove here is that two DIFFERENT machines still don't share a
    /// watermark.
    #[test]
    fn subjects_have_independent_counters() {
        let mut seen = SubjectSeq::new();
        let a = subject();
        let b = Subject {
            machine_id: MachineId::new("tr-hostkey-203.0.113.20").expect("machine id"),
            ..subject()
        };
        seen.accept(&a, 9).expect("machine a");
        seen.accept(&b, 1).expect("machine b is not fenced by machine a's seq");
        assert_eq!(seen.highest(&b), 1);
    }
}
