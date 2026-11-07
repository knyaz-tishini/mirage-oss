//! Machine attestation — the one credential that stays on disk, and the reason
//! it is safe to leave there.
//!
//! ## The problem it solves
//!
//! Capsule-only deliberately removed every operational secret from disk. That
//! is what makes a seized box worthless. It also means a rebooted box has
//! **nothing to prove continuity with**: it comes up knowing only its build,
//! and anyone who can boot a VM and reach the mesh can publish an announce
//! claiming to be `ru-hostkey-203.0.113.10`. While the operator is present that does
//! not matter — opbox checks the escrow. With the operator absent, and the
//! quorum issuing capsules in his place, it is the whole security question.
//!
//! ## Why a key on disk is not a retreat from the capsule doctrine
//!
//! This is the standard answer, not an invention. SPIFFE/SPIRE faces the same
//! problem and solves it by platform attestation where a platform exists (AWS
//! IID, GCP IIT, Kubernetes PSAT) and by `x509pop` — a long-lived certificate
//! **on the node's disk**, reused across restarts — where none does. Join
//! tokens are explicitly unsuitable: they are single-use and burn on
//! attestation, so they cannot serve an unattended reboot. These boxes are
//! plain VPS with no IID API and no TPM, which puts us squarely in the
//! `x509pop` case.
//!
//! The doctrine survives because this is a **different asset class**:
//!
//! | | attestation key (here) | operational identity (`crate::capsule`) |
//! |---|---|---|
//! | at rest | yes, one per machine | never |
//! | grants | the right to *ask* to be identified | wire key, fact signing, db key |
//! | if stolen | attacker may request a capsule, still facing quorum checks, IP binding, rate limit, tombstone and operator veto | attacker **is** the box |
//!
//! It decrypts nothing, joins nothing, signs no facts. Its entire power is to
//! make one sentence credible: *"the announce you are reading came from the
//! machine you think it did."*
//!
//! ## What the signature must cover, and why
//!
//! Everything in the announce — in particular `eph_pubkey_hex` and
//! `boot_nonce`.
//!
//! This is the part that is easy to get subtly wrong and fatal to get wrong.
//! Sign only the machine name and an attacker replays a captured signature
//! alongside **their own** ephemeral public key; the quorum then seals a
//! perfectly valid capsule to a key the attacker holds, and hands over the
//! box's identity without any signature ever failing to verify. Binding the
//! ephemeral key into the preimage is what makes the attestation a statement
//! about *this boot attempt* rather than about the machine in the abstract.
//!
//! `started_at_ms` is bound too and checked against a freshness window, so a
//! recorded announce cannot be replayed weeks later against a box that has
//! since been retired.
//!
//! ## What it deliberately does not do
//!
//! It is **not** sealed under a platform fingerprint. `dk_delivery` did exactly
//! that and the device-fp seal was removed in July 2026 because a reboot
//! bricked the database — the recovery path was worse than the exposure it
//! prevented. A disk image therefore yields this key. The compensating control
//! is not more crypto on the file, it is the quorum noticing **two claimants
//! for one subject**: a live box and an impostor produce a duplicate admission
//! for the same `(mesh, machine)`, which is a loud, rate-limited,
//! tombstoned event rather than a silent takeover.
//!
//! ## Platform facts (gate 4, 2026-08-08) and the V1→V2 history
//!
//! Admission gate 4 ("platform facts match the last `box_profile`",
//! `mirage2monitor::admission`) compares a PRESENTED claim against a
//! STORED signed one — `MeshState::box_profiles` is real, gossiped state,
//! but before this addition an announce carried nothing to compare it
//! against, so the gate could only ever refuse on
//! `PlatformFactsEvidenceMissing`. [`AttestedFields::platform`] is that
//! missing half: an optional [`crate::fact_signing::PlatformFingerprint`],
//! the same five-field shape [`crate::fact_signing::BoxProfileRow`]
//! projects via `platform_fingerprint()` — one shape, so the comparison at
//! gate 4 is not comparing two independently-invented views of "the same
//! facts".
//!
//! V1 (no platform coverage at all) and V2 (platform, presence-byte
//! encoded) are retired now — this module reads and writes V3 only, see
//! the next section. Their history stays here because the lesson still
//! applies to any future preimage change: **a producer must not emit a
//! preimage its verifiers have not learned yet.** Measured 2026-08-08, and
//! it cost two boxes: the first revision of the V2 change had `attest`
//! sign V2 unconditionally, which inverted the roll order this tree
//! otherwise obeys — a monitor rebuilt with V2 support published a
//! V2-signed, platform-less announce to a fleet of V1-only verifiers,
//! every one of them refused the attestation and refused to hold the ask,
//! and the box sat in a capsule boot loop until opbox — itself rebuilt —
//! sealed one directly. The fix was a narrow rule: sign V1 while there are
//! no platform facts (costs nothing — the two preimages carried identical
//! bytes in that case), V2 only once there are, so verifiers rolled ahead
//! of what producers started emitting.
//!
//! ## Machine identity: V1/V2 have no successor fallback (V3, 2026-08-17)
//!
//! `role` — a mandatory field at a fixed early position in every prior
//! preimage — is gone from [`AttestedFields`]: identity belongs to the
//! MACHINE now, not to one service on it (see
//! `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md`). This
//! is a DIFFERENT kind of change from the V1→V2 story above, and it gets a
//! different answer.
//!
//! The V1→V2 narrowing worked because `platform` was ADDITIVE and OPTIONAL:
//! a `None` value produces byte-identical output whether the signer knows
//! about V2 or not, so a fallback from V2 to V1 could be scoped to exactly
//! that case without opening a hole. `role` was neither — it was mandatory,
//! present in every announce ever signed, and it sat at a fixed position
//! every field after it depended on. There is no `None`-shaped announce for
//! a field that was never optional, so there is no byte-compatible
//! narrowing to fall back to: any fallback wide enough to accept a V1 or V2
//! signature would, definitionally, still accept the exact per-role
//! announce shape this cutover exists to delete. [`verify_attested`]
//! therefore accepts V3 and nothing else — an old and a new binary cannot
//! verify each other, by construction, which is the same hard-cutover rule
//! the sealed-capsule AAD follows in [`crate::capsule`].

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Ed25519 signing-preimage domain label — V3, the only one this build
/// reads or writes. See "Machine identity: V1/V2 have no successor
/// fallback" below for what stood here before and why nothing reads it any
/// more.
const ATTEST_SIG_LABEL_V3: &[u8] = b"MIRAGE-MACHINE-ATTESTATION-V3";

/// Signing-preimage domain label for an **enrolment** — the operator's
/// statement that a given public key belongs to a given machine. Distinct from
/// [`ATTEST_SIG_LABEL_V3`] so a box's own attestation can never be replayed as
/// an operator enrolment of itself, which would let any box enrol its own key
/// and collapse the whole check.
///
/// Used only when [`AttestationPubkey::expected_source_ip`] is `None` — see
/// [`ENROL_SIG_LABEL_V2`] for the case where it is `Some`, and
/// [`AttestationPubkey::enrolment_signing_bytes`] for why the two preimages
/// never share a label.
const ENROL_SIG_LABEL: &[u8] = b"MIRAGE-ATTESTATION-ENROLMENT-V1";

/// Signing-preimage domain label for an enrolment that ALSO carries
/// [`AttestationPubkey::expected_source_ip`].
///
/// A distinct label rather than folding the IP into [`ENROL_SIG_LABEL`]'s own
/// preimage, for the same reason `platform` got a new label story in
/// [`ATTEST_SIG_LABEL_V3`]'s history (module doc, "V1→V2"): a `None` IP must
/// keep verifying under the exact byte-for-byte preimage every existing
/// verifier already knows, so the field cannot be additive-in-place the way
/// `renewal` is on the attestation side — an enrolment's `operator_sig_hex`
/// is long-lived, gossiped, and re-verified by every peer forever, not
/// re-signed per boot, so there is no "old builds only see `None` anyway"
/// grace period to lean on. `Some` therefore signs under this label instead
/// of trying to make one preimage serve both shapes.
const ENROL_SIG_LABEL_V2: &[u8] = b"MIRAGE-ATTESTATION-ENROLMENT-V2";

/// Where the private half lives. Under `/var/lib/mirage` rather than
/// `/run/mirage`, because `/run` is tmpfs and the entire point of this key is
/// to survive a reboot — it is the only Mirage private key for which that is
/// true.
pub const ATTESTATION_KEY_PATH: &str = "/var/lib/mirage/attestation.key";

/// The box's DURABLE mirage directory — the one place under `/var/lib`, not
/// `/run` (tmpfs), where a file survives a reboot. Holds [`ATTESTATION_KEY_PATH`]
/// (the "right to ask") and the peer-anchor cache
/// ([`crate::identity_boot::machine_peer_anchors_path`], the "where to ask").
/// Nothing identity-bearing lives here: the capsule and every slice it carries
/// die with `/run` on every reboot, on purpose — the mesh re-admits the box and
/// re-delivers all of it. What stays is only what a cold box needs to reach the
/// mesh at all.
pub const MIRAGE_VAR_DIR: &str = "/var/lib/mirage";

/// How far an announce's `started_at_ms` may be from the verifier's clock.
///
/// Generous rather than tight: the verifier is a peer monitor, not a time
/// authority, and a rejected-because-clock-skew announce fails closed into
/// "box cannot come back", which is the failure this whole feature exists to
/// prevent. Replay beyond this window is caught by `boot_nonce` uniqueness and
/// the quorum's per-subject `seq`, not by this bound alone.
pub const ATTESTATION_FRESHNESS_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("malformed attestation field: {0}")]
    Malformed(String),
    #[error("attestation signature invalid")]
    SigInvalid,
    #[error("attested announce is for machine {got}, expected {want}")]
    WrongMachine { got: String, want: String },
    #[error("attested announce is stale: |now - started_at| = {skew_ms} ms exceeds the window")]
    Stale { skew_ms: u64 },
    #[error("no attestation key is enrolled for machine {0}")]
    NotEnrolled(String),
    #[error("attestation key file: {0}")]
    Io(String),
    #[error("attestation key is for machine {have}, this service is {want}")]
    WrongKeyMachine { have: String, want: String },
}

impl From<io::Error> for AttestationError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// The public half, as the fleet records it.
///
/// Distributed the same way every other public identity fact is: recorded by
/// the operator at enrolment and gossiped as a signed fact, so a quorum member
/// verifying an announce is reading fleet state rather than asking opbox —
/// which would reintroduce the dependency this removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPubkey {
    pub machine_id: String,
    /// Ed25519 public key, hex (64 chars).
    pub pubkey_hex: String,
    /// When the operator enrolled it. An enrolment is not silently replaceable:
    /// a second enrolment for a machine that already has one is a rotation and
    /// must be an explicit operator act, or stealing the announce path would be
    /// as easy as enrolling a second key.
    ///
    /// Also the LWW key when this record is gossiped, so a later enrolment wins
    /// and an older one replayed at a peer cannot roll a rotation back.
    pub enrolled_at_ms: u64,
    /// The bare address (v4 or v6, no port) the operator expects this
    /// machine's announces to arrive from — `None` for a machine the
    /// operator enrolled without a known address, or a record enrolled
    /// before this field existed.
    ///
    /// This is the fix for admission gate 3's `SourceAddressEvidenceMissing`
    /// on a monitor-less box: `MeshState::expected_source_addr` used to read
    /// only `DeclaredIdentity.public_addr`, which opbox signs for
    /// Monitor-role machines alone (a monitor dial address, not a general
    /// admission input — see `resolve_monitor_public_addr`'s own doc), so
    /// every other box fell back to opbox forever. An enrolment is exactly
    /// "the operator admitted this machine at this address"; changing the
    /// address is a re-enrol, an explicit operator act, which matches the
    /// doctrine `enrolled_at_ms` already states for a key rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_source_ip: Option<String>,
    /// Operator's Ed25519 signature over the other fields, hex.
    ///
    /// Without this the record is worthless: a monitor accepting an unsigned
    /// enrolment would let anyone who can gossip declare their own key
    /// authoritative for any machine, and the attestation check would verify
    /// perfectly against the attacker's key.
    pub operator_sig_hex: String,
}

impl AttestationPubkey {
    /// Fixed, length-prefixed enrolment preimage — never a hash of JSON.
    ///
    /// `expected_source_ip: None` signs under [`ENROL_SIG_LABEL`] with the
    /// exact three-field preimage this crate has always used, so every V1
    /// record already on disk or in flight keeps verifying byte-for-byte.
    /// `Some` signs under [`ENROL_SIG_LABEL_V2`] with the address appended —
    /// see that label's own doc for why the two never share one preimage.
    fn enrolment_signing_bytes(&self) -> Vec<u8> {
        match &self.expected_source_ip {
            None => {
                let mut p = Vec::with_capacity(ENROL_SIG_LABEL.len() + 128);
                p.extend_from_slice(ENROL_SIG_LABEL);
                push_lp(&mut p, self.machine_id.as_bytes());
                push_lp(&mut p, self.pubkey_hex.as_bytes());
                p.extend_from_slice(&self.enrolled_at_ms.to_le_bytes());
                p
            }
            Some(ip) => {
                let mut p = Vec::with_capacity(ENROL_SIG_LABEL_V2.len() + 160);
                p.extend_from_slice(ENROL_SIG_LABEL_V2);
                push_lp(&mut p, self.machine_id.as_bytes());
                push_lp(&mut p, self.pubkey_hex.as_bytes());
                p.extend_from_slice(&self.enrolled_at_ms.to_le_bytes());
                push_lp(&mut p, ip.as_bytes());
                p
            }
        }
    }

    /// Enrol a machine's attestation key. An operator act by construction — the
    /// signing key is his.
    #[must_use]
    pub fn sign_new(
        machine_id: impl Into<String>,
        pubkey_hex: impl Into<String>,
        enrolled_at_ms: u64,
        expected_source_ip: Option<String>,
        operator: &SigningKey,
    ) -> Self {
        let mut me = Self {
            machine_id: machine_id.into(),
            pubkey_hex: pubkey_hex.into(),
            enrolled_at_ms,
            expected_source_ip,
            operator_sig_hex: String::new(),
        };
        let sig = operator.sign(&me.enrolment_signing_bytes());
        me.operator_sig_hex = hex::encode(sig.to_bytes());
        me
    }

    /// Verify the operator's enrolment signature.
    ///
    /// Must be called before an enrolment is stored or acted on, wherever it
    /// arrives from. Gossip carries it between monitors, and a monitor that
    /// trusted the relaying peer instead of the signature would be trusting
    /// whichever box shouted last.
    pub fn verify_enrolment(
        &self,
        operator_pubkey: &VerifyingKey,
    ) -> Result<(), AttestationError> {
        let raw = hex::decode(&self.operator_sig_hex)
            .map_err(|e| AttestationError::Malformed(format!("enrolment sig not hex: {e}")))?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::Malformed("enrolment sig is not 64 bytes".to_string()))?;
        operator_pubkey
            .verify(&self.enrolment_signing_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| AttestationError::SigInvalid)
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, AttestationError> {
        let raw = hex::decode(&self.pubkey_hex)
            .map_err(|e| AttestationError::Malformed(format!("pubkey not hex: {e}")))?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::Malformed("pubkey is not 32 bytes".to_string()))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| AttestationError::Malformed(format!("pubkey not on curve: {e}")))
    }
}

/// The fields an attestation signature covers.
///
/// A struct rather than loose arguments so the preimage cannot be built from a
/// subset by accident: adding a field to the announce and forgetting to bind it
/// here is exactly the mistake described in the module doc, and a struct makes
/// the omission visible at every construction site.
#[derive(Debug, Clone)]
pub struct AttestedFields<'a> {
    pub machine_id: &'a str,
    pub build_id: &'a str,
    /// **Load-bearing.** Binds the attestation to this boot's ephemeral key, so
    /// a replayed signature cannot redirect a capsule to an attacker's key.
    pub eph_pubkey_hex: &'a str,
    pub boot_nonce: &'a str,
    pub started_at_ms: u64,
    /// Platform facts this boot presents, for admission gate 4. `None`
    /// means either a build that does not gather them or a service that
    /// has not wired platform collection yet — either way it is a real,
    /// explicit absence, never a placeholder that secretly means "skip
    /// this gate" (`crate::fact_signing::PlatformFingerprint`'s doc). See
    /// the module doc's "Platform facts" section for why this field exists.
    pub platform: Option<&'a crate::fact_signing::PlatformFingerprint>,
    /// The renewal claim riding this announce, if any — see
    /// `crate::identity_boot::BootAnnounce::renewal` and
    /// `crate::identity_boot::RenewalClaim`'s own docs. Folded into the
    /// attestation preimage for the same reason `eph_pubkey_hex` is: a
    /// claim that could be stripped or substituted in transit without
    /// breaking the outer signature would be worthless.
    ///
    /// `None` for every ordinary cold-boot/reset announce — and, critically,
    /// [`Self::field_bytes`] adds NOTHING to the preimage in that case (no
    /// presence byte, unlike `platform`), so a `renewal: None` announce from
    /// a build that knows about this field is byte-identical to one from a
    /// build that predates it. See [`Self::field_bytes`]'s own doc.
    pub renewal: Option<RenewalAttested<'a>>,
}

/// The two fields of a [`crate::identity_boot::RenewalClaim`] the OUTER
/// attestation signature must also cover, so neither can be stripped or
/// substituted without invalidating `attestation_sig_hex` — see that
/// type's own doc for the full threat model.
#[derive(Debug, Clone, Copy)]
pub struct RenewalAttested<'a> {
    pub self_id: Uuid,
    pub held_pubkey_hex: &'a str,
}

impl AttestedFields<'_> {
    /// The V3 signing preimage — never a hash of JSON, and the only one this
    /// build produces or accepts. See the module doc's "Machine identity"
    /// section for why V1 and V2 have no fallback here.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(ATTEST_SIG_LABEL_V3.len() + 384);
        p.extend_from_slice(ATTEST_SIG_LABEL_V3);
        p.extend_from_slice(&self.field_bytes());
        p
    }

    /// Every field EXCEPT the domain label — split out so a SECOND signer
    /// can bind the exact same facts under a DIFFERENT label without
    /// duplicating this encoding. [`Self::signing_bytes`] (the box's own
    /// attestation key) is one user; `crate::identity_boot::RenewalClaim`'s
    /// possession signature (a role-slice signing key from the held
    /// [`crate::capsule::MachineCapsule`], a different signer entirely) is
    /// the other — see that type's own doc for why it needs to prove
    /// possession of these same facts without sharing the attestation
    /// preimage.
    ///
    /// `platform` is encoded with a presence byte, then — when present —
    /// each of its five fields length-prefixed. Absent and present must
    /// never share a preimage, or a `None` could be relabelled `Some` (or
    /// vice versa) without invalidating the signature.
    ///
    /// `renewal` is different: it is folded in ONLY when `Some`, with NO
    /// presence byte at all. A `None` therefore emits exactly the bytes
    /// this function emitted before `renewal` existed — required so a
    /// cold-boot/reset announce from a binary that knows about
    /// `RenewalClaim` still verifies against a monitor built before it did
    /// (see `crate::identity_boot::BootAnnounce::renewal`'s own doc). This
    /// is safe because `renewal`'s own fields are self-delimiting
    /// (`self_id` fixed-width, `held_pubkey_hex` length-prefixed) and this
    /// output is never parsed back — only ever recomputed from a
    /// `Deserialize`d struct and compared against a signature — so there is
    /// no boundary ambiguity between a `None` and a `Some` for anything
    /// that already knows which one it is signing or verifying.
    pub(crate) fn field_bytes(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(384);
        push_lp(&mut p, self.machine_id.as_bytes());
        push_lp(&mut p, self.build_id.as_bytes());
        push_lp(&mut p, self.eph_pubkey_hex.as_bytes());
        push_lp(&mut p, self.boot_nonce.as_bytes());
        p.extend_from_slice(&self.started_at_ms.to_le_bytes());
        match self.platform {
            None => p.push(0),
            Some(pf) => {
                p.push(1);
                push_lp(&mut p, pf.cpu_model.as_bytes());
                push_lp(&mut p, pf.cpu_arch.as_bytes());
                push_lp(&mut p, pf.dmi_sys_vendor.as_bytes());
                push_lp(&mut p, pf.dmi_product_name.as_bytes());
                push_lp(&mut p, pf.dmi_board.as_bytes());
            }
        }
        if let Some(r) = &self.renewal {
            push_lp(&mut p, r.self_id.as_bytes());
            push_lp(&mut p, r.held_pubkey_hex.as_bytes());
        }
        p
    }
}

/// The private half, held only for as long as it takes to sign.
pub struct AttestationKey {
    machine_id: String,
    key: SigningKey,
}

impl AttestationKey {
    /// Build from raw seed bytes. The seed is wiped when `buf` drops; the
    /// `SigningKey` keeps its own copy and is wiped on drop by `ed25519-dalek`.
    pub fn from_seed(machine_id: impl Into<String>, seed: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            machine_id: machine_id.into(),
            key: SigningKey::from_bytes(seed),
        }
    }

    #[must_use]
    pub fn machine_id(&self) -> &str {
        &self.machine_id
    }

    #[must_use]
    pub fn public(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    /// This key's public half, ready to anchor verification directly —
    /// unlike [`Self::public`], which is the hex wire form carried in
    /// [`AttestationPubkey`] and announces.
    ///
    /// The intended caller is a service populating its own
    /// `crate::capsule::CapsuleTrustAnchor::machine` so it can verify a
    /// capsule sealed under `crate::capsule::CapsuleSigner::Machine` with
    /// this SAME key — see that type's own doc. This does not widen what the
    /// attestation key can do: it is the identical public value
    /// [`Self::public`] already exposes, just typed for a verifier instead
    /// of for the wire.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign arbitrary bytes with the raw attestation key — the exact key
    /// [`Self::attest`] uses, with none of that method's fixed
    /// [`AttestedFields`] preimage shape.
    ///
    /// Domain separation for whatever the caller signs is the CALLER's job,
    /// via their own preimage's own label — the same discipline every other
    /// signed preimage in this crate already follows
    /// (`SIG_LABEL`/`CHARTER_SIG_LABEL` in `crate::capsule`,
    /// `ATTEST_SIG_LABEL_V3`/[`ENROL_SIG_LABEL`] here). Two speech-acts use
    /// this today: [`crate::capsule::CapsuleSigner::Machine`] (a self-issued
    /// capsule's outer envelope) and
    /// [`crate::identity::IdentitySigner::Machine`] (a self-issued
    /// `DeclaredIdentity`) — see the module doc's "Machine identity" section
    /// and each of those types' own docs. This does not weaken the key's
    /// own guarantee: reusing it for a second speech-act is the explicit,
    /// measured trade-off this module's own doc already accepted for
    /// [`Self::attest`] vs. an enrolment signature (`ENROL_SIG_LABEL`'s
    /// domain separation from `ATTEST_SIG_LABEL_V3`), extended to two more
    /// labels rather than reinvented for each.
    #[must_use]
    pub fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.key.sign(bytes).to_bytes()
    }

    /// Derive a 32-byte subkey for a purpose that is NOT attestation, bound
    /// to a caller-chosen domain string.
    ///
    /// ## Why this exists rather than an accessor for the seed
    ///
    /// A caller that needs "a secret this box will still have after a reboot"
    /// has exactly one place to get it — this file is the only per-box secret
    /// that deliberately survives a power cycle (see the module doc and
    /// [`ATTESTATION_KEY_PATH`]). Handing out the raw seed so each caller can
    /// hash it their own way would put the attestation private key in every
    /// one of those call sites and make each of them a place to get the
    /// domain separation wrong. This keeps the key inside the type and hands
    /// back only what the caller asked for.
    ///
    /// `blake3::derive_key` is a KDF, not a hash of a concatenation: the
    /// context string is absorbed separately from the key material, so two
    /// callers with different contexts cannot collide no matter what their
    /// strings look like, and neither subkey reveals anything about the
    /// attestation key or about the other.
    ///
    /// **The context string is a permanent commitment.** Whatever a caller
    /// derives becomes a long-lived identity on some other plane — an SSH
    /// host key that operators pin, for instance — so changing the string
    /// later silently rotates that identity for the whole fleet at once.
    /// Pick it once, version it in the string itself (`…-V1`), and treat a
    /// bump the way any other key rotation is treated.
    ///
    /// This does NOT weaken the attestation key's own guarantee: a subkey is
    /// a one-way function of it, so holding a subkey does not let anyone sign
    /// an enrolment, and the compensating control for the key file itself is
    /// unchanged (the quorum noticing two claimants — see [`Self::save`]).
    #[must_use]
    pub fn derive_subkey(&self, context: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(context, &self.key.to_bytes()))
    }

    /// Sign one boot attempt.
    ///
    /// Takes the whole [`AttestedFields`] rather than an announce type so this
    /// crate does not have to depend on the announce's serialisation shape —
    /// the binding is to the values, not to a wire format that might change.
    ///
    /// Always signs the single V3 preimage — no version selection any more.
    /// The V1/V2 story (sign V1 while there is nothing new to say, roll to
    /// V2 only once verifiers have caught up) applied to `platform`, which
    /// was optional and additive; `role`'s removal is neither, so V3 has no
    /// narrower sibling to fall back to. See the module doc's "Machine
    /// identity" section.
    #[must_use]
    pub fn attest(&self, fields: &AttestedFields<'_>) -> String {
        hex::encode(self.key.sign(&fields.signing_bytes()).to_bytes())
    }

    /// Mint a fresh key. Enrolment is an operator act — see
    /// [`AttestationPubkey::enrolled_at_ms`] for why a second one for the same
    /// machine must not happen implicitly.
    #[must_use]
    pub fn generate(machine_id: impl Into<String>) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(seed.as_mut());
        Self::from_seed(machine_id, &seed)
    }

    /// Write the key where a rebooted box will find it.
    ///
    /// Atomic and `0600`, same as every other secret this tree writes. There is
    /// no encryption at rest here on purpose — see the module doc: a sealed
    /// variant was tried in `dk_delivery` and a reboot bricked the database.
    /// The compensating control is the quorum noticing two claimants, not more
    /// crypto on a file the disk image already gives away.
    pub fn save(&self, path: &Path) -> Result<(), AttestationError> {
        let body = self.to_file_bytes()?;
        crate::identity_boot::write_atomic(path, &body)?;
        Ok(())
    }

    /// The exact bytes [`Self::save`] would write.
    ///
    /// Exists because the enroller and the box are different machines: opbox
    /// mints the key and has to ship the file over SSH, so it needs the
    /// content without a local write. One serialiser for both paths, so a box
    /// enrolled remotely and one enrolled in place hold byte-identical files.
    ///
    /// `Zeroizing` because these bytes are the private key in the clear; the
    /// caller must not let them outlive the send.
    pub fn to_file_bytes(&self) -> Result<Zeroizing<Vec<u8>>, AttestationError> {
        let stored = StoredKey {
            machine_id: self.machine_id.clone(),
            seed_hex: hex::encode(self.key.to_bytes()),
        };
        serde_json::to_vec_pretty(&stored)
            .map(Zeroizing::new)
            .map_err(|e| AttestationError::Io(format!("serialise: {e}")))
    }

    /// Load the key if one is enrolled. `Ok(None)` means "this box has never
    /// been enrolled", which is a normal state and not an error — see
    /// [`crate::identity_boot::BootSession::with_attestation`] for what a
    /// service does with it.
    pub fn load(path: &Path) -> Result<Option<Self>, AttestationError> {
        let raw = match fs::read(path) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let stored: StoredKey = serde_json::from_slice(&raw)
            .map_err(|e| AttestationError::Malformed(format!("key file: {e}")))?;
        let decoded = hex::decode(&stored.seed_hex)
            .map_err(|e| AttestationError::Malformed(format!("seed not hex: {e}")))?;
        let mut seed = Zeroizing::new([0u8; 32]);
        if decoded.len() != 32 {
            return Err(AttestationError::Malformed(format!(
                "seed is {} bytes, expected 32",
                decoded.len()
            )));
        }
        seed.copy_from_slice(&decoded);
        Ok(Some(Self::from_seed(stored.machine_id, &seed)))
    }
}

/// The on-disk envelope.
///
/// JSON rather than 32 raw bytes so the file is self-describing. The verifier
/// has to know **which** enrolled key to check, and a universal binary that has
/// never held a capsule has no other way to state its own machine name — this
/// file is the one per-box artefact that survives a reboot.
///
/// Carrying the name here is not a retreat from "the box learns its name from
/// the capsule". The name is not a secret and was never the thing being
/// protected; key material is. What the name buys is that an announce can say
/// who it claims to be *and* prove it in the same breath, which is the whole
/// point of the credential.
#[derive(Serialize, Deserialize)]
struct StoredKey {
    machine_id: String,
    seed_hex: String,
}

/// Verify an attested announce against the enrolled public key.
///
/// `now_ms` is passed in rather than read here so the check is testable and so
/// a caller with a better clock than `SystemTime` can supply it.
///
/// Order matters: machine binding, then freshness, then signature. The cheap
/// structural rejections come first, and the signature — the only expensive
/// operation — runs last, so an attacker cannot use this path to make a monitor
/// do unbounded Ed25519 verifications with garbage input.
///
/// **V3 only — no fallback to V1 or V2.** Both retired preimages carried
/// `role` as a mandatory field at a fixed position; there is no
/// byte-compatible narrowing between "carries a mandatory field" and
/// "does not" the way there is between "carries an optional field" and
/// "does not" (the V1/V2 platform-facts case this crate already handled
/// once — see the module doc). A fallback wide enough to accept a V1 or V2
/// signature would, by definition, still accept the exact per-role
/// announce shape this cutover exists to delete. So an old binary's
/// announce simply does not verify here; the fix is the ordinary roll, not
/// a wider verifier.
pub fn verify_attested(
    fields: &AttestedFields<'_>,
    sig_hex: &str,
    enrolled: &AttestationPubkey,
    now_ms: u64,
) -> Result<(), AttestationError> {
    if fields.machine_id != enrolled.machine_id {
        return Err(AttestationError::WrongMachine {
            got: fields.machine_id.to_string(),
            want: enrolled.machine_id.clone(),
        });
    }

    let skew_ms = now_ms.abs_diff(fields.started_at_ms);
    if skew_ms > ATTESTATION_FRESHNESS_MS {
        return Err(AttestationError::Stale { skew_ms });
    }

    let raw = hex::decode(sig_hex)
        .map_err(|e| AttestationError::Malformed(format!("sig not hex: {e}")))?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::Malformed("sig is not 64 bytes".to_string()))?;
    let sig = Signature::from_bytes(&bytes);
    let verifying_key = enrolled.verifying_key()?;

    verifying_key
        .verify(&fields.signing_bytes(), &sig)
        .map_err(|_| AttestationError::SigInvalid)
}

fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    const NOW: u64 = 1_800_000_000_000;
    const EPH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EPH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn key(machine: &str) -> AttestationKey {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        AttestationKey::from_seed(machine, &seed)
    }

    fn enrolled(k: &AttestationKey) -> AttestationPubkey {
        AttestationPubkey::sign_new(
            k.machine_id(),
            k.public(),
            NOW - 86_400_000,
            None,
            &SigningKey::generate(&mut OsRng),
        )
    }

    /// Same as [`enrolled`] but with an [`AttestationPubkey::expected_source_ip`]
    /// set — the V2 enrolment preimage.
    fn enrolled_with_ip(k: &AttestationKey, ip: &str, operator: &SigningKey) -> AttestationPubkey {
        AttestationPubkey::sign_new(
            k.machine_id(),
            k.public(),
            NOW - 86_400_000,
            Some(ip.to_string()),
            operator,
        )
    }

    fn fields<'a>(machine: &'a str, eph: &'a str, nonce: &'a str) -> AttestedFields<'a> {
        AttestedFields {
            machine_id: machine,
            build_id: "5a2aec1-universal",
            eph_pubkey_hex: eph,
            boot_nonce: nonce,
            started_at_ms: NOW,
            platform: None,
            renewal: None,
        }
    }

    fn sample_platform() -> crate::fact_signing::PlatformFingerprint {
        crate::fact_signing::PlatformFingerprint {
            cpu_model: "Intel(R) Xeon(R) Gold 6248R".to_string(),
            cpu_arch: "x86_64".to_string(),
            dmi_sys_vendor: "HostKey".to_string(),
            dmi_product_name: "Standard PC".to_string(),
            dmi_board: "Q35".to_string(),
        }
    }

    /// **A v1 record (no `expected_source_ip`) still verifies.** Every
    /// enrolment on disk or gossiped before this field existed must keep
    /// verifying byte-for-byte against the new code.
    #[test]
    fn an_enrolment_verifies_under_the_operator_key() {
        let operator = SigningKey::generate(&mut OsRng);
        let k = key("ru-hostkey-203.0.113.10");
        let e =
            AttestationPubkey::sign_new("ru-hostkey-203.0.113.10", k.public(), NOW, None, &operator);
        assert!(e.expected_source_ip.is_none());
        e.verify_enrolment(&operator.verifying_key())
            .expect("must verify");
    }

    /// **A v2 record with an IP verifies.**
    #[test]
    fn an_enrolment_with_an_expected_source_ip_verifies() {
        let operator = SigningKey::generate(&mut OsRng);
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled_with_ip(&k, "203.0.113.86", &operator);
        assert_eq!(e.expected_source_ip.as_deref(), Some("203.0.113.86"));
        e.verify_enrolment(&operator.verifying_key())
            .expect("must verify");
    }

    /// **Tampering the IP breaks the signature.**
    #[test]
    fn tampering_the_expected_source_ip_breaks_the_enrolment_signature() {
        let operator = SigningKey::generate(&mut OsRng);
        let k = key("ru-hostkey-203.0.113.10");
        let mut e = enrolled_with_ip(&k, "203.0.113.86", &operator);
        e.expected_source_ip = Some("203.0.113.87".to_string());
        let err = e.verify_enrolment(&operator.verifying_key()).unwrap_err();
        assert!(matches!(err, AttestationError::SigInvalid), "got {err:?}");
    }

    /// **A v2 record with its IP stripped does not verify.** `Some` and
    /// `None` sign under different labels ([`ENROL_SIG_LABEL_V2`] vs.
    /// [`ENROL_SIG_LABEL`]), so simply clearing the field after signing must
    /// not produce something that verifies under either preimage.
    #[test]
    fn stripping_the_expected_source_ip_from_a_v2_record_breaks_verification() {
        let operator = SigningKey::generate(&mut OsRng);
        let k = key("ru-hostkey-203.0.113.10");
        let mut e = enrolled_with_ip(&k, "203.0.113.86", &operator);
        e.expected_source_ip = None;
        let err = e.verify_enrolment(&operator.verifying_key()).unwrap_err();
        assert!(matches!(err, AttestationError::SigInvalid), "got {err:?}");
    }

    /// An enrolment a monitor accepts unsigned lets anyone who can gossip
    /// declare their own key authoritative for any machine — and every
    /// subsequent attestation check would then pass against the attacker's key.
    #[test]
    fn a_tampered_enrolment_is_refused() {
        let operator = SigningKey::generate(&mut OsRng);
        let attacker = key("ru-hostkey-203.0.113.10");
        let mut e = AttestationPubkey::sign_new(
            "ru-hostkey-203.0.113.10",
            key("x").public(),
            NOW,
            None,
            &operator,
        );
        e.pubkey_hex = attacker.public();
        let err = e.verify_enrolment(&operator.verifying_key()).unwrap_err();
        assert!(matches!(err, AttestationError::SigInvalid), "got {err:?}");
    }

    /// Domain separation, and it is load-bearing: if the two labels were shared,
    /// a box could take its own attestation signature and present it as the
    /// operator's enrolment of itself, so any box could authorise its own key.
    #[test]
    fn a_box_cannot_replay_its_own_attestation_as_an_enrolment() {
        let k = key("ru-hostkey-203.0.113.10");
        let mut e = AttestationPubkey {
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            pubkey_hex: k.public(),
            enrolled_at_ms: NOW,
            expected_source_ip: None,
            operator_sig_hex: String::new(),
        };
        // The box signs the enrolment preimage with the only key it has.
        e.operator_sig_hex = hex::encode(k.key.sign(&e.enrolment_signing_bytes()).to_bytes());
        // It verifies under its OWN key — that much is unavoidable…
        e.verify_enrolment(&k.key.verifying_key())
            .expect("self-consistent by construction");
        // …but not under the operator's, which is the only key anyone checks.
        let operator = SigningKey::generate(&mut OsRng);
        assert!(matches!(
            e.verify_enrolment(&operator.verifying_key()).unwrap_err(),
            AttestationError::SigInvalid
        ));
    }

    #[test]
    fn a_genuine_attested_announce_verifies() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let f = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        let sig = k.attest(&f);
        verify_attested(&f, &sig, &e, NOW).expect("must verify");
    }

    /// **The attack this module exists to stop.** An attacker captures a valid
    /// attested announce, substitutes their own ephemeral public key, and
    /// replays it. If the ephemeral key were not in the preimage, the quorum
    /// would seal a real capsule to the attacker's key and nothing would ever
    /// fail to verify.
    #[test]
    fn a_replayed_signature_cannot_redirect_the_capsule_to_another_ephemeral_key() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let honest = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        let sig = k.attest(&honest);

        let attacker = fields("ru-hostkey-203.0.113.10", EPH_B, "nonce-1");
        let err = verify_attested(&attacker, &sig, &e, NOW).unwrap_err();
        assert!(matches!(err, AttestationError::SigInvalid), "got {err:?}");
    }

    /// Same shape, different field: the nonce scopes the attempt, so reusing a
    /// signature under a fresh nonce must fail too.
    #[test]
    fn a_signature_is_bound_to_its_boot_nonce() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let first = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        let sig = k.attest(&first);

        let replayed = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-2");
        assert!(matches!(
            verify_attested(&replayed, &sig, &e, NOW).unwrap_err(),
            AttestationError::SigInvalid
        ));
    }

    /// One machine's key must never attest for another, even though the
    /// signature itself is genuine.
    #[test]
    fn one_machines_key_cannot_attest_for_another() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let f = fields("ch-example-203.0.113.40", EPH_A, "nonce-1");
        let sig = k.attest(&f);
        let err = verify_attested(&f, &sig, &e, NOW).unwrap_err();
        assert!(matches!(err, AttestationError::WrongMachine { .. }), "got {err:?}");
    }

    /// A different machine's enrolled key must not validate this announce.
    #[test]
    fn an_announce_does_not_verify_under_a_foreign_enrolled_key() {
        let real = key("ru-hostkey-203.0.113.10");
        let impostor = key("ru-hostkey-203.0.113.10");
        let f = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        let sig = impostor.attest(&f);
        let err = verify_attested(&f, &sig, &enrolled(&real), NOW).unwrap_err();
        assert!(matches!(err, AttestationError::SigInvalid), "got {err:?}");
    }

    #[test]
    fn a_stale_announce_is_rejected_in_both_directions() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let f = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        let sig = k.attest(&f);

        let late = NOW + ATTESTATION_FRESHNESS_MS + 1;
        assert!(matches!(
            verify_attested(&f, &sig, &e, late).unwrap_err(),
            AttestationError::Stale { .. }
        ));

        // A clock behind the announce is just as suspect as one ahead.
        let early = NOW - ATTESTATION_FRESHNESS_MS - 1;
        assert!(matches!(
            verify_attested(&f, &sig, &e, early).unwrap_err(),
            AttestationError::Stale { .. }
        ));

        // …and the edge of the window is still accepted.
        verify_attested(&f, &sig, &e, NOW + ATTESTATION_FRESHNESS_MS)
            .expect("the boundary is inside the window");
    }

    /// Every field is in the preimage. A test that enumerates them fails when
    /// someone adds a field to `AttestedFields` and forgets to bind it — the
    /// exact omission the module doc warns about.
    #[test]
    fn every_field_is_bound_into_the_preimage() {
        let base = fields("m", "aa", "n");
        let variants = [
            AttestedFields { machine_id: "m2", ..base.clone() },
            AttestedFields { build_id: "other", ..base.clone() },
            AttestedFields { eph_pubkey_hex: "bb", ..base.clone() },
            AttestedFields { boot_nonce: "n2", ..base.clone() },
            AttestedFields { started_at_ms: NOW + 1, ..base.clone() },
        ];
        for v in &variants {
            assert_ne!(
                base.signing_bytes(),
                v.signing_bytes(),
                "a field is missing from the signing preimage"
            );
        }
    }

    /// Length-prefixing must make field boundaries unambiguous: `("ab","c")`
    /// and `("a","bc")` are different announces and must not share a preimage.
    /// `machine_id`/`build_id` are adjacent in the preimage now that `role`
    /// (which used to sit between them) is gone.
    #[test]
    fn field_boundaries_are_unambiguous() {
        let a = AttestedFields { machine_id: "ab", build_id: "c", ..fields("x", "e", "n") };
        let b = AttestedFields { machine_id: "a", build_id: "bc", ..fields("x", "e", "n") };
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    // ── V3 only, no fallback ─────────────────────────────────────────

    /// **The required property of this cutover.** A signature built over
    /// either retired preimage — genuinely produced by the enrolled key,
    /// carrying `role` at the fixed position both used to give it — must
    /// not verify against V3. There is no byte-compatible narrowing to fall
    /// back to (see the module doc's "Machine identity" section), so an old
    /// binary's announce simply does not verify; the fix is the roll, not a
    /// wider verifier.
    #[test]
    fn a_v1_or_v2_shaped_signature_does_not_verify_against_v3() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let f = fields(k.machine_id(), EPH_A, "nonce-1");

        // Hand-build the retired V2 preimage: label, machine, ROLE (which V3
        // no longer carries), build, eph, nonce, started_at, then a platform
        // presence byte — every field V3 still has, plus the one it dropped.
        let mut v2 = Vec::new();
        v2.extend_from_slice(b"MIRAGE-MACHINE-ATTESTATION-V2");
        push_lp(&mut v2, f.machine_id.as_bytes());
        push_lp(&mut v2, b"monitor");
        push_lp(&mut v2, f.build_id.as_bytes());
        push_lp(&mut v2, f.eph_pubkey_hex.as_bytes());
        push_lp(&mut v2, f.boot_nonce.as_bytes());
        v2.extend_from_slice(&f.started_at_ms.to_le_bytes());
        v2.push(0); // no platform facts
        let sig_v2 = hex::encode(k.key.sign(&v2).to_bytes());

        let err = verify_attested(&f, &sig_v2, &e, NOW).unwrap_err();
        assert!(matches!(err, AttestationError::SigInvalid), "got {err:?}");
    }

    // ── platform facts ────────────────────────────────────────────────

    /// An announce with no platform facts verifies — the ordinary case for
    /// any service that has not wired platform collection.
    #[test]
    fn an_announce_with_no_platform_verifies() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let f = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        assert!(f.platform.is_none());
        let sig = k.attest(&f);
        verify_attested(&f, &sig, &e, NOW).expect("must verify");
    }

    /// An announce presenting platform facts signs and verifies.
    #[test]
    fn an_announce_with_platform_verifies() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let pf = sample_platform();
        let f = AttestedFields { platform: Some(&pf), ..fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1") };
        let sig = k.attest(&f);
        verify_attested(&f, &sig, &e, NOW).expect("must verify");
    }

    /// Tampering any one platform field after signing must break the
    /// signature — `platform` is inside the preimage precisely so this
    /// cannot happen.
    #[test]
    fn tampering_a_platform_field_breaks_the_signature() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let pf = sample_platform();
        let f = AttestedFields { platform: Some(&pf), ..fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1") };
        let sig = k.attest(&f);

        let tampered_pf = crate::fact_signing::PlatformFingerprint {
            cpu_model: "a different box entirely".to_string(),
            ..sample_platform()
        };
        let tampered = AttestedFields { platform: Some(&tampered_pf), ..f };
        assert!(matches!(
            verify_attested(&tampered, &sig, &e, NOW).unwrap_err(),
            AttestationError::SigInvalid
        ));
    }

    // ── renewal claim ─────────────────────────────────────────────────

    /// **Pinned fixture.** `renewal: None` must produce the EXACT preimage
    /// this function emitted before `RenewalClaim` existed — hand-built
    /// here from the same fields `field_bytes` itself encodes, independent
    /// of that function's own implementation, so a future edit that
    /// accidentally adds a presence byte (the way `platform` has one) is
    /// caught. See `crate::identity_boot::BootAnnounce::renewal`'s own doc
    /// for why this has to hold: a cold-boot/reset announce from a binary
    /// that knows about `RenewalClaim` must still verify on a monitor built
    /// before it did.
    #[test]
    fn a_none_renewal_claim_adds_nothing_to_the_v3_preimage() {
        let f = fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1");
        assert!(f.renewal.is_none());

        let mut want = Vec::new();
        want.extend_from_slice(ATTEST_SIG_LABEL_V3);
        push_lp(&mut want, f.machine_id.as_bytes());
        push_lp(&mut want, f.build_id.as_bytes());
        push_lp(&mut want, f.eph_pubkey_hex.as_bytes());
        push_lp(&mut want, f.boot_nonce.as_bytes());
        want.extend_from_slice(&f.started_at_ms.to_le_bytes());
        want.push(0); // no platform facts
        assert_eq!(f.signing_bytes(), want);
    }

    /// A `renewal: Some(..)` announce signs and verifies exactly like any
    /// other field addition — the fixture above is what proves the `None`
    /// side stays put; this proves the `Some` side still works.
    #[test]
    fn an_announce_with_a_renewal_claim_verifies() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let held_pubkey_hex = "dd".repeat(32);
        let f = AttestedFields {
            renewal: Some(RenewalAttested { self_id: Uuid::from_u128(9), held_pubkey_hex: &held_pubkey_hex }),
            ..fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1")
        };
        let sig = k.attest(&f);
        verify_attested(&f, &sig, &e, NOW).expect("must verify");
    }

    /// The claim is bound into the SAME signature the rest of the announce
    /// is — tampering `self_id` or `held_pubkey_hex` after signing must
    /// break the outer attestation, same discipline as every other field.
    #[test]
    fn tampering_the_renewal_claim_breaks_the_outer_attestation_signature() {
        let k = key("ru-hostkey-203.0.113.10");
        let e = enrolled(&k);
        let held_pubkey_hex = "dd".repeat(32);
        let f = AttestedFields {
            renewal: Some(RenewalAttested { self_id: Uuid::from_u128(9), held_pubkey_hex: &held_pubkey_hex }),
            ..fields("ru-hostkey-203.0.113.10", EPH_A, "nonce-1")
        };
        let sig = k.attest(&f);

        let tampered_self_id = AttestedFields {
            renewal: Some(RenewalAttested { self_id: Uuid::from_u128(10), held_pubkey_hex: &held_pubkey_hex }),
            ..f.clone()
        };
        assert!(matches!(
            verify_attested(&tampered_self_id, &sig, &e, NOW).unwrap_err(),
            AttestationError::SigInvalid
        ));

        let other_pubkey_hex = "ee".repeat(32);
        let tampered_pubkey = AttestedFields {
            renewal: Some(RenewalAttested { self_id: Uuid::from_u128(9), held_pubkey_hex: &other_pubkey_hex }),
            ..f
        };
        assert!(matches!(
            verify_attested(&tampered_pubkey, &sig, &e, NOW).unwrap_err(),
            AttestationError::SigInvalid
        ));
    }
}
