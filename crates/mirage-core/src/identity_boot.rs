//! `Unidentified → announce → capsule → Identified` — one boot state machine,
//! shared by every Mirage service.
//!
//! A universal binary starts with no identity at all. It generates an X25519
//! keypair and a boot nonce **in RAM**, publishes the public half as an
//! *announce*, and waits for an issuer (opbox today, the mesh quorum later) to
//! seal a [`crate::capsule::MachineCapsule`] to it. Nothing is written to disk
//! in that exchange except the announce itself and the sealed capsule, both
//! under `/run` — tmpfs, so both die with the box.
//!
//! The one thing it does know is **which box it is running on**, from the
//! enrolment at [`crate::attestation::ATTESTATION_KEY_PATH`] — and it can prove
//! it, which is the whole reason that file exists. A box with no enrolment does
//! not announce; see [`BootSession::for_service`]. That is not a per-box
//! constant creeping back into the binary: one build still serves the fleet,
//! and the name lives in the operator-written enrolment file next to the key
//! that proves it, never in the binary and never in a unit `Environment=`.
//!
//! The shape is copied deliberately from db-worker's DK wait
//! (`await_dk_over_wire`), which has been in production since custody W8: a
//! **fresh ephemeral key and a fresh boot nonce per attempt**, so a capsule
//! that arrives late for a previous attempt fails its AAD instead of being
//! accepted out of order. Retry is the caller's loop — drop the session and
//! make a new one.
//!
//! Why a file and not just the wire: the warden is zero-network by design and
//! can never receive a wire-delivered capsule, and a bare box has no wire at
//! all until mshd is up. The tmpfs pair works for every service in every state,
//! and the wire path (once a monitor is reachable) is an optimisation layered
//! on top, not a replacement.
//!
//! ## What this module refuses
//!
//! Unsealing is not the same as trusting. [`BootSession::accept`] additionally
//! proves the capsule is internally coherent before any service acts on it:
//! the enclosed `DeclaredIdentity` verifies under the operator key, it names
//! the same box/role/mesh as the capsule, the private keys actually match the
//! public ones the operator signed, and any enclosed charter verifies too.
//! Seven services would otherwise each have to remember to do this — the baked
//! path made exactly this cross-check by hand in every one of them.
//!
//! ## The machine-scoped store is a third thing, not a variant of either
//!
//! [`machine_capsule_path`] / [`write_machine_capsule_file`] /
//! [`read_machine_capsule_file`] persist the ALREADY-UNSEALED, already-
//! [`check_coherent`]-checked [`crate::capsule::MachineCapsule`] itself —
//! not the announce (public, unsigned-by-construction — see
//! [`machine_announce_path`], which is machine-scoped the same way), not
//! the sealed capsule (single-use, bound to one boot's ephemeral key by its
//! AAD). It replaces the eight per-role rest-capsule caches this module
//! used to keep (`/run/mirage/<role>/rest_capsule`) with the single store
//! `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §2
//! describes — one file the keeper (`mirage-warden`) writes once per
//! machine reset, and every OTHER service can read across its own
//! restarts instead of maintaining an independent cache. Whoever reads it
//! back still has to call [`check_coherent`] before trusting it, exactly
//! like any other delivery — this module only owns where it lives and how
//! it is written and read; the keeper owns the policy that decides when
//! writing a fresh one is warranted.
//!
//! ## `take_machine_slice` — the shared consumer entry point
//!
//! [`take_machine_slice`] is what every service (other than the keeper
//! itself) calls instead of running its own announce/wait loop: dial
//! [`crate::local_endpoint::LocalChannel::MachineIdentity`], ask for this
//! role's slice, and wait — **without a deadline**. See its own doc for why
//! a bounded wait would reintroduce exactly the per-service race this plan
//! deletes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::capsule::{
    unseal_capsule, CapsuleError, CapsulePeer, CapsuleSigner, CapsuleTrustAnchor, MachineAnchor,
    MachineCapsule, SealedCapsule,
};
use crate::crypto::KeyPair;
use crate::identity::{IdentityError, ServiceRole};
use crate::local_endpoint::LocalChannel;
use crate::machine_identity_query::{
    MachineIdentityRequest, MachineIdentityResponse, MachineSlice, RenewalStallState,
};

/// tmpfs directory the announce/capsule pair lives in. Already used by the
/// warden's operator-command relay, so the mount and its ownership are an
/// established part of the box layout.
pub const RUNTIME_DIR: &str = "/run/mirage";

/// Default freshness window for a sealed capsule (unix-ms skew, either way).
pub const DEFAULT_MAX_SKEW_MS: u64 = 60_000;

/// How long one [`BootSession`] stays open waiting to be answered.
///
/// This has to exceed the issuer's whole round trip — read the announce, seal
/// against it, deliver it back — or the session rotates mid-flight and the
/// arriving capsule is bound to a nonce nobody is listening for any more.
/// Measured on ch-124 during the first live capsule boot: with a 30 s window
/// and a 30 s reconcile tick, every single delivery lost the race and was
/// rejected as `BindingMismatch` — the binding did its job, the impatience was
/// the bug.
///
/// Rotating the ephemeral key buys nothing while an offer is simply unanswered
/// (it never left this process), so waiting longer costs nothing. What it must
/// still do is rotate promptly after a *rejected* capsule, which is the case
/// that could be someone probing.
pub const DEFAULT_SESSION_WINDOW_MS: u64 = 300_000;

/// How often to look for a delivered capsule inside one session.
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 500;

/// Backoff before opening a fresh session after one lapsed unanswered.
pub const DEFAULT_SESSION_BACKOFF_MS: u64 = 5_000;

/// Default lead time before `not_after_ms` at which renewal should start —
/// generous enough that a failed renewal has several retries left while the
/// current capsule is still valid.
pub const DEFAULT_RENEW_LEAD_MS: u64 = 15 * 60_000;

/// Width of the per-(machine, role) spread added on top of
/// [`DEFAULT_RENEW_LEAD_MS`].
///
/// ## Why a fleet with no spread cannot recover one
///
/// A capsule's `not_after_ms` is `issued_at_ms + TTL`, so **the moment a
/// capsule is issued becomes the anchor for every expiry that follows it**.
/// Everything that renews in the same instant therefore expires in the same
/// instant, one TTL later, and keeps doing so — there is nothing in a fixed
/// lead to pull two roles apart once they have converged.
///
/// Measured on `ch-example-203.0.113.41`, 2026-08-11: before an issuer outage
/// sentry expired at 11:56 and node at 12:26, half an hour apart. The outage
/// held both past expiry, both were sealed inside the same recovery minute,
/// and their expiries came out **37 seconds** apart. Fleet-wide the
/// non-warden roles collapsed into a 155-second band. `mirage-warden` escaped
/// only because its window happened to miss the outage.
///
/// So one synchronised failure permanently synchronises the fleet, and the
/// next issuer outage of any length takes every role at once instead of the
/// fraction whose window it actually covered.
///
/// The jitter is deterministic in `(machine_id, role)` — a restart must not
/// re-roll it, or a crash-looping service would walk its own schedule around
/// and re-converge with someone else. It only ever ADDS to the lead, so no
/// service ever gets a *shorter* safety margin than the default; the cost is
/// at most this much unused capsule life.
pub const DEFAULT_RENEW_JITTER_SPAN_MS: u64 = 2 * 60 * 60_000;

/// Deterministic `[0, span_ms)` offset for one `(machine_id, role)` pair.
///
/// Domain-separated so this hash can never collide with another use of the
/// same two strings elsewhere in the codebase.
pub fn renew_jitter_ms(machine_id: &str, role: &str, span_ms: u64) -> u64 {
    if span_ms == 0 {
        return 0;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"mirage-renew-jitter-v1");
    h.update(machine_id.as_bytes());
    h.update(&[0u8]);
    h.update(role.as_bytes());
    let digest = h.finalize();
    let mut b = [0u8; 8];
    b.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(b) % span_ms
}

/// The lead this `(machine, role)` should use, clamped so it can never
/// swallow the capsule it is meant to renew.
///
/// Without the clamp a short-TTL capsule (the TTL is operator-settable via
/// `MIRAGE_CAPSULE_TTL_SECS`) would meet a lead longer than its own life, the
/// "sleep until due" loop would fall straight through on every pass, and the
/// service would hammer the issuer continuously instead of renewing once.
/// Half the remaining validity is the ceiling: it keeps the renewal in the
/// back half of the capsule's life whatever the TTL is.
pub fn renew_lead_for(machine_id: &str, role: &str, not_after_ms: u64, now: u64) -> u64 {
    let wanted =
        DEFAULT_RENEW_LEAD_MS + renew_jitter_ms(machine_id, role, DEFAULT_RENEW_JITTER_SPAN_MS);
    let remaining = not_after_ms.saturating_sub(now);
    wanted.min(remaining / 2)
}

#[derive(Debug, Error)]
pub enum BootError {
    #[error("capsule io: {0}")]
    Io(#[from] io::Error),
    #[error("capsule json: {0}")]
    Json(String),
    #[error(transparent)]
    Capsule(#[from] CapsuleError),
    #[error("capsule identity does not verify: {0}")]
    Identity(#[from] IdentityError),
    #[error("capsule is internally inconsistent: {0}")]
    Incoherent(String),
    #[error("capsule already expired on arrival")]
    Expired,
}

/// What a service publishes while it has no identity.
///
/// Public material only: an ephemeral X25519 public key that exists for this
/// boot, the nonce that scopes it, and enough labelling for the issuer to know
/// which escrow row to seal. An observer who reads this learns nothing it could
/// not learn from the process list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootAnnounce {
    /// Which box this is, from the enrolled attestation key — the one per-box
    /// artefact that survives a reboot.
    ///
    /// This does not weaken capsule-only. The name is not a secret and never
    /// was what capsule-only protected; key material is. What it buys is that
    /// an announce states who it claims to be *and* proves it in the same
    /// breath, which is the entire point of the credential. It also makes the
    /// `machine_id` check in the capsule's AAD strict on every boot instead of
    /// only on renewals.
    pub machine_id: String,
    /// Build this binary was cut from — lets the issuer refuse to identify a
    /// binary it does not recognise.
    pub build_id: String,
    /// X25519 public key the capsule must be sealed to (hex, 64 chars).
    pub eph_pubkey_hex: String,
    /// Scopes this attempt. A capsule for a different nonce fails its AAD.
    pub boot_nonce: String,
    /// Unix-ms this attempt started, for the issuer's staleness bookkeeping.
    pub started_at_ms: u64,
    /// Platform facts this boot presents, for admission gate 4 ("platform
    /// facts match the last `box_profile`",
    /// `mirage2monitor::admission::admission_verdict`). `None` when the
    /// caller never attached any via [`BootSession::with_platform`] — a
    /// real, explicit absence (an old build, or a service that has not
    /// wired platform collection yet), never a placeholder that secretly
    /// means "skip this gate".
    ///
    /// `#[serde(default)]` so an announce written by a binary built before
    /// this field existed still deserialises — the same reason
    /// `crate::machine_park::MachineParkFact`'s additive fields carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<crate::fact_signing::PlatformFingerprint>,
    /// A claim, riding on THIS announce, that the box already holds a live
    /// identity and is asking to RENEW it — not asking to be admitted as if
    /// freshly reset. See [`RenewalClaim`]'s own doc for the full shape and
    /// the threat model it closes.
    ///
    /// `None` for every ordinary cold-boot/reset announce — the only value
    /// a box with no stored identity, or an operator-forced
    /// `OpenDeliveryWindow`, may ever send (see `mirage-warden`'s
    /// `machine_store` module for which caller sends what).
    ///
    /// `#[serde(default)]` for the same reason `platform` carries it: an
    /// announce written by a binary built before this field existed must
    /// still deserialise. See [`crate::attestation::AttestedFields::renewal`]
    /// for why a `None` here also leaves the ATTESTED bytes untouched, not
    /// only the wire encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal: Option<RenewalClaim>,
    /// Ed25519 signature by this machine's enrolled attestation key over every
    /// other field, hex — see [`crate::attestation`].
    ///
    /// **Mandatory.** There is no unattested announce: a box that cannot sign
    /// does not publish, it waits and says so. An optional signature would
    /// only degrade into a state the quorum rejects anyway, silently and far
    /// from its cause — where a missing one fails visibly and is repaired by
    /// one operator call that writes a file over SSH, with no reboot.
    pub attestation_sig_hex: String,
}

impl BootAnnounce {
    /// The fields the attestation signature covers.
    ///
    /// Built here rather than at each verifier so there is one place that
    /// decides what the signature covers. A verifier that assembled these by
    /// hand could omit `eph_pubkey_hex` and would then accept a replayed
    /// signature pointing at an attacker's key — the failure the attestation
    /// module's doc calls out as fatal.
    #[must_use]
    pub fn attested_fields(&self) -> crate::attestation::AttestedFields<'_> {
        crate::attestation::AttestedFields {
            machine_id: &self.machine_id,
            build_id: &self.build_id,
            eph_pubkey_hex: &self.eph_pubkey_hex,
            boot_nonce: &self.boot_nonce,
            started_at_ms: self.started_at_ms,
            platform: self.platform.as_ref(),
            renewal: self.renewal.as_ref().map(|r| crate::attestation::RenewalAttested {
                self_id: r.self_id,
                held_pubkey_hex: &r.held_pubkey_hex,
            }),
        }
    }

    /// Verify this announce against the machine's enrolled key.
    pub fn verify_attestation(
        &self,
        enrolled: &crate::attestation::AttestationPubkey,
        now_ms: u64,
    ) -> Result<(), crate::attestation::AttestationError> {
        crate::attestation::verify_attested(
            &self.attested_fields(),
            &self.attestation_sig_hex,
            enrolled,
            now_ms,
        )
    }
}

/// Domain-separation tag for [`RenewalClaim::possession_sig_hex`]'s
/// preimage — a distinct speech act from the attestation signature, so a
/// genuine one of either kind can never be replayed as the other. Same
/// discipline as every other label in this crate (`SIG_LABEL`,
/// `ATTEST_SIG_LABEL_V3`, `CHARTER_SIG_LABEL`, `ENROL_SIG_LABEL`).
const RENEWAL_POSSESSION_LABEL: &[u8] = b"mirage/capsule-renewal-possession/v1";

/// A box's claim, riding inside a [`BootAnnounce`], that it already holds a
/// live [`crate::capsule::MachineCapsule`] and is asking to RENEW it —
/// never a claim to be admitted as if freshly reset.
///
/// ## Why the attestation signature alone cannot make this claim
///
/// `BootAnnounce::attestation_sig_hex` is signed by the box's ENROLLED key
/// ([`crate::attestation::AttestationKey`]), which lives at
/// [`crate::attestation::ATTESTATION_KEY_PATH`] — durable, on disk, and
/// therefore in the hands of anyone who images that disk, live box or not
/// (see that module's own doc: "a disk image therefore yields this key").
/// If renewal were provable with that signature alone, a disk image would
/// be enough, on its own, to claim "I already hold `self_id` X, just extend
/// it" for any `self_id` the imaged box was ever admitted under — exactly
/// the forged-continuity shape admission's reachability gate exists to
/// refuse, with the attacker now supplying the one field that was supposed
/// to rule it out.
///
/// What only a LIVE box has is the [`crate::capsule::MachineCapsule`]
/// itself — `/run/mirage/machine/capsule`, tmpfs, wiped by the very
/// reset/reboot that separates "renewing" from "reset". `possession_sig_hex`
/// is signed by a role-slice signing key drawn from THAT capsule
/// ([`crate::capsule::RoleSlice::signing_privkey`]) — material a disk-only
/// attacker never had, because it was minted by the quorum or the operator
/// and delivered over the wire, never written to durable storage.
///
/// ## What is and is not bound
///
/// `self_id` and `held_pubkey_hex` are folded into the OUTER attestation
/// preimage too (see [`crate::attestation::AttestedFields::renewal`]), so
/// neither can be swapped out from under a genuine `possession_sig_hex`
/// without also breaking `attestation_sig_hex`. `possession_sig_hex` itself
/// binds the same announce fields a second time
/// ([`renewal_possession_bytes`]) — `eph_pubkey_hex`, `boot_nonce`,
/// `started_at_ms`, plus `self_id`/`held_pubkey_hex` — under
/// [`RENEWAL_POSSESSION_LABEL`], so a captured possession signature cannot
/// be replayed against a different boot attempt either.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalClaim {
    /// The `self_id` of the [`crate::capsule::MachineCapsule`] this box
    /// currently holds and is asking to renew.
    pub self_id: Uuid,
    /// Hex-encoded Ed25519 public half of the role-slice signing key
    /// `possession_sig_hex` was produced with — one of the held capsule's
    /// own [`crate::capsule::RoleSlice::signing_pubkey_hex`] values, never
    /// the box's attestation key.
    pub held_pubkey_hex: String,
    /// Signature over [`renewal_possession_bytes`] by the private half of
    /// `held_pubkey_hex`.
    pub possession_sig_hex: String,
}

#[derive(Debug, Error)]
pub enum RenewalClaimError {
    #[error("renewal claim pubkey is malformed: {0}")]
    MalformedPubkey(String),
    #[error("renewal claim signature is malformed: {0}")]
    MalformedSignature(String),
    #[error("renewal claim possession signature does not verify under its own claimed key")]
    SignatureInvalid,
}

/// [`RENEWAL_POSSESSION_LABEL`] plus the shared field encoding
/// [`crate::attestation::AttestedFields::field_bytes`] also uses for the
/// outer attestation preimage — same facts, different label, per
/// [`RenewalClaim`]'s own doc.
fn renewal_possession_bytes(fields: &crate::attestation::AttestedFields<'_>) -> Vec<u8> {
    let mut p = Vec::with_capacity(RENEWAL_POSSESSION_LABEL.len() + 384);
    p.extend_from_slice(RENEWAL_POSSESSION_LABEL);
    p.extend_from_slice(&fields.field_bytes());
    p
}

impl RenewalClaim {
    /// Build and sign a renewal claim for `self_id`, to attach to
    /// `announce` — whose OTHER attested fields (`eph_pubkey_hex`,
    /// `boot_nonce`, `started_at_ms`, `machine_id`, `build_id`, `platform`)
    /// must already be final; `announce.renewal` itself is ignored here,
    /// since that is what this call produces. `signing_key` is a role-slice
    /// signing key from the [`crate::capsule::MachineCapsule`] currently
    /// held for `self_id` — see this type's own doc for why the box's
    /// durable attestation key cannot be used instead.
    #[must_use]
    pub fn sign_for(announce: &BootAnnounce, self_id: Uuid, signing_key: &SigningKey) -> Self {
        let held_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let fields = crate::attestation::AttestedFields {
            renewal: Some(crate::attestation::RenewalAttested {
                self_id,
                held_pubkey_hex: &held_pubkey_hex,
            }),
            ..announce.attested_fields()
        };
        let preimage = renewal_possession_bytes(&fields);
        let possession_sig_hex = hex::encode(signing_key.sign(&preimage).to_bytes());
        Self { self_id, held_pubkey_hex, possession_sig_hex }
    }

    /// Verify this claim's possession signature against `announce`'s OTHER
    /// attested fields. Does **not** check whether `self_id` is actually
    /// the identity a verifier currently holds for this box — that
    /// cross-check belongs to the caller (admission gate 6's own decision,
    /// on the monitor side), since this crate has no notion of "what a
    /// monitor currently holds".
    pub fn verify(&self, announce: &BootAnnounce) -> Result<(), RenewalClaimError> {
        let pubkey_raw = hex::decode(&self.held_pubkey_hex)
            .map_err(|e| RenewalClaimError::MalformedPubkey(e.to_string()))?;
        let pubkey_bytes: [u8; 32] = pubkey_raw
            .try_into()
            .map_err(|_| RenewalClaimError::MalformedPubkey("expected 32 bytes".to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| RenewalClaimError::MalformedPubkey(format!("not on curve: {e}")))?;

        let sig_raw = hex::decode(&self.possession_sig_hex)
            .map_err(|e| RenewalClaimError::MalformedSignature(e.to_string()))?;
        let sig_bytes: [u8; 64] = sig_raw
            .try_into()
            .map_err(|_| RenewalClaimError::MalformedSignature("expected 64 bytes".to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let fields = crate::attestation::AttestedFields {
            renewal: Some(crate::attestation::RenewalAttested {
                self_id: self.self_id,
                held_pubkey_hex: &self.held_pubkey_hex,
            }),
            ..announce.attested_fields()
        };
        let preimage = renewal_possession_bytes(&fields);
        verifying_key
            .verify(&preimage, &signature)
            .map_err(|_| RenewalClaimError::SignatureInvalid)
    }
}

/// One attempt at getting identified. Holds the ephemeral secret in RAM and
/// nowhere else; dropping it invalidates every capsule sealed for it.
pub struct BootSession {
    role: String,
    build_id: String,
    boot_nonce: String,
    eph: KeyPair,
    started_at_ms: u64,
    /// Not optional. A session that cannot attest cannot announce — see
    /// [`BootAnnounce::attestation_sig_hex`].
    attestation: crate::attestation::AttestationKey,
    /// Platform facts to present, if any were attached via
    /// [`Self::with_platform`]. `None` by default — gathering them is the
    /// caller's job (this crate stays platform-collection-agnostic), and a
    /// session that never attaches any announces exactly as it did before
    /// this field existed.
    platform: Option<crate::fact_signing::PlatformFingerprint>,
}

impl BootSession {
    /// Start a fresh attempt: new ephemeral keypair, new boot nonce.
    ///
    /// Callers retry by constructing a new session, never by reusing one — that
    /// is what keeps a late capsule from landing after the state it was sealed
    /// for is gone.
    ///
    /// The session takes the box's enrolled attestation key, and takes its own
    /// name from it. There is no unnamed, unattested session: a box that
    /// cannot prove where it is cannot ask to be identified.
    ///
    /// This does not reintroduce a per-box constant into the binary. One build
    /// still serves the whole fleet — the name lives in the enrolment file the
    /// operator writes, next to the key that proves it, not in the binary and
    /// not in a unit `Environment=`.
    pub fn new(
        role: impl Into<String>,
        build_id: impl Into<String>,
        started_at_ms: u64,
        attestation: crate::attestation::AttestationKey,
    ) -> Self {
        Self {
            role: role.into(),
            build_id: build_id.into(),
            boot_nonce: Uuid::new_v4().to_string(),
            eph: KeyPair::generate(),
            started_at_ms,
            attestation,
            platform: None,
        }
    }

    /// Attach this boot's platform facts, so the announce presents them and
    /// its attestation covers them (admission gate 4). Optional and
    /// additive — a session that never calls this announces exactly as it
    /// did before `platform` existed, still fully attested (V2, `platform:
    /// None`).
    ///
    /// A builder method rather than a `new` parameter: gathering platform
    /// facts is not this crate's job (see [`Self::platform`]'s field doc),
    /// so every existing caller of [`Self::new`] / [`Self::for_service`]
    /// keeps compiling unchanged, and a caller that has the facts attaches
    /// them in one extra step.
    #[must_use]
    pub fn with_platform(mut self, platform: crate::fact_signing::PlatformFingerprint) -> Self {
        self.platform = Some(platform);
        self
    }

    /// What a Mirage service calls at boot: load the enrolled key from
    /// [`crate::attestation::ATTESTATION_KEY_PATH`] and open a session with it.
    ///
    /// `Err` means this box cannot announce at all — it is not enrolled, or its
    /// key file is unreadable. The caller must **wait and say so**, not fall
    /// back to announcing unattested. There is no such fallback by design: an
    /// unattested announce only degrades into a state the quorum rejects
    /// anyway, silently and far from its cause. Failing here is visible, and
    /// the repair is one operator call (`POST /inventory/enrol/{id}`) that
    /// writes a file over SSH — no reboot, no redeploy.
    pub fn for_service(
        role: impl Into<String>,
        build_id: impl Into<String>,
        started_at_ms: u64,
    ) -> Result<Self, crate::attestation::AttestationError> {
        let path = Path::new(crate::attestation::ATTESTATION_KEY_PATH);
        let key = crate::attestation::AttestationKey::load(path)?.ok_or_else(|| {
            crate::attestation::AttestationError::NotEnrolled(path.display().to_string())
        })?;
        Ok(Self::new(role, build_id, started_at_ms, key))
    }

    pub fn machine_id(&self) -> &str {
        self.attestation.machine_id()
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn boot_nonce(&self) -> &str {
        &self.boot_nonce
    }

    /// The public half to hand the issuer, always signed.
    ///
    /// The signature is computed from the announce that is actually being
    /// published — not from fields assembled separately — so the two cannot
    /// drift apart.
    pub fn announce(&self) -> BootAnnounce {
        let mut announce = BootAnnounce {
            machine_id: self.attestation.machine_id().to_string(),
            build_id: self.build_id.clone(),
            eph_pubkey_hex: hex::encode(self.eph.public.to_bytes()),
            boot_nonce: self.boot_nonce.clone(),
            started_at_ms: self.started_at_ms,
            platform: self.platform.clone(),
            // Per-role `BootSession` never claims renewal — only the
            // machine-scoped keeper (`mirage-warden::machine_store`) holds
            // a `MachineCapsule` to prove possession of. See
            // `RenewalClaim`'s own doc.
            renewal: None,
            attestation_sig_hex: String::new(),
        };
        announce.attestation_sig_hex = self.attestation.attest(&announce.attested_fields());
        announce
    }

    /// Verify a sealed capsule against this session and prove it coherent.
    ///
    /// Transport-agnostic: the bytes may have come from the tmpfs drop, from a
    /// monitor relay frame, or from an mshd exec. Where they came from cannot
    /// make them more or less trustworthy — only the signature and the AAD can.
    pub fn accept(
        &self,
        sealed: &SealedCapsule,
        operator_pubkey: &VerifyingKey,
        charter: Option<&crate::capsule::GroupCharter>,
        now_ms: u64,
        max_skew_ms: u64,
    ) -> Result<MachineCapsule, BootError> {
        let anchor = CapsuleTrustAnchor {
            operator: operator_pubkey,
            charter,
            // This session already holds the box's own enrolled attestation
            // key (see the struct's own doc: a session that cannot attest
            // cannot announce, so `self.attestation` is never absent). A
            // self-issued capsule can therefore only ever verify as THIS
            // box's own — see `CapsuleSigner::Machine`'s own doc for why the
            // machine_id cross-check in `verifying_key_for` matters even
            // though nothing mints this variant yet.
            machine: Some(MachineAnchor {
                machine_id: self.attestation.machine_id(),
                attestation: self.attestation.verifying_key(),
            }),
        };
        // Strict on every boot, not only on renewals: the session always knows
        // its own name now, from the enrolment. A capsule addressed to another
        // box is rejected on the name as well as on the AEAD, which previously
        // only held once a box had been identified at least once.
        let capsule = unseal_capsule(
            sealed,
            &self.eph.secret.to_bytes(),
            self.attestation.machine_id(),
            &self.boot_nonce,
            &anchor,
            now_ms,
            max_skew_ms,
        )?;

        check_coherent(&capsule, operator_pubkey, sealed.signer.clone(), now_ms)?;
        Ok(capsule)
    }

    /// Write the announce where the issuer will look for it.
    ///
    /// Atomic (`.new` + rename) so a reader never sees a half-written file, and
    /// `0600` because there is no reason for anything but root to read it.
    pub fn publish_announce(&self, dir: &Path) -> Result<PathBuf, BootError> {
        let path = announce_path(dir, &self.role);
        let body = serde_json::to_vec_pretty(&self.announce())
            .map_err(|e| BootError::Json(e.to_string()))?;
        write_atomic(&path, &body)?;
        Ok(path)
    }

    /// Take a capsule from the tmpfs drop if one is there.
    ///
    /// The file is **consumed before it is verified**: a capsule is single-use
    /// by construction (its AAD binds this boot nonce), and leaving a rejected
    /// blob in place would make the service re-read the same failure forever
    /// instead of announcing again.
    pub fn take_capsule_file(
        &self,
        dir: &Path,
        operator_pubkey: &VerifyingKey,
        charter: Option<&crate::capsule::GroupCharter>,
        now_ms: u64,
        max_skew_ms: u64,
    ) -> Result<Option<MachineCapsule>, BootError> {
        let path = capsule_path(dir, &self.role);
        let raw = match fs::read(&path) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let _ = fs::remove_file(&path);

        // Same delivery, so the same lifetime: the charter is consumed with the
        // capsule it came with rather than left at rest for a later boot to
        // find. The issuer writes both on every seed.
        let delivered = read_charter_file(dir, &self.role, operator_pubkey);
        let anchor = pick_charter(charter, delivered.as_ref());

        let sealed: SealedCapsule =
            serde_json::from_slice(&raw).map_err(|e| BootError::Json(e.to_string()))?;
        let capsule = self.accept(&sealed, operator_pubkey, anchor, now_ms, max_skew_ms)?;
        Ok(Some(capsule))
    }

    /// Remove this session's announce — call once identified, so the issuer
    /// stops seeing a box that is still asking.
    pub fn clear_announce(&self, dir: &Path) -> Result<(), BootError> {
        let path = announce_path(dir, &self.role);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// What a service should do with a freshly renewed capsule.
///
/// Renewal is usually boring: the issuer re-seals the **same** identity with a
/// later `not_after_ms`, so the running process only has to move its deadline —
/// no key swap, no reconnect, no window where the service is half-identified.
/// That is the case this enum exists to separate from the interesting one.
///
/// When the identity actually changed — an operator rotated the box's keys, or
/// a quorum re-admitted it after a recovery — swapping keys underneath a live
/// process would mean re-doing every handshake, cache and registration that was
/// derived from the old ones. This codebase already has a better answer for
/// that shape of problem and uses it throughout the L0 stack: exit and let the
/// supervisor restart you into a clean boot, which runs the ordinary
/// `Unidentified → capsule → Identified` path with nothing stale left over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// Same identity, later deadline. Keep running; just store the new expiry.
    Extended,
    /// Same identity, same deadline handling as [`Extended`] — but the
    /// `service_config` inside the capsule is not the one this process is
    /// serving.
    ///
    /// The doc on [`classify_renewal`] used to say service config "is
    /// re-read rather than baked into handshakes", and for peers and the
    /// charter that is true. For the perimeter it is not: its face list —
    /// which ordinary ports the box answers on — is read ONCE, at bind
    /// time, because a listener is a socket and a socket cannot be re-read.
    /// A capsule carrying a new face list and the same keys classified as
    /// `Extended`, so the process kept serving the old ports and the
    /// operator, reading the faces back, saw the OLD list and concluded the
    /// change had not applied. It had; it needed a SECOND restart to take
    /// effect.
    ///
    /// Separated from [`IdentityRotated`] rather than folded into it
    /// because the two are not the same event: no key changed, no peer has
    /// to re-learn anything, and a service whose config it does not bind
    /// (every role except the perimeter today) is right to keep running.
    /// Each caller decides — the variant only guarantees it is TOLD.
    ServiceConfigChanged,
    /// The identity changed. The caller should exit cleanly and be restarted.
    IdentityRotated,
}

/// Compare a freshly acquired capsule against the one currently in use, for
/// ONE role.
///
/// Scoped to a single role rather than the whole capsule: a machine capsule
/// now bundles every role's slice, and a renewal watcher must react only to
/// the slice belonging to the service running it — a sibling role rotating
/// its own key is not this process's business and must not force a restart
/// it did nothing to earn. See [`identity_digest`].
///
/// Only the fields that would invalidate live state count as a rotation: the
/// identity itself and the role's two private keys. Peers and the charter are
/// allowed to change under a running process — those are genuinely re-read.
///
/// `service_config` is NOT in that set, and saying it was is what made #48
/// take two restarts: see [`RenewalOutcome::ServiceConfigChanged`]. A config
/// change is reported separately so the one role that binds it can act, and
/// every other role can keep running.
pub fn classify_renewal(
    current: &MachineCapsule,
    fresh: &MachineCapsule,
    role: &str,
) -> RenewalOutcome {
    if identity_digest(current, role) != identity_digest(fresh, role) {
        return RenewalOutcome::IdentityRotated;
    }
    if service_config_digest(current) != service_config_digest(fresh) {
        return RenewalOutcome::ServiceConfigChanged;
    }
    RenewalOutcome::Extended
}

/// This machine's slice for `role`, matched on the slice's `Display` form —
/// the same canonical string [`BootSession`] and [`RenewalWatch`] already
/// track role by, so no caller has to parse a [`ServiceRole`] back out of a
/// string to use this.
fn slice_for_role<'a>(capsule: &'a MachineCapsule, role: &str) -> Option<&'a crate::capsule::RoleSlice> {
    capsule.slices.iter().find(|s| s.role.to_string() == role)
}

/// A non-secret fingerprint of ONE role's key material inside a machine
/// capsule.
///
/// Used to answer "did the identity change" across a renewal without keeping a
/// second copy of the private keys around for the lifetime of the process. A
/// role missing from the slice set entirely digests to a value distinct from
/// any real slice, so losing a role's slice on renewal is ALSO caught as a
/// change — the capsule no longer serves this process, which is exactly what
/// a restart into a fresh `Unidentified` boot exists to notice.
pub fn identity_digest(capsule: &MachineCapsule, role: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(capsule.self_id.as_bytes());
    match slice_for_role(capsule, role) {
        Some(slice) => {
            h.update([1u8]);
            h.update(slice.wire_privkey);
            match &slice.signing_privkey {
                Some(k) => {
                    h.update([1u8]);
                    h.update(k);
                }
                None => h.update([0u8]),
            }
        }
        None => h.update([0u8]),
    }
    h.finalize().into()
}

/// A fingerprint of the `service_config` a capsule carries.
///
/// Hashes the WHOLE struct rather than the one field the perimeter binds
/// today, deliberately. `CapsuleServiceConfig` carries no version field, so
/// there is nothing to compare cheaply; and a per-field allow-list is a
/// standing invitation to add a field, forget the list, and reintroduce
/// exactly the defect this closes — silently, for whichever role reads the
/// new field. Measured before choosing: config versions over 2.5 months run
/// v2–v15 per role, single digits per quarter, so a false "changed" costs a
/// process restart nobody will notice, while a false "unchanged" costs an
/// outage the operator cannot see.
///
/// Serialised through `serde_json`: field order is fixed by the struct
/// declaration and `skip_serializing_if` is deterministic, so the same config
/// always produces the same bytes within a build. This digest never leaves
/// the process and is never signed — it only has to be stable across the
/// lifetime of one process, not across builds.
pub fn service_config_digest(capsule: &MachineCapsule) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    match serde_json::to_vec(&capsule.service_config) {
        Ok(bytes) => h.update(&bytes),
        // A config that cannot be serialised must not silently compare
        // equal to every other unserialisable config — that would be the
        // old defect with extra steps. Fold in a marker so the digest is at
        // least stable-and-distinct, and let the caller's own logging speak.
        Err(_) => h.update(b"mirage-service-config-unserialisable"),
    }
    h.finalize().into()
}

/// What a running service must remember in order to renew.
///
/// Deliberately holds a digest rather than the keys themselves: renewal only
/// needs to know whether the identity changed, and keeping a spare copy of a
/// private key alive for hours to answer that would be a poor trade.
pub struct RenewalWatch {
    pub machine_id: String,
    pub role: String,
    pub build_id: String,
    pub runtime_dir: PathBuf,
    pub identity: [u8; 32],
    /// Digest of the `service_config` this process is actually serving — see
    /// [`RenewalOutcome::ServiceConfigChanged`]. Held for the same reason as
    /// `identity`: to answer "did it change" without keeping a second copy.
    pub service_config: [u8; 32],
    pub not_after_ms: u64,
    pub renew_lead_ms: u64,
    pub max_skew_ms: u64,
}

impl RenewalWatch {
    /// Build a watch from the capsule a service just booted with, for the
    /// role that service runs. `role` can no longer be read off the capsule
    /// — a machine capsule carries every role's slice — so the caller states
    /// which one it is, the same way [`BootSession::new`] already does.
    ///
    /// The lead carries a per-(machine, role) spread — see
    /// [`DEFAULT_RENEW_JITTER_SPAN_MS`] for why a fleet with a fixed lead
    /// cannot recover from a single synchronised outage.
    pub fn from_capsule(
        capsule: &MachineCapsule,
        role: impl Into<String>,
        build_id: impl Into<String>,
    ) -> Self {
        let machine_id = capsule.machine_id.as_str().to_string();
        let role = role.into();
        let renew_lead_ms = renew_lead_for(&machine_id, &role, capsule.not_after_ms, now_ms());
        Self {
            identity: identity_digest(capsule, &role),
            service_config: service_config_digest(capsule),
            machine_id,
            role,
            build_id: build_id.into(),
            runtime_dir: PathBuf::from(RUNTIME_DIR),
            not_after_ms: capsule.not_after_ms,
            renew_lead_ms,
            max_skew_ms: DEFAULT_MAX_SKEW_MS,
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The ask callback for a service that has no wire of its own: it never asks,
/// so an operator push is the only thing that can identify or renew it.
///
/// This exists to make that dependency **greppable**. Measured 2026-08-11,
/// only three of the eight services that hold a capsule carry a
/// `CapsuleAsker` at all — mshd, the monitor and the perimeter. The other
/// five acquire their boot capsule by polling the tmpfs file and nothing
/// else, so the quorum fallback built to cover an issuer outage
/// (`unattended_issuance`, S5.6) could never reach them, at boot or at
/// renewal. Passing a silent closure at each of those call sites would have
/// left that fact invisible; passing this names it.
///
/// `mirage-warden` is the one service for which this is permanent and
/// correct: it is zero-network by design and is controlled only through
/// operator-signed commands delivered via mshd. Every other user of this is a
/// gap waiting to be closed.
pub fn no_ask(announce: BootAnnounce) -> std::future::Ready<Option<CapsuleAnswer>> {
    let _ = announce;
    std::future::ready(None)
}

/// Renew this service's capsule for as long as the identity stays the same.
///
/// Returns only when the identity has actually **changed** — a rotation by the
/// operator, or a quorum re-admission — at which point the caller should log
/// and `exit(0)` so the supervisor restarts it into a clean
/// `Unidentified → capsule → Identified` boot. Swapping keys underneath a live
/// process would invalidate every handshake, cache and registration derived
/// from the old ones; this codebase already answers that shape of problem with
/// a restart everywhere else in the L0 stack.
///
/// **Expiry is deliberately fail-open inside the process.** If renewal keeps
/// failing past `not_after_ms` this logs at ERROR and keeps trying, rather than
/// killing a service that is working. Turning an issuer outage into a fleet
/// outage would be a self-inflicted denial of service, and expiry is already
/// enforced where it belongs and cannot be fooled: monitors reject a peer whose
/// signed `DeclaredIdentity` has lapsed. What the TTL buys is that a captured
/// RAM image ages out — and that property is unaffected by how politely this
/// loop behaves.
/// `ask` is the same callback [`acquire_capsule`] takes at boot — the
/// service's own `CapsuleAsker`, which lives in `mirage-mesh-client` and so
/// cannot be named here. Passing it makes the renewal reachable by the quorum
/// fallback (`unattended_issuance`, S5.6) instead of by opbox alone.
///
/// A service with no wire of its own passes [`no_ask`], which is a statement,
/// not a placeholder: see that function's doc.
pub async fn watch_for_renewal<F, Fut>(
    mut watch: RenewalWatch,
    operator_pubkey: &VerifyingKey,
    mut charter: Option<crate::capsule::GroupCharter>,
    mut ask: F,
) -> RenewalOutcome
where
    F: FnMut(BootAnnounce) -> Fut,
    Fut: std::future::Future<Output = Option<CapsuleAnswer>>,
{
    loop {
        // Sleep until the renewal lead-in, re-checking periodically so a clock
        // jump cannot park us past the deadline.
        loop {
            let now = now_ms();
            let due = watch.not_after_ms.saturating_sub(watch.renew_lead_ms);
            if now >= due {
                break;
            }
            let nap = (due - now).min(60_000);
            tokio::time::sleep(std::time::Duration::from_millis(nap)).await;
        }

        let mut session = match BootSession::for_service(
            watch.role.clone(),
            watch.build_id.clone(),
            now_ms(),
        ) {
            Ok(s) => s,
            Err(e) => {
                // Renewal is fail-open by the same argument as expiry below:
                // a lost enrolment must not kill a service that is working.
                // Retry from the top of the loop; the operator repairs it with
                // one call and no restart.
                tracing::error!(
                    role = %watch.role, error = %e,
                    "capsule renewal: this box cannot attest — enrol it \
                     (POST /inventory/enrol/{{id}}); retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    DEFAULT_SESSION_BACKOFF_MS,
                ))
                .await;
                continue;
            }
        };
        if let Some(pf) = crate::platform_probe::collect() {
            session = session.with_platform(pf);
        }
        // The enrolment and the identity must agree on which box this is. They
        // are written by the same operator through different paths, so a
        // disagreement means one of them is stale — announce under the wrong
        // name and the issuer would seal for a different machine entirely.
        if session.machine_id() != watch.machine_id {
            tracing::error!(
                role = %watch.role,
                enrolment = %session.machine_id(),
                identity = %watch.machine_id,
                "capsule renewal: enrolment names a different machine than this \
                 service's identity — refusing to announce; re-enrol this box"
            );
            tokio::time::sleep(std::time::Duration::from_millis(DEFAULT_SESSION_BACKOFF_MS))
                .await;
            continue;
        }
        if let Err(e) = session.publish_announce(&watch.runtime_dir) {
            tracing::warn!(role = %watch.role, error = %e, "capsule renewal: could not publish announce");
        }

        // BOTH halves of the wait, exactly as `acquire_capsule` runs them at
        // boot: the tmpfs file an operator push writes, and the ask over the
        // wire that reaches the monitors — whichever lands first.
        //
        // This loop used to poll the file alone. The quorum fallback that
        // answers an ask opbox has not served
        // (`mirage2monitor::unattended_issuance`, S5.6) was therefore reachable
        // on a boot and unreachable on a renewal, because nothing ever told a
        // monitor a renewal was pending — so an issuer outage could not be
        // covered by the very mechanism built to cover it. Measured 2026-08-11:
        // the dev box was down 04:32-12:29Z and four roles on all nine boxes
        // went past their signed expiry with the quorum idle beside them.
        let fresh = match acquire_capsule(
            &session,
            &watch.runtime_dir,
            operator_pubkey,
            charter.as_ref(),
            watch.max_skew_ms,
            std::time::Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
            std::time::Duration::from_millis(DEFAULT_SESSION_WINDOW_MS),
            &mut ask,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                // Same disposition the old loop gave a rejected capsule: log
                // and let the window lapse into the retry below. A renewal
                // must not kill a working service.
                tracing::warn!(role = %watch.role, error = %e,
                    "capsule renewal: rejected an offered capsule");
                None
            }
        };
        let _ = session.clear_announce(&watch.runtime_dir);

        let Some(fresh) = fresh else {
            if now_ms() >= watch.not_after_ms {
                tracing::error!(role = %watch.role, machine = %watch.machine_id,
                    "capsule renewal: capsule EXPIRED and no replacement arrived — still serving, \
                     monitors will reject this identity once its signed expiry lapses");
            } else {
                tracing::warn!(role = %watch.role,
                    "capsule renewal: no capsule this round — retrying before expiry");
            }
            tokio::time::sleep(std::time::Duration::from_millis(DEFAULT_SESSION_BACKOFF_MS)).await;
            continue;
        };

        if identity_digest(&fresh, &watch.role) != watch.identity {
            tracing::warn!(role = %watch.role, machine = %watch.machine_id,
                "capsule renewal: IDENTITY CHANGED — exiting for a clean re-identified boot");
            return RenewalOutcome::IdentityRotated;
        }

        // Same keys, different config. Reported, never swallowed: the role
        // that BINDS its config (the perimeter, and its face list) cannot
        // re-read a socket, and for two months a config change there needed
        // a second restart nobody knew to perform. What the caller does with
        // this is the caller's decision — see the variant's doc.
        if service_config_digest(&fresh) != watch.service_config {
            tracing::warn!(role = %watch.role, machine = %watch.machine_id,
                "capsule renewal: SERVICE CONFIG CHANGED under the same identity — \
                 a role that binds its config must act on this, not extend past it");
            return RenewalOutcome::ServiceConfigChanged;
        }

        // Same identity, later deadline: move the expiry and keep serving. No
        // key swap, no reconnect, no half-identified window.
        watch.not_after_ms = fresh.not_after_ms;
        // Recompute the lead against the capsule we actually hold now. The
        // jitter is deterministic so this does not move, but the clamp inside
        // `renew_lead_for` is relative to the remaining validity — a capsule
        // issued under a shorter `MIRAGE_CAPSULE_TTL_SECS` than the one this
        // watch was built from would otherwise keep the old, too-long lead
        // and renew continuously.
        watch.renew_lead_ms =
            renew_lead_for(&watch.machine_id, &watch.role, watch.not_after_ms, now_ms());
        if let Some(c) = &fresh.charter {
            if charter.as_ref().map(|held| c.epoch > held.epoch).unwrap_or(true) {
                charter = Some(c.clone());
            }
        }
        tracing::info!(role = %watch.role, not_after_ms = watch.not_after_ms,
            "capsule renewal: extended in place");
    }
}

/// Per-role runtime directory: `/run/mirage/<role>/`.
///
/// ## This directory's ownership IS the authentication of an announce
///
/// An announce cannot be signed. A service that has no identity yet has nothing
/// to sign with — that is the bootstrap problem, not an oversight. So an
/// announce is an **unauthenticated request for an identity**, and whoever can
/// write one gets a capsule sealed to a key they chose.
///
/// The only thing standing between that and an identity handover is the
/// filesystem. Hence one directory per role, writable only by the user that
/// role runs as (`RuntimeDirectory=mirage/<role>` in the unit, so systemd
/// creates it owned by `User=`), under a parent that is traversable but not
/// writable:
///
/// ```text
/// /run/mirage/           root:root      0755   traverse only
/// /run/mirage/monitor/   mirage:mirage  0700
/// /run/mirage/warden/  root:root      0700
/// ```
///
/// A flat `/run/mirage/<role>.announce` layout was tried first and is wrong:
/// making the shared directory group-writable so a de-privileged monitor could
/// write its own announce would also let it write `warden.announce` and be
/// handed the warden's identity — undoing, to make this mechanism work, the
/// exact hardening someone had deliberately applied to that box. The fleet is
/// heterogeneous here (some monitors run as root, some as `mirage`), which is
/// how the flat layout looked fine on two boxes and failed on five.
pub fn role_dir(dir: &Path, role: &str) -> PathBuf {
    dir.join(role)
}

/// Where a role's announce lives.
pub fn announce_path(dir: &Path, role: &str) -> PathBuf {
    role_dir(dir, role).join("announce")
}

/// Where a role's sealed capsule is dropped.
pub fn capsule_path(dir: &Path, role: &str) -> PathBuf {
    role_dir(dir, role).join("capsule")
}

/// Where the charter that verifies a group-signed capsule is dropped.
///
/// ## Why the charter has to travel BESIDE the capsule and not inside it
///
/// A group-signed capsule is verified with the group key, and the group key
/// lives in the charter. The charter also rides inside the capsule — which is
/// fine for keeping it fresh and useless for bootstrapping, because opening
/// the capsule is what needs it. A service that has just started holds
/// nothing, so a group-signed capsule dies at `CapsuleError::NoCharter`
/// *before decrypt*, which is the right order and a dead end.
///
/// So the charter is a sibling artifact of the same delivery. It is not a
/// secret — it is a public, operator-signed statement of who the quorum is —
/// and it is verified against the **baked** operator key before it is allowed
/// to verify anything. That is the whole difference from the two deliveries
/// this codebase got wrong before: `db-key.raw` moved a secret and left it at
/// rest, and the pubkey refresh let the channel being trusted supply the key
/// that judged it. Here nothing secret moves, and the key that judges the
/// charter never travels at all.
pub fn charter_path(dir: &Path, role: &str) -> PathBuf {
    role_dir(dir, role).join("charter")
}

/// The machine-scoped identity store's directory — one per BOX, not one per
/// role. Replaces the eight `role_dir`-scoped rest-capsule caches; see the
/// module doc's "The machine-scoped store is a third thing" section.
///
/// `/run` is tmpfs, so the difference between "a service restarted" and "the
/// machine was reset" is the mere PRESENCE of [`machine_capsule_path`] under
/// this directory — a fact of the filesystem, not a heuristic, not an age
/// check. See `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md`
/// §2.
pub fn machine_dir(dir: &Path) -> PathBuf {
    dir.join("machine")
}

/// Where this box's current announce lives — role-less, one per machine
/// reset. Written by the keeper; every OTHER service only ever reads
/// [`machine_capsule_path`], never this file — see
/// `identity_boot::take_machine_slice`.
pub fn machine_announce_path(dir: &Path) -> PathBuf {
    machine_dir(dir).join("announce")
}

/// Where this box's machine capsule lives once admitted.
///
/// The machine-scoped analogue of the old per-role REST capsule cache: the
/// last [`MachineCapsule`] the keeper accepted through the announce/capsule
/// exchange, kept so a RESTART of any OTHER service — not a reboot; this
/// directory is `/run/mirage`, tmpfs, and a reboot clears it along with
/// everything else this module writes there — never needs the keeper to
/// re-ask the quorum. This module only owns where it lives and how it is
/// written and read; the keeper (`mirage-warden`) owns the policy that
/// decides when writing a fresh one is warranted.
pub fn machine_capsule_path(dir: &Path) -> PathBuf {
    machine_dir(dir).join("capsule")
}

/// **Keeper-side helper.** Cache the machine capsule the keeper has already
/// accepted, for every restart to read back. Same atomic write, same `0600`,
/// as every other file this module writes.
pub fn write_machine_capsule_file(dir: &Path, capsule: &MachineCapsule) -> Result<PathBuf, BootError> {
    let path = machine_capsule_path(dir);
    let body = serde_json::to_vec_pretty(capsule).map_err(|e| BootError::Json(e.to_string()))?;
    write_atomic(&path, &body)?;
    Ok(path)
}

/// Read the machine capsule back, if this box has admitted one since its
/// last reset. `Ok(None)` is ordinary — a freshly reset machine, or a reboot
/// that cleared tmpfs — never an error.
///
/// Unlike a single-use sealed-capsule delivery, this is NOT consumed by
/// reading: the keeper serves every OTHER service's restart from this same
/// file, so a single-use take would starve every caller after the first.
///
/// Returns the capsule UNCHECKED. This function only reads bytes off disk —
/// it is not a trust boundary. The caller MUST still run [`check_coherent`]
/// before using anything it returns.
pub fn read_machine_capsule_file(dir: &Path) -> Result<Option<MachineCapsule>, BootError> {
    let path = machine_capsule_path(dir);
    match fs::read(&path) {
        Ok(raw) => {
            let capsule: MachineCapsule = serde_json::from_slice(&raw)
                .map_err(|e| BootError::Json(e.to_string()))?;
            Ok(Some(capsule))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A durable, box-local list of monitor peers to dial for admission while
/// this box holds no capsule.
///
/// Unlike every other artifact this module writes (all under `/run`, tmpfs,
/// gone on reboot), this one lives under the box's DURABLE dir
/// ([`crate::attestation::MIRAGE_VAR_DIR`]) so it survives a reboot. It is the
/// "where to ask" sibling of the attestation key's "right to ask", and the ONLY
/// thing a rebooted box carries about its mesh. It holds no secret: every entry
/// is an operator/quorum-signed public `DeclaredIdentity`, re-verified by the
/// asker against the baked operator key before anything is dialled, so a
/// tampered file buys an attacker nothing but a dial that fails verification.
///
/// It replaces the compile-time `BOOTSTRAP_ASK_MONITORS` anchor list a box
/// binary used to carry: a box does not learn its peers from its own build, it
/// learns them from the capsule the mesh delivered, and keeps the last such
/// list only so a cold reboot has somewhere to start the ask. A box that has
/// never been admitted has no file here and no baked list either — its
/// admission is operator-driven, exactly as a fresh enrolment already is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnchors {
    /// The mesh the cached peers belong to — the capsule's own `mesh_id`,
    /// passed straight to `CapsuleAsker` so it drops any entry that does not
    /// match (a self-correcting guard, since every entry here came from ONE
    /// capsule and shares its mesh).
    pub mesh_id: String,
    /// Serialised `DeclaredIdentity` JSON, one per peer — the exact `&[&str]`
    /// shape `CapsuleAsker::new` consumes, so the reader hands them straight
    /// through with no reshaping. The transitional `CapsulePeer::addr` is not
    /// carried: the anchor list it replaces never carried it either, and the
    /// authoritative dial address is `identity.public_addr`.
    pub anchors: Vec<String>,
}

/// Where the durable peer-anchor cache lives under the box's durable dir.
pub fn machine_peer_anchors_path(durable_dir: &Path) -> PathBuf {
    durable_dir.join("peers.json")
}

/// **Keeper-side helper.** Cache the peers of a capsule the keeper has just
/// accepted, so a cold reboot has monitors to ask. Same atomic write, same
/// `0600`, as every other file this module writes — but under the DURABLE dir,
/// not `/run`. See [`PeerAnchors`] for why this one file survives a reboot when
/// nothing else does.
///
/// A capsule with no peers (a self-issued one) writes an empty anchor list,
/// which is the honest state: a box that only ever self-issued has no mesh
/// peers to remember.
pub fn write_peer_anchors_file(
    durable_dir: &Path,
    mesh_id: &str,
    peers: &[CapsulePeer],
) -> Result<PathBuf, BootError> {
    let anchors = peers
        .iter()
        .map(|p| serde_json::to_string(&p.identity).map_err(|e| BootError::Json(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let cache = PeerAnchors { mesh_id: mesh_id.to_string(), anchors };
    let body = serde_json::to_vec_pretty(&cache).map_err(|e| BootError::Json(e.to_string()))?;
    let path = machine_peer_anchors_path(durable_dir);
    write_atomic(&path, &body)?;
    Ok(path)
}

/// Read the durable peer-anchor cache back. `Ok(None)` is ordinary — a box
/// that has never been admitted has no cache, and its admission is
/// operator-driven. Returns the anchors UNVERIFIED: this only reads bytes off
/// disk, and every consumer (`CapsuleAsker`) re-verifies each against the
/// baked operator key before dialling.
pub fn read_peer_anchors_file(durable_dir: &Path) -> Result<Option<PeerAnchors>, BootError> {
    let path = machine_peer_anchors_path(durable_dir);
    match fs::read(&path) {
        Ok(raw) => {
            let cache: PeerAnchors =
                serde_json::from_slice(&raw).map_err(|e| BootError::Json(e.to_string()))?;
            Ok(Some(cache))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// **Keeper-side helper.** Publish the one announce this machine is asking
/// under. Same atomic write, same `0600`, as every other file this module
/// writes.
pub fn write_machine_announce_file(dir: &Path, announce: &BootAnnounce) -> Result<PathBuf, BootError> {
    let path = machine_announce_path(dir);
    let body =
        serde_json::to_vec_pretty(announce).map_err(|e| BootError::Json(e.to_string()))?;
    write_atomic(&path, &body)?;
    Ok(path)
}

/// Read this box's current announce, if it is asking. `Ok(None)` means the
/// keeper already holds a capsule, or has not yet decided it needs one.
pub fn read_machine_announce_file(dir: &Path) -> Result<Option<BootAnnounce>, BootError> {
    let path = machine_announce_path(dir);
    match fs::read(&path) {
        Ok(raw) => {
            let a: BootAnnounce =
                serde_json::from_slice(&raw).map_err(|e| BootError::Json(e.to_string()))?;
            Ok(Some(a))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// One issuer's answer: the sealed capsule, and — when the issuer knows it —
/// the charter needed to verify it.
///
/// The two are one delivery. Returning them separately is what let the pull
/// path answer with a capsule nobody could open.
pub struct CapsuleAnswer {
    pub sealed: SealedCapsule,
    /// Already verified against the operator key by whoever produced this
    /// value. `accept` re-verifies rather than trusting that: the producer is
    /// a callback supplied by the service, not code this module controls.
    pub charter: Option<crate::capsule::GroupCharter>,
}

/// Choose which charter anchors this acceptance: the one this process already
/// holds, or the one that just arrived.
///
/// Highest epoch wins, which is the same monotonic rule `watch_for_renewal`
/// applies to a charter arriving inside a capsule. At first boot `held` is
/// `None` and the delivered one is all there is — a replayed OLD charter can
/// only make this box refuse a capsule the current quorum signed, never make
/// it accept one the quorum did not, because an attacker cannot produce a
/// signature under a group key whose shares no longer exist.
fn pick_charter<'a>(
    held: Option<&'a crate::capsule::GroupCharter>,
    delivered: Option<&'a crate::capsule::GroupCharter>,
) -> Option<&'a crate::capsule::GroupCharter> {
    match (held, delivered) {
        (Some(h), Some(d)) => Some(if d.epoch > h.epoch { d } else { h }),
        (Some(h), None) => Some(h),
        (None, d) => d,
    }
}

/// Read and VERIFY a charter dropped beside a capsule. Absent is ordinary —
/// an operator-signed capsule needs no charter at all.
///
/// A charter that does not verify is dropped with a warning rather than
/// returned: an unverified charter is an attacker-chosen group key, and the
/// only thing worse than having no anchor is having a forged one.
fn read_charter_file(
    dir: &Path,
    role: &str,
    operator_pubkey: &VerifyingKey,
) -> Option<crate::capsule::GroupCharter> {
    let path = charter_path(dir, role);
    let raw = fs::read(&path).ok()?;
    let _ = fs::remove_file(&path);
    match serde_json::from_slice::<crate::capsule::GroupCharter>(&raw) {
        Ok(charter) => match charter.verify(operator_pubkey) {
            Ok(()) => Some(charter),
            Err(e) => {
                tracing::warn!(
                    %role, error = %e,
                    "capsule boot: a charter was delivered that does not verify against the \
                     baked operator key — ignored"
                );
                None
            }
        },
        Err(e) => {
            tracing::warn!(%role, error = %e, "capsule boot: delivered charter will not parse");
            None
        }
    }
}

/// Wait for this boot's capsule, ASKING for it rather than only waiting.
///
/// ## Why this exists
///
/// Until now the whole protocol was "write an announce, wait for a file". That
/// makes every service depend on someone reaching IN to it, and after a reboot
/// there is nobody who can: the perimeter has no faces until it is identified,
/// so nothing is listening, and mshd does not register with any monitor until
/// it is identified either, so nothing is dialling out. The only remaining door
/// is the foreign `sshd` on `:22` — which is precisely the door this arc exists
/// to close. A box that reboots with `:22` shut would sit there announcing into
/// an empty room forever.
///
/// It never had to be that way. The announce is **self-proving** — signed with
/// the machine's enrolled attestation key, and an unattested announce is
/// refused by construction — so an issuer can verify who is asking without any
/// prior session. And the mesh already accepts an anonymous ephemeral-key dial.
/// The missing piece was only that nobody asked.
///
/// ## Why the asking half is a callback and not code in this crate
///
/// `mirage-core` sits underneath the transport: the wire client depends on it,
/// not the other way round. Putting a dial in here would invert that. So the
/// service supplies `ask` — it already owns a wire client and the baked
/// bootstrap list of monitors to try — and this function owns the state
/// machine: when to ask, how often, and what to do with the answer.
///
/// ## Push still works
///
/// A capsule that arrives as a file is taken exactly as before. `ask` is only
/// consulted between polls, so an operator push and a box-initiated pull race
/// harmlessly: whichever lands first identifies the service, and the loser is a
/// capsule for a boot nonce that is already satisfied.
pub async fn acquire_capsule<F, Fut>(
    session: &BootSession,
    dir: &Path,
    operator_pubkey: &VerifyingKey,
    charter: Option<&crate::capsule::GroupCharter>,
    max_skew_ms: u64,
    poll_every: std::time::Duration,
    give_up_after: std::time::Duration,
    ask: F,
) -> Result<Option<MachineCapsule>, BootError>
where
    F: FnMut(BootAnnounce) -> Fut,
    Fut: std::future::Future<Output = Option<CapsuleAnswer>>,
{
    acquire_capsule_validated(
        session,
        dir,
        operator_pubkey,
        charter,
        max_skew_ms,
        poll_every,
        give_up_after,
        ask,
        |_| CapsuleVerdict::Accept,
    )
    .await
}

/// What a service makes of a capsule this crate has already proved valid.
///
/// [`BootSession::accept`] establishes that an envelope is operator-vouched
/// and internally coherent. It cannot establish that the capsule is USABLE by
/// the particular service that asked: a sentry signs facts and a capsule with
/// no fact-signing key leaves it unable to do its job, and `identity_boot`
/// binds only `(machine_id, boot_nonce)` into its AAD, so a capsule naming a
/// different mesh passes every check this crate makes.
///
/// Those checks lived in each service's own hand-rolled poll loop, which is
/// exactly why those loops could not adopt [`acquire_capsule`] and never
/// gained the ability to ASK — see the module-level story on `acquire_capsule`.
/// Keeping the verdict as a callback keeps the knowledge where it belongs
/// (the service knows what it needs) while the state machine stays here.
#[derive(Debug, Clone)]
pub enum CapsuleVerdict {
    /// Usable. Return it.
    Accept,
    /// Structurally valid, unusable by this service. The reason is logged and
    /// the loop keeps going on the SAME session.
    ///
    /// Deliberately not an error: the capsule file is already consumed, and
    /// tearing the session down would re-announce under a new boot nonce and
    /// invalidate the corrected capsule an issuer may already be sealing.
    Discard(String),
}

/// [`acquire_capsule`], plus the service's own usability check.
#[allow(clippy::too_many_arguments)]
pub async fn acquire_capsule_validated<F, Fut, V>(
    session: &BootSession,
    dir: &Path,
    operator_pubkey: &VerifyingKey,
    charter: Option<&crate::capsule::GroupCharter>,
    max_skew_ms: u64,
    poll_every: std::time::Duration,
    give_up_after: std::time::Duration,
    mut ask: F,
    validate: V,
) -> Result<Option<MachineCapsule>, BootError>
where
    F: FnMut(BootAnnounce) -> Fut,
    Fut: std::future::Future<Output = Option<CapsuleAnswer>>,
    V: Fn(&MachineCapsule) -> CapsuleVerdict,
{
    let started = std::time::Instant::now();
    loop {
        if let Some(capsule) =
            session.take_capsule_file(dir, operator_pubkey, charter, now_ms(), max_skew_ms)?
        {
            match validate(&capsule) {
                CapsuleVerdict::Accept => return Ok(Some(capsule)),
                CapsuleVerdict::Discard(why) => {
                    tracing::warn!(
                        role = %session.role, self_id = %capsule.self_id, reason = %why,
                        "capsule boot: pushed capsule is not usable by this service — \
                         discarding, keeping this session's announce up"
                    );
                }
            }
        }

        // Ask. A `None` here is ordinary — no issuer reachable this round, or
        // the quorum has not gathered enough shares yet — so it is not logged
        // per attempt: this loop runs every few seconds and a line per turn
        // would bury the one event that matters.
        if let Some(answer) = ask(session.announce()).await {
            // The charter that came WITH the answer is what makes a
            // group-signed capsule openable at all on a boot that holds
            // nothing. Re-verified here rather than taken on the asker's word:
            // `ask` is a callback the service supplies, and this module does
            // not get to assume what it checked.
            let delivered = answer.charter.filter(|c| {
                c.verify(operator_pubkey)
                    .inspect_err(|e| {
                        tracing::warn!(
                            role = %session.role, error = %e,
                            "capsule pull: the answer carried a charter that does not verify \
                             against the baked operator key — ignored"
                        );
                    })
                    .is_ok()
            });
            let anchor = pick_charter(charter, delivered.as_ref());
            match session.accept(&answer.sealed, operator_pubkey, anchor, now_ms(), max_skew_ms) {
                Ok(capsule) => match validate(&capsule) {
                    CapsuleVerdict::Accept => return Ok(Some(capsule)),
                    CapsuleVerdict::Discard(why) => {
                        // Same treatment as a pushed capsule, and it matters
                        // more here: an issuer that answers with something
                        // unusable will keep answering the same way, so a
                        // silent discard would look exactly like no issuer
                        // at all.
                        tracing::warn!(
                            role = %session.role, self_id = %capsule.self_id, reason = %why,
                            "capsule pull: an issuer answered with a capsule this service \
                             cannot use — discarding, keeping this session's announce up"
                        );
                    }
                },
                Err(e) => {
                    // A capsule that does not verify is a real event, not
                    // noise: it means an issuer answered with something this
                    // boot cannot open, and swallowing it would leave the
                    // service looking merely slow.
                    tracing::warn!(
                        role = %session.role, error = %e,
                        "capsule pull: issuer answered with a capsule this boot cannot accept"
                    );
                }
            }
        }

        if started.elapsed() >= give_up_after {
            return Ok(None);
        }
        tokio::time::sleep(poll_every).await;
    }
}

/// **Issuer side helper.** Drop a sealed capsule where the service will find it.
/// Same atomic write, same permissions — a service must never read a partial
/// envelope and conclude the issuer is broken.
pub fn write_capsule_file(
    dir: &Path,
    role: &str,
    sealed: &SealedCapsule,
) -> Result<PathBuf, BootError> {
    let path = capsule_path(dir, role);
    let body = serde_json::to_vec(sealed).map_err(|e| BootError::Json(e.to_string()))?;
    write_atomic(&path, &body)?;
    Ok(path)
}

/// **Issuer side helper.** Drop the charter that verifies a group-signed
/// capsule beside it.
///
/// **Write this BEFORE the capsule.** The capsule file is the trigger — the
/// service polls for it — so a charter that lands second arrives after the
/// capsule has already been consumed and refused, and a consumed capsule does
/// not come back. Ordering is the whole contract between these two writes.
pub fn write_charter_file(
    dir: &Path,
    role: &str,
    charter: &crate::capsule::GroupCharter,
) -> Result<PathBuf, BootError> {
    let path = charter_path(dir, role);
    let body = serde_json::to_vec(charter).map_err(|e| BootError::Json(e.to_string()))?;
    write_atomic(&path, &body)?;
    Ok(path)
}

/// **Issuer side helper.** Read a service's announce, if it is asking.
pub fn read_announce_file(dir: &Path, role: &str) -> Result<Option<BootAnnounce>, BootError> {
    let path = announce_path(dir, role);
    match fs::read(&path) {
        Ok(raw) => {
            let a: BootAnnounce =
                serde_json::from_slice(&raw).map_err(|e| BootError::Json(e.to_string()))?;
            Ok(Some(a))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Prove a capsule is internally consistent, operator-vouched, and — when it
/// carries a quorum rotation — that its keys are AUTHORIZED and not merely
/// self-consistent.
///
/// Unsealing proves *who sent it* and *who it was addressed to*. This proves
/// the contents actually describe a usable identity: each slice's private
/// keys match the public keys sealed beside them (the check the baked path
/// performed by hand in every service), and, when `capsule.rotation` is
/// present, every slice's public key is one the quorum actually named — see
/// the per-slice loop and the rotation block below for what each half checks
/// and why neither is a substitute for the other.
///
/// **No longer compares roles.** `capsule.slices` names every role the box
/// runs; there is no single role left on the envelope to compare against
/// `declared_identity` the way the old per-role capsule's `role` field was.
///
/// `signer` is the [`CapsuleSigner`] that was already verified against the
/// trust anchor by [`crate::capsule::unseal_capsule`] before this function
/// ever runs — this function does not re-verify it, only reads which one it
/// was, because whether an absent `rotation` is tolerable depends on it: see
/// the rotation branch below.
///
/// Equivalent to [`check_coherent_full`] with `machine_anchor: None` — every
/// existing caller of this exact 4-argument signature (inside this crate and
/// out) keeps compiling and keeps its exact current behaviour, INCLUDING for
/// a [`crate::identity::IdentitySigner::Machine`]-signed
/// `declared_identity`: with no machine anchor to check it against, that
/// case now refuses (`IdentityError::NoMachineAnchor`, folded into
/// [`BootError::Identity`]) rather than the pre-self-issuance behaviour of
/// unconditionally trying the operator key — fail-closed either way, and no
/// existing caller could ever have received a `Machine`-signed identity
/// before this variant existed to mint one.
pub fn check_coherent(
    capsule: &MachineCapsule,
    operator_pubkey: &VerifyingKey,
    signer: CapsuleSigner,
    now_ms: u64,
) -> Result<(), BootError> {
    check_coherent_full(capsule, operator_pubkey, signer, now_ms, None)
}

/// [`check_coherent`], plus an explicit machine attestation anchor for
/// verifying a [`crate::identity::IdentitySigner::Machine`]-signed
/// `declared_identity` — the anchor a keeper-side caller (`mirage-warden`'s
/// machine-identity store, outside this crate) holds when re-checking a
/// capsule THIS box self-issued, built from its own already-loaded
/// [`crate::attestation::AttestationKey`].
///
/// `machine_anchor: None` does not mean "skip the check" — it means "no
/// anchor is available", and a `declared_identity` that claims
/// `IdentitySigner::Machine` with none supplied is refused
/// (`IdentityError::NoMachineAnchor`), never silently waved through or
/// silently re-checked under the operator key. See
/// [`crate::identity::DeclaredIdentity::verify_with_anchor`] for exactly how
/// the anchor is resolved and refused.
pub fn check_coherent_full(
    capsule: &MachineCapsule,
    operator_pubkey: &VerifyingKey,
    signer: CapsuleSigner,
    now_ms: u64,
    machine_anchor: Option<&MachineAnchor<'_>>,
) -> Result<(), BootError> {
    if capsule.is_expired(now_ms) {
        return Err(BootError::Expired);
    }

    // A machine capsule naming no role identifies nothing. Checked early,
    // before any signature verification, on the same "cheap rejection
    // first" principle `unseal_capsule`'s own binding check already follows.
    if capsule.slices.is_empty() {
        return Err(BootError::Incoherent(
            "capsule carries no role slices".to_string(),
        ));
    }

    let decl = &capsule.declared_identity;
    let anchor = CapsuleTrustAnchor {
        operator: operator_pubkey,
        charter: None,
        machine: machine_anchor.map(|ma| MachineAnchor {
            machine_id: ma.machine_id,
            attestation: ma.attestation,
        }),
    };
    decl.verify_with_anchor(&anchor)?;

    if decl.self_id != capsule.self_id {
        return Err(BootError::Incoherent(format!(
            "declared self_id {} != capsule self_id {}",
            decl.self_id, capsule.self_id
        )));
    }
    if decl.machine_id.as_str() != capsule.machine_id.as_str() {
        return Err(BootError::Incoherent(format!(
            "declared machine_id {} != capsule machine_id {}",
            decl.machine_id.as_str(),
            capsule.machine_id.as_str()
        )));
    }
    if decl.mesh_id.as_str() != capsule.mesh_id.as_str() {
        return Err(BootError::Incoherent(format!(
            "declared mesh_id {} != capsule mesh_id {}",
            decl.mesh_id.as_str(),
            capsule.mesh_id.as_str()
        )));
    }
    if decl.revoked {
        return Err(BootError::Incoherent(
            "declared identity is revoked".to_string(),
        ));
    }

    // A charter is a verification key for future capsules — an unverified one
    // would be an attacker choosing who may identify this box tomorrow. Checked
    // BEFORE the key material below, because a quorum rotation is verified
    // against it and a verifier must never anchor on something it has not yet
    // established.
    if let Some(charter) = &capsule.charter {
        charter.verify(operator_pubkey)?;
        if charter.mesh_id.as_str() != capsule.mesh_id.as_str() {
            return Err(BootError::Incoherent(format!(
                "charter mesh {} != capsule mesh {}",
                charter.mesh_id.as_str(),
                capsule.mesh_id.as_str()
            )));
        }
    }

    // Each slice's private key must be the one behind its OWN public key,
    // otherwise that role would come up unable to complete a single
    // handshake and the failure would surface as an unexplained peer-side
    // auth error. Self-consistency alone, though — see the rotation block
    // below for why that is not the same thing as authorization.
    for slice in &capsule.slices {
        slice_keys_match(slice)?;
    }

    // Self-consistency is satisfiable by any forger who mints a fresh,
    // internally-matched keypair; it is not authorization. What restores
    // the binding removed when the old per-role `authorized_keys` machinery
    // was deleted: the machine's slice keys, named PER ROLE by a
    // quorum-signed `IdentityRotated` event and carried alongside the
    // capsule at `rotation`. When present, every slice's wire pubkey must
    // match the entry the event names FOR THAT SLICE'S OWN ROLE — not
    // merely appear somewhere in an untagged set. The untagged shape was a
    // specification error: it left a multi-role machine's rotation
    // unresolvable by its own peers (see `quorum::IdentityRotated::
    // new_role_keys`'s own doc), and — worse, here — it would have let a
    // slice wear a key the rotation authorized for a DIFFERENT role and
    // still pass, since the old check only ever asked "is this key
    // anywhere in the set." Checked identically below regardless of
    // `signer`, because a `rotation` that IS present is verified on its own
    // signature, not on who sealed the envelope around it.
    //
    // Whether an ABSENT `rotation` is tolerable, though, depends entirely on
    // `signer`, and that is the gap this match closes: this function used to
    // treat every absent `rotation` alike, which let a Group-sealed capsule
    // with `rotation` omitted — an issuer bug, or a coordinator that wants
    // this check gone — pass silently, because nothing here was ever told
    // which key sealed the outer envelope. Now it is.
    match (&capsule.rotation, signer) {
        // The ONLY permitted skip. An operator seal is over the entire
        // plaintext byte-for-byte — `capsule.slices` included — verified
        // already in `capsule::unseal_capsule` before this function ever
        // runs. There is nothing left for a second, narrower check to add:
        // the operator vouching for the bytes already vouches for the keys
        // inside them. This is the box's first-ever admission, with no
        // prior identity to chain a rotation from.
        (None, CapsuleSigner::Operator) => {}
        // Mirrors the `Operator` arm above, for the same reason: the
        // signature already covers the entire plaintext byte-for-byte
        // (`sig_preimage` binds the ciphertext), and self-consistency for
        // every slice was already checked unconditionally above. What a
        // `rotation` event adds for `Group` is EXTERNAL authorization from a
        // party other than the signer — a quorum member vouching, blind to
        // the plaintext, for specific key material (see `SealAttestation`'s
        // own doc). A `Machine` signer is not asking anyone else to vouch:
        // it is the box's own durable attestation key certifying the box's
        // own freshly-minted keys to itself, which is exactly what
        // presentation-before-acceptance means — see
        // `docs/mirage/plans/self-issued-identity-2026-08-18.md`. Requiring
        // a quorum-signed `rotation` here would make a self-issued capsule
        // permanently unusable at the one moment it exists to serve: a cold
        // boot with neither operator nor quorum reachable. Peer-side
        // ACCEPTANCE of what this box presents — the actual grant of
        // authority — is a separate, later decision this function does not
        // make; every call site here checks a capsule against the box's own
        // identity, never a peer's.
        (None, CapsuleSigner::Machine { .. }) => {}
        // A FROST group signature does NOT carry that same guarantee: a
        // co-signer signs BLIND to the plaintext (see
        // `capsule::SealAttestation`'s own doc — a member sees the
        // ciphertext and the binding fields, never what is inside), so a
        // coordinator that stuffed attacker-chosen keys into an otherwise
        // legitimately quorum-sealed envelope would sail past
        // self-consistency alone with nothing left to catch it.
        // `rotation` is the one artefact a quorum member actually looked at
        // before signing — its own preimage names the key material
        // explicitly — so a Group-sealed capsule that omits it has nothing
        // authorizing its slice keys at all, and must be refused rather
        // than silently admitted.
        (None, CapsuleSigner::Group { .. }) => {
            return Err(BootError::Incoherent(
                "capsule is group-sealed but carries no rotation event — a group-sealed \
                 capsule without a rotation event cannot have its slice keys authorized"
                    .to_string(),
            ));
        }
        (Some(signed), _) => {
            let Some(charter) = &capsule.charter else {
                return Err(BootError::Incoherent(
                    "capsule carries a quorum rotation but no charter to verify it against"
                        .to_string(),
                ));
            };

            signed
                .verify(&capsule.mesh_id, operator_pubkey, |epoch| {
                    (epoch == charter.epoch)
                        .then(|| charter.group_verifying_key().ok())
                        .flatten()
                })
                .map_err(|e| BootError::Incoherent(format!("quorum rotation refused: {e}")))?;

            let crate::quorum::QuorumEvent::IdentityRotated(ev) = &signed.event else {
                return Err(BootError::Incoherent(
                    "capsule rotation is not an identity rotation".to_string(),
                ));
            };

            // The event has to speak about THIS identity on THIS box.
            // Without both, a rotation minted for a different box would
            // authorize key material in this one's capsule.
            if ev.self_id != capsule.self_id {
                return Err(BootError::Incoherent(format!(
                    "rotation names self_id {} != capsule self_id {}",
                    ev.self_id, capsule.self_id
                )));
            }
            if ev.subject.machine_id.as_str() != capsule.machine_id.as_str() {
                return Err(BootError::Incoherent(format!(
                    "rotation names machine {} != capsule machine {}",
                    ev.subject.machine_id.as_str(),
                    capsule.machine_id.as_str()
                )));
            }

            for slice in &capsule.slices {
                let wire_lower = slice.wire_pubkey_hex.to_lowercase();
                let authorized = ev.new_role_keys.iter().any(|rk| {
                    rk.role == slice.role && rk.wire_pubkey_hex.to_lowercase() == wire_lower
                });
                if !authorized {
                    return Err(BootError::Incoherent(format!(
                        "role {} wire public key is not in the rotation's authorized set for this role",
                        slice.role
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Verify ONE slice's private key(s) actually match the public key(s) sealed
/// beside them. Shared by [`check_coherent`]'s per-slice loop and
/// [`take_machine_slice`]'s check on the single slice it received — the same
/// self-consistency property, checked in the two places a slice's keys are
/// ever looked at.
fn slice_keys_match(slice: &crate::capsule::RoleSlice) -> Result<(), BootError> {
    let derived_wire = hex::encode(KeyPair::from_secret(slice.wire_privkey).public.to_bytes());
    if derived_wire != slice.wire_pubkey_hex.to_lowercase() {
        return Err(BootError::Incoherent(format!(
            "role {} wire private key does not match its own public key",
            slice.role
        )));
    }
    match (&slice.signing_privkey, &slice.signing_pubkey_hex) {
        (Some(sk), Some(expected)) => {
            let derived = hex::encode(SigningKey::from_bytes(sk).verifying_key().to_bytes());
            if derived != expected.to_lowercase() {
                return Err(BootError::Incoherent(format!(
                    "role {} signing private key does not match its own public key",
                    slice.role
                )));
            }
        }
        (Some(_), None) => {
            return Err(BootError::Incoherent(format!(
                "role {} carries a signing key with no public key to match it",
                slice.role
            )));
        }
        (None, Some(_)) => {
            return Err(BootError::Incoherent(format!(
                "role {} declares a signing public key but carries no private key",
                slice.role
            )));
        }
        (None, None) => {}
    }
    Ok(())
}

/// Prove a [`MachineSlice`] the keeper handed over is internally consistent
/// and vouched for by whichever authority its own [`DeclaredIdentity::
/// signer`] claims — the per-slice analogue of [`check_coherent`], run by
/// [`take_machine_slice`] so every consumer of the keeper socket gets the
/// same cross-check the old per-role capsule flow used to perform via
/// `BootSession::accept`.
///
/// For [`crate::identity::IdentitySigner::Machine`] the anchor is resolved
/// from [`MachineSlice::attestation_pubkey_hex`] rather than from a
/// parameter — this function's own caller, [`take_machine_slice`], is a
/// consumer with no attestation key of its own to pass in (unlike
/// [`check_coherent_full`]'s keeper-side caller), so the slice has to carry
/// what it needs to be checked with. See that field's own doc for why
/// carrying a public key here reveals nothing a peer could not already
/// read.
fn check_slice_coherent(
    slice: &MachineSlice,
    role: ServiceRole,
    operator_pubkey: &VerifyingKey,
    now_ms: u64,
) -> Result<(), BootError> {
    if now_ms >= slice.not_after_ms {
        return Err(BootError::Expired);
    }
    if slice.slice.role != role {
        return Err(BootError::Incoherent(format!(
            "keeper answered a request for role {role} with a slice for role {}",
            slice.slice.role
        )));
    }

    let decl = &slice.declared_identity;
    let machine_anchor = match &decl.signer {
        crate::identity::IdentitySigner::Operator => None,
        crate::identity::IdentitySigner::Machine { machine_id } => {
            let pubkey_hex = slice.attestation_pubkey_hex.as_deref().ok_or_else(|| {
                BootError::Incoherent(format!(
                    "role {role} slice's declared identity claims a machine signer \
                     ({machine_id}) but the slice carries no attestation pubkey to check it \
                     against"
                ))
            })?;
            Some(MachineAnchor {
                machine_id: machine_id.as_str(),
                attestation: decode_attestation_pubkey(pubkey_hex)?,
            })
        }
    };
    let anchor = CapsuleTrustAnchor {
        operator: operator_pubkey,
        charter: None,
        machine: machine_anchor,
    };
    decl.verify_with_anchor(&anchor)?;

    if decl.self_id != slice.self_id {
        return Err(BootError::Incoherent(format!(
            "declared self_id {} != slice self_id {}",
            decl.self_id, slice.self_id
        )));
    }
    if decl.machine_id.as_str() != slice.machine_id.as_str() {
        return Err(BootError::Incoherent(format!(
            "declared machine_id {} != slice machine_id {}",
            decl.machine_id.as_str(),
            slice.machine_id.as_str()
        )));
    }
    if decl.mesh_id.as_str() != slice.mesh_id.as_str() {
        return Err(BootError::Incoherent(format!(
            "declared mesh_id {} != slice mesh_id {}",
            decl.mesh_id.as_str(),
            slice.mesh_id.as_str()
        )));
    }
    if !decl.roles.contains(&role) {
        return Err(BootError::Incoherent(format!(
            "declared identity does not name role {role}, which this slice is for"
        )));
    }
    if decl.revoked {
        return Err(BootError::Incoherent(
            "declared identity is revoked".to_string(),
        ));
    }

    if let Some(charter) = &slice.charter {
        charter.verify(operator_pubkey)?;
        if charter.mesh_id.as_str() != slice.mesh_id.as_str() {
            return Err(BootError::Incoherent(format!(
                "charter mesh {} != slice mesh {}",
                charter.mesh_id.as_str(),
                slice.mesh_id.as_str()
            )));
        }
    }

    slice_keys_match(&slice.slice)
}

/// Decode a hex-encoded Ed25519 verifying key, naming the field on failure —
/// [`check_slice_coherent`]'s own use for [`MachineSlice::
/// attestation_pubkey_hex`]. Malformed hex, wrong length and an off-curve
/// point are all reported as [`BootError::Incoherent`] rather than panicking
/// or falling back to any default key.
fn decode_attestation_pubkey(hex_str: &str) -> Result<VerifyingKey, BootError> {
    let raw = hex::decode(hex_str)
        .map_err(|e| BootError::Incoherent(format!("attestation pubkey hex: {e}")))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| BootError::Incoherent("attestation pubkey must be 32 bytes".to_string()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| BootError::Incoherent(format!("attestation pubkey not on curve: {e}")))
}

/// How long to wait between attempts to reach the keeper's slice socket.
///
/// Short: a missing socket this early in boot is an ordinary startup race
/// against the keeper's own bind (it starts before every other unit, but
/// "before" is not "already listening"), not a fault to back off from
/// slowly. The same interval covers the keeper answering `NotYetAdmitted`
/// while it is still waiting on its own admission — both are conditions
/// this function waits through rather than gives up on; see this function's
/// own doc for why there is no deadline.
const MACHINE_SLICE_RETRY_MS: u64 = 500;

/// How long [`take_machine_slice`] waits, unlogged, before its first
/// visibility WARN. Long enough that an ordinary boot race against the
/// keeper's own bind (see [`MACHINE_SLICE_RETRY_MS`]'s own doc) never logs
/// anything — the keeper is normally serving within a second or two of its
/// own start — short enough that "the keeper never came up" is visible well
/// inside an operator's first look at the journal, long before anyone
/// thinks to doubt `systemctl status` reporting the unit `active (running)`.
const MACHINE_SLICE_WARN_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Cadence of the WARN once [`MACHINE_SLICE_WARN_AFTER`] has passed. A human
/// who opens the journal while this is still stuck should see the line
/// again inside a minute, not once and never again.
const MACHINE_SLICE_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// How often [`watch_machine_slice`] re-asks the keeper for a role's slice,
/// once that role's own boot-time [`take_machine_slice`] call has already
/// returned once.
///
/// The SAME cadence `mirage-perimeter`'s own `Surface::watch_for_a_new_capsule`
/// re-reads its capsule on — that crate's `CAPSULE_WATCH_INTERVAL` reuses
/// THIS constant rather than a private literal of its own (see that
/// constant's own doc), so there is exactly one number in the workspace for
/// "how long a box can run on a capsule its own daemon has not noticed is
/// stale", not two that happen to agree today and are free to drift apart
/// the next time either one is touched.
///
/// # Why sixty seconds and not five
///
/// This was 5 s until 2026-08-28, inherited from the boot-time wait's own
/// urgency — but the boot wait is a different loop with a different number
/// ([`MACHINE_SLICE_RETRY_MS`], 500 ms), and nothing about it applies here.
/// What THIS cadence has to catch is a capsule RENEWAL, and the keeper
/// opens its delivery window `lead_ms = 21_600_000` — six hours — before
/// expiry. Polling every 5 s meant 17 280 asks per renewal, of an event
/// that happens about once a day. Sixty seconds still leaves 360x headroom
/// inside that window.
///
/// The cost was not the polling itself. Each ask is a fresh
/// [`crate::local_endpoint::LocalChannel::MachineIdentity`] connect, and
/// every accept makes the keeper run
/// [`crate::local_endpoint::peer_image_admitted`], whose
/// `readlink("/proc/<caller pid>/exe")` is exactly what Tier-2's
/// `ptrace_access_check` denies for a protected caller. Five steady-state
/// watchers (secd, the monitor, the node, the sentry, and the perimeter via
/// its own `CAPSULE_WATCH_INTERVAL`) therefore drove 60 kernel deny events
/// a minute on any box where Tier-2 actually fires — measured 94-103/min
/// total on `us-example-203.0.113.25`, which collapsed that fleet's
/// kernel-event history to about a minute. `mirage-warden`'s
/// `sensor_fwd::is_self_inflicted_ptrace_deny` stops those being SIGNED;
/// this number is what stops them being CAUSED.
pub const MACHINE_SLICE_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Ask the keeper (`mirage-warden`) for this role's slice out of the current
/// machine capsule, and wait for it — **without a deadline**.
///
/// ## Why there is no timeout, and no fallback
///
/// A bounded wait that fell through to "announce for myself" would
/// reintroduce exactly the per-service announce loop this plan deletes, turn
/// it into a race with every other restarting service, and — with admission
/// now keyed per machine instead of per `(machine, role)` — leave the losers
/// of that race sitting out the machine's own rate-limit window. If the
/// keeper cannot answer, the box has a broken supervisor, and the operator's
/// way in is mshd's recovery door, which is capsule-independent for exactly
/// this reason. See
/// `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §4.
///
/// ## What DOES return an error
///
/// A slice that fails [`check_slice_coherent`] for any reason OTHER than
/// expiry — a bad signature, a self-inconsistent key pair, a role the
/// declared identity does not name — is not something retrying fixes, and
/// silently waiting past it would hide a keeper serving corrupt or forged
/// material. Expiry alone is retried: the keeper's own machine capsule is
/// expected to renew, and that is exactly the kind of transient condition
/// this function otherwise waits through.
///
/// ## A blocked wait must not be an invisible one
///
/// Every per-attempt outcome above already logs at `debug`/`warn`/`error`,
/// but none of that reaches a human who has not gone looking — and a
/// warden that failed to start leaves every consumer sitting in this loop
/// forever while systemd keeps reporting the unit `active (running)`. This
/// function additionally escalates to `WARN` once the WHOLE wait — not any
/// one attempt — has run past [`MACHINE_SLICE_WARN_AFTER`], and repeats at
/// most every [`MACHINE_SLICE_WARN_INTERVAL`] after that, naming the socket
/// and the elapsed time so one journal line is enough to tell an operator
/// the keeper never came up. This is visibility only: no deadline is added,
/// no fallback path opens, and the loop below is unchanged.
/// What this binary can currently tell about a `Take` attempt against the
/// keeper — named so both the escalating "still waiting" WARN and the
/// once-per-transition decode-failure ERROR in [`take_machine_slice`] can
/// report exactly which of these is true right now, rather than a bare
/// "could not reach the keeper" that says nothing about which of several
/// very different facts is holding up the wait.
///
/// The `Renewal` reply case (the keeper answering a `Take` with the wrong
/// response shape — a keeper-side protocol bug, not a normal wait state)
/// has no dedicated variant here: it folds into [`Self::Unreachable`]
/// rather than growing a sixth state nothing else in this loop produces,
/// since an operator reading the escalation line has the same actionable
/// answer either way ("the keeper is not answering this ask correctly").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SliceAskOutcome {
    /// The keeper holds no machine capsule at all yet.
    NotYetAdmitted,
    /// The keeper's slice for this role has expired; waiting for it to renew.
    Expired,
    /// The keeper's capsule carries no slice for this role at all.
    NoSuchRole,
    /// Could not even reach the keeper, or the keeper answered something
    /// this loop cannot retry through — connect/write/read failed, or a
    /// wrong-shape reply. Transient by nature: the keeper may simply not
    /// have bound its socket yet.
    Unreachable,
    /// The keeper answered, but this binary could not decode the reply as
    /// a [`MachineIdentityResponse`] — almost always a binary built against
    /// a different wire shape than the capsule the keeper is serving.
    /// Retrying never fixes this; only a matching build does. See
    /// [`AskKeeperError::Decode`]'s own doc for the incident this closes.
    DecodeFailed,
}

impl std::fmt::Display for SliceAskOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SliceAskOutcome::NotYetAdmitted => "not_yet_admitted",
            SliceAskOutcome::Expired => "expired",
            SliceAskOutcome::NoSuchRole => "no_such_role",
            SliceAskOutcome::Unreachable => "unreachable",
            SliceAskOutcome::DecodeFailed => "decode_failed",
        })
    }
}

pub async fn take_machine_slice(
    role: ServiceRole,
    operator_pubkey: &VerifyingKey,
) -> Result<MachineSlice, BootError> {
    let req = MachineIdentityRequest::Take { role };
    let started = std::time::Instant::now();
    let mut last_warn: Option<std::time::Instant> = None;
    let mut last_outcome: Option<SliceAskOutcome> = None;
    loop {
        let outcome = match ask_keeper(&req).await {
            Ok(MachineIdentityResponse::Slice(slice)) => {
                match check_slice_coherent(&slice, role, operator_pubkey, now_ms()) {
                    Ok(()) => return Ok(*slice),
                    Err(BootError::Expired) => {
                        tracing::debug!(
                            %role,
                            "take_machine_slice: keeper's slice has expired — waiting for it to renew"
                        );
                        SliceAskOutcome::Expired
                    }
                    Err(e) => {
                        tracing::error!(%role, error = %e,
                            "take_machine_slice: the keeper handed over a slice that does not check out");
                        return Err(e);
                    }
                }
            }
            Ok(MachineIdentityResponse::NotYetAdmitted) => {
                tracing::debug!(%role, "take_machine_slice: keeper has no machine capsule yet");
                SliceAskOutcome::NotYetAdmitted
            }
            Ok(MachineIdentityResponse::NoSuchRole) => {
                tracing::warn!(
                    %role,
                    "take_machine_slice: keeper holds a capsule with no slice for this role"
                );
                SliceAskOutcome::NoSuchRole
            }
            Ok(MachineIdentityResponse::Renewal(_)) => {
                // Only ever answers `RenewalStatus` — a keeper sending this
                // back for a `Take` is answering the wrong question, not a
                // state this loop can retry through.
                tracing::error!(
                    %role,
                    "take_machine_slice: keeper answered a Take request with a Renewal reply — \
                     retrying"
                );
                SliceAskOutcome::Unreachable
            }
            Err(AskKeeperError::Transport(e)) => {
                tracing::debug!(
                    %role, error = %e,
                    "take_machine_slice: could not reach the keeper — retrying"
                );
                SliceAskOutcome::Unreachable
            }
            Err(AskKeeperError::Decode(e)) => {
                // Named once per transition INTO this state, never once per
                // attempt: at `MACHINE_SLICE_RETRY_MS` this loop turns over
                // twice a second, and a stuck decode failure would otherwise
                // flood the journal with an identical line forever while
                // changing nothing a human could act on differently.
                //
                // Measured live on `ae-example-203.0.113.86`, 2026-09-24: an
                // `mshd` binary built 2026-09-23, before
                // `CapsuleServiceConfig::subscriber_entrance`'s own
                // `socks_addr` field was retired, could not decode a keeper
                // reply carrying the NEW shape. `ask_keeper` returned a bare
                // `io::Error` this loop logged at `debug!` and retried
                // forever, indistinguishable from an ordinary "keeper not up
                // yet" connect failure — the only visible symptom was the
                // generic "still waiting" WARN below, naming neither the
                // cause nor the fix.
                if last_outcome != Some(SliceAskOutcome::DecodeFailed) {
                    tracing::error!(
                        %role, error = %e,
                        "take_machine_slice: the keeper answered but this binary could not decode \
                         the reply — this binary is older or newer than the capsule shape the \
                         keeper serves; redeploy it"
                    );
                }
                SliceAskOutcome::DecodeFailed
            }
        };
        last_outcome = Some(outcome);

        // Escalating visibility only — see this function's own doc, "A
        // blocked wait must not be an invisible one". Checked once per
        // attempt rather than logged once per attempt: at
        // `MACHINE_SLICE_RETRY_MS` this loop turns over twice a second, and
        // a line every turn would bury the one event actually worth a
        // human's attention. Names `last_outcome` so a human reading ONE
        // journal line knows which of the five facts above is currently
        // true, rather than only "still waiting".
        let waited = started.elapsed();
        if waited >= MACHINE_SLICE_WARN_AFTER
            && last_warn.is_none_or(|t| t.elapsed() >= MACHINE_SLICE_WARN_INTERVAL)
        {
            tracing::warn!(
                %role,
                channel = LocalChannel::MachineIdentity.label(),
                socket = LocalChannel::MachineIdentity.unix_path(),
                waited = ?waited,
                last_outcome = %outcome,
                "take_machine_slice: still waiting on the keeper for this role's slice — if \
                 mirage-warden never came up, systemd will keep reporting this unit active while \
                 this wait continues forever by design"
            );
            last_warn = Some(std::time::Instant::now());
        }

        tokio::time::sleep(std::time::Duration::from_millis(MACHINE_SLICE_RETRY_MS)).await;
    }
}

/// What went wrong on one dial to the keeper's slice socket — split from a
/// bare `io::Error` so a caller (concretely, [`take_machine_slice`]) can
/// tell "the keeper is not reachable" (transient — the socket may simply
/// not be bound yet) apart from "the keeper answered, but this binary
/// cannot read it" (permanent until this binary is rebuilt/redeployed
/// against the same wire shape the keeper is serving). See
/// [`SliceAskOutcome`]'s own doc for the incident that made the two worth
/// telling apart.
#[derive(Debug)]
enum AskKeeperError {
    /// Connect, write, or read itself failed.
    Transport(io::Error),
    /// The keeper answered, but the bytes did not deserialise as a
    /// [`MachineIdentityResponse`].
    Decode(String),
}

impl std::fmt::Display for AskKeeperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AskKeeperError::Transport(e) => write!(f, "transport: {e}"),
            AskKeeperError::Decode(e) => write!(f, "decode: {e}"),
        }
    }
}

/// Dial the keeper's slice socket once and read its answer. Split out of
/// [`take_machine_slice`] so the retry loop stays free of the socket
/// framing details.
///
/// Reads the frame BODY via [`crate::local_rpc::read_body`] and decodes it
/// here, rather than delegating the whole read to
/// [`crate::local_rpc::read_frame`], specifically so a decode failure comes
/// back as [`AskKeeperError::Decode`] and never gets folded into the same
/// `io::Error` shape a transport failure produces — see [`AskKeeperError`]'s
/// own doc for why that distinction is load-bearing for the caller.
async fn ask_keeper(req: &MachineIdentityRequest) -> Result<MachineIdentityResponse, AskKeeperError> {
    let mut stream = LocalChannel::MachineIdentity.connect().await.map_err(AskKeeperError::Transport)?;
    crate::local_rpc::write_frame(&mut stream, req).await.map_err(AskKeeperError::Transport)?;
    let body = crate::local_rpc::read_body(&mut stream)
        .await
        .map_err(AskKeeperError::Transport)?
        .ok_or_else(|| {
            AskKeeperError::Transport(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the keeper closed the slice channel without answering",
            ))
        })?;
    decode_slice_response(&body)
}

/// [`ask_keeper`]'s decode step, split out so it is directly unit-testable
/// against raw bytes instead of a live socket — the same reasoning every
/// other pure-decision extraction in this crate follows.
fn decode_slice_response(body: &[u8]) -> Result<MachineIdentityResponse, AskKeeperError> {
    serde_json::from_slice(body).map_err(|e| AskKeeperError::Decode(e.to_string()))
}

/// One-shot read of the keeper's renewal-stall state
/// ([`MachineIdentityRequest::RenewalStatus`]).
///
/// Unlike [`take_machine_slice`], this never loops and never blocks past one
/// dial: a caller building `/perimeter/stats` (or any other cheap read)
/// needs an answer for THIS read, not a wait for a keeper that has not come
/// up yet. `Err` only when the keeper's socket itself could not be reached
/// or answered something this frame cannot decode; `Ok(None)` is the
/// ordinary case — nothing is stalled.
pub async fn ask_renewal_status() -> io::Result<Option<RenewalStallState>> {
    match ask_keeper(&MachineIdentityRequest::RenewalStatus).await {
        Ok(MachineIdentityResponse::Renewal(state)) => Ok(state),
        Ok(other) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("keeper answered RenewalStatus with an unexpected shape: {other:?}"),
        )),
        Err(AskKeeperError::Transport(e)) => Err(e),
        Err(AskKeeperError::Decode(e)) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}

/// Poll the keeper for `role`'s machine slice on
/// [`MACHINE_SLICE_WATCH_INTERVAL`] and publish every successfully-acquired
/// [`MachineSlice`] onto `tx` — never returns.
///
/// # What this is FOR
///
/// `mirage-warden` self-issues a machine identity the instant it starts, so
/// a box with no capsule still runs; the operator's real capsule is a
/// network delivery and always lands afterwards — measured 2 m 4 s
/// afterwards on `us-example-203.0.113.25`, 2026-08-20. Every service that reads
/// its capsule exactly once at boot ([`take_machine_slice`], called from
/// this crate's own boot-time acquire paths) keeps whatever slice it
/// happened to boot on FOREVER, because nothing about the running process
/// ever asks again. Concretely, on that box: `mirage-secd` took a
/// self-issued slice at 00:46:57, the operator capsule was admitted at
/// 00:49:01, and secd went on presenting the self-issued envelope
/// indefinitely — the co-located monitor refused every one of its
/// `/secd/kernel-security-event` posts under it, 155 in one minute, each
/// refusal discarding one kernel deny event (the only direct record that a
/// Tier2 hook fired). The same shape had already run once before, for
/// fourteen hours, before anyone noticed.
///
/// This function is the shared, generic half of the fix: a service that
/// wants to stop being that box spawns this once, alongside its own
/// boot-time acquire — never instead of it, see "Never the caller's ONLY
/// read" below — and gets told about every slice the keeper hands out from
/// then on, including ones identical to what it already holds.
///
/// # Detection only
///
/// This function does exactly one thing: notice. It does not decide what a
/// fresher slice MEANS to the caller, because the right answer differs by
/// service and none of the three existing/planned answers generalise:
/// `mirage-perimeter` can swap its surface in place because only its FACES
/// depend on the capsule (`Surface::watch_for_a_new_capsule`, the working
/// reference this primitive generalises the detection half of, and nothing
/// else); `mirage2monitor` parks at boot until handed a capsule it can
/// serve, because its identity, keys and peer table are boot-scoped; and
/// `mirage-secd` must do neither — local enforcement does not depend on
/// this identity at all, so parking would trade the box's defence for its
/// telemetry, and secd instead keeps running and rebuilds only the identity
/// it REPORTS under (`mirage-secd::capsule_boot::run_identity_swap_watcher`).
/// A dedupe rule baked in here would be wrong for at least one of these: the
/// perimeter compares `self_id` AND the whole face list — a re-sealed
/// capsule can carry a new `service_config` under the SAME `self_id` —
/// while the monitor and secd both compare `self_id` alone. So this
/// function is not a change-detector, it is a courier: it calls
/// [`take_machine_slice`] on a cadence and hands the caller whatever the
/// keeper actually served, unconditionally, on every successful call.
/// Publish what the keeper served; the caller decides what counts as a
/// change.
///
/// # Never the caller's ONLY read
///
/// Spawn this ALONGSIDE the service's own boot-time [`take_machine_slice`]
/// call (or a role-specific wrapper around it) — never in place of it. The
/// first slice a process acts on should always come from that boot-time
/// call, exactly as it does today; this function only starts mattering once
/// that first slice has already landed, and its own first tick is
/// [`MACHINE_SLICE_WATCH_INTERVAL`] after it is spawned.
///
/// # Failure handling
///
/// A failed acquire is not an event this function surfaces at all — logged
/// at `debug` and nothing published, so every subscriber simply sees no
/// change and keeps whatever it already held, the same way a keeper that is
/// briefly unreachable leaves `mirage-perimeter`'s own surface untouched.
/// Only a successful [`take_machine_slice`] call publishes.
pub async fn watch_machine_slice(
    role: ServiceRole,
    operator_pubkey: VerifyingKey,
    tx: tokio::sync::watch::Sender<Option<MachineSlice>>,
) {
    loop {
        tokio::time::sleep(MACHINE_SLICE_WATCH_INTERVAL).await;

        match take_machine_slice(role, &operator_pubkey).await {
            Ok(slice) => {
                // No dedupe here by design — see this function's own doc,
                // "Detection only". `watch::Sender::send` always bumps the
                // channel's version and wakes every subscriber's
                // `changed()` regardless of whether `slice` is equal to
                // what was there before, which is exactly what every
                // caller needs; a filter here would be right for at most
                // one of them.
                let _ = tx.send(Some(slice));
            }
            Err(e) => {
                tracing::debug!(
                    %role, error = %e,
                    "watch_machine_slice: a re-read of this role's slice did not resolve — \
                     publishing nothing, asking again next tick"
                );
            }
        }
    }
}

#[cfg(test)]
mod machine_slice_watch_tests {
    use super::MACHINE_SLICE_WATCH_INTERVAL;

    /// `mirage-perimeter`'s `CAPSULE_WATCH_INTERVAL` reuses this constant
    /// (see its own doc) rather than a private literal of its own — this
    /// pins the value itself, so a change here is a deliberate, visible
    /// edit rather than an accidental drift the two crates discover by
    /// disagreeing at runtime.
    #[test]
    fn the_watch_interval_is_sixty_seconds() {
        assert_eq!(MACHINE_SLICE_WATCH_INTERVAL, std::time::Duration::from_secs(60));
    }

    /// The steady-state watch must never poll faster than the boot-time
    /// wait, which is the loop that actually needs to be quick — the two
    /// numbers were conflated until 2026-08-28 and that conflation is what
    /// drove the deny flood. This fails if anyone re-collapses them.
    #[test]
    fn the_watch_is_far_slower_than_the_boot_wait() {
        assert!(
            MACHINE_SLICE_WATCH_INTERVAL
                > std::time::Duration::from_millis(super::MACHINE_SLICE_RETRY_MS * 10)
        );
    }
}

/// Atomic write with `0600`, matching [`crate::box_signing`]'s idiom.
pub(crate) fn write_atomic(path: &Path, body: &[u8]) -> io::Result<()> {
    let tmp = {
        let mut p = path.to_path_buf();
        let mut name = p
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
            .to_os_string();
        name.push(".new");
        p.set_file_name(name);
        p
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod renew_jitter_tests {
    use super::*;

    const DAY_MS: u64 = 24 * 3600 * 1000;
    /// Nine live boxes; the roles that renew on each.
    const BOXES: [&str; 9] = [
        "ch-example-203.0.113.41",
        "nl-example-203.0.113.31",
        "nl-example-203.0.113.30",
        "ru-hostkey-203.0.113.10",
        "ru-example-203.0.113.50",
        "tr-hostkey-203.0.113.20",
        "us-example-203.0.113.25",
        "us-example-203.0.113.25",
        "us-example-203.0.113.25",
    ];
    const ROLES: [&str; 5] = ["node-v2", "sentry", "mshd", "db-worker", "perimeter"];

    /// A restart must not re-roll the offset, or a crash-looping service
    /// walks its own schedule around and re-converges with someone else.
    #[test]
    fn the_offset_is_stable_for_one_machine_and_role() {
        let a = renew_jitter_ms("ru-hostkey-203.0.113.10", "sentry", DEFAULT_RENEW_JITTER_SPAN_MS);
        let b = renew_jitter_ms("ru-hostkey-203.0.113.10", "sentry", DEFAULT_RENEW_JITTER_SPAN_MS);
        assert_eq!(a, b);
    }

    #[test]
    fn two_roles_on_one_box_do_not_share_an_offset() {
        let node = renew_jitter_ms("ru-hostkey-203.0.113.10", "node-v2", DEFAULT_RENEW_JITTER_SPAN_MS);
        let sentry = renew_jitter_ms("ru-hostkey-203.0.113.10", "sentry", DEFAULT_RENEW_JITTER_SPAN_MS);
        assert_ne!(node, sentry);
    }

    #[test]
    fn one_role_on_two_boxes_does_not_share_an_offset() {
        let a = renew_jitter_ms("ru-hostkey-203.0.113.10", "mshd", DEFAULT_RENEW_JITTER_SPAN_MS);
        let b = renew_jitter_ms("tr-hostkey-203.0.113.20", "mshd", DEFAULT_RENEW_JITTER_SPAN_MS);
        assert_ne!(a, b);
    }

    /// The domain separator must actually separate: `("ab", "c")` and
    /// `("a", "bc")` are different pairs and must not hash alike.
    #[test]
    fn the_pair_is_separated_not_concatenated() {
        let a = renew_jitter_ms("ab", "c", DEFAULT_RENEW_JITTER_SPAN_MS);
        let b = renew_jitter_ms("a", "bc", DEFAULT_RENEW_JITTER_SPAN_MS);
        assert_ne!(a, b);
    }

    #[test]
    fn a_zero_span_is_no_jitter_rather_than_a_panic() {
        assert_eq!(renew_jitter_ms("ru-hostkey-203.0.113.10", "sentry", 0), 0);
    }

    /// Jitter only ever ADDS, so no service gets a shorter safety margin than
    /// it had before this existed.
    #[test]
    fn the_lead_is_never_shorter_than_the_default() {
        let now = 1_700_000_000_000;
        for m in BOXES {
            for r in ROLES {
                let lead = renew_lead_for(m, r, now + DAY_MS, now);
                assert!(
                    lead >= DEFAULT_RENEW_LEAD_MS,
                    "{m}/{r} lead {lead} < default"
                );
                assert!(lead <= DEFAULT_RENEW_LEAD_MS + DEFAULT_RENEW_JITTER_SPAN_MS);
            }
        }
    }

    /// The actual point: 45 role-capsules must not renew in one instant.
    /// Measured band on 2026-08-11 after the fleet converged was 155 s.
    #[test]
    fn the_fleet_spreads_across_the_span_instead_of_one_instant() {
        let now = 1_700_000_000_000;
        let mut leads: Vec<u64> = Vec::new();
        for m in BOXES {
            for r in ROLES {
                leads.push(renew_lead_for(m, r, now + DAY_MS, now));
            }
        }
        leads.sort_unstable();
        let band = leads[leads.len() - 1] - leads[0];
        assert!(
            band > 60 * 60_000,
            "45 capsules spread over only {band} ms — that is still one instant"
        );
        // And no two of them land on the same millisecond.
        let mut dedup = leads.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), leads.len(), "two capsules share a renewal instant");
    }

    /// Without the clamp a short-TTL capsule meets a lead longer than its own
    /// life, the "sleep until due" loop falls straight through every pass, and
    /// the service hammers the issuer instead of renewing once.
    #[test]
    fn a_short_ttl_capsule_clamps_the_lead_instead_of_renewing_forever() {
        let now = 1_700_000_000_000;
        let ttl = 10 * 60_000; // 10 minutes, well under the 15-minute default
        let lead = renew_lead_for("ru-hostkey-203.0.113.10", "sentry", now + ttl, now);
        assert!(lead <= ttl / 2, "lead {lead} would fire immediately on a {ttl} ms capsule");
        assert!(lead > 0);
    }

    /// An already-expired capsule must produce a zero lead — "renew now" —
    /// not an underflowed enormous one.
    #[test]
    fn an_expired_capsule_does_not_underflow_the_clamp() {
        let now = 1_700_000_000_000;
        assert_eq!(renew_lead_for("ru-hostkey-203.0.113.10", "sentry", now - 1, now), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{seal_capsule, CapsulePeer, CapsuleServiceConfig, CapsuleSigner};
    use crate::identity::{DeclaredIdentity, RolePublicKeys, ServiceRole};
    use crate::ids::{MachineId, MeshId};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    const MACHINE: &str = "ru-hostkey-203.0.113.10";
    const NOW: u64 = 1_700_000_000_000;

    struct Env {
        op: SigningKey,
        op_pub: VerifyingKey,
        wire: KeyPair,
        sign: SigningKey,
    }

    fn env() -> Env {
        let op = SigningKey::generate(&mut OsRng);
        let op_pub = op.verifying_key();
        Env {
            op,
            op_pub,
            wire: KeyPair::generate(),
            sign: SigningKey::generate(&mut OsRng),
        }
    }

    /// A single-slice machine capsule, role `Sentry` throughout — the
    /// common fixture most tests below build on.
    fn capsule(e: &Env, with_signing: bool) -> MachineCapsule {
        let role = ServiceRole::Sentry;
        let signing_pub = with_signing.then(|| hex::encode(e.sign.verifying_key().to_bytes()));
        let decl = DeclaredIdentity::sign_new_full(
            Uuid::from_u128(42),
            MachineId::new(MACHINE).unwrap(),
            MeshId::new("v3-staging").unwrap(),
            vec![role],
            vec![RolePublicKeys {
                role,
                wire_pubkey_hex: hex::encode(e.wire.public.to_bytes()),
                signing_pubkey_hex: signing_pub,
            }],
            NOW - 1000,
            None,
            None,
            Vec::new(),
            None,
            &e.op,
        );
        MachineCapsule {
            self_id: Uuid::from_u128(42),
            machine_id: MachineId::new(MACHINE).unwrap(),
            mesh_id: MeshId::new("v3-staging").unwrap(),
            slices: vec![crate::capsule::RoleSlice {
                role,
                wire_privkey: e.wire.secret.to_bytes(),
                signing_privkey: with_signing.then(|| e.sign.to_bytes()),
                wire_pubkey_hex: hex::encode(e.wire.public.to_bytes()),
                signing_pubkey_hex: with_signing
                    .then(|| hex::encode(e.sign.verifying_key().to_bytes())),
            }],
            declared_identity: decl,
            peers: vec![],
            service_config: CapsuleServiceConfig::default(),
            charter: None,
            rotation: None,
            db_key: None,
            issued_at_ms: NOW,
            not_after_ms: NOW + 3_600_000,
        }
    }

    fn session() -> BootSession {
        BootSession::new("sentry", "build-abc", NOW, attest_key(MACHINE))
    }

    fn seal_for(e: &Env, s: &BootSession, c: &MachineCapsule) -> SealedCapsule {
        let eph_pub = hex::decode(&s.announce().eph_pubkey_hex).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&eph_pub);
        seal_capsule(
            c,
            &arr,
            s.boot_nonce(),
            "issue-1",
            NOW,
            CapsuleSigner::Operator,
            &e.op,
        )
        .unwrap()
    }

    #[test]
    fn announce_carries_only_public_material() {
        let s = session();
        let a = s.announce();
        // The box knows its own name on every boot now, from the enrolment.
        assert_eq!(a.machine_id, MACHINE);
        assert_eq!(a.build_id, "build-abc");
        assert_eq!(a.eph_pubkey_hex.len(), 64);
        assert!(!a.boot_nonce.is_empty());
        // Nothing in the serialised announce may resemble a private key.
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("priv"), "{json}");
    }

    #[test]
    fn each_session_gets_fresh_key_material() {
        let a = session().announce();
        let b = session().announce();
        assert_ne!(a.eph_pubkey_hex, b.eph_pubkey_hex);
        assert_ne!(a.boot_nonce, b.boot_nonce);
    }

    #[test]
    fn accept_roundtrip() {
        let e = env();
        let s = session();
        let c = capsule(&e, true);
        let sealed = seal_for(&e, &s, &c);
        let got = s.accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS);
        assert!(got.is_ok(), "{:?}", got.err());
    }

    #[test]
    fn capsule_sealed_for_a_previous_attempt_is_refused() {
        // The exact failure the fresh-per-attempt rule exists to prevent.
        let e = env();
        let old = session();
        let sealed = seal_for(&e, &old, &capsule(&e, true));
        let new = session();
        let err = new
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(
            matches!(err, BootError::Capsule(CapsuleError::BindingMismatch)),
            "got {err:?}"
        );
    }

    #[test]
    fn a_session_rejects_a_capsule_for_another_box() {
        // Enforced on EVERY boot, not just renewals: the session takes its name
        // from the enrolment, so there is no first-boot window where a capsule
        // addressed elsewhere would be adopted on the strength of the AEAD
        // alone.
        let e = env();
        let s = session();
        let sealed = seal_for(&e, &s, &capsule(&e, true));
        let other = BootSession::new(
            "sentry",
            "build-abc",
            NOW,
            attest_key("tr-hostkey-203.0.113.20"),
        );
        let err = other
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(
            matches!(err, BootError::Capsule(CapsuleError::BindingMismatch)),
            "got {err:?}"
        );
    }

    #[test]
    fn wire_privkey_must_match_the_signed_pubkey() {
        let e = env();
        let s = session();
        let mut c = capsule(&e, true);
        c.slices[0].wire_privkey = KeyPair::generate().secret.to_bytes();
        let sealed = seal_for(&e, &s, &c);
        let err = s
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(
            matches!(&err, BootError::Incoherent(m) if m.contains("wire private key")),
            "got {err:?}"
        );
    }

    #[test]
    fn signing_privkey_must_match_the_signed_pubkey() {
        let e = env();
        let s = session();
        let mut c = capsule(&e, true);
        c.slices[0].signing_privkey = Some(SigningKey::generate(&mut OsRng).to_bytes());
        let sealed = seal_for(&e, &s, &c);
        let err = s
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(
            matches!(&err, BootError::Incoherent(m) if m.contains("signing private key")),
            "got {err:?}"
        );
    }

    #[test]
    fn missing_signing_key_for_a_signing_role_is_refused() {
        let e = env();
        let s = session();
        let mut c = capsule(&e, true);
        c.slices[0].signing_privkey = None;
        let sealed = seal_for(&e, &s, &c);
        let err = s
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(
            matches!(&err, BootError::Incoherent(m) if m.contains("carries no private key")),
            "got {err:?}"
        );
    }

    #[test]
    fn role_without_a_signing_key_is_fine() {
        let e = env();
        let s = session();
        let sealed = seal_for(&e, &s, &capsule(&e, false));
        assert!(s
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .is_ok());
    }

    #[test]
    fn revoked_identity_is_refused() {
        let e = env();
        let s = session();
        let mut c = capsule(&e, true);
        // Flip the column the way a stale escrow row would, then re-sign the
        // envelope so the failure is provably the revocation gate.
        c.declared_identity.revoked = true;
        let sealed = seal_for(&e, &s, &c);
        let err = s
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        // `revoked` is outside the signed bytes, so the identity still verifies
        // and the refusal comes from the coherence gate, not the signature.
        assert!(
            matches!(&err, BootError::Incoherent(m) if m.contains("revoked")),
            "got {err:?}"
        );
    }

    #[test]
    fn expired_capsule_is_refused() {
        let e = env();
        let s = session();
        let mut c = capsule(&e, true);
        c.not_after_ms = NOW + 1;
        let sealed = seal_for(&e, &s, &c);
        let err = s
            .accept(&sealed, &e.op_pub, None, NOW + 2, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(matches!(err, BootError::Expired), "got {err:?}");
    }

    #[test]
    fn identity_signed_by_another_operator_is_refused() {
        let e = env();
        let s = session();
        let other = SigningKey::generate(&mut OsRng);
        let mut c = capsule(&e, true);
        // Same keys, but the envelope is signed by someone else.
        c.declared_identity = DeclaredIdentity::sign_new_full(
            Uuid::from_u128(42),
            MachineId::new(MACHINE).unwrap(),
            MeshId::new("v3-staging").unwrap(),
            vec![ServiceRole::Sentry],
            vec![RolePublicKeys {
                role: ServiceRole::Sentry,
                wire_pubkey_hex: hex::encode(e.wire.public.to_bytes()),
                signing_pubkey_hex: Some(hex::encode(e.sign.verifying_key().to_bytes())),
            }],
            NOW - 1000,
            None,
            None,
            Vec::new(),
            None,
            &other,
        );
        let sealed = seal_for(&e, &s, &c);
        let err = s
            .accept(&sealed, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap_err();
        assert!(matches!(err, BootError::Identity(_)), "got {err:?}");
    }

    // ── quorum-rotated keys (machine-scoped) ─────────────────────────────
    //
    // The operator never signed these keys. The quorum did, and that is the
    // whole point: without it every unattended reboot needs the holder of
    // the operator key to be reachable. See `MachineCapsule::rotation`'s
    // own doc.

    fn charter_for(e: &Env, group: &SigningKey, epoch: u64) -> crate::capsule::GroupCharter {
        crate::capsule::GroupCharter::sign_new(
            MeshId::new("v3-staging").unwrap(),
            epoch,
            hex::encode(group.verifying_key().to_bytes()),
            5,
            vec![Uuid::from_u128(1), Uuid::from_u128(2)],
            NOW - 10_000,
            &e.op,
        )
    }

    /// A capsule carrying FRESH key material for every slice plus the
    /// quorum event that authorizes the whole set, exactly as a
    /// monitor-issued machine capsule would after an unattended reboot.
    fn rotated_capsule(e: &Env, group: &SigningKey, epoch: u64, subject_machine: &str) -> MachineCapsule {
        let mut c = capsule(e, true);
        let new_wire = KeyPair::generate();
        let new_sign = SigningKey::generate(&mut OsRng);
        c.slices[0].wire_privkey = new_wire.secret.to_bytes();
        c.slices[0].wire_pubkey_hex = hex::encode(new_wire.public.to_bytes());
        c.slices[0].signing_privkey = Some(new_sign.to_bytes());
        c.slices[0].signing_pubkey_hex = Some(hex::encode(new_sign.verifying_key().to_bytes()));
        c.charter = Some(charter_for(e, group, epoch));

        let ev = crate::quorum::QuorumEvent::IdentityRotated(crate::quorum::IdentityRotated {
            subject: crate::quorum::Subject {
                mesh_id: MeshId::new("v3-staging").unwrap(),
                machine_id: MachineId::new(subject_machine).unwrap(),
            },
            self_id: c.self_id,
            prev_wire_pubkeys: vec![hex::encode(e.wire.public.to_bytes())],
            new_role_keys: vec![RolePublicKeys {
                role: c.slices[0].role,
                wire_pubkey_hex: hex::encode(new_wire.public.to_bytes()),
                signing_pubkey_hex: Some(hex::encode(new_sign.verifying_key().to_bytes())),
            }],
            charter_epoch: epoch,
            seq: 1,
            issued_at_ms: NOW - 500,
        });
        c.rotation = Some(crate::quorum::SignedQuorumEvent::sign(
            ev,
            crate::quorum::EventSigner::Quorum { charter_epoch: epoch },
            group,
        ));
        c
    }

    #[test]
    fn a_quorum_rotation_authorizes_keys_the_operator_never_signed() {
        let e = env();
        let group = SigningKey::generate(&mut OsRng);
        let c = rotated_capsule(&e, &group, 4, MACHINE);
        // The declared identity still carries the OLD operator-signed key,
        // and that is the situation: the operator is unreachable and
        // cannot re-sign.
        assert_ne!(
            c.declared_identity.wire_pubkey_for(&ServiceRole::Sentry),
            Some(c.slices[0].wire_pubkey_hex.as_str())
        );
        check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .expect("a quorum-rotated capsule is coherent");
    }

    /// **The documented exception, and it is signer-conditioned.** No
    /// `rotation` at all — a first admission, nothing to chain from — and
    /// the set check is skipped, but ONLY because the envelope is
    /// operator-sealed: the operator signature already vouches for the
    /// entire plaintext byte-for-byte, `capsule.slices` included, so there
    /// is nothing left for a narrower check to add. Self-consistency is all
    /// that runs, and a self-consistent slice with no rotation event is
    /// accepted. See the sibling test below for the other signer, where the
    /// same absence is fatal instead.
    #[test]
    fn an_operator_sealed_capsule_with_no_rotation_event_is_accepted() {
        let e = env();
        let c = capsule(&e, true);
        assert!(c.rotation.is_none());
        check_coherent(&c, &e.op_pub, CapsuleSigner::Operator, NOW)
            .expect("no rotation to chain from is not an error for an operator seal");
    }

    /// **The gap this task closes.** `check_coherent` used to skip the
    /// rotation↔slice-set binding for EVERY absent `rotation`, regardless of
    /// who sealed the envelope — so a Group-sealed capsule with `rotation`
    /// omitted (an issuer bug, or a coordinator that wants this check gone)
    /// passed silently. A FROST co-signer signs blind to the plaintext (see
    /// `capsule::SealAttestation`'s own doc), so unlike an operator seal it
    /// vouches for nothing inside — with no `rotation` to authorize the
    /// slice keys, a Group-sealed capsule has nothing establishing them at
    /// all and must be refused.
    #[test]
    fn a_group_sealed_capsule_with_no_rotation_event_is_rejected() {
        let e = env();
        let c = capsule(&e, true);
        assert!(c.rotation.is_none());
        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no rotation event"), "{msg}");
        assert!(
            msg.contains("cannot have its slice keys authorized"),
            "{msg}"
        );
    }

    #[test]
    fn without_a_charter_a_rotation_cannot_be_verified() {
        let e = env();
        let group = SigningKey::generate(&mut OsRng);
        let mut c = rotated_capsule(&e, &group, 4, MACHINE);
        c.charter = None;
        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .unwrap_err();
        assert!(format!("{err}").contains("no charter"), "{err}");
    }

    #[test]
    fn a_rotation_signed_by_anything_but_the_group_key_is_refused() {
        let e = env();
        let group = SigningKey::generate(&mut OsRng);
        let impostor = SigningKey::generate(&mut OsRng);
        let mut c = rotated_capsule(&e, &group, 4, MACHINE);
        // Same event, signed by a key the charter does not name.
        let ev = match &c.rotation {
            Some(s) => s.event.clone(),
            None => unreachable!(),
        };
        c.rotation = Some(crate::quorum::SignedQuorumEvent::sign(
            ev,
            crate::quorum::EventSigner::Quorum { charter_epoch: 4 },
            &impostor,
        ));
        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .unwrap_err();
        assert!(format!("{err}").contains("rotation refused"), "{err}");
    }

    #[test]
    fn a_rotation_minted_for_another_box_does_not_authorize_this_capsule() {
        let e = env();
        let group = SigningKey::generate(&mut OsRng);
        let c = rotated_capsule(&e, &group, 4, "tr-hostkey-203.0.113.20");
        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .unwrap_err();
        assert!(format!("{err}").contains("rotation names machine"), "{err}");
    }

    /// A slice whose wire pubkey the rotation event does not name for its
    /// own role must be rejected, and the error must say WHICH role. Still
    /// Group-sealed, still names the role: this is the pre-existing check
    /// the signer-conditioned rotation-presence rule above must not
    /// disturb.
    #[test]
    fn a_slice_pubkey_missing_from_the_rotation_set_is_rejected_and_names_the_role() {
        let e = env();
        let group = SigningKey::generate(&mut OsRng);
        let mut c = rotated_capsule(&e, &group, 4, MACHINE);
        // A different private key (and matching pubkey) than the event
        // authorizes — self-consistent on its own, but never named in the
        // set.
        let forged = KeyPair::generate();
        c.slices[0].wire_privkey = forged.secret.to_bytes();
        c.slices[0].wire_pubkey_hex = hex::encode(forged.public.to_bytes());
        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("role sentry"), "the error must name the offending role: {msg}");
        assert!(msg.contains("not in the rotation"), "{msg}");
    }

    /// **Strictly stronger than the pre-fix, untagged check.** Before
    /// `IdentityRotated` tagged its key material by role, the rotation's
    /// authorized set was one flat SET of wire pubkeys with nothing saying
    /// which entry belonged to which role — a slice presenting a DIFFERENT
    /// role's authorized key passed, because that key genuinely sat
    /// somewhere in the set. This is the exact class of bug that shape
    /// could never catch: a Sentry slice wearing the key the rotation
    /// actually authorized for Monitor. Role-tagging closes it — a slice's
    /// wire key must match the rotation's entry FOR ITS OWN ROLE, not
    /// merely appear anywhere in the set.
    #[test]
    fn a_slice_wearing_a_different_roles_rotation_entry_is_rejected() {
        let e = env();
        let group = SigningKey::generate(&mut OsRng);
        // What each role is ACTUALLY authorized to use.
        let sentry_key = KeyPair::generate();
        let monitor_key = KeyPair::generate();

        let mut c = capsule(&e, false);
        c.charter = Some(charter_for(&e, &group, 4));
        // The Sentry slice presents MONITOR's authorized key — self
        // consistent (its private key matches its own public key) but
        // wearing the wrong role's authorization.
        c.slices[0].wire_privkey = monitor_key.secret.to_bytes();
        c.slices[0].wire_pubkey_hex = hex::encode(monitor_key.public.to_bytes());

        let ev = crate::quorum::QuorumEvent::IdentityRotated(crate::quorum::IdentityRotated {
            subject: crate::quorum::Subject {
                mesh_id: MeshId::new("v3-staging").unwrap(),
                machine_id: MachineId::new(MACHINE).unwrap(),
            },
            self_id: c.self_id,
            prev_wire_pubkeys: vec![hex::encode(e.wire.public.to_bytes())],
            new_role_keys: vec![
                RolePublicKeys {
                    role: ServiceRole::Sentry,
                    wire_pubkey_hex: hex::encode(sentry_key.public.to_bytes()),
                    signing_pubkey_hex: None,
                },
                RolePublicKeys {
                    role: ServiceRole::Monitor,
                    wire_pubkey_hex: hex::encode(monitor_key.public.to_bytes()),
                    signing_pubkey_hex: None,
                },
            ],
            charter_epoch: 4,
            seq: 1,
            issued_at_ms: NOW - 500,
        });
        c.rotation = Some(crate::quorum::SignedQuorumEvent::sign(
            ev,
            crate::quorum::EventSigner::Quorum { charter_epoch: 4 },
            &group,
        ));

        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Group { charter_epoch: 4 }, NOW)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("role sentry"), "the error must name the offending role: {msg}");
        assert!(msg.contains("not in the rotation"), "{msg}");
    }

    #[test]
    fn each_role_owns_a_separate_directory() {
        // The layout IS the access control: two roles must never share a
        // directory, or either can request the other's identity.
        let base = Path::new("/run/mirage");
        assert_eq!(
            announce_path(base, "monitor"),
            Path::new("/run/mirage/monitor/announce")
        );
        assert_eq!(
            capsule_path(base, "warden"),
            Path::new("/run/mirage/warden/capsule")
        );
        assert_ne!(
            role_dir(base, "monitor"),
            role_dir(base, "warden"),
            "roles must not share a runtime directory"
        );
        // Two node epochs on one box are distinct roles too.
        assert_ne!(role_dir(base, "node-v2"), role_dir(base, "node-v3"));
    }

    // ── S3: attestation on the announce ─────────────────────────────────────

    fn attest_key(machine: &str) -> crate::attestation::AttestationKey {
        crate::attestation::AttestationKey::generate(machine)
    }

    fn enrolled(
        k: &crate::attestation::AttestationKey,
    ) -> crate::attestation::AttestationPubkey {
        crate::attestation::AttestationPubkey::sign_new(
            k.machine_id(),
            k.public(),
            NOW - 1,
            None,
            &SigningKey::generate(&mut rand::rngs::OsRng),
        )
    }

    /// **The gate for the hard cutover.** A box with no enrolment must not
    /// produce a session at all. There is no unattested announce to fall back
    /// to: it would only yield a capsule the quorum refuses, silently and far
    /// from the cause. Failing here is visible, and the repair writes a file
    /// over SSH with no reboot.
    #[test]
    fn an_unenrolled_box_cannot_open_a_session() {
        // `ATTESTATION_KEY_PATH` is an absolute Linux path that exists on no
        // dev box, which is exactly the unenrolled case.
        match BootSession::for_service("sentry", "build-abc", NOW) {
            Err(crate::attestation::AttestationError::NotEnrolled(_)) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            // `match`, not `unwrap_err`: `BootSession` is deliberately not
            // `Debug` — it holds this boot's ephemeral secret.
            Ok(_) => panic!("an unenrolled box must not get a session"),
        }
    }

    /// Every announce is signed. A verifier never has to decide what an
    /// unsigned one is worth, because there is no such thing.
    #[test]
    fn every_announce_is_attested() {
        let k = attest_key(MACHINE);
        let e = enrolled(&k);
        let s = BootSession::new("sentry", "build-abc", NOW, k);

        let a = s.announce();
        assert_eq!(a.machine_id, MACHINE);
        assert!(!a.attestation_sig_hex.is_empty());
        a.verify_attestation(&e, NOW).expect("must verify");
    }

    /// The signature covers this boot's ephemeral key, so a captured announce
    /// cannot be replayed with the attacker's key substituted — the quorum
    /// would otherwise seal a real capsule to a key the attacker holds.
    #[test]
    fn an_announce_signature_does_not_transfer_to_another_boot() {
        let k = attest_key(MACHINE);
        let e = enrolled(&k);
        let first = BootSession::new("sentry", "build-abc", NOW, k);
        let stolen = first.announce().attestation_sig_hex;

        let second = BootSession::new("sentry", "build-abc", NOW, attest_key(MACHINE));
        let mut forged = second.announce();
        forged.attestation_sig_hex = stolen;

        let err = forged.verify_attestation(&e, NOW).unwrap_err();
        assert!(
            matches!(err, crate::attestation::AttestationError::SigInvalid),
            "got {err:?}"
        );
    }

    /// A misplaced key file makes a box announce as its neighbour, and the
    /// announce is internally valid. What stops it is the enrolment: the
    /// neighbour's recorded public key does not match this box's signature.
    #[test]
    fn a_box_announcing_under_another_name_fails_that_name_s_enrolment() {
        let ours = attest_key(MACHINE);
        let theirs = attest_key("ch-example-203.0.113.40");
        let their_enrolment = enrolled(&theirs);

        // We hold a key minted for THEIR machine_id — a misplaced file.
        let misplaced = attest_key("ch-example-203.0.113.40");
        let s = BootSession::new("sentry", "build-abc", NOW, misplaced);
        let a = s.announce();
        assert_eq!(a.machine_id, "ch-example-203.0.113.40");

        let err = a.verify_attestation(&their_enrolment, NOW).unwrap_err();
        assert!(
            matches!(err, crate::attestation::AttestationError::SigInvalid),
            "got {err:?}"
        );
        drop(ours);
    }

    #[test]
    fn an_enrolled_key_round_trips_through_disk_and_still_attests() {
        let dir = std::env::temp_dir().join(format!("mirage-attest-rt-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("attestation.key");

        let k = attest_key(MACHINE);
        let e = enrolled(&k);
        k.save(&path).expect("save");

        let loaded = crate::attestation::AttestationKey::load(&path)
            .expect("load")
            .expect("a saved key must be there");
        let s = BootSession::new("sentry", "build-abc", NOW, loaded);
        s.announce().verify_attestation(&e, NOW).expect("must verify");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── platform facts (gate 4) ──────────────────────────────────────

    fn sample_platform() -> crate::fact_signing::PlatformFingerprint {
        crate::fact_signing::PlatformFingerprint {
            cpu_model: "Intel(R) Xeon(R) Gold 6248R".to_string(),
            cpu_arch: "x86_64".to_string(),
            dmi_sys_vendor: "HostKey".to_string(),
            dmi_product_name: "Standard PC".to_string(),
            dmi_board: "Q35".to_string(),
        }
    }

    /// Compat: a session that never attaches platform facts (every session
    /// before this field existed, and every session today that has not
    /// wired collection) still announces a fully verifying, V2-signed
    /// announce with `platform: None`.
    #[test]
    fn an_announce_with_no_platform_still_verifies() {
        let k = attest_key(MACHINE);
        let e = enrolled(&k);
        let s = BootSession::new("sentry", "build-abc", NOW, k);

        let a = s.announce();
        assert!(a.platform.is_none());
        a.verify_attestation(&e, NOW).expect("must verify");
    }

    /// The new shape: a session that attaches platform facts produces an
    /// announce that carries and verifies them.
    #[test]
    fn an_announce_with_platform_attached_verifies() {
        let k = attest_key(MACHINE);
        let e = enrolled(&k);
        let s = BootSession::new("sentry", "build-abc", NOW, k).with_platform(sample_platform());

        let a = s.announce();
        assert_eq!(a.platform, Some(sample_platform()));
        a.verify_attestation(&e, NOW).expect("must verify");
    }

    /// Tampering the presented platform facts after signing must break
    /// verification — `platform` is inside the attested preimage precisely
    /// so this cannot happen, which is what makes gate 4's comparison
    /// trustworthy in the first place.
    #[test]
    fn tampering_the_platform_facts_after_signing_breaks_verification() {
        let k = attest_key(MACHINE);
        let e = enrolled(&k);
        let s = BootSession::new("sentry", "build-abc", NOW, k).with_platform(sample_platform());

        let mut a = s.announce();
        a.platform = Some(crate::fact_signing::PlatformFingerprint {
            cpu_model: "a different box entirely".to_string(),
            ..sample_platform()
        });

        let err = a.verify_attestation(&e, NOW).unwrap_err();
        assert!(
            matches!(err, crate::attestation::AttestationError::SigInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn file_drop_roundtrip_consumes_the_capsule() {
        let e = env();
        let s = session();
        let dir = std::env::temp_dir().join(format!("mirage-boot-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        s.publish_announce(&dir).unwrap();
        let announced = read_announce_file(&dir, "sentry").unwrap().unwrap();
        assert_eq!(announced.boot_nonce, s.boot_nonce());

        let sealed = seal_for(&e, &s, &capsule(&e, true));
        write_capsule_file(&dir, "sentry", &sealed).unwrap();

        let got = s
            .take_capsule_file(&dir, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap();
        assert!(got.is_some());
        // Consumed: a second read finds nothing, so a rejected blob can never
        // wedge the retry loop.
        let again = s
            .take_capsule_file(&dir, &e.op_pub, None, NOW + 100, DEFAULT_MAX_SKEW_MS)
            .unwrap();
        assert!(again.is_none());

        s.clear_announce(&dir).unwrap();
        assert!(read_announce_file(&dir, "sentry").unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_re_sealed_identity_is_an_extension_not_a_rotation() {
        // The common case: opbox re-seals the same escrow row with a later
        // deadline. A running service must NOT tear itself down for that.
        let e = env();
        let current = capsule(&e, true);
        let mut fresh = capsule(&e, true);
        fresh.issued_at_ms = current.issued_at_ms + 3_000_000;
        fresh.not_after_ms = current.not_after_ms + 3_000_000;
        fresh.peers.push(CapsulePeer {
            identity: current.declared_identity.clone(),
            addr: Some("1.2.3.4:19444".to_string()),
        });
        assert_eq!(
            classify_renewal(&current, &fresh, "sentry"),
            RenewalOutcome::Extended
        );
    }

    /// The durable peer-anchor cache round-trips: what the keeper writes from a
    /// capsule's peers is what a cold-booting `machine_carry` reads back, mesh
    /// and anchor JSON intact — and a missing file reads as `None`, not an
    /// error (a never-admitted box).
    #[test]
    fn peer_anchors_cache_round_trips_and_absence_is_not_an_error() {
        let e = env();
        let src = capsule(&e, true);
        let peers = vec![
            CapsulePeer {
                identity: src.declared_identity.clone(),
                addr: Some("203.0.113.7:19444".to_string()),
            },
            CapsulePeer { identity: src.declared_identity.clone(), addr: None },
        ];

        let dir = std::env::temp_dir().join("mirage-peer-anchors-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        assert!(
            read_peer_anchors_file(&dir).expect("read empty").is_none(),
            "no file yet reads as None, not an error"
        );

        write_peer_anchors_file(&dir, "mesh-alpha", &peers).expect("write");
        let back = read_peer_anchors_file(&dir).expect("read").expect("present");
        assert_eq!(back.mesh_id, "mesh-alpha");
        assert_eq!(back.anchors.len(), 2);
        // Each anchor is the peer's identity as JSON, re-parseable verbatim.
        let parsed: crate::identity::DeclaredIdentity =
            serde_json::from_str(&back.anchors[0]).expect("anchor parses");
        assert_eq!(parsed.self_id, src.declared_identity.self_id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_key_material_is_a_rotation() {
        let e = env();
        let current = capsule(&e, true);

        let mut new_wire = capsule(&e, true);
        new_wire.slices[0].wire_privkey = KeyPair::generate().secret.to_bytes();
        assert_eq!(
            classify_renewal(&current, &new_wire, "sentry"),
            RenewalOutcome::IdentityRotated
        );

        let mut new_signing = capsule(&e, true);
        new_signing.slices[0].signing_privkey = Some(SigningKey::generate(&mut OsRng).to_bytes());
        assert_eq!(
            classify_renewal(&current, &new_signing, "sentry"),
            RenewalOutcome::IdentityRotated
        );

        let mut new_self = capsule(&e, true);
        new_self.self_id = Uuid::from_u128(99);
        assert_eq!(
            classify_renewal(&current, &new_self, "sentry"),
            RenewalOutcome::IdentityRotated
        );
    }

    /// A sibling role's slice rotating its own key is not this process's
    /// business — `classify_renewal` is scoped to the ONE role asking, so a
    /// change to a DIFFERENT slice in the same machine capsule must not
    /// report a rotation.
    #[test]
    fn a_sibling_roles_key_rotating_does_not_report_a_rotation() {
        let e = env();
        let current = capsule(&e, true);
        let mut fresh = capsule(&e, true);
        fresh.slices.push(crate::capsule::RoleSlice {
            role: ServiceRole::Monitor,
            wire_privkey: [0x77; 32],
            signing_privkey: None,
            wire_pubkey_hex: hex::encode(KeyPair::from_secret([0x77; 32]).public.to_bytes()),
            signing_pubkey_hex: None,
        });
        assert_eq!(
            classify_renewal(&current, &fresh, "sentry"),
            RenewalOutcome::Extended,
            "the sentry slice this process cares about did not change"
        );
    }

    #[test]
    fn a_new_face_list_under_the_same_keys_is_reported_not_extended() {
        // #48: the perimeter binds `control_plane_endpoints` at bind time,
        // and a socket cannot be re-read. Before this, the capsule below
        // classified `Extended` and the process kept serving the OLD ports
        // while the operator, reading the faces back, saw the old list and
        // concluded the change had not applied.
        let e = env();
        let current = capsule(&e, true);
        let mut fresh = capsule(&e, true);
        fresh.issued_at_ms = current.issued_at_ms + 3_000_000;
        fresh.not_after_ms = current.not_after_ms + 3_000_000;
        fresh.service_config.control_plane_endpoints.push(
            crate::capsule::CapsuleControlEndpoint {
                port: 8443,
                camouflage: crate::mirage::wire::camouflage::TransportCamouflage::None,
                wire_version: None,
                purpose: None,
            },
        );
        assert_eq!(
            classify_renewal(&current, &fresh, "sentry"),
            RenewalOutcome::ServiceConfigChanged
        );
    }

    #[test]
    fn a_rotation_outranks_a_config_change() {
        // Both changed at once: the identity is the one that invalidates
        // live handshakes, so it must be the verdict. Reporting the config
        // instead would send a service into a config-reload path while its
        // keys were already stale.
        let e = env();
        let current = capsule(&e, true);
        let mut fresh = capsule(&e, true);
        fresh.slices[0].wire_privkey = KeyPair::generate().secret.to_bytes();
        fresh.service_config.public_addr = Some("9.9.9.9:19444".to_string());
        assert_eq!(
            classify_renewal(&current, &fresh, "sentry"),
            RenewalOutcome::IdentityRotated
        );
    }

    #[test]
    fn peers_and_charter_still_move_freely_under_a_running_process() {
        // The doctrine that survives: what a service RE-READS may change
        // without a restart. Only what it BINDS may not. This test is the
        // fence between the two — if a later change makes the digest cover
        // peers or the charter, it fails here rather than in production as
        // a restart loop.
        let e = env();
        let current = capsule(&e, true);
        let mut fresh = capsule(&e, true);
        fresh.issued_at_ms = current.issued_at_ms + 3_000_000;
        fresh.not_after_ms = current.not_after_ms + 3_000_000;
        fresh.peers.push(CapsulePeer {
            identity: current.declared_identity.clone(),
            addr: Some("5.6.7.8:19444".to_string()),
        });
        assert_eq!(
            classify_renewal(&current, &fresh, "sentry"),
            RenewalOutcome::Extended
        );
    }

    #[test]
    fn the_config_digest_is_stable_for_an_unchanged_config() {
        // A digest that moved on its own would restart every service on
        // every renewal — the failure mode a whole-struct hash has to rule
        // out before it can be trusted.
        let e = env();
        let c = capsule(&e, true);
        assert_eq!(service_config_digest(&c), service_config_digest(&c));
        let again = capsule(&e, true);
        assert_eq!(service_config_digest(&c), service_config_digest(&again));
    }

    #[test]
    fn no_capsule_file_is_not_an_error() {
        let e = env();
        let s = session();
        let dir = std::env::temp_dir().join(format!("mirage-boot-empty-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let got = s
            .take_capsule_file(&dir, &e.op_pub, None, NOW, DEFAULT_MAX_SKEW_MS)
            .unwrap();
        assert!(got.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    // ── machine-scoped store ─────────────────────────────────────────

    /// The slice SET survives the round trip intact — every role, not just
    /// the first one.
    #[test]
    fn machine_capsule_round_trips_and_survives_a_second_read() {
        let e = env();
        let dir = std::env::temp_dir().join(format!("mirage-machine-capsule-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let mut c = capsule(&e, true);
        c.slices.push(crate::capsule::RoleSlice {
            role: ServiceRole::Monitor,
            wire_privkey: [0x55; 32],
            signing_privkey: None,
            wire_pubkey_hex: hex::encode(KeyPair::from_secret([0x55; 32]).public.to_bytes()),
            signing_pubkey_hex: None,
        });
        write_machine_capsule_file(&dir, &c).unwrap();

        let got = read_machine_capsule_file(&dir)
            .unwrap()
            .expect("just-written machine capsule must read back");
        assert_eq!(got.self_id, c.self_id);
        assert_eq!(got.slices.len(), 2);
        assert_eq!(
            got.slice_for(&ServiceRole::Sentry).unwrap().wire_privkey,
            c.slice_for(&ServiceRole::Sentry).unwrap().wire_privkey
        );
        assert_eq!(
            got.slice_for(&ServiceRole::Monitor).unwrap().wire_privkey,
            [0x55; 32]
        );

        // Unlike a single-use capsule delivery, the machine store is NOT
        // consumed by reading it — every OTHER service's restart reads the
        // same file, so a second read must still find it.
        let again = read_machine_capsule_file(&dir).unwrap();
        assert!(again.is_some(), "the machine capsule must survive a second read");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_machine_capsule_file_is_not_an_error() {
        let dir =
            std::env::temp_dir().join(format!("mirage-machine-capsule-empty-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let got = read_machine_capsule_file(&dir).unwrap();
        assert!(got.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn machine_announce_round_trips() {
        let dir = std::env::temp_dir().join(format!("mirage-machine-announce-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();

        let s = session();
        write_machine_announce_file(&dir, &s.announce()).unwrap();
        let got = read_machine_announce_file(&dir)
            .unwrap()
            .expect("just-written announce must read back");
        assert_eq!(got.boot_nonce, s.boot_nonce());

        let _ = fs::remove_dir_all(&dir);
    }

    // ── RenewalClaim ─────────────────────────────────────────────────

    #[test]
    fn an_old_announce_without_the_renewal_field_deserialises() {
        // Exactly the shape a build that predates `RenewalClaim` would have
        // written — no `"renewal"` key at all.
        let json = format!(
            r#"{{"machine_id":"{MACHINE}","build_id":"build-abc","eph_pubkey_hex":"{}","boot_nonce":"nonce-1","started_at_ms":{NOW},"attestation_sig_hex":"{}"}}"#,
            "aa".repeat(32),
            "bb".repeat(64),
        );
        let announce: BootAnnounce =
            serde_json::from_str(&json).expect("old-shaped announce must still deserialise");
        assert!(announce.renewal.is_none());
    }

    #[test]
    fn a_none_renewal_announce_round_trips_and_omits_the_field_on_the_wire() {
        let s = session();
        let announce = s.announce();
        assert!(announce.renewal.is_none());

        let encoded = serde_json::to_string(&announce).expect("encode");
        assert!(
            !encoded.contains("\"renewal\""),
            "skip_serializing_if must omit an absent renewal claim, got: {encoded}"
        );

        let back: BootAnnounce = serde_json::from_str(&encoded).expect("decode");
        assert!(back.renewal.is_none());
        assert_eq!(back.boot_nonce, announce.boot_nonce);
    }

    #[test]
    fn a_renewal_claim_round_trips() {
        let s = session();
        let mut announce = s.announce();
        let signing_key = SigningKey::generate(&mut OsRng);
        let self_id = Uuid::from_u128(77);
        announce.renewal = Some(RenewalClaim::sign_for(&announce, self_id, &signing_key));

        let encoded = serde_json::to_string(&announce).expect("encode");
        assert!(encoded.contains("\"renewal\""));
        let back: BootAnnounce = serde_json::from_str(&encoded).expect("decode");
        let claim = back.renewal.expect("renewal claim must round-trip");
        assert_eq!(claim.self_id, self_id);
    }

    #[test]
    fn a_good_renewal_claim_verifies() {
        let s = session();
        let mut announce = s.announce();
        let signing_key = SigningKey::generate(&mut OsRng);
        let claim = RenewalClaim::sign_for(&announce, Uuid::from_u128(77), &signing_key);
        announce.renewal = Some(claim.clone());
        claim.verify(&announce).expect("a genuine claim must verify");
    }

    /// A signature genuinely produced by SOME key, but `held_pubkey_hex`
    /// naming a DIFFERENT one — the shape a forger who does not hold the
    /// real signing key would have to produce.
    #[test]
    fn a_renewal_claim_signed_by_the_wrong_key_is_refused() {
        let s = session();
        let announce = s.announce();
        let real_key = SigningKey::generate(&mut OsRng);
        let mut claim = RenewalClaim::sign_for(&announce, Uuid::from_u128(77), &real_key);
        let impostor = SigningKey::generate(&mut OsRng);
        claim.held_pubkey_hex = hex::encode(impostor.verifying_key().to_bytes());

        let err = claim.verify(&announce).unwrap_err();
        assert!(matches!(err, RenewalClaimError::SignatureInvalid), "got {err:?}");
    }

    #[test]
    fn a_renewal_claim_is_refused_after_the_nonce_is_tampered() {
        let s = session();
        let announce = s.announce();
        let signing_key = SigningKey::generate(&mut OsRng);
        let claim = RenewalClaim::sign_for(&announce, Uuid::from_u128(77), &signing_key);

        let mut tampered = announce;
        tampered.boot_nonce = format!("{}-tampered", tampered.boot_nonce);
        let err = claim.verify(&tampered).unwrap_err();
        assert!(matches!(err, RenewalClaimError::SignatureInvalid), "got {err:?}");
    }

    #[test]
    fn a_renewal_claim_is_refused_after_self_id_is_tampered() {
        let s = session();
        let announce = s.announce();
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut claim = RenewalClaim::sign_for(&announce, Uuid::from_u128(77), &signing_key);
        claim.self_id = Uuid::from_u128(78);

        let err = claim.verify(&announce).unwrap_err();
        assert!(matches!(err, RenewalClaimError::SignatureInvalid), "got {err:?}");
    }

    #[test]
    fn the_machine_capsule_and_the_machine_announce_live_at_different_paths() {
        let base = Path::new("/run/mirage");
        assert_eq!(
            machine_capsule_path(base),
            Path::new("/run/mirage/machine/capsule")
        );
        assert_eq!(
            machine_announce_path(base),
            Path::new("/run/mirage/machine/announce")
        );
        assert_ne!(
            machine_capsule_path(base),
            machine_announce_path(base),
            "the capsule must never collide with the announce it answers"
        );
        assert_ne!(
            machine_capsule_path(base),
            capsule_path(base, "perimeter"),
            "the machine store must never collide with a per-role single-use delivery file"
        );
    }

    // ── check_coherent: empty slice set ─────────────────────────────────

    #[test]
    fn an_empty_slice_set_is_refused() {
        let e = env();
        let mut c = capsule(&e, true);
        c.slices.clear();
        // Signer is irrelevant here — the empty-slice-set rejection happens
        // before this function ever looks at `signer`.
        let err = check_coherent(&c, &e.op_pub, CapsuleSigner::Operator, NOW).unwrap_err();
        assert!(
            matches!(&err, BootError::Incoherent(m) if m.contains("no role slices")),
            "got {err:?}"
        );
    }

    // ── take_machine_slice: the per-slice coherence check ───────────────

    /// Build the [`MachineSlice`] the keeper would answer `Take { role }`
    /// with, from the same fixture the rest of this module uses.
    fn machine_slice_for(c: &MachineCapsule, role: ServiceRole) -> MachineSlice {
        MachineSlice {
            self_id: c.self_id,
            machine_id: c.machine_id.clone(),
            mesh_id: c.mesh_id.clone(),
            slice: c.slice_for(&role).expect("fixture must carry this role").clone(),
            declared_identity: c.declared_identity.clone(),
            peers: c.peers.clone(),
            service_config: c.service_config.clone(),
            charter: c.charter.clone(),
            db_key: c.db_key,
            issued_at_ms: c.issued_at_ms,
            not_after_ms: c.not_after_ms,
            signer: CapsuleSigner::Operator,
            attestation_pubkey_hex: None,
        }
    }

    #[test]
    fn check_slice_coherent_accepts_a_well_formed_slice() {
        let e = env();
        let c = capsule(&e, true);
        let slice = machine_slice_for(&c, ServiceRole::Sentry);
        check_slice_coherent(&slice, ServiceRole::Sentry, &e.op_pub, NOW).expect("must accept");
    }

    /// The keeper answering a `Take { role }` with a slice for a DIFFERENT
    /// role is a defensive check, not a trust decision — the keeper is
    /// still the one enforcing SO_PEERCRED — but it costs nothing to catch
    /// here too.
    #[test]
    fn check_slice_coherent_rejects_a_role_mismatch() {
        let e = env();
        let c = capsule(&e, true);
        let slice = machine_slice_for(&c, ServiceRole::Sentry);
        let err = check_slice_coherent(&slice, ServiceRole::Monitor, &e.op_pub, NOW).unwrap_err();
        assert!(
            matches!(&err, BootError::Incoherent(m) if m.contains("answered a request for role")),
            "got {err:?}"
        );
    }

    /// Expiry is the ONE failure [`take_machine_slice`] retries rather than
    /// surfaces — proven here at the level below it, where the distinction
    /// is a plain `matches!` on the error variant.
    #[test]
    fn check_slice_coherent_reports_expiry_as_its_own_variant() {
        let e = env();
        let c = capsule(&e, true);
        let slice = machine_slice_for(&c, ServiceRole::Sentry);
        let err =
            check_slice_coherent(&slice, ServiceRole::Sentry, &e.op_pub, NOW + 3_600_001)
                .unwrap_err();
        assert!(matches!(err, BootError::Expired), "got {err:?}");
    }

    // ── ask_keeper decode vs transport (ae-example-203.0.113.86, 2026-09-24) ──

    /// A `MachineSlice` whose `service_config.subscriber_entrance` carries no
    /// `socks_addr` at all — the exact shape a current opbox seals
    /// (`SubscriberEntranceConfig::legacy_socks_addr` is `#[serde(default,
    /// skip_serializing)]`) — must still decode through the same path
    /// [`ask_keeper`] uses. Measured live on `ae-example-203.0.113.86`,
    /// 2026-09-24: an `mshd` binary built 2026-09-23, before that field went
    /// optional, could not decode exactly this shape — `ask_keeper` returned
    /// a bare `io::Error` `take_machine_slice` logged at `debug!` and
    /// retried forever, indistinguishable from an ordinary connect failure.
    /// This proves the CURRENT shape decodes, so the fix stays landed.
    #[test]
    fn a_slice_with_a_subscriber_entrance_missing_socks_addr_still_decodes() {
        let e = env();
        let mut c = capsule(&e, true);
        c.service_config.subscriber_entrance = Some(crate::config::SubscriberEntranceConfig {
            legacy_socks_addr: None,
            aggregate_rate_bytes_per_sec: None,
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        });
        let slice = machine_slice_for(&c, ServiceRole::Sentry);
        let response = MachineIdentityResponse::Slice(Box::new(slice));

        let value = serde_json::to_value(&response).expect("encodes");
        let entrance = value
            .get("slice")
            .and_then(|s| s.get("service_config"))
            .and_then(|c| c.get("subscriber_entrance"))
            .expect("subscriber_entrance must be present in the encoded reply");
        assert!(
            entrance.get("socks_addr").is_none(),
            "a current seal never carries socks_addr: {entrance}"
        );

        let bytes = serde_json::to_vec(&response).expect("encodes to bytes");
        match decode_slice_response(&bytes) {
            Ok(MachineIdentityResponse::Slice(_)) => {}
            other => panic!("expected a decoded Slice, got {other:?}"),
        }
    }

    /// [`decode_slice_response`] tells a decode failure (bytes that do not
    /// deserialise as a [`MachineIdentityResponse`] at all — the class
    /// [`AskKeeperError::Decode`] exists to name) apart from a valid reply,
    /// and a valid reply still decodes through the same function.
    #[test]
    fn decode_slice_response_reports_a_decode_failure_and_still_decodes_a_valid_reply() {
        let err = decode_slice_response(br#"{"not":"a-machine-identity-response"}"#).unwrap_err();
        assert!(matches!(err, AskKeeperError::Decode(_)), "got {err:?}");

        let ok = decode_slice_response(
            &serde_json::to_vec(&MachineIdentityResponse::NotYetAdmitted).expect("encodes"),
        );
        assert!(
            matches!(ok, Ok(MachineIdentityResponse::NotYetAdmitted)),
            "got {ok:?}"
        );
    }

    /// The five outcomes [`take_machine_slice`]'s escalating WARN can name
    /// must each print a distinct, non-empty string — an operator reading
    /// one journal line has to be able to tell them apart at a glance.
    #[test]
    fn every_slice_ask_outcome_names_itself_distinctly() {
        let outcomes = [
            SliceAskOutcome::NotYetAdmitted,
            SliceAskOutcome::Expired,
            SliceAskOutcome::NoSuchRole,
            SliceAskOutcome::Unreachable,
            SliceAskOutcome::DecodeFailed,
        ];
        let mut seen = std::collections::HashSet::new();
        for o in outcomes {
            let name = o.to_string();
            assert!(!name.is_empty(), "{o:?} must not print an empty name");
            assert!(seen.insert(name), "outcome names must be pairwise distinct");
        }
    }
}
