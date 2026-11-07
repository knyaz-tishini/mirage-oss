//! Identity capsules — the sealed, RAM-only replacement for baked identity.
//!
//! Today every Mirage binary carries its box's private key as a `bootstrap.rs`
//! constant: a seized disk is a seized identity, and every code change costs a
//! per-box rebuild because identity is a compile-time value. A capsule moves
//! that material onto the wire, sealed to a key that only ever lived in RAM.
//!
//! This is deliberately the **same envelope** [`crate::dk_delivery`] already
//! uses to hand db-worker its SQLCipher key — issuer per-release ephemeral
//! X25519 → ECDH with the service's boot-ephemeral public key → HKDF-SHA256 →
//! ChaCha20-Poly1305, plus an Ed25519 signature over a fixed length-prefixed
//! preimage and a freshness window. Only the plaintext differs: instead of one
//! 32-byte key it is a [`MachineCapsule`] — the whole identity a machine
//! needs to exist, every role it runs included, and who its peers are.
//!
//! Two properties are load-bearing and neither is negotiable:
//!
//! - **AAD = `(machine_id, boot_nonce)`.** A capsule sealed for one box and
//!   one boot cannot be replayed to another box or the same box after a
//!   restart — the AEAD tag fails. Machine-scoped, not per-role: identity
//!   belongs to the MACHINE now (see
//!   `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md`), and
//!   [`MachineCapsule`] carries a `slices: Vec<RoleSlice>` — one per role
//!   the box runs — sealed inside a single envelope rather than one
//!   envelope per role.
//! - **Dual trust anchor.** A capsule is accepted when signed by the pinned
//!   operator key *or* by the FROST group key of the [`GroupCharter`] the
//!   service currently holds. The group key cannot be a compile-time constant
//!   (it does not exist until the fleet runs DKG, which happens *after* these
//!   binaries ship), so it travels inside an operator-signed charter delivered
//!   by the capsule itself. That is what lets quorum recovery switch on later
//!   without a second forced fleet roll.
//!
//! Nothing here writes to disk. The caller unseals into RAM, uses the keys, and
//! drops the capsule — [`MachineCapsule`] and each [`RoleSlice`] zeroize their
//! own secret fields on drop.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{derive_key, shared_secret, AeadCipher, AeadSuite, KeyPair};
use crate::identity::{DeclaredIdentity, ServiceRole};
use crate::ids::{MachineId, MeshId};

/// HKDF `info` label — domain-separates the capsule seal key from the DK seal
/// key and from every other key derived off an X25519 shared secret here.
const SEAL_INFO: &[u8] = b"mirage-capsule-seal-v1";

/// Ed25519 signing-preimage domain label for a sealed capsule.
const SIG_LABEL: &[u8] = b"MIRAGE-IDENTITY-CAPSULE-V1";

/// Ed25519 signing-preimage domain label for a group charter.
const CHARTER_SIG_LABEL: &[u8] = b"MIRAGE-GROUP-CHARTER-V1";

#[derive(Debug, Error)]
pub enum CapsuleError {
    #[error("malformed capsule field: {0}")]
    Malformed(String),
    #[error("capsule signature invalid")]
    SigInvalid,
    #[error("capsule stale: |now - ts| exceeds the freshness window")]
    Stale,
    #[error("capsule bound to a different machine/boot than expected")]
    BindingMismatch,
    #[error("capsule unseal failed (AEAD auth) — wrong ephemeral key, tampered blob, or AAD mismatch")]
    Unseal,
    #[error("capsule is group-signed but no charter for epoch {0} is held")]
    NoCharter(u64),
    #[error("charter signature invalid")]
    CharterSigInvalid,
    #[error("capsule is machine-signed but no machine anchor is held")]
    NoMachineAnchor,
    #[error("capsule is machine-signed for {got}, this anchor is for {want}")]
    MachineAnchorMismatch { got: String, want: String },
    #[error("capsule contents disagree with its envelope: {0}")]
    ContentMismatch(String),
    #[error("capsule already expired at issue time (not_after <= issued_at)")]
    ExpiryInvalid,
}

// ── Group charter ─────────────────────────────────────────────────────

/// The operator's declaration of which FROST group key speaks for the mesh.
///
/// Carried inside a capsule and cached in RAM. It exists because the group
/// verification key is not knowable at build time: the fleet must already be
/// running capsule-capable binaries before it can run DKG. Anchoring the group
/// key in an operator-signed record instead of a constant means quorum recovery
/// turns on with a capsule re-issue rather than a fleet-wide rebuild.
///
/// The group key is public material; publishing it to every box is safe. What
/// it authorises is *identity issuance*, and that is exactly what the quorum is
/// meant to be able to do without the operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCharter {
    /// Mesh this charter speaks for. A charter for another mesh is ignored.
    pub mesh_id: MeshId,
    /// Monotonic charter epoch. Bumped by DKG and by every resharing
    /// (`MembershipChange`); a service accepts only the highest epoch it has
    /// seen operator-signed, so an old charter cannot be replayed to reinstate
    /// a retired group key.
    pub epoch: u64,
    /// FROST-Ed25519 **group verification** key (hex, 64 chars). A threshold
    /// signature produced by `t`-of-`n` members verifies against this as an
    /// ordinary Ed25519 signature — which is why the verifier below needs no
    /// FROST-specific code path.
    pub group_pubkey_hex: String,
    /// `t` — signatures required. Recorded for audit and for the operator's
    /// own bookkeeping; the verifier cannot observe it from a signature.
    pub threshold: u16,
    /// `self_id` of every member holding a share, for auditability.
    pub members: Vec<Uuid>,
    /// Unix-ms the operator signed this charter.
    pub issued_at_ms: u64,
    /// Ed25519 signature by the pinned operator key over [`Self::signing_bytes`].
    pub operator_sig_hex: String,
}

impl GroupCharter {
    /// Fixed, length-prefixed signing preimage — never a JSON hash.
    fn signing_bytes(
        mesh_id: &MeshId,
        epoch: u64,
        group_pubkey_hex: &str,
        threshold: u16,
        members: &[Uuid],
        issued_at_ms: u64,
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(CHARTER_SIG_LABEL.len() + 128 + members.len() * 20);
        p.extend_from_slice(CHARTER_SIG_LABEL);
        push_lp(&mut p, mesh_id.as_str().as_bytes());
        p.extend_from_slice(&epoch.to_le_bytes());
        push_lp(&mut p, group_pubkey_hex.as_bytes());
        p.extend_from_slice(&threshold.to_le_bytes());
        // Count-prefixed so a member list cannot be truncated or extended
        // without changing the preimage.
        p.extend_from_slice(&(members.len() as u32).to_le_bytes());
        for m in members {
            push_lp(&mut p, m.as_bytes());
        }
        p.extend_from_slice(&issued_at_ms.to_le_bytes());
        p
    }

    /// **operator side.** Mint a signed charter.
    pub fn sign_new(
        mesh_id: MeshId,
        epoch: u64,
        group_pubkey_hex: String,
        threshold: u16,
        members: Vec<Uuid>,
        issued_at_ms: u64,
        operator_signing_key: &SigningKey,
    ) -> Self {
        let bytes = Self::signing_bytes(
            &mesh_id,
            epoch,
            &group_pubkey_hex,
            threshold,
            &members,
            issued_at_ms,
        );
        let sig = operator_signing_key.sign(&bytes);
        Self {
            mesh_id,
            epoch,
            group_pubkey_hex,
            threshold,
            members,
            issued_at_ms,
            operator_sig_hex: hex::encode(sig.to_bytes()),
        }
    }

    /// **box side.** Verify the operator signature. Must be called before a
    /// charter is cached — an unverified charter is an attacker-chosen
    /// verification key.
    pub fn verify(&self, operator_pubkey: &VerifyingKey) -> Result<(), CapsuleError> {
        let bytes = Self::signing_bytes(
            &self.mesh_id,
            self.epoch,
            &self.group_pubkey_hex,
            self.threshold,
            &self.members,
            self.issued_at_ms,
        );
        let sig_bytes = decode_64(&self.operator_sig_hex)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        operator_pubkey
            .verify(&bytes, &sig)
            .map_err(|_| CapsuleError::CharterSigInvalid)
    }

    /// The group verification key as an Ed25519 key.
    pub fn group_verifying_key(&self) -> Result<VerifyingKey, CapsuleError> {
        let raw = decode_32(&self.group_pubkey_hex, "group_pubkey")?;
        VerifyingKey::from_bytes(&raw)
            .map_err(|e| CapsuleError::Malformed(format!("group_pubkey not on curve: {e}")))
    }
}

// ── Trust anchor ──────────────────────────────────────────────────────

/// Who signed a sealed capsule.
///
/// No longer [`Copy`] once [`Self::Machine`] exists: a `String` payload
/// cannot be. Every call site that used to rely on an implicit copy now
/// clones or borrows explicitly — see the callers of [`CapsuleTrustAnchor::
/// verifying_key_for`] and [`UnsignedSeal::signer`]/[`UnsignedSeal::
/// attestation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CapsuleSigner {
    /// The pinned operator key — the genesis path, and the only path that
    /// works before the quorum exists.
    Operator,
    /// A FROST threshold signature by the mesh quorum, verified against the
    /// charter with this epoch.
    Group { charter_epoch: u64 },
    /// Self-issued: signed by the box's own durable attestation key
    /// ([`crate::attestation::AttestationKey`]), the raw key rather than a
    /// [`crate::attestation::AttestationKey::derive_subkey`] output —
    /// `derive_subkey` is private-seed-only, so no peer could ever verify a
    /// presented capsule signed with a derived key, which defeats
    /// presentation. The raw key is externally verifiable today because
    /// `AttestationPubkey` is already gossiped fleet-wide for announce
    /// verification (see `crate::attestation`'s module doc).
    ///
    /// `machine_id` names which box's attestation key must verify this
    /// signature, so a capsule minted by box A can never be verified under
    /// box B's anchor — see [`CapsuleTrustAnchor::verifying_key_for`], which
    /// refuses rather than falls through to any other key when this does not
    /// match the anchor it is asked against.
    ///
    /// **Nothing in this crate mints this variant yet.** [`begin_seal`] and
    /// [`seal_capsule`] are unchanged, and every issuance path outside this
    /// crate stays exactly as it is — this addition teaches every verifier
    /// to recognise and check a self-issued capsule before anything anywhere
    /// emits one. `SealedCapsule.signer` is a serde-tagged enum, so an old
    /// binary fails to DESERIALIZE this variant before any crypto runs —
    /// that fail-closed property is what makes rolling verifiers ahead of
    /// producers safe here.
    Machine { machine_id: String },
}

impl CapsuleSigner {
    fn tag(&self) -> &'static str {
        match self {
            CapsuleSigner::Operator => "operator",
            CapsuleSigner::Group { .. } => "group",
            CapsuleSigner::Machine { .. } => "machine",
        }
    }

    fn charter_epoch(&self) -> u64 {
        match self {
            CapsuleSigner::Operator => 0,
            CapsuleSigner::Group { charter_epoch } => *charter_epoch,
            // No charter applies to a self-issued capsule — the same
            // "not meaningful for this signer" placeholder `Operator`
            // already uses. Safe to share: `tag()` ("machine" vs
            // "operator") already disambiguates the two in the preimage, so
            // an identical placeholder value here creates no collision.
            CapsuleSigner::Machine { .. } => 0,
        }
    }
}

/// The machine's own attestation identity, for a service willing to trust a
/// capsule it self-issued (or, once quorum promotion exists, a peer's).
///
/// `machine_id` is who this anchor speaks for. [`CapsuleTrustAnchor::
/// verifying_key_for`] checks it against the signer's own claimed
/// `machine_id` before ever reaching for `attestation`, so a capsule minted
/// by box A cannot verify under an anchor built for box B even though both
/// fields would individually look valid in isolation.
pub struct MachineAnchor<'a> {
    pub machine_id: &'a str,
    pub attestation: VerifyingKey,
}

/// What a booting service is willing to trust: always the pinned operator
/// key, plus the group key of the charter it currently holds (if any), plus
/// — only where the caller already holds its own enrolled attestation
/// identity — the anchor that lets it verify a
/// [`CapsuleSigner::Machine`]-signed capsule.
///
/// The charter must already have been [`GroupCharter::verify`]-ed against the
/// same operator key before it lands here.
pub struct CapsuleTrustAnchor<'a> {
    pub operator: &'a VerifyingKey,
    pub charter: Option<&'a GroupCharter>,
    /// `None` refuses every [`CapsuleSigner::Machine`] envelope outright —
    /// see [`Self::verifying_key_for`]. [`Self::operator_only`] always sets
    /// this to `None`; its meaning is otherwise unchanged by this field's
    /// existence.
    pub machine: Option<MachineAnchor<'a>>,
}

impl<'a> CapsuleTrustAnchor<'a> {
    pub fn operator_only(operator: &'a VerifyingKey) -> Self {
        Self {
            operator,
            charter: None,
            machine: None,
        }
    }

    /// Resolve the verification key for a signer, refusing a group signature
    /// when no charter for that epoch is held, and refusing a machine
    /// signature when no machine anchor is held or that anchor speaks for a
    /// different box. Neither refusal ever falls through to the operator
    /// key — a signer this anchor cannot resolve is refused outright, never
    /// silently reinterpreted under a different root of trust.
    fn verifying_key_for(&self, signer: &CapsuleSigner) -> Result<VerifyingKey, CapsuleError> {
        match signer {
            CapsuleSigner::Operator => Ok(*self.operator),
            CapsuleSigner::Group { charter_epoch } => {
                let charter = self
                    .charter
                    .filter(|c| c.epoch == *charter_epoch)
                    .ok_or(CapsuleError::NoCharter(*charter_epoch))?;
                charter.group_verifying_key()
            }
            CapsuleSigner::Machine { machine_id } => {
                let anchor = self.machine.as_ref().ok_or(CapsuleError::NoMachineAnchor)?;
                if anchor.machine_id != machine_id.as_str() {
                    return Err(CapsuleError::MachineAnchorMismatch {
                        got: machine_id.clone(),
                        want: anchor.machine_id.to_string(),
                    });
                }
                Ok(anchor.attestation)
            }
        }
    }
}

// ── Capsule contents ──────────────────────────────────────────────────

/// A peer this service should be able to reach.
///
/// The signed [`DeclaredIdentity`] is the authority: it carries the peer's
/// `self_id`, wire public key and (once the fleet mints it) `public_addr`.
/// This replaces the baked `PEER_SNAPSHOT` / `MONITOR_SNAPSHOT` tuples and the
/// `monitor_urls` table, whose rows outlived the ports they named.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsulePeer {
    /// The operator-signed identity — verify it before trusting anything here.
    pub identity: DeclaredIdentity,
    /// **Transitional.** Dial address for peers whose identity predates
    /// `public_addr`. The authoritative source is `identity.public_addr`; this
    /// field exists only until the whole fleet runs the `public_addr` verifier
    /// and opbox re-issues identities carrying it, after which it is deleted.
    /// Until then a signed identity carrying an address would be rejected by
    /// any box still on the old verifier — the signed-bytes rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

impl CapsulePeer {
    /// Address to dial: the signed one when present, else the transitional one.
    pub fn dial_addr(&self) -> Option<&str> {
        self.identity
            .public_addr
            .as_deref()
            .or(self.addr.as_deref())
    }
}

/// One face's jail override: which port, and what that port does with a
/// touch that is not ours.
///
/// A typed pair rather than a `HashMap<u16, String>` because the capsule's
/// contract is typed fields, not a JSON bag — and because a port that appears
/// twice has to be visible as a duplicate rather than silently last-wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleJailFace {
    pub port: u16,
    /// `"jail"` or `"hard_cut"`. Anything unrecognised resolves to `jail`:
    /// the safe default when a setting cannot be understood is the one that
    /// tells an observer less.
    pub disposition: String,
}

/// Per-box service settings that used to be compile-time constants
/// (`PUBLIC_ADDR`, `MONITOR_CONTROL_BIND_ADDR`, `SHORTNAME`, `LIFECYCLE`,
/// `NODE_SEEDS`). Typed fields, not a JSON bag: a field nobody reads is a field
/// that should be deleted, and that has to be visible at the call sites.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapsuleServiceConfig {
    /// Routable `<ip>:<port>` this service serves on. All roles that listen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_addr: Option<String>,
    /// The ordinary ports this service answers on, each with the outer
    /// camouflage a dialer must present there. Monitor.
    ///
    /// The receiver binds ONE listener per entry and the dialer walks the
    /// same list per candidate — both sides of that mechanism have existed
    /// since Brick 4, and both fell back to the single bare `(19444, None)`
    /// endpoint because nothing could deliver a list. The capsule is the
    /// only config path a service has had since the 2026-07-26 cutover, and
    /// this field is what was missing from it: measured 2026-08-01, setting
    /// `control_plane_endpoints` in the stored `service_config` changed
    /// nothing on the box, because `monitor_config_from_capsule` builds its
    /// `MonitorConfig` from this struct and this struct had nowhere to put
    /// the list.
    ///
    /// Empty (the default) preserves the legacy single-endpoint behaviour
    /// exactly, so a box that has not been given a list keeps working.
    ///
    /// Read by TWO roles as the arc3 core/periphery split lands: the
    /// monitor still binds this list directly (legacy — every box that has
    /// not yet been fronted by a perimeter). The target state is the
    /// perimeter (`ServiceRole::Perimeter`) binding it instead
    /// (`mirage-perimeter::config::PerimeterConfig::from_capsule`) and
    /// splicing accepted wire connections inward to the monitor on
    /// loopback via `perimeter_inner_addr` below — at which point the
    /// monitor stops binding these ports itself. Both roles read the SAME
    /// field rather than each carrying their own parallel list, because the
    /// list describes one thing regardless of who terminates it: which
    /// ordinary ports this box answers Mirage on, and what camouflage each
    /// one presents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_plane_endpoints: Vec<CapsuleControlEndpoint>,
    /// Where the perimeter splices an accepted, classified-as-wire
    /// connection through to the co-located monitor on loopback.
    /// Perimeter only.
    ///
    /// `None` defaults to `127.0.0.1:19444` — the same bare endpoint every
    /// box's monitor has always listened on directly, before the perimeter
    /// existed to stand in front of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perimeter_inner_addr: Option<String>,
    /// Loopback bind address for the perimeter's own read-only stats
    /// reader (`GET /health`, `GET /perimeter/stats`). Perimeter only.
    ///
    /// `None` defaults to `127.0.0.1:19470`. Loopback-only by construction
    /// — see `mirage-perimeter::stats`'s module doc for why this process
    /// must never expose an API to the internet: it IS the internet-facing
    /// process, so an internet-reachable admin surface on it would defeat
    /// its own purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perimeter_stats_bind: Option<String>,
    /// Where the perimeter splices an accepted connection whose first bytes
    /// are an SSH banner, rather than a Mirage ClientHello. Perimeter only.
    ///
    /// This is the front door's SECOND inward destination, and the reason it
    /// is a router at all rather than a one-way valve: wire goes to the
    /// monitor, SSH-shaped goes to mshd, and the box stops needing a foreign
    /// sshd bound to a well-known port for the operator to get in.
    ///
    /// `None` means the perimeter has no SSH destination and an SSH-shaped
    /// connection is rejected exactly like any other non-wire traffic — which
    /// is the state of every box until mshd is serving.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perimeter_ssh_addr: Option<String>,
    /// What the perimeter does with a touch that is not ours, for any face
    /// without its own entry in [`Self::perimeter_jail_faces`]. Perimeter
    /// only. `"jail"` (the default when absent) holds the connection and
    /// returns nothing; `"hard_cut"` closes it immediately.
    ///
    /// A per-BOX default plus per-face overrides rather than one setting,
    /// because camouflage is not wanted everywhere: the same box can want to
    /// look like a website on `:443` and be a plain wall on a service port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perimeter_jail_default: Option<String>,
    /// Per-face overrides of [`Self::perimeter_jail_default`]. Perimeter only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub perimeter_jail_faces: Vec<CapsuleJailFace>,
    /// How long a jailed connection is held before release, in ms. Perimeter
    /// only; `None` takes the perimeter's own default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perimeter_jail_hold_ms: Option<u64>,
    /// Concurrently held connections allowed PER FACE. Perimeter only.
    ///
    /// Holding costs a file descriptor and a task for the hold duration, on
    /// boxes with one vCPU. Without a ceiling the jail is a way to take the
    /// box down; a face at capacity degrades to a hard cut rather than
    /// queueing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perimeter_jail_max_held_per_face: Option<usize>,
    /// Local control-plane bind address. Monitor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_bind_addr: Option<String>,
    /// Short human name for logs and telemetry. Sentry, mshd, secd, warden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shortname: Option<String>,
    /// Lifecycle mode string. mshd.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
    /// Seed node addresses. Node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_seeds: Vec<String>,
    /// Box-local subscriber-entrance configuration — set only on a box
    /// provisioned to accept paying-customer dials on its own `NodeChain`
    /// face (`docs/mirage/plans/subscriber-gate-and-fork-2026-09-17.md`).
    /// `None` on every box that is not such a box. Node.
    ///
    /// Set once at provisioning — opbox writes this into the sealed capsule
    /// — never discovered at runtime. The hand-off itself rides a fixed unix
    /// channel (`crate::local_endpoint::LocalChannel::EdgeClientEntrance`),
    /// not an address carried in this config — see
    /// [`crate::config::SubscriberEntranceConfig`]'s own doc. Mirrors
    /// `mirage-node::core::node_toml::NodeLocalConfig::subscriber_entrance`
    /// before that box-local file was retired in favour of this field: a box
    /// holds no static config of its own, so the setting travels in the
    /// sealed capsule opbox already mints and pushes, exactly like every
    /// other per-box service setting on this struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscriber_entrance: Option<crate::config::SubscriberEntranceConfig>,
    /// Path to this box's subscriber-key file — the JSON `opbox` writes and
    /// `mirage-node`'s `core::subscriber_keys::spawn_hot_reload` polls. `None`
    /// on every box that is not provisioned as a subscriber entrance. Node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscriber_keys_path: Option<std::path::PathBuf>,
    /// Which customer devices this edge admits from its signed subscriber
    /// set (`crate::crypto::credential::subscriber_set`): `Public` admits
    /// public-scope entries (one device key works on every public edge);
    /// `Private` admits only entries scoped to this box's own machine id.
    /// `None` = not set by opbox, and mirage-edge then admits NOBODY — a
    /// private box must never fall back to admitting public customers.
    /// Edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_scope: Option<EdgeScopeKind>,
    /// Country -> CIDR ranges, operator-supplied: ISO-3166-1 **alpha-2**
    /// country code -> the IP ranges that belong to that country. Monitor
    /// only.
    ///
    /// Set by the operator through the stored `service_config` blob's
    /// `geo_split.country_cidrs` block and carried HERE because the capsule
    /// is the only config path a fleet box has: a monitor reads no config
    /// file, so a country table that is not in the capsule cannot reach it.
    /// The only other door was the monitor's in-memory
    /// `PUT /relay/clients/geo-split` override, and that is lost on every
    /// restart — a roll is routine, so it cannot be the production path.
    ///
    /// The monitor's exit rule needs this table to know the CLIENT's own
    /// country: in `auto` exit mode the chosen exit must not sit in the
    /// client's country. With no table the client's country is UNKNOWN, and
    /// an unknown country never refuses anything — the rule simply does not
    /// apply.
    ///
    /// Plain data on purpose. `mirage-core` does not depend on
    /// `mirage2monitor` and must not start to, so this cannot be the
    /// monitor's own `GeoSplitConfig`; the monitor maps this map into its
    /// own type at the single point where it builds its `MonitorConfig`.
    ///
    /// Empty map (the default) = the operator supplied no country data and
    /// the mesh knows no country for any client. It is the ABSENCE of the
    /// table, not a claim that every client is in no country.
    ///
    /// `skip_serializing_if` is load-bearing, not cosmetic: this struct is
    /// signed as a length-prefixed JSON tail (see
    /// `crate::service_config_anchor::ServiceConfigAnchor::signing_bytes`),
    /// so a field that serialised as a present-but-empty object would
    /// change the signed bytes of EVERY already-issued capsule and break
    /// verification fleet-wide. A capsule that carries no country map must
    /// serialise byte-for-byte as it did before this field existed.
    ///
    /// ## The table travels COMPRESSED
    ///
    /// The serialised form of this field is NOT a nested JSON object but a
    /// `base64(gzip(canonical JSON))` string — see
    /// [`crate::country_table`] for the codec. The reason is size: the
    /// operator's country table is ~826 KB as plain JSON, and that size
    /// broke three boundaries the table has to cross:
    ///
    /// - the quorum signature share (`POST /relay/quorum/sign/share`) —
    ///   its HTTP body measured ~3.3 MB against axum's 2 MiB default body
    ///   limit, so the share was refused with a 413;
    /// - the box-local RPC frame (`crate::local_rpc::MAX_RPC_LEN`, 1 MiB)
    ///   — the handover-deliver frame carrying the capsule measured
    ///   2 271 299 B and did not fit;
    /// - this very struct's signed preimage inside the gossiped
    ///   `service_config` anchor — an uncompressed table is re-signed and
    ///   re-gossiped in full every time a single CIDR changes.
    ///
    /// gzip + base64 brings the same table down to ~207 KB, which fits all
    /// three. The IN-MEMORY type did not change: it is still
    /// `BTreeMap<String, Vec<String>>`, so every consumer
    /// (`mirage2monitor`'s `client_geo::detect_country`, `mirage2monitor`'s
    /// `capsule_boot`, `operator-box`'s merge step) keeps speaking the map
    /// it always spoke. Only the serialised representation changed.
    ///
    /// ## The legacy plain form is still read
    ///
    /// Deserialisation accepts BOTH forms: the compressed string, and the
    /// plain JSON map that already-issued capsules and anchors carry. Those
    /// artefacts are in the park and still verify, so a reader that
    /// refused them would drop the country table of every box sealed
    /// before the compressed form existed. The two are told apart by their
    /// JSON type — a string is the compressed form, a map is the legacy
    /// one — and both converge on the same in-memory table.
    ///
    /// ## The compressor is pinned
    ///
    /// The compressed bytes are INSIDE a signed preimage
    /// (`ServiceConfigAnchor::signing_bytes` embeds this struct's JSON),
    /// so operator-box signs the compressed bytes and the monitors verify
    /// them. Every workspace that builds `mirage-core` must therefore
    /// produce byte-identical output for the same table — which is why
    /// `flate2` is pinned to an exact version (and `miniz_oxide` with it)
    /// in this crate's `Cargo.toml`, and why `crate::country_table` freezes
    /// the output in a golden-vector test. A compressor bump that changed
    /// a single byte would silently invalidate every anchor in the park.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        serialize_with = "crate::country_table::serialize_field",
        deserialize_with = "crate::country_table::deserialize_field"
    )]
    pub country_cidrs: BTreeMap<String, Vec<String>>,
}

/// An edge box's admission scope, set by opbox at provisioning from the
/// order tier that created the box. See [`CapsuleServiceConfig::edge_scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeScopeKind {
    Public,
    Private,
}

/// What a face carries inward, and therefore which box-local service the
/// perimeter splices a wire verdict to.
///
/// The perimeter reads NOTHING to decide this — the decision is a property of
/// the face the connection arrived on, declared in the box's signed identity.
/// That is what keeps the classifier's job "is this the wire" and not "whose
/// wire is this": adding a second inward service must not add a second thing
/// the internet-facing process parses.
///
/// The variants are deliberately not "monitor" and "node" but the ROLE the
/// traffic plays, because a box can run both and the face is about what
/// arrives, not about who happens to be listening.
///
/// Rides inside [`CapsuleControlEndpoint::purpose`] and therefore inside
/// `DeclaredIdentity`'s signed face list — see that field's own doc. An
/// unsigned announcement of a face's purpose would let a relay point chain
/// traffic wherever it liked, so the MONITOR reads this from the signed
/// identity, not from local config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacePurpose {
    /// Mesh control traffic — spliced to the monitor. The default, and what
    /// every face on every box carries today.
    #[default]
    MonitorWire,
    /// Chain data-plane traffic — spliced to the node.
    NodeChain,
    /// A subscriber/customer entrance on an Edge box — spliced to
    /// `mirage-edge`, never to a node (an Edge box runs no `mirage-node` at
    /// all — see `docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Perimeter
    /// face target and capsule change"). Additive: `FacePurpose` rides
    /// inside the sealed capsule PLAINTEXT (see this enum's own doc above),
    /// so this new variant changes the ciphertext and not the signature
    /// preimage — no previously-minted capsule's signature is affected.
    ///
    /// The perimeter's own routing (`mirage-perimeter::face::inward_target`)
    /// is a deliberately exhaustive match with no catch-all — adding this
    /// variant here is step 1 of that plan's step order; wiring the new
    /// `InnerKind`/`inward_target` arm is step 2, in `mirage-perimeter`
    /// itself, not this crate.
    EdgeEntrance,
}

impl FacePurpose {
    /// Stable short name for logs and for the operator readout.
    pub const fn label(self) -> &'static str {
        match self {
            FacePurpose::MonitorWire => "monitor-wire",
            FacePurpose::NodeChain => "node-chain",
            FacePurpose::EdgeEntrance => "edge-entrance",
        }
    }
}

/// One ordinary port this box answers Mirage on, and the outer camouflage a
/// dialer must present there.
///
/// Deliberately a plain data record in `mirage-core` rather than a re-use of
/// `mirage_mesh_client::ControlPlaneEndpoint`: this crate is the shared
/// vocabulary both the operator and every service already depend on, and
/// `mirage-core` must not gain a dependency on a client crate to carry a
/// three-field struct. The monitor converts one into the other at the single
/// point where it builds its `MonitorConfig`.
///
/// Carried inside the sealed capsule plaintext, so adding this type changes
/// the ciphertext and not the signature preimage — the Ed25519 signature is
/// over the sealed envelope, so an older service simply ignores a field it
/// does not know and keeps its legacy single-endpoint behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleControlEndpoint {
    /// TCP port to listen on / dial. An ORDINARY port — `443`, `80`, `22` —
    /// not an exotic one: an exotic port is itself the giveaway.
    pub port: u16,
    /// Outer camouflage applied to connections on this port. A dialer that
    /// presents the wrong shape for the port is not Mirage as far as this
    /// endpoint is concerned.
    pub camouflage: crate::mirage::wire::camouflage::TransportCamouflage,
    /// Wire protocol version for dialing this endpoint. `None` leaves the
    /// service's own default in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_version: Option<u8>,
    /// Which inward service this face's traffic is spliced to. `None` means
    /// the pre-existing meaning, monitor control traffic — the same thing
    /// every face carries today — and `skip_serializing_if` is what keeps an
    /// unset value out of the JSON and therefore out of the
    /// `DeclaredIdentity::signing_bytes` preimage: a capsule minted before
    /// this field existed, and any face left unset since, signs identically
    /// to before. THIS FIELD IS PART OF THE SIGNED FACE LIST — see
    /// `DeclaredIdentity::signing_bytes`'s own doc on the faces tail. Do not
    /// let the monitor treat an unsigned announcement of purpose as
    /// authoritative; this is what makes it a fact of the identity instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<FacePurpose>,
}

/// One role's own keys inside a machine capsule.
///
/// **Why a set of role keys and not one machine keypair.** One identity per
/// machine is the requirement; one KEY per machine is not, and it would be a
/// privilege regression: the weakest service on the box (sentry, node — the
/// ones that face traffic) would hold the key the monitor signs quorum facts
/// with. Today that blast radius is contained per role, and the fleet's own
/// privilege doctrine — de-rooted perimeter, secd as policy-enforcement,
/// sentry as telemetry — depends on it. The slice set keeps both properties:
/// the box has one identity the quorum admits once, and no service can sign
/// as another.
///
/// Secret fields are zeroized on drop, same as [`MachineCapsule`] itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSlice {
    pub role: ServiceRole,
    /// X25519 private key — what `*_PRIVKEY` is baked into the ELF today.
    #[serde(with = "crate::hex_fixed::hex32")]
    pub wire_privkey: [u8; 32],
    /// Ed25519 private key for signed facts. `None` for roles that do not
    /// sign facts (monitor, mshd, db-worker today).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
    pub signing_privkey: Option<[u8; 32]>,
    /// The public half of `wire_privkey`, hex. Gossiped, and carried here —
    /// not only derivable — because it is what a coherence check compares
    /// the private key against without a second round of key derivation at
    /// every call site.
    pub wire_pubkey_hex: String,
    /// The public half of `signing_privkey`, hex. `None` exactly when
    /// `signing_privkey` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pubkey_hex: Option<String>,
}

impl RoleSlice {
    /// The wire private key, in a buffer that wipes itself.
    pub fn wire_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.wire_privkey)
    }

    /// The fact-signing private key, in a buffer that wipes itself.
    pub fn signing_secret(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.signing_privkey.map(Zeroizing::new)
    }
}

impl Drop for RoleSlice {
    fn drop(&mut self) {
        self.wire_privkey.zeroize();
        if let Some(k) = self.signing_privkey.as_mut() {
            k.zeroize();
        }
    }
}

/// Everything the MACHINE needs to exist, delivered per boot and held in
/// RAM — one capsule per box, carrying one [`RoleSlice`] per role it runs.
///
/// Replaces the per-role capsule: `self_id` is now one UUID per machine
/// (not one per role), and `role` + the two private keys are gone from this
/// struct in favour of [`Self::slices`]. `declared_identity`,
/// `service_config`, `peers`, `charter`, `rotation` and `db_key` stay
/// machine-scoped exactly as they already were — a flat bag serving every
/// role was never the per-role part of the old shape.
///
/// Secret fields are zeroized on drop (each [`RoleSlice`] zeroizes its own,
/// this type zeroizes `db_key`). Never serialised to disk by any code path
/// in `mirage-core` itself — it exists in the sealed envelope, in the
/// keeper's tmpfs store ([`crate::identity_boot`]'s machine-scoped store),
/// and in process memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineCapsule {
    pub self_id: Uuid,
    pub machine_id: MachineId,
    pub mesh_id: MeshId,

    /// The set — one slice per role this box runs. Never empty: a machine
    /// capsule naming no role identifies nothing, and
    /// `identity_boot::check_coherent` refuses one before it does anything
    /// else with it.
    pub slices: Vec<RoleSlice>,

    /// This machine's own operator-signed public envelope, naming every
    /// role it runs (see [`crate::identity::DeclaredIdentity::roles`]).
    pub declared_identity: DeclaredIdentity,
    /// Who to talk to, as signed identities rather than a parallel table.
    #[serde(default)]
    pub peers: Vec<CapsulePeer>,
    #[serde(default)]
    pub service_config: CapsuleServiceConfig,

    /// The mesh's current group charter, if one exists yet. Cache it (after
    /// verifying) and use it to accept quorum-signed capsules later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charter: Option<GroupCharter>,

    /// A quorum-signed authorization for key material the operator never signed.
    ///
    /// ## Why this field has to exist
    ///
    /// Without it the operator is a hard dependency for every unattended
    /// reboot. A box that comes back holds nothing, so someone must hand it
    /// fresh private keys — and self-consistency alone (a slice's own
    /// private key matches its own public key) is satisfiable by any forger
    /// who mints a fresh, internally-matched pair. What only the operator
    /// could previously supply was a PAIRING the box could trust: a signed
    /// statement that THESE are the box's keys. This field is the quorum's
    /// equivalent of that statement, produced without the operator.
    ///
    /// The quorum cannot supply the *old* keys — deliberately. Secret-sharing
    /// every box's long-term key across internet-facing machines would mean
    /// capturing `t` of them yields the whole fleet, strictly worse than the one
    /// escrow it replaces. So it mints **fresh** keys and keeps the name: the
    /// `self_id` is a UUID, not a secret, and peer tables and chain bindings are
    /// keyed on it. Only the public keys move, and they move through this event.
    ///
    /// ## What it does and does not change about trust
    ///
    /// The operator stays the root for **who this box is** — the enclosed
    /// `DeclaredIdentity` must still verify under the operator key and must
    /// still name the same box and mesh, and a rotation never rewrites it.
    /// The quorum authorizes only **which keys the machine's slices now
    /// use**: `DeclaredIdentity`'s own per-role keys
    /// ([`crate::identity::DeclaredIdentity::role_keys`]) are a separate,
    /// older operator statement, and a rotated capsule is EXPECTED to
    /// disagree with it — that disagreement is exactly the situation this
    /// field exists to authorize. Verification of the rotation event
    /// anchors on the charter, which is itself operator-signed and verified
    /// in the same function, so this adds no trust root: it re-uses the one
    /// the dual verifier already established for the envelope.
    ///
    /// ## Wired to the slice set
    ///
    /// `identity_boot::check_coherent` consults this field directly: when
    /// present, it must be a verified `IdentityRotated` event naming THIS
    /// box's `self_id` and `machine_id`, and every slice's `wire_pubkey_hex`
    /// must match the entry the event's `new_role_keys` set carries FOR
    /// THAT SLICE'S OWN ROLE. One event still authorizes the machine's
    /// whole slice set at once (`quorum::Subject` lost `role` in the same
    /// stage this field's own type followed), but each entry in that set is
    /// now tagged by role rather than being two flat, untagged pubkey
    /// lists — see `quorum::IdentityRotated::new_role_keys`'s own doc for
    /// the fleet-wide resolution failure the untagged shape used to cause.
    ///
    /// **Whether `rotation` may be absent depends on [`CapsuleSigner`], not
    /// on this field alone.** `check_coherent` is told which key sealed the
    /// envelope and the set check is skipped only for
    /// `CapsuleSigner::Operator` — a first admission, nothing to chain from,
    /// and an operator seal already vouches for the entire plaintext
    /// byte-for-byte, `capsule.slices` included. For `CapsuleSigner::Group`
    /// an absent `rotation` is refused outright: a FROST co-signer signs
    /// blind to the plaintext (see [`SealAttestation`]'s own doc), so a
    /// group-sealed capsule with no rotation event has nothing authorizing
    /// its slice keys at all. Every slice is still checked for
    /// SELF-consistency regardless of signer or `rotation`. See
    /// `identity_boot::check_coherent`'s own doc for the full rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<crate::quorum::SignedQuorumEvent>,

    /// SQLCipher master key, for db-worker only — folding it in here means one
    /// delivery per boot instead of two. `None` for every other role.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_hex32")]
    pub db_key: Option<[u8; 32]>,

    pub issued_at_ms: u64,
    /// Hard expiry. A captured RAM image ages out instead of granting
    /// indefinite access; the service renews over the mesh before this.
    pub not_after_ms: u64,
}

impl MachineCapsule {
    /// Has this capsule passed its hard expiry?
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.not_after_ms
    }

    /// Should the service be asking for a fresh capsule already? `lead_ms` is
    /// how long before expiry renewal starts, so a failed renewal has time to
    /// retry while the current capsule is still valid.
    pub fn needs_renewal(&self, now_ms: u64, lead_ms: u64) -> bool {
        now_ms.saturating_add(lead_ms) >= self.not_after_ms
    }

    /// This machine's slice for `role`, if the capsule carries one.
    pub fn slice_for(&self, role: &ServiceRole) -> Option<&RoleSlice> {
        self.slices.iter().find(|s| &s.role == role)
    }
}

impl Drop for MachineCapsule {
    fn drop(&mut self) {
        // Each `RoleSlice` zeroizes its own secrets on drop; `Vec`'s own
        // drop already runs theirs. Only `db_key` is this type's to wipe.
        if let Some(k) = self.db_key.as_mut() {
            k.zeroize();
        }
    }
}

/// serde for `Option<[u8; 32]>` as an optional hex string.
mod opt_hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(bytes) => s.serialize_str(&hex::encode(bytes)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let opt = Option::<String>::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 32] = v
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
                Ok(Some(arr))
            }
        }
    }
}

// ── Sealed envelope ───────────────────────────────────────────────────

/// A sealed capsule. Opaque to whatever relays it — a monitor, mshd, or a file
/// in `/run` — because only the service holding the matching boot-ephemeral
/// secret can open it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedCapsule {
    /// The issuer's per-capsule ephemeral X25519 public key (hex).
    pub issuer_eph_pubkey_hex: String,
    /// AEAD nonce (hex, 12 bytes).
    pub nonce_hex: String,
    /// ChaCha20-Poly1305 ciphertext ‖ 16-byte tag (hex).
    pub ciphertext_hex: String,
    /// Box this capsule is for — AAD.
    pub machine_id: String,
    /// The boot this capsule answers — AAD. Ties it to one process lifetime.
    pub boot_nonce: String,
    /// Opaque issuance id for the issuer's audit trail.
    pub issue_id: String,
    /// Issuer seal timestamp (unix ms) — freshness-checked on unseal.
    pub ts_ms: u64,
    /// Which key signed this envelope.
    pub signer: CapsuleSigner,
    /// Ed25519 signature over the fixed preimage.
    pub sig_hex: String,
}

/// Length-prefix `bytes` (u32-LE length) into `out`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// AEAD additional-authenticated-data: binds the ciphertext to one box and
/// one boot. Built identically on seal and unseal — unseal uses the
/// *expected* values, so a mismatched binding fails the tag rather than
/// decrypting into something the caller has to remember to check.
///
/// Machine-scoped, not per-role: a [`MachineCapsule`] names every role the
/// box runs inside `slices`, so there is no single role left to bind — see
/// the module doc.
fn seal_aad(machine_id: &str, boot_nonce: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(machine_id.len() + boot_nonce.len() + 8);
    push_lp(&mut aad, machine_id.as_bytes());
    push_lp(&mut aad, boot_nonce.as_bytes());
    aad
}

/// Fixed, length-prefixed signing preimage. The signer tag and charter epoch
/// are inside it, so an operator-signed envelope cannot be re-labelled as
/// group-signed (or pointed at a different charter) without breaking the
/// signature.
#[allow(clippy::too_many_arguments)]
fn sig_preimage(
    signer: &CapsuleSigner,
    issuer_eph_pub: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    machine_id: &str,
    boot_nonce: &str,
    issue_id: &str,
    ts_ms: u64,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(SIG_LABEL.len() + 32 + 12 + ciphertext.len() + 160);
    p.extend_from_slice(SIG_LABEL);
    push_lp(&mut p, signer.tag().as_bytes());
    p.extend_from_slice(&signer.charter_epoch().to_le_bytes());
    push_lp(&mut p, issuer_eph_pub);
    push_lp(&mut p, nonce);
    push_lp(&mut p, ciphertext);
    push_lp(&mut p, machine_id.as_bytes());
    push_lp(&mut p, boot_nonce.as_bytes());
    push_lp(&mut p, issue_id.as_bytes());
    p.extend_from_slice(&ts_ms.to_le_bytes());
    p
}

/// **Issuer side** (opbox today, a quorum member later). Seal `capsule` to the
/// service's boot-ephemeral public key and sign the envelope.
///
/// `signer` must describe the key actually passed as `signing_key`: pass
/// [`CapsuleSigner::Operator`] with the operator key, or
/// [`CapsuleSigner::Group`] with a FROST-aggregated signature's key. The
/// binding fields are taken from the capsule itself so an envelope can never
/// be addressed to a box the contents do not name.
/// A capsule encrypted and bound, waiting only for a signature.
///
/// Exists because a **threshold** signature cannot be produced from a
/// `SigningKey`: FROST aggregates shares from `t` members, and the bytes being
/// signed are not known until the ciphertext exists. So sealing splits in two —
/// [`begin_seal`] does everything up to the signature, and [`Self::finish`]
/// accepts one from wherever it came.
///
/// The critical property is that the operator path and the quorum path sign the
/// **same preimage**, because both go through this type. Giving the quorum its
/// own preimage would mean `CapsuleSigner::Operator` and `CapsuleSigner::Group`
/// authenticate different bytes, and the dual verifier would silently stop
/// meaning one thing.
///
/// Holds no secret: the plaintext is already encrypted and the issuer's
/// ephemeral secret was dropped inside [`begin_seal`].
pub struct UnsignedSeal {
    issuer_eph_pubkey: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    machine_id: String,
    boot_nonce: String,
    issue_id: String,
    ts_ms: u64,
    signer: CapsuleSigner,
    preimage: Vec<u8>,
}

impl UnsignedSeal {
    /// The exact bytes to sign. Whoever signs — a single operator key or an
    /// aggregated group signature — signs these and nothing else.
    #[must_use]
    pub fn signing_bytes(&self) -> &[u8] {
        &self.preimage
    }

    /// Which signer this seal was built for. The preimage commits to it, so a
    /// signature made for one cannot be presented as the other.
    #[must_use]
    pub fn signer(&self) -> CapsuleSigner {
        self.signer.clone()
    }

    /// What a threshold co-signer is shown: every field the preimage commits
    /// to, and no plaintext. See [`SealAttestation`] for why the co-signer
    /// needs this rather than the bytes or the capsule.
    #[must_use]
    pub fn attestation(&self) -> SealAttestation {
        SealAttestation {
            signer: self.signer.clone(),
            issuer_eph_pubkey_hex: hex::encode(self.issuer_eph_pubkey),
            nonce_hex: hex::encode(self.nonce),
            ciphertext_hex: hex::encode(&self.ciphertext),
            machine_id: self.machine_id.clone(),
            boot_nonce: self.boot_nonce.clone(),
            issue_id: self.issue_id.clone(),
            ts_ms: self.ts_ms,
        }
    }

    /// Attach a signature and produce the sealed capsule.
    ///
    /// Takes raw bytes rather than an `ed25519_dalek::Signature` so a FROST
    /// aggregate — which is an ordinary Ed25519 signature but arrives from a
    /// different type — needs no conversion dance at the call site.
    #[must_use]
    pub fn finish(self, sig_bytes: &[u8; 64]) -> SealedCapsule {
        SealedCapsule {
            issuer_eph_pubkey_hex: hex::encode(self.issuer_eph_pubkey),
            nonce_hex: hex::encode(self.nonce),
            ciphertext_hex: hex::encode(&self.ciphertext),
            machine_id: self.machine_id,
            boot_nonce: self.boot_nonce,
            issue_id: self.issue_id,
            ts_ms: self.ts_ms,
            signer: self.signer,
            sig_hex: hex::encode(sig_bytes),
        }
    }
}

/// Everything a threshold co-signer needs in order to decide whether to sign,
/// and **nothing it must not see**.
///
/// ## Why this type exists
///
/// A FROST signing round has a coordinator that assembles the `SigningPackage`.
/// The coordinator cannot forge a signature and cannot learn a share — but it
/// chooses the message, so a quorum whose members sign whatever they are handed
/// is not a quorum, it is `t` rubber stamps behind one compromised coordinator.
/// The whole point of moving issuance off a single operator key is lost at that
/// moment.
///
/// So a member must reconstruct the preimage itself and compare. It cannot do
/// that from an opaque byte string, and it must not be sent the capsule: the
/// plaintext holds every role's `wire_privkey`, its SQLCipher DK and its SSH
/// host seed, and five monitors learning those would destroy per-box identity
/// far more thoroughly than a single-key issuer ever did.
///
/// The split works because [`sig_preimage`] commits to the **ciphertext and the
/// public binding fields only** — never the plaintext. So this carries exactly
/// those fields: a member recomputes the bytes, checks they match what it is
/// being asked to sign, and applies its own policy to what they say — which
/// box, issued when, under which charter epoch. That is a real attestation:
/// *this envelope is being issued to that box at that time*. What is inside
/// (including which roles it names) stays sealed to the requesting service's
/// ephemeral key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealAttestation {
    /// Which signer the preimage commits to. A member that expects to be
    /// producing a group signature must refuse an `Operator` attestation.
    pub signer: CapsuleSigner,
    /// Issuer's per-capsule ephemeral X25519 public key (hex, 32 bytes).
    pub issuer_eph_pubkey_hex: String,
    /// AEAD nonce (hex, 12 bytes).
    pub nonce_hex: String,
    /// The sealed bytes. Opaque to a co-signer by construction — it holds no
    /// key that opens them.
    pub ciphertext_hex: String,
    /// The box this envelope is addressed to.
    pub machine_id: String,
    /// The service's per-boot nonce, binding this envelope to one boot.
    pub boot_nonce: String,
    /// Issuance id, so a member can recognise a replay of a round it already
    /// signed.
    pub issue_id: String,
    /// Issuance timestamp in ms.
    pub ts_ms: u64,
}

impl SealAttestation {
    /// Recompute the exact bytes a signature over this envelope must cover.
    ///
    /// This is the check that makes a co-signer more than a rubber stamp: the
    /// result must equal the message inside the coordinator's `SigningPackage`,
    /// or the coordinator is asking for a signature over something other than
    /// what it described.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CapsuleError> {
        let eph: [u8; 32] = decode_fixed(&self.issuer_eph_pubkey_hex, "issuer_eph_pubkey")?;
        let nonce: [u8; 12] = decode_fixed(&self.nonce_hex, "nonce")?;
        let ciphertext = hex::decode(&self.ciphertext_hex)
            .map_err(|e| CapsuleError::Malformed(format!("ciphertext hex: {e}")))?;
        Ok(sig_preimage(
            &self.signer,
            &eph,
            &nonce,
            &ciphertext,
            &self.machine_id,
            &self.boot_nonce,
            &self.issue_id,
            self.ts_ms,
        ))
    }
}

/// Decode a hex string into a fixed-size array, naming the field on failure.
fn decode_fixed<const N: usize>(hexed: &str, field: &str) -> Result<[u8; N], CapsuleError> {
    let raw =
        hex::decode(hexed).map_err(|e| CapsuleError::Malformed(format!("{field} hex: {e}")))?;
    raw.as_slice()
        .try_into()
        .map_err(|_| CapsuleError::Malformed(format!("{field} must be {N} bytes")))
}

/// Encrypt and bind a capsule, stopping short of signing it.
///
/// See [`UnsignedSeal`] for why this is split out. Callers holding an ordinary
/// signing key should use [`seal_capsule`], which is this plus a signature.
#[allow(clippy::too_many_arguments)]
pub fn begin_seal(
    capsule: &MachineCapsule,
    service_eph_pubkey: &[u8; 32],
    boot_nonce: &str,
    issue_id: &str,
    ts_ms: u64,
    signer: CapsuleSigner,
) -> Result<UnsignedSeal, CapsuleError> {
    if capsule.not_after_ms <= capsule.issued_at_ms {
        return Err(CapsuleError::ExpiryInvalid);
    }

    let machine_id = capsule.machine_id.as_str().to_string();

    let plaintext = serde_json::to_vec(capsule)
        .map_err(|e| CapsuleError::Malformed(format!("capsule serialise: {e}")))?;

    // Fresh per-capsule ephemeral for the issuer — neither side's ECDH key
    // outlives the exchange.
    let issuer_eph = KeyPair::generate();
    let issuer_eph_pub = issuer_eph.public.to_bytes();

    let service_pub = PublicKey::from(*service_eph_pubkey);
    let shared = shared_secret(&issuer_eph.secret, &service_pub);
    let seal_key = derive_key(&shared, b"", SEAL_INFO);

    let mut nonce = [0u8; 12];
    use rand::{rngs::OsRng, RngCore};
    OsRng.fill_bytes(&mut nonce);

    let aad = seal_aad(&machine_id, boot_nonce);
    let ciphertext = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &seal_key)
        .encrypt(&nonce, &plaintext, &aad)
        .map_err(|_| CapsuleError::Unseal)?;

    let preimage = sig_preimage(
        &signer,
        &issuer_eph_pub,
        &nonce,
        &ciphertext,
        &machine_id,
        boot_nonce,
        issue_id,
        ts_ms,
    );
    Ok(UnsignedSeal {
        issuer_eph_pubkey: issuer_eph_pub,
        nonce,
        ciphertext,
        machine_id,
        boot_nonce: boot_nonce.to_string(),
        issue_id: issue_id.to_string(),
        ts_ms,
        signer,
        preimage,
    })
}

/// Seal and sign with a single key — the operator path, unchanged.
///
/// Kept as-is so every existing caller is untouched; it is now
/// [`begin_seal`] plus one signature.
#[allow(clippy::too_many_arguments)]
pub fn seal_capsule(
    capsule: &MachineCapsule,
    service_eph_pubkey: &[u8; 32],
    boot_nonce: &str,
    issue_id: &str,
    ts_ms: u64,
    signer: CapsuleSigner,
    signing_key: &SigningKey,
) -> Result<SealedCapsule, CapsuleError> {
    let unsigned = begin_seal(capsule, service_eph_pubkey, boot_nonce, issue_id, ts_ms, signer)?;
    let sig = signing_key.sign(unsigned.signing_bytes());
    Ok(unsigned.finish(&sig.to_bytes()))
}

/// **Service side.** Verify binding, freshness and signature, then ECDH-unseal
/// with the RAM-only boot-ephemeral secret.
///
/// Order matters and mirrors [`crate::dk_delivery::unseal_dk`]: cheap binding
/// rejection first, then freshness, then the signature *before* any decrypt, so
/// an unauthenticated blob never reaches the AEAD. Finally the unsealed
/// contents are checked against the envelope — a signer cannot address a
/// capsule to one `machine` and put a different identity inside.
///
/// No `expected_role` parameter any more — the AAD and preimage bind
/// `(machine_id, boot_nonce)` only, see [`seal_aad`].
#[allow(clippy::too_many_arguments)]
pub fn unseal_capsule(
    sealed: &SealedCapsule,
    service_eph_secret: &[u8; 32],
    expected_machine_id: &str,
    expected_boot_nonce: &str,
    anchor: &CapsuleTrustAnchor<'_>,
    now_ms: u64,
    max_skew_ms: u64,
) -> Result<MachineCapsule, CapsuleError> {
    // 1. Binding — reject before any crypto if it is not addressed to us.
    if sealed.machine_id != expected_machine_id || sealed.boot_nonce != expected_boot_nonce {
        return Err(CapsuleError::BindingMismatch);
    }

    // 2. Freshness — bound the replay window (absolute skew, either direction).
    if now_ms.abs_diff(sealed.ts_ms) > max_skew_ms {
        return Err(CapsuleError::Stale);
    }

    // 3. Parse the wire fields.
    let issuer_eph_pub = decode_32(&sealed.issuer_eph_pubkey_hex, "issuer_eph_pubkey")?;
    let nonce = decode_12(&sealed.nonce_hex)?;
    let ciphertext = hex::decode(&sealed.ciphertext_hex)
        .map_err(|e| CapsuleError::Malformed(format!("ciphertext hex: {e}")))?;
    let sig_bytes = decode_64(&sealed.sig_hex)?;

    // 4. Resolve the trust anchor and verify BEFORE decrypt. A group-signed
    //    capsule with no matching charter dies here, not after we have already
    //    decrypted attacker-chosen bytes.
    let verifying_key = anchor.verifying_key_for(&sealed.signer)?;
    let preimage = sig_preimage(
        &sealed.signer,
        &issuer_eph_pub,
        &nonce,
        &ciphertext,
        &sealed.machine_id,
        &sealed.boot_nonce,
        &sealed.issue_id,
        sealed.ts_ms,
    );
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&preimage, &sig)
        .map_err(|_| CapsuleError::SigInvalid)?;

    // 5. ECDH + HKDF + AEAD unseal, with the AAD rebuilt from the EXPECTED
    //    values so a capsule sealed for anyone else fails the tag.
    let service_secret = StaticSecret::from(*service_eph_secret);
    let issuer_pub = PublicKey::from(issuer_eph_pub);
    let shared = shared_secret(&service_secret, &issuer_pub);
    let seal_key = derive_key(&shared, b"", SEAL_INFO);
    let aad = seal_aad(expected_machine_id, expected_boot_nonce);

    let pt = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &seal_key)
        .decrypt(&nonce, &ciphertext, &aad)
        .map_err(|_| CapsuleError::Unseal)?;

    let capsule: MachineCapsule = serde_json::from_slice(&pt)
        .map_err(|e| CapsuleError::Malformed(format!("capsule deserialise: {e}")))?;

    // 6. Contents must agree with the envelope they arrived in.
    if capsule.machine_id.as_str() != expected_machine_id {
        return Err(CapsuleError::ContentMismatch(format!(
            "machine_id {} != envelope {}",
            capsule.machine_id.as_str(),
            expected_machine_id
        )));
    }
    if capsule.not_after_ms <= capsule.issued_at_ms {
        return Err(CapsuleError::ExpiryInvalid);
    }

    Ok(capsule)
}

fn decode_32(hex_str: &str, field: &str) -> Result<[u8; 32], CapsuleError> {
    let v =
        hex::decode(hex_str).map_err(|e| CapsuleError::Malformed(format!("{field} hex: {e}")))?;
    v.try_into()
        .map_err(|_| CapsuleError::Malformed(format!("{field} must be 32 bytes")))
}

fn decode_12(hex_str: &str) -> Result<[u8; 12], CapsuleError> {
    let v = hex::decode(hex_str).map_err(|e| CapsuleError::Malformed(format!("nonce hex: {e}")))?;
    v.try_into()
        .map_err(|_| CapsuleError::Malformed("nonce must be 12 bytes".to_string()))
}

fn decode_64(hex_str: &str) -> Result<[u8; 64], CapsuleError> {
    let v = hex::decode(hex_str).map_err(|e| CapsuleError::Malformed(format!("sig hex: {e}")))?;
    v.try_into()
        .map_err(|_| CapsuleError::Malformed("signature must be 64 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    struct Fixture {
        op_sign: SigningKey,
        op_verify: VerifyingKey,
        svc_eph: KeyPair,
        machine_id: String,
        boot_nonce: String,
        ts_ms: u64,
    }

    fn machine() -> MachineId {
        MachineId::new("ru-hostkey-203.0.113.10").expect("valid machine id")
    }

    fn mesh() -> MeshId {
        MeshId::new("v3-staging").expect("valid mesh id")
    }

    fn declared(op: &SigningKey, role: ServiceRole) -> DeclaredIdentity {
        DeclaredIdentity::sign_new_full(
            Uuid::from_u128(7),
            machine(),
            mesh(),
            vec![role],
            vec![crate::identity::RolePublicKeys {
                role,
                wire_pubkey_hex: "aa".repeat(32),
                signing_pubkey_hex: None,
            }],
            1_000,
            None,
            None,
            Vec::new(),
            None,
            op,
        )
    }

    fn fixture() -> Fixture {
        let op_sign = SigningKey::generate(&mut OsRng);
        let op_verify = op_sign.verifying_key();
        Fixture {
            op_sign,
            op_verify,
            svc_eph: KeyPair::generate(),
            machine_id: "ru-hostkey-203.0.113.10".to_string(),
            boot_nonce: "boot-nonce-abc".to_string(),
            ts_ms: 1_000_000,
        }
    }

    /// A single-slice machine capsule — the common case most tests below
    /// exercise. [`RoleSlice::wire_privkey`] is fixed at `0x11` and
    /// `signing_privkey` at `0x22` throughout, so a test that wants to
    /// assert on the recovered key material has a stable value to check.
    fn capsule_for(f: &Fixture, role: ServiceRole) -> MachineCapsule {
        let wire_pubkey_hex = hex::encode(KeyPair::from_secret([0x11; 32]).public.to_bytes());
        let signing_pubkey_hex = hex::encode(
            SigningKey::from_bytes(&[0x22; 32]).verifying_key().to_bytes(),
        );
        MachineCapsule {
            self_id: Uuid::from_u128(7),
            machine_id: machine(),
            mesh_id: mesh(),
            slices: vec![RoleSlice {
                role,
                wire_privkey: [0x11; 32],
                signing_privkey: Some([0x22; 32]),
                wire_pubkey_hex,
                signing_pubkey_hex: Some(signing_pubkey_hex),
            }],
            declared_identity: declared(&f.op_sign, role),
            peers: vec![],
            service_config: CapsuleServiceConfig {
                public_addr: Some("10.0.0.1:19444".to_string()),
                ..Default::default()
            },
            charter: None,
            rotation: None,
            db_key: None,
            issued_at_ms: f.ts_ms,
            not_after_ms: f.ts_ms + 3_600_000,
        }
    }

    fn seal(f: &Fixture, capsule: &MachineCapsule) -> SealedCapsule {
        seal_capsule(
            capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-1",
            f.ts_ms,
            CapsuleSigner::Operator,
            &f.op_sign,
        )
        .expect("seal")
    }

    fn unseal(
        f: &Fixture,
        sealed: &SealedCapsule,
        anchor: &CapsuleTrustAnchor<'_>,
    ) -> Result<MachineCapsule, CapsuleError> {
        unseal_capsule(
            sealed,
            &f.svc_eph.secret.to_bytes(),
            &f.machine_id,
            &f.boot_nonce,
            anchor,
            f.ts_ms + 500,
            60_000,
        )
    }

    #[test]
    fn roundtrip_recovers_identity() {
        let f = fixture();
        let capsule = capsule_for(&f, ServiceRole::Monitor);
        let sealed = seal(&f, &capsule);
        let got = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&f.op_verify))
            .expect("unseal");
        assert_eq!(got.self_id, capsule.self_id);
        let slice = got.slice_for(&ServiceRole::Monitor).expect("the monitor slice");
        assert_eq!(slice.wire_privkey, [0x11; 32]);
        assert_eq!(slice.signing_privkey, Some([0x22; 32]));
        assert_eq!(
            got.service_config.public_addr.as_deref(),
            Some("10.0.0.1:19444")
        );
    }

    /// The set, not a role-scoped envelope: a capsule naming several roles
    /// seals and unseals with every slice intact, none of them affecting
    /// another's key material.
    #[test]
    fn a_multi_slice_capsule_round_trips_every_slice_intact() {
        let f = fixture();
        let mut capsule = capsule_for(&f, ServiceRole::Monitor);
        let secd_wire_pub = hex::encode(KeyPair::from_secret([0x44; 32]).public.to_bytes());
        capsule.slices.push(RoleSlice {
            role: ServiceRole::Secd,
            wire_privkey: [0x44; 32],
            signing_privkey: None,
            wire_pubkey_hex: secd_wire_pub,
            signing_pubkey_hex: None,
        });

        let sealed = seal(&f, &capsule);
        let got = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&f.op_verify))
            .expect("unseal");
        assert_eq!(got.slices.len(), 2);
        assert_eq!(
            got.slice_for(&ServiceRole::Monitor).expect("monitor slice").wire_privkey,
            [0x11; 32]
        );
        assert_eq!(
            got.slice_for(&ServiceRole::Secd).expect("secd slice").wire_privkey,
            [0x44; 32]
        );
        assert!(got.slice_for(&ServiceRole::Mshd).is_none());
    }

    /// A co-signer must arrive at the SAME bytes the coordinator is asking it
    /// to sign, from the attestation alone. If this drifts, every member is
    /// back to trusting the coordinator's word for what the message is.
    #[test]
    fn an_attestation_reproduces_the_seals_own_signing_bytes() {
        let f = fixture();
        let capsule = capsule_for(&f, ServiceRole::Monitor);
        let unsigned = begin_seal(
            &capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-1",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 3 },
        )
        .expect("begin_seal");

        let rebuilt = unsigned.attestation().signing_bytes().expect("recompute");
        assert_eq!(
            rebuilt,
            unsigned.signing_bytes(),
            "the attestation must reproduce the preimage exactly"
        );
    }

    /// The reason a member is shown an attestation instead of the capsule:
    /// five monitors co-signing must not learn the box's private keys. The
    /// preimage commits to the ciphertext, so this costs the check nothing.
    #[test]
    fn an_attestation_carries_no_capsule_plaintext() {
        let f = fixture();
        let mut capsule = capsule_for(&f, ServiceRole::Monitor);
        capsule.db_key = Some([0x33; 32]);
        let unsigned = begin_seal(
            &capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-1",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 3 },
        )
        .expect("begin_seal");

        let shown = serde_json::to_string(&unsigned.attestation()).expect("serialise");
        for (secret, what) in [
            ("11".repeat(32), "wire_privkey"),
            ("22".repeat(32), "signing_privkey"),
            ("33".repeat(32), "db_key"),
        ] {
            assert!(
                !shown.contains(&secret),
                "a co-signer must never be shown the {what}"
            );
        }
    }

    /// Every binding field is inside the preimage, so a coordinator cannot
    /// describe one issuance to the members and collect a signature over
    /// another.
    #[test]
    fn changing_any_binding_field_changes_what_must_be_signed() {
        let f = fixture();
        let capsule = capsule_for(&f, ServiceRole::Monitor);
        let unsigned = begin_seal(
            &capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-1",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 3 },
        )
        .expect("begin_seal");
        let honest = unsigned.attestation().signing_bytes().expect("recompute");

        let mutate: [(&str, fn(&mut SealAttestation)); 5] = [
            ("machine", |a| a.machine_id = "tr-hostkey-203.0.113.20".to_string()),
            ("boot nonce", |a| a.boot_nonce = "another-boot".to_string()),
            ("issue id", |a| a.issue_id = "issue-2".to_string()),
            ("timestamp", |a| a.ts_ms += 1),
            ("charter epoch", |a| {
                a.signer = CapsuleSigner::Group { charter_epoch: 4 }
            }),
        ];
        for (what, apply) in mutate {
            let mut tampered = unsigned.attestation();
            apply(&mut tampered);
            assert_ne!(
                tampered.signing_bytes().expect("recompute"),
                honest,
                "changing the {what} must change the bytes a member signs"
            );
        }
    }

    /// A group signature must not be collectable for an envelope labelled
    /// `Operator`: the two are different claims about who authorised issuance.
    #[test]
    fn an_attestation_cannot_relabel_the_signer() {
        let f = fixture();
        let capsule = capsule_for(&f, ServiceRole::Monitor);
        let unsigned = begin_seal(
            &capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-1",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 3 },
        )
        .expect("begin_seal");

        let mut relabelled = unsigned.attestation();
        relabelled.signer = CapsuleSigner::Operator;
        assert_ne!(
            relabelled.signing_bytes().expect("recompute"),
            unsigned.signing_bytes(),
            "the signer tag is inside the preimage"
        );
    }

    #[test]
    fn wrong_boot_nonce_rejected_before_crypto() {
        let f = fixture();
        let sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        let err = unseal_capsule(
            &sealed,
            &f.svc_eph.secret.to_bytes(),
            &f.machine_id,
            "a-different-boot",
            &CapsuleTrustAnchor::operator_only(&f.op_verify),
            f.ts_ms,
            60_000,
        )
        .unwrap_err();
        assert!(matches!(err, CapsuleError::BindingMismatch), "got {err:?}");
    }

    /// The other AAD-bound field: a capsule sealed for one box must not open
    /// under a different box's expected `machine_id`, even with a correct
    /// boot nonce. `role` used to be a third bound field here (two node
    /// epochs on one box, same machine and boot, different role) — the AAD
    /// no longer carries it, so that case is gone on purpose: see the
    /// module doc's AAD note.
    #[test]
    fn wrong_machine_id_rejected_before_crypto() {
        let f = fixture();
        let sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        let err = unseal_capsule(
            &sealed,
            &f.svc_eph.secret.to_bytes(),
            "tr-hostkey-203.0.113.20",
            &f.boot_nonce,
            &CapsuleTrustAnchor::operator_only(&f.op_verify),
            f.ts_ms,
            60_000,
        )
        .unwrap_err();
        assert!(matches!(err, CapsuleError::BindingMismatch), "got {err:?}");
    }

    #[test]
    fn wrong_ephemeral_secret_fails_aead() {
        let f = fixture();
        let sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        let attacker = KeyPair::generate();
        let err = unseal_capsule(
            &sealed,
            &attacker.secret.to_bytes(),
            &f.machine_id,
            &f.boot_nonce,
            &CapsuleTrustAnchor::operator_only(&f.op_verify),
            f.ts_ms,
            60_000,
        )
        .unwrap_err();
        assert!(matches!(err, CapsuleError::Unseal), "got {err:?}");
    }

    #[test]
    fn forged_signature_rejected() {
        let f = fixture();
        let sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        let err = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&other)).unwrap_err();
        assert!(matches!(err, CapsuleError::SigInvalid), "got {err:?}");
    }

    #[test]
    fn stale_capsule_rejected() {
        let f = fixture();
        let sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        let err = unseal_capsule(
            &sealed,
            &f.svc_eph.secret.to_bytes(),
            &f.machine_id,
            &f.boot_nonce,
            &CapsuleTrustAnchor::operator_only(&f.op_verify),
            f.ts_ms + 120_000,
            60_000,
        )
        .unwrap_err();
        assert!(matches!(err, CapsuleError::Stale), "got {err:?}");
    }

    #[test]
    fn tampered_ciphertext_fails_aead_not_signature() {
        let f = fixture();
        let mut sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        let mut ct = hex::decode(&sealed.ciphertext_hex).unwrap();
        ct[0] ^= 0xff;
        sealed.ciphertext_hex = hex::encode(&ct);
        // Re-sign so the failure is provably the AEAD tag, not the signature.
        let eph = decode_32(&sealed.issuer_eph_pubkey_hex, "x").unwrap();
        let nonce = decode_12(&sealed.nonce_hex).unwrap();
        let preimage = sig_preimage(
            &sealed.signer,
            &eph,
            &nonce,
            &ct,
            &sealed.machine_id,
            &sealed.boot_nonce,
            &sealed.issue_id,
            sealed.ts_ms,
        );
        sealed.sig_hex = hex::encode(f.op_sign.sign(&preimage).to_bytes());
        let err = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&f.op_verify)).unwrap_err();
        assert!(matches!(err, CapsuleError::Unseal), "got {err:?}");
    }

    /// A capsule sealed before `CapsuleServiceConfig::subscriber_entrance` /
    /// `::subscriber_keys_path` existed — the OLD wire shape a live-fleet
    /// opbox would still be minting — must still deserialise, with both new
    /// fields resolving to `None`. Built by serialising an ordinary fixture
    /// (whose `service_config` already omits both fields via
    /// `skip_serializing_if`) rather than by stripping them from a JSON blob
    /// that already carried them, so this proves the actual old shape rather
    /// than only this struct's own skip-if-None behaviour.
    #[test]
    fn existing_capsule_json_predating_subscriber_fields_still_deserialises() {
        let f = fixture();
        let old_shape_capsule = capsule_for(&f, ServiceRole::Monitor);
        let value = serde_json::to_value(&old_shape_capsule).expect("serialise");
        let service_config = value
            .get("service_config")
            .and_then(|v| v.as_object())
            .expect("service_config is a JSON object");
        assert!(
            !service_config.contains_key("subscriber_entrance"),
            "a fixture with no subscriber_entrance must not emit the key at all"
        );
        assert!(
            !service_config.contains_key("subscriber_keys_path"),
            "a fixture with no subscriber_keys_path must not emit the key at all"
        );

        let restored: MachineCapsule =
            serde_json::from_value(value).expect("old-shape capsule JSON must still deserialise");
        assert!(restored.service_config.subscriber_entrance.is_none());
        assert!(restored.service_config.subscriber_keys_path.is_none());
    }

    // ── dual anchor ───────────────────────────────────────────────────

    fn charter(op: &SigningKey, group: &SigningKey, epoch: u64) -> GroupCharter {
        GroupCharter::sign_new(
            mesh(),
            epoch,
            hex::encode(group.verifying_key().to_bytes()),
            5,
            vec![Uuid::from_u128(1), Uuid::from_u128(2)],
            900_000,
            op,
        )
    }

    #[test]
    fn group_signed_capsule_accepted_with_matching_charter() {
        let f = fixture();
        let group = SigningKey::generate(&mut OsRng);
        let ch = charter(&f.op_sign, &group, 1);
        ch.verify(&f.op_verify).expect("charter verifies");

        let capsule = capsule_for(&f, ServiceRole::Monitor);
        let sealed = seal_capsule(
            &capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-q",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 1 },
            &group,
        )
        .expect("seal");

        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: Some(&ch),
            machine: None,
        };
        let got = unseal(&f, &sealed, &anchor).expect("unseal");
        assert_eq!(got.self_id, capsule.self_id);
    }

    #[test]
    fn group_signed_capsule_rejected_without_a_charter() {
        let f = fixture();
        let group = SigningKey::generate(&mut OsRng);
        let sealed = seal_capsule(
            &capsule_for(&f, ServiceRole::Monitor),
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-q",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 1 },
            &group,
        )
        .expect("seal");
        let err = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&f.op_verify)).unwrap_err();
        assert!(matches!(err, CapsuleError::NoCharter(1)), "got {err:?}");
    }

    #[test]
    fn group_signature_against_a_different_charter_epoch_is_rejected() {
        let f = fixture();
        let group = SigningKey::generate(&mut OsRng);
        let held = charter(&f.op_sign, &group, 2);
        let sealed = seal_capsule(
            &capsule_for(&f, ServiceRole::Monitor),
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-q",
            f.ts_ms,
            CapsuleSigner::Group { charter_epoch: 1 },
            &group,
        )
        .expect("seal");
        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: Some(&held),
            machine: None,
        };
        let err = unseal(&f, &sealed, &anchor).unwrap_err();
        assert!(matches!(err, CapsuleError::NoCharter(1)), "got {err:?}");
    }

    #[test]
    fn operator_envelope_cannot_be_relabelled_as_group_signed() {
        // The signer tag is inside the preimage, so flipping it invalidates
        // the signature instead of silently changing which key is consulted.
        let f = fixture();
        let group = SigningKey::generate(&mut OsRng);
        let ch = charter(&f.op_sign, &group, 1);
        let mut sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        sealed.signer = CapsuleSigner::Group { charter_epoch: 1 };
        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: Some(&ch),
            machine: None,
        };
        let err = unseal(&f, &sealed, &anchor).unwrap_err();
        assert!(matches!(err, CapsuleError::SigInvalid), "got {err:?}");
    }

    #[test]
    fn charter_with_a_forged_operator_signature_is_rejected() {
        let f = fixture();
        let group = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let ch = charter(&attacker, &group, 1);
        let err = ch.verify(&f.op_verify).unwrap_err();
        assert!(matches!(err, CapsuleError::CharterSigInvalid), "got {err:?}");
    }

    #[test]
    fn charter_member_list_is_tamper_evident() {
        let f = fixture();
        let group = SigningKey::generate(&mut OsRng);
        let mut ch = charter(&f.op_sign, &group, 1);
        ch.members.push(Uuid::from_u128(99));
        let err = ch.verify(&f.op_verify).unwrap_err();
        assert!(matches!(err, CapsuleError::CharterSigInvalid), "got {err:?}");
    }

    // ── machine anchor ───────────────────────────────────────────────

    #[test]
    fn machine_signed_capsule_accepted_with_matching_anchor() {
        let f = fixture();
        let attestation = SigningKey::generate(&mut OsRng);
        let capsule = capsule_for(&f, ServiceRole::Monitor);
        let sealed = seal_capsule(
            &capsule,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-m",
            f.ts_ms,
            CapsuleSigner::Machine { machine_id: f.machine_id.clone() },
            &attestation,
        )
        .expect("seal");

        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: &f.machine_id,
                attestation: attestation.verifying_key(),
            }),
        };
        let got = unseal(&f, &sealed, &anchor)
            .expect("a machine-signed capsule must verify under its own machine anchor");
        assert_eq!(got.self_id, capsule.self_id);
    }

    #[test]
    fn machine_signed_capsule_rejected_without_a_machine_anchor() {
        let f = fixture();
        let attestation = SigningKey::generate(&mut OsRng);
        let sealed = seal_capsule(
            &capsule_for(&f, ServiceRole::Monitor),
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-m",
            f.ts_ms,
            CapsuleSigner::Machine { machine_id: f.machine_id.clone() },
            &attestation,
        )
        .expect("seal");

        // The ordinary operator-only anchor a service holds before it has
        // any reason to trust a self-issued capsule — must refuse, never
        // fall through to the operator key.
        let err = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&f.op_verify)).unwrap_err();
        assert!(matches!(err, CapsuleError::NoMachineAnchor), "got {err:?}");
    }

    /// A capsule minted by box A must never verify under an anchor built for
    /// box B, even though both the anchor and the envelope are individually
    /// well-formed.
    #[test]
    fn machine_signed_capsule_rejected_for_a_different_machine_anchor() {
        let f = fixture();
        let attestation = SigningKey::generate(&mut OsRng);
        let sealed = seal_capsule(
            &capsule_for(&f, ServiceRole::Monitor),
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-m",
            f.ts_ms,
            CapsuleSigner::Machine { machine_id: f.machine_id.clone() },
            &attestation,
        )
        .expect("seal");

        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: "tr-hostkey-203.0.113.20",
                attestation: attestation.verifying_key(),
            }),
        };
        let err = unseal(&f, &sealed, &anchor).unwrap_err();
        assert!(
            matches!(err, CapsuleError::MachineAnchorMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn operator_envelope_cannot_be_relabelled_as_machine_signed() {
        // Same property `operator_envelope_cannot_be_relabelled_as_group_
        // signed` proves for the group tag: the signer tag is inside the
        // preimage, so flipping it invalidates the signature instead of
        // silently changing which key is consulted — even when the anchor
        // holds a machine key that WOULD verify a genuine machine signature
        // for this exact machine_id.
        let f = fixture();
        let attestation = SigningKey::generate(&mut OsRng);
        let mut sealed = seal(&f, &capsule_for(&f, ServiceRole::Monitor));
        sealed.signer = CapsuleSigner::Machine { machine_id: f.machine_id.clone() };
        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: &f.machine_id,
                attestation: attestation.verifying_key(),
            }),
        };
        let err = unseal(&f, &sealed, &anchor).unwrap_err();
        assert!(matches!(err, CapsuleError::SigInvalid), "got {err:?}");
    }

    /// **The byte-level claim behind this crate's domain separation from
    /// `crate::attestation`.** The same raw attestation key now signs two
    /// object classes: boot announces (`AttestationKey::attest`) and, once
    /// something mints one, a capsule (this module's `sig_preimage`). A
    /// signature genuinely produced over an announce must never verify as a
    /// capsule signature, or a captured announce attestation could be
    /// replayed to redirect a capsule. Proven directly — take a real
    /// announce signature and try it as `sig_hex` — rather than only arguing
    /// from the two preimages' fixed label bytes: `SIG_LABEL` (26 bytes,
    /// `"MIRAGE-IDENTITY-CAPSULE-V1"`) and `ATTEST_SIG_LABEL_V3` (29 bytes,
    /// `"MIRAGE-MACHINE-ATTESTATION-V3"`) share only the 7-byte `"MIRAGE-"`
    /// prefix before diverging at byte offset 7 (`I` vs `M`) — different
    /// lengths and different content from that point on. Both are prepended
    /// whole via `extend_from_slice` (not length-prefixed, not hashed) as
    /// the FIRST bytes of their respective preimage, ahead of every
    /// producer- or attacker-controlled field, so the two preimages can
    /// never be equal as byte strings regardless of what either one carries
    /// after its label.
    #[test]
    fn an_announce_attestation_cannot_be_replayed_as_a_capsule_signature() {
        let f = fixture();
        let attestation = crate::attestation::AttestationKey::generate(f.machine_id.clone());
        let announce_fields = crate::attestation::AttestedFields {
            machine_id: &f.machine_id,
            build_id: "test-build",
            eph_pubkey_hex: &hex::encode(f.svc_eph.public.to_bytes()),
            boot_nonce: &f.boot_nonce,
            started_at_ms: f.ts_ms,
            platform: None,
            renewal: None,
        };
        let announce_sig_hex = attestation.attest(&announce_fields);
        let sig_bytes: [u8; 64] = hex::decode(&announce_sig_hex)
            .expect("attest() always returns hex")
            .try_into()
            .expect("an ed25519 signature is 64 bytes");

        let unsigned = begin_seal(
            &capsule_for(&f, ServiceRole::Monitor),
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-m",
            f.ts_ms,
            CapsuleSigner::Machine { machine_id: f.machine_id.clone() },
        )
        .expect("begin_seal");
        let sealed = unsigned.finish(&sig_bytes);

        let anchor = CapsuleTrustAnchor {
            operator: &f.op_verify,
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: &f.machine_id,
                attestation: attestation.verifying_key(),
            }),
        };
        let err = unseal(&f, &sealed, &anchor).unwrap_err();
        assert!(
            matches!(err, CapsuleError::SigInvalid),
            "an announce attestation must never verify as a capsule signature — got {err:?}"
        );
    }

    // ── contents vs envelope ──────────────────────────────────────────

    #[test]
    fn contents_naming_another_machine_are_rejected() {
        // Seal a capsule whose payload names box A while the envelope is
        // addressed to box A too, then unseal expecting box A — but with the
        // payload's machine_id swapped. Reproduced by sealing with an envelope
        // built from a DIFFERENT machine than the contents.
        let f = fixture();
        let mut capsule = capsule_for(&f, ServiceRole::Monitor);
        capsule.machine_id = MachineId::new("tr-hostkey-203.0.113.20").unwrap();

        // Seal manually so the envelope keeps the fixture's machine id while
        // the contents name another box.
        let plaintext = serde_json::to_vec(&capsule).unwrap();
        let issuer_eph = KeyPair::generate();
        let shared = shared_secret(
            &issuer_eph.secret,
            &PublicKey::from(f.svc_eph.public.to_bytes()),
        );
        let seal_key = derive_key(&shared, b"", SEAL_INFO);
        let nonce = [7u8; 12];
        let aad = seal_aad(&f.machine_id, &f.boot_nonce);
        let ct = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &seal_key)
            .encrypt(&nonce, &plaintext, &aad)
            .unwrap();
        let signer = CapsuleSigner::Operator;
        let preimage = sig_preimage(
            &signer,
            &issuer_eph.public.to_bytes(),
            &nonce,
            &ct,
            &f.machine_id,
            &f.boot_nonce,
            "issue-x",
            f.ts_ms,
        );
        let sealed = SealedCapsule {
            issuer_eph_pubkey_hex: hex::encode(issuer_eph.public.to_bytes()),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(&ct),
            machine_id: f.machine_id.clone(),
            boot_nonce: f.boot_nonce.clone(),
            issue_id: "issue-x".to_string(),
            ts_ms: f.ts_ms,
            signer,
            sig_hex: hex::encode(f.op_sign.sign(&preimage).to_bytes()),
        };

        let err = unseal(&f, &sealed, &CapsuleTrustAnchor::operator_only(&f.op_verify)).unwrap_err();
        assert!(
            matches!(err, CapsuleError::ContentMismatch(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn expiry_helpers() {
        let f = fixture();
        let c = capsule_for(&f, ServiceRole::Monitor);
        assert!(!c.is_expired(f.ts_ms));
        assert!(c.is_expired(f.ts_ms + 3_600_000));
        assert!(!c.needs_renewal(f.ts_ms, 60_000));
        assert!(c.needs_renewal(f.ts_ms + 3_500_000, 300_000));
    }

    #[test]
    fn zero_ttl_capsule_refused_at_seal() {
        let f = fixture();
        let mut c = capsule_for(&f, ServiceRole::Monitor);
        c.not_after_ms = c.issued_at_ms;
        let err = seal_capsule(
            &c,
            &f.svc_eph.public.to_bytes(),
            &f.boot_nonce,
            "issue-1",
            f.ts_ms,
            CapsuleSigner::Operator,
            &f.op_sign,
        )
        .unwrap_err();
        assert!(matches!(err, CapsuleError::ExpiryInvalid), "got {err:?}");
    }

    #[test]
    fn peer_dial_addr_prefers_the_signed_address() {
        let f = fixture();
        let mut identity = declared(&f.op_sign, ServiceRole::Monitor);
        let transitional = CapsulePeer {
            identity: identity.clone(),
            addr: Some("1.2.3.4:19444".to_string()),
        };
        assert_eq!(transitional.dial_addr(), Some("1.2.3.4:19444"));

        identity.public_addr = Some("5.6.7.8:19444".to_string());
        let signed = CapsulePeer {
            identity,
            addr: Some("1.2.3.4:19444".to_string()),
        };
        assert_eq!(signed.dial_addr(), Some("5.6.7.8:19444"));
    }

    // ── the country map: byte-for-byte compatibility ──────────────────
    //
    // The country map is the newest field on this struct and the ONLY one
    // whose absence must be invisible in the signed bytes. `CapsuleService-
    // Config` is signed as a length-prefixed JSON tail (see
    // `crate::service_config_anchor::ServiceConfigAnchor::signing_bytes`),
    // so a field that serialised as a present-but-empty object would change
    // the signed bytes of every already-issued capsule in the fleet and
    // break verification everywhere at once. These two tests are the proof
    // that it does not — not a promise in a doc comment.

    /// A config carrying a representative set of the fields that DO exist
    /// before the country map, and no country map.
    fn pre_country_map_config() -> CapsuleServiceConfig {
        CapsuleServiceConfig {
            public_addr: Some("203.0.113.10:19444".to_string()),
            control_bind_addr: Some("127.0.0.1:19444".to_string()),
            shortname: Some("ams-edge-01".to_string()),
            node_seeds: vec!["v2-seed-a".to_string(), "v2-seed-b".to_string()],
            edge_scope: Some(EdgeScopeKind::Public),
            ..Default::default()
        }
    }

    /// The EXACT bytes this config serialised to before the country map
    /// existed. Written out literally rather than compared against a
    /// freshly-computed value: a comparison against "whatever the code
    /// produces today" would pass even if the bytes had changed, which is
    /// the one thing this test exists to catch.
    ///
    /// The country map is absent from it — that IS the guarantee.
    #[test]
    fn a_service_config_without_a_country_map_serialises_byte_for_byte_as_before() {
        let json = serde_json::to_string(&pre_country_map_config()).expect("serialise");
        assert_eq!(
            json,
            r#"{"public_addr":"203.0.113.10:19444","control_bind_addr":"127.0.0.1:19444","shortname":"ams-edge-01","node_seeds":["v2-seed-a","v2-seed-b"],"edge_scope":"public"}"#,
            "a config carrying no country map must serialise exactly as it did \
             before the field existed — the signed bytes of every already-issued \
             capsule depend on it"
        );
        assert!(
            !json.contains("country_cidrs"),
            "the country map must not appear in the serialisation at all when it is empty"
        );
    }

    /// The empty case is the one that matters most: every field on this
    /// struct is `skip_serializing_if`, so a default config serialises to
    /// the empty object — and a field added later WITHOUT that attribute
    /// would break this test, which is exactly the alarm we want.
    #[test]
    fn a_default_service_config_still_serialises_to_the_empty_object() {
        assert_eq!(
            serde_json::to_string(&CapsuleServiceConfig::default()).expect("serialise"),
            "{}"
        );
    }

    /// And the other direction: a config that DOES carry a country map
    /// serialises it, so the map is not merely absent-but-declared.
    ///
    /// The serialised form is the COMPRESSED one (a base64 string, not a
    /// nested object) — see the field's own doc for why. The assertion
    /// below therefore checks the two things that matter: the field is
    /// present as a string, and what that string decodes to is EXACTLY
    /// the map that went in. A "the JSON contains some base64" check
    /// alone would pass for a table that went in wrong.
    #[test]
    fn a_service_config_with_a_country_map_carries_it() {
        let mut cfg = pre_country_map_config();
        cfg.country_cidrs = BTreeMap::from([(
            "RU".to_string(),
            vec!["5.8.0.0/16".to_string(), "5.9.0.0/16".to_string()],
        )]);
        let json = serde_json::to_string(&cfg).expect("serialise");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let encoded = value
            .get("country_cidrs")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("the map must reach the capsule as a string: {json}"));
        assert_eq!(
            crate::country_table::decode(encoded).expect("decode"),
            cfg.country_cidrs,
            "the compressed form must decode back to exactly the map that went in"
        );
        assert!(
            !json.contains(r#""country_cidrs":{"#),
            "the country table must not travel as a plain JSON object any more: {json}"
        );
    }
}
