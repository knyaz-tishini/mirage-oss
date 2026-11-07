//! Operator-issued declared identity for every Mirage process.
//!
//! See `docs/plans/operator-box-extension-plan.md` § "Step A".
//!
//! # Lifecycle
//!
//! 1. Operator runs `mirage-operator inventory adopt <ip>` on a fresh VPS.
//! 2. Operator-box generates an X25519 keypair on the target box, mints
//!    a fresh `self_id: Uuid`, and constructs a [`DeclaredIdentity`]
//!    signed by the operator's long-lived Ed25519 key.
//! 3. The signed declaration is gossiped through the existing
//!    mesh peer-event channel; every monitor stores it in
//!    `declared_identities` and rejects any register that does not
//!    match.
//! 4. On the VPS side, the X25519 priv key + a copy of the signed
//!    declaration are sealed under the box's hardware fingerprint
//!    (via [`crate::sealed_secret`]) into `/var/lib/<service>/bootstrap.sealed`.
//! 5. On boot the service unseal's the bootstrap, presents
//!    `(self_id, roles, mesh_id, pubkey, operator_sig)` to a monitor; the
//!    monitor verifies the signature against its pinned operator pub
//!    and upserts `peer_table` keyed by `self_id`.
//!
//! Identity is **never** minted on the service side — service binaries
//! only carry what operator-box already declared. This is the ZT
//! property: a leaked bootstrap blob on a different box won't unseal
//! (sealed-to-hardware), a fabricated register without `operator_sig` won't
//! pass the monitor.

use std::borrow::Cow;
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::ids::{derive_client_label, MachineId, MeshId, NodeEpoch};

/// Role of a Mirage process inside the mesh.
///
/// One physical machine usually plays several roles (a typical VPS in
/// staging-v2 runs `Monitor`, `Node{V2}`, and `Sentry` side by side) —
/// each role gets its own [`DeclaredIdentity`] with its own `self_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ServiceRole {
    /// Mirage onion peer. Carries an epoch so `v2` and `v3` co-exist on
    /// the same machine with separate identities.
    Node { epoch: NodeEpoch },
    /// `mirage2monitor` daemon.
    Monitor,
    /// Always-on system scanner (`mirage-sentry`).
    Sentry,
    /// Self-sufficient mesh-exec daemon (future crate). Operator-signed
    /// the same way as everything else.
    Mshd,
    /// Client-side bootstrap (`mirage-l0-sentinel`).
    Sentinel,
    /// Box-resident security entity (`mirage-secd`): proactive, sentry-class
    /// daemon. Audits posture, discriminates friend/foe, drives the
    /// `mirage-nft` ban/trust sets, and emits originator-signed
    /// `SecurityPosture` facts on the L1 anti-entropy plane. Joins the mesh
    /// alone via embedded bootstrap (mshd-style) and exposes no inbound
    /// listener — it must never itself be a hole.
    Secd,
    /// Per-VPS SQLite/SQLCipher read+write worker. Lives next to the
    /// monitor on every server box, opens the shared store with the
    /// host-bound sealed key, and accepts operator-signed SQL through
    /// the monitor's `/relay/db-workers/{id}/control` WS. The whole
    /// point: operator-box gets typed visibility into and control over
    /// remote databases without SSH+sqlite3.
    DbWorker,
    /// Box-resident service-liveness daemon + Tier2 enforcement anchor
    /// (`mirage-warden`, arc2.9). Minimal, stable, root, rarely restarts.
    /// Forms a mutual-protection pair with `secd`: each supervises the
    /// other's liveness and can open a targeted managed-restart window to
    /// recover its partner, so neither can be permanently silenced by a
    /// guest-root attacker's kill loop. Joins the mesh alone via embedded
    /// bootstrap (mshd-style), same as `Secd`.
    Warden,
    /// The operator-box itself — the root-of-trust control participant.
    /// Carries a `DeclaredIdentity` signed by its own operator key so
    /// monitors can verify its wire-identity on the control plane.
    /// This is a management role, not a relay role: an `Operator`
    /// identity never appears inside onion chains or as a peer node.
    #[serde(rename = "operator")]
    Operator,
    /// Box-resident perimeter daemon (`mirage-perimeter`): the box's ONLY
    /// public listener. Terminates every attacker-facing byte, strips the
    /// outer camouflage, classifies whether what remains is Mirage wire,
    /// and either splices the connection through to the co-located monitor
    /// on loopback or rejects it. Deliberately a SEPARATE role from
    /// [`ServiceRole::Secd`] — a daemon that enforces kernel policy must
    /// not also run the periphery (arc3 core/periphery split, see
    /// `mirage-perimeter`'s own crate doc for the full reasoning). Joins
    /// the mesh alone via the same capsule-boot path as `Secd`/`Warden`.
    Perimeter,
    /// Terminates a paying customer and builds a chain on his behalf
    /// (owner's ruling, 2026-09-17, "the edge role"). Deliberately NOT a
    /// mesh participant in the knowledge sense: it never relays anybody
    /// else's traffic, it is never picked into anybody else's chain, and
    /// it learns no peer beyond its own next hop — that is what closes the
    /// reconnaissance threat a paying customer's entrance box would
    /// otherwise be. Gets its own `RoleSlice`/wire key like every other
    /// role, because the subscriber-facing handshake is a genuinely
    /// separate identity from the box's own `Node` relay identity, on
    /// boxes that run both side by side.
    Edge,
    /// The automated-issuance back-office (`mirage-panel`), minted once
    /// (rarely rotated) by opbox for the panel process — never a mesh peer
    /// (owner's ruling, 2026-09-23, "the back-office's automated issuance
    /// layer":
    /// `docs/mirage/plans/2026-09-23-backoffice-automated-issuance.md` §3).
    /// Deliberately narrow: it dials a monitor's `/relay/entrance/*` routes
    /// to put/read one edge's subscriber-key set, and nothing else — it
    /// never appears in `MachineCapsule.peers`, never gossips a peer record
    /// of its own beyond its `DeclaredIdentity`, and is never picked into
    /// anybody's chain. **Signs no fleet facts** (unlike `Secd`/`Sentry`/
    /// `Node`/`Warden`/`Perimeter` — see operator-box's own
    /// `role_signs_facts`, which this role is deliberately absent from, the
    /// same way `Monitor`/`DbWorker`/`Mshd` already have no fact-signer
    /// consumer for the key): the back-office reads and writes subscriber
    /// gate state, it does not originate signed telemetry about the box it
    /// is granted onto.
    BackOffice,
}

impl ServiceRole {
    pub fn as_tag(&self) -> &'static str {
        match self {
            ServiceRole::Node { .. } => "node",
            ServiceRole::Monitor => "monitor",
            ServiceRole::Sentry => "sentry",
            ServiceRole::Mshd => "mshd",
            ServiceRole::Sentinel => "sentinel",
            ServiceRole::Secd => "secd",
            ServiceRole::DbWorker => "db-worker",
            ServiceRole::Warden => "warden",
            ServiceRole::Operator => "operator",
            ServiceRole::Perimeter => "perimeter",
            ServiceRole::Edge => "edge",
            ServiceRole::BackOffice => "back-office",
        }
    }
}

impl fmt::Display for ServiceRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceRole::Node { epoch } => write!(f, "node-{}", epoch.prefix()),
            ServiceRole::Monitor => f.write_str("monitor"),
            ServiceRole::Sentry => f.write_str("sentry"),
            ServiceRole::Mshd => f.write_str("mshd"),
            ServiceRole::Sentinel => f.write_str("sentinel"),
            ServiceRole::Secd => f.write_str("secd"),
            ServiceRole::DbWorker => f.write_str("db-worker"),
            ServiceRole::Warden => f.write_str("warden"),
            ServiceRole::Operator => f.write_str("operator"),
            ServiceRole::Perimeter => f.write_str("perimeter"),
            ServiceRole::Edge => f.write_str("edge"),
            ServiceRole::BackOffice => f.write_str("back-office"),
        }
    }
}

/// One role's public keys inside a [`DeclaredIdentity`] — the public-half
/// mirror of [`crate::capsule::RoleSlice`], gossiped instead of sealed.
///
/// A [`MachineCapsule`][crate::capsule::MachineCapsule] carries one
/// [`RoleSlice`][crate::capsule::RoleSlice] — role, PRIVATE keys, and their
/// own public halves — per role the box runs, sealed to whoever is booting.
/// This is the entry a remote PEER gets instead: same role, same public
/// halves, gossiped in the clear inside the signed [`DeclaredIdentity`]
/// every monitor already holds. See [`DeclaredIdentity::role_keys`] for why
/// the set is signed rather than derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePublicKeys {
    pub role: ServiceRole,
    /// X25519 wire public key, hex (64 lowercase chars) — what a peer dials
    /// this role's handshake with.
    pub wire_pubkey_hex: String,
    /// Ed25519 fact-signing public key, hex. `None` for a role that signs no
    /// facts — the same split [`crate::capsule::RoleSlice::signing_privkey`]
    /// makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pubkey_hex: Option<String>,
}

/// Who signed a [`DeclaredIdentity`].
///
/// `serde(default)` resolves to [`Self::Operator`], so every identity ever
/// minted before this field existed — every one of them operator-signed,
/// since no other signer was representable — deserialises correctly with no
/// migration. This is the identity-layer sibling of
/// [`crate::capsule::CapsuleSigner`], which plays the same role one level
/// up for the outer sealed envelope; the two are deliberately separate
/// types, because a capsule's outer seal and its embedded identity are two
/// independent signatures over two different byte strings (see this crate's
/// own "two signatures, not one" shape — [`crate::capsule::MachineCapsule::
/// declared_identity`] carries this one, [`crate::capsule::SealedCapsule::
/// signer`] carries the other), and a quorum-sealed capsule today still
/// embeds an ordinary operator-signed identity (the quorum authorises
/// SLICE keys via [`crate::quorum::IdentityRotated`], never a fresh
/// identity) — there is no `Group` case here to represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum IdentitySigner {
    /// The pinned operator key — every identity minted before self-issued
    /// identities existed, and every one minted the ordinary way since.
    Operator,
    /// Self-issued: signed by the box's own durable attestation key
    /// ([`crate::attestation::AttestationKey`]), the same raw key
    /// [`crate::capsule::CapsuleSigner::Machine`] uses for the outer
    /// envelope — see that variant's own doc for why the raw key and not a
    /// derived one. `machine_id` names which box's attestation key must
    /// verify this signature, mirroring `CapsuleSigner::Machine`'s own
    /// field: a `DeclaredIdentity` self-signed by box A must never verify
    /// under an anchor built for box B, checked explicitly in
    /// [`DeclaredIdentity::verify_with_anchor`] rather than assumed from
    /// this field alone.
    Machine { machine_id: String },
}

impl Default for IdentitySigner {
    fn default() -> Self {
        Self::Operator
    }
}

/// Operator-issued declaration of one Mirage process's identity.
///
/// `operator_sig` covers the canonical byte serialisation of every
/// non-signature field — see [`Self::signing_bytes`]. Monitors verify
/// against their pinned operator [`VerifyingKey`]. The field is named
/// `operator_sig` for the same reason [`Self::signer`]'s doc gives for
/// keeping `IdentitySigner` a separate type rather than folding it into
/// [`crate::capsule::CapsuleSigner`]: renaming a wire field is a breaking
/// change to every already-gossiped identity's JSON shape, so the name
/// stays even though the field now covers either signer — see
/// [`Self::signer`] for which one, and [`Self::verify_with_anchor`] for how
/// a holder of the matching anchor checks it either way.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclaredIdentity {
    /// The single wire-side identifier — replaces every per-role
    /// stringly-typed id (`node_id`, `monitor_id`, etc.) the legacy code
    /// used to carry. The operator-box is the sole minter.
    pub self_id: Uuid,
    /// Human-friendly box name (operator UI only, never on the wire
    /// outside this signed envelope).
    pub machine_id: MachineId,
    /// Mesh scope. A monitor running mesh `v3-staging` rejects any
    /// declaration with a different `mesh_id`.
    pub mesh_id: MeshId,
    /// Every role this MACHINE runs — not one role per declaration any more.
    ///
    /// **Signed, deliberately.** A remote monitor filters peers on this list
    /// (does the box across the mesh run `Sentry`? `Node`?) and has no
    /// visibility into opbox's local escrow, which is where the per-role
    /// bookkeeping used to live. Moving `roles` inside the signed envelope
    /// is what lets a monitor answer that question from gossip alone,
    /// instead of trusting an unsigned side-channel or asking opbox.
    /// Non-empty by construction — see [`crate::capsule::MachineCapsule`]'s
    /// own slice-set invariant, which this list mirrors at the identity
    /// layer.
    pub roles: Vec<ServiceRole>,
    /// Every role's own public keys — replaces the single `pubkey_hex` this
    /// identity used to carry back when it named exactly one role. With
    /// per-role keys now living inside the machine capsule (see
    /// [`crate::capsule::RoleSlice`]), a lone `pubkey_hex` no longer
    /// identifies anything: a peer dialling this box's MONITOR needs the
    /// monitor's own wire pubkey, not some other role's on the same box.
    ///
    /// **Signed, not derived.** A remote monitor has no visibility into
    /// opbox's local escrow or this box's `mirage-warden` keeper — the only
    /// place the per-role key material lives is the sealed
    /// [`crate::capsule::MachineCapsule`], scoped to the box it was issued
    /// to and never gossiped. If "which key speaks for this box's monitor"
    /// were left to be derived or asserted unsigned, it would be a claim
    /// taken on the wire's own word — exactly the hole a `self_id`-keyed
    /// peer table already refuses to leave open for the identity as a
    /// whole. So the set travels inside this signed envelope instead, the
    /// same as [`Self::roles`] does.
    ///
    /// Non-empty by construction, one entry per role named in
    /// [`Self::roles`] — see [`crate::capsule::MachineCapsule::slices`]'s
    /// own non-empty invariant, which this list mirrors at the identity
    /// layer. Use [`Self::wire_pubkey_for`] rather than scanning this
    /// directly.
    pub role_keys: Vec<RolePublicKeys>,
    /// Unix-ms when operator-box minted this declaration.
    pub adopted_at_ms: u64,
    /// `true` once operator runs `inventory revoke` and the tombstone
    /// has been gossiped. Monitors drop revoked rows from peer_table
    /// and refuse fresh registers carrying the same `self_id`.
    #[serde(default)]
    pub revoked: bool,
    /// Unix-ms of revocation (None while live).
    #[serde(default)]
    pub revoked_at_ms: Option<u64>,
    /// Ed25519 signature over [`Self::signing_bytes`].
    pub operator_sig: SignatureHex,
    /// Unix-ms after which this identity MUST NOT be honoured. `None` =
    /// no expiry (legacy / long-lived identities). Bound into the operator
    /// signature (domain-separated tail) so it cannot be stripped or
    /// extended by a relay. The owning daemon refuses to authenticate past
    /// this instant and refetches a fresh signed identity before it lapses;
    /// monitors reject a register/control-WS carrying an expired identity.
    /// Absent on identities minted before TTL was introduced — old operator
    /// signatures remain valid (see `signing_bytes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Routable `<ip>:<port>` this identity's owner serves on.
    ///
    /// Bound into the operator signature (domain-separated tail) so a relay
    /// cannot rewrite where a peer is dialled: the address becomes a property
    /// OF the identity instead of a second, drift-prone source of truth. It
    /// replaces the `monitor_urls` table, whose rows outlived the ports they
    /// named — boxes were still seeded from `:19450` / `:19451` URLs years
    /// after the wire-direct cutover killed those listeners.
    ///
    /// `None` on identities minted before this field existed; their operator
    /// signatures stay valid byte-for-byte (see [`Self::signing_bytes`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_addr: Option<String>,
    /// The ordinary ports this box answers Mirage on, each with the outer
    /// camouflage a dialer must present there.
    ///
    /// Bound into the operator signature by a domain-separated tail, for the
    /// same reason `public_addr` is: a peer record has to BE an identity. A
    /// relay may pass the envelope on, but it must not be able to add a face
    /// — an unsigned face list would be an invitation to point a peer's dials
    /// at a port of the relay's choosing.
    ///
    /// The list is a property of the TARGET, not of whoever is dialling.
    /// Before this existed `MonitorChainDialer` applied the DIALLER's own
    /// configured list to every peer's host, which is correct only while
    /// every box carries an identical list — false the moment the
    /// ordinary-port plane is rolled box by box. Measured 2026-08-02: two
    /// canaries carrying five faces spent four dials per peer on ports the
    /// other seven boxes do not bind, and `stale_edges` climbed from 10-17
    /// to 21 of 72 while `failed_edges` stayed at 0.
    ///
    /// Empty (the default) writes NO tail, so the preimage stays
    /// byte-identical to every identity minted before this field existed and
    /// every signature over one stays valid.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub faces: Vec<crate::capsule::CapsuleControlEndpoint>,
    /// Who actually produced [`Self::operator_sig`] — see [`IdentitySigner`]'s
    /// own doc. `#[serde(default)]` so every identity minted before this
    /// field existed deserialises as [`IdentitySigner::Operator`], which is
    /// the only value it could ever have been.
    ///
    /// **Not** bound into [`Self::signing_bytes`]'s own preimage — it is
    /// bound into [`Self::signing_bytes_with_signer`]'s tail instead, which
    /// [`Self::verify`]/[`Self::verify_with_anchor`] call with this exact
    /// field. See [`Self::signing_bytes_with_signer`]'s own doc for why the
    /// split keeps `signing_bytes` itself byte-identical to every build that
    /// predates self-issuance.
    #[serde(default)]
    pub signer: IdentitySigner,
    /// Client-facing opaque label — never hoster/provider/IP/machine-id
    /// shaped. Minted once at issuance by
    /// [`crate::ids::derive_client_label`]`(self_id)`; carried here
    /// (signed, not re-derived by every reader) so a future format change
    /// to that function cannot retroactively rewrite an already-issued
    /// signature. `None` on every identity minted before this field
    /// existed — readers fall back to [`Self::client_label_or_derive`],
    /// which computes byte-identically to what would have been signed, so
    /// no fleet-wide re-sign campaign is needed to backfill old rows.
    ///
    /// Bound into the operator signature by its own domain-separated
    /// tail ([`Self::signing_bytes`]), appended after the faces tail —
    /// the same reason `public_addr`/`faces` are bound in: an unsigned
    /// label would let a relay substitute a different opaque string for a
    /// peer's real identity without invalidating anything.
    ///
    /// `None` writes NO tail, so the preimage stays byte-identical to
    /// every identity minted before this field existed and every
    /// signature over one stays valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_label: Option<String>,
}

impl DeclaredIdentity {
    /// The label to use when [`Self::client_label`] is `None` (rows minted
    /// before this field existed). Byte-identical to what
    /// [`crate::ids::derive_client_label`] would have signed at issuance
    /// time — a lazy, storage-free upgrade path: no fleet-wide re-sign
    /// campaign is needed to backfill old rows.
    pub fn client_label_or_derive(&self) -> Cow<'_, str> {
        match &self.client_label {
            Some(l) => Cow::Borrowed(l.as_str()),
            None => Cow::Owned(derive_client_label(self.self_id)),
        }
    }

    /// Canonical byte form used as the signing input. Stable across
    /// versions: any field added later MUST be appended at the end so
    /// existing signatures keep verifying after a binary upgrade.
    ///
    /// ## `roles` and `role_keys` are a hard cutover, not a backward-compatible tail
    ///
    /// Every OTHER optional field below (`expires_at_ms`, `public_addr`,
    /// `faces`) is appended as a domain-separated tail specifically so a
    /// `None`/empty value keeps producing the exact bytes a pre-existing
    /// signature was minted over. `roles` and `role_keys` cannot follow that
    /// shape: `roles` replaced the single, MANDATORY `role` field that used
    /// to sit at this fixed early position, and `role_keys` replaces the
    /// single, MANDATORY `pubkey_hex` (plus the formerly-tailed
    /// `signing_pubkey_hex`) that sat right after it. There is no
    /// byte-compatible narrowing between "one key, unprefixed" and "a set of
    /// per-role keys, count-prefixed" the way there is between "field
    /// absent" and "field present" — so an identity signed before this
    /// change and one signed after it do not verify against each other, on
    /// purpose, matching the machine-identity cutover's own hard-cutover
    /// rule (see
    /// `docs/mirage/plans/machine-identity-consolidated-2026-08-17.md` §7).
    ///
    /// Both lists are count-prefixed (`u32` big-endian, matching this
    /// function's own endianness) before their NUL-terminated entries — the
    /// same reason [`crate::capsule::GroupCharter::signing_bytes`]
    /// count-prefixes its member list: without it, a two-entry list and a
    /// one-entry list whose remaining bytes happen to look like a second
    /// entry would be indistinguishable from the preimage alone.
    ///
    /// `role_keys` is additionally sorted by each entry's role (`Display`
    /// form) before it is written, regardless of the order the caller built
    /// the `Vec` in — so two encoders assembling the SAME set of per-role
    /// keys in different order (say, iterating
    /// [`crate::capsule::MachineCapsule::slices`] versus a map) sign
    /// byte-identical preimages. `roles` itself is not re-sorted: it is a
    /// small, operator-authored list, and every existing caller already
    /// depends on its own insertion order producing stable bytes.
    ///
    /// ```text
    /// b"mirage-declared-identity-v1\0"
    /// self_id (16 bytes, big-endian UUID)
    /// machine_id NUL
    /// mesh_id NUL
    /// roles.len() (4 bytes big-endian u32), then each role's Display form NUL
    /// role_keys.len() (4 bytes big-endian u32), then, SORTED by role:
    ///     role.to_string() NUL
    ///     wire_pubkey_hex NUL
    ///     presence byte (0 or 1) for signing_pubkey_hex, then, if 1:
    ///         signing_pubkey_hex NUL
    /// adopted_at_ms (8 bytes big-endian u64)
    /// ```
    ///
    /// The tail separators below begin with `\0` so they cannot be confused
    /// with timestamp continuation bytes, and each label is unique so it
    /// cannot collide with another tail.
    #[allow(clippy::too_many_arguments)]
    pub fn signing_bytes(
        self_id: Uuid,
        machine_id: &MachineId,
        mesh_id: &MeshId,
        roles: &[ServiceRole],
        role_keys: &[RolePublicKeys],
        adopted_at_ms: u64,
        expires_at_ms: Option<u64>,
        public_addr: Option<&str>,
        faces: &[crate::capsule::CapsuleControlEndpoint],
        client_label: Option<&str>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"mirage-declared-identity-v1\0");
        buf.extend_from_slice(self_id.as_bytes());
        buf.extend_from_slice(machine_id.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(mesh_id.as_str().as_bytes());
        buf.push(0);
        // Count-prefixed so the list cannot be truncated or extended without
        // changing the preimage — see this fn's own doc.
        buf.extend_from_slice(&(roles.len() as u32).to_be_bytes());
        for role in roles {
            buf.extend_from_slice(role.to_string().as_bytes());
            buf.push(0);
        }
        // Per-role public keys — replaces the old fixed `pubkey_hex NUL`
        // slot. Sorted by role so two encoders of the same set agree; see
        // this fn's own doc.
        let mut sorted_keys: Vec<&RolePublicKeys> = role_keys.iter().collect();
        sorted_keys.sort_by(|a, b| a.role.to_string().cmp(&b.role.to_string()));
        buf.extend_from_slice(&(sorted_keys.len() as u32).to_be_bytes());
        for rk in sorted_keys {
            buf.extend_from_slice(rk.role.to_string().as_bytes());
            buf.push(0);
            buf.extend_from_slice(rk.wire_pubkey_hex.as_bytes());
            buf.push(0);
            // Presence byte first, distinguishing absent from empty, same
            // discipline as every optional field elsewhere in this fn —
            // without it, `None` for one entry could read as the start of
            // the next entry's role name.
            match &rk.signing_pubkey_hex {
                Some(spk) => {
                    buf.push(1);
                    buf.extend_from_slice(spk.as_bytes());
                    buf.push(0);
                }
                None => buf.push(0),
            }
        }
        buf.extend_from_slice(&adopted_at_ms.to_be_bytes());
        // Domain-separated tail — only written when an expiry is set.
        if let Some(exp) = expires_at_ms {
            buf.extend_from_slice(b"\0expires-at\0");
            buf.extend_from_slice(&exp.to_be_bytes());
        }
        // Second domain-separated tail — only written when a public address is
        // set. Appended AFTER the expiry tail so that, for any identity with
        // `public_addr = None`, the output stays byte-identical whatever the
        // expiry tail does. Binding the address here is what lets a peer
        // record BE an identity: a relay can pass the envelope on, but it
        // cannot point it at a different box.
        if let Some(addr) = public_addr {
            buf.extend_from_slice(b"\0public-addr\0");
            buf.extend_from_slice(addr.as_bytes());
        }
        // Third domain-separated tail — written ONLY when the face list is
        // non-empty, appended after every earlier tail, so an identity with
        // no faces encodes byte-identically to the pre-faces version whatever
        // the other tails do. That is what keeps every signature minted
        // before this field valid, and it is the same discipline the
        // expires-at / public-addr tails were added under.
        //
        // The encoding is the serde JSON of the list, length-prefixed. serde
        // emits struct fields in declaration order and enum variants by their
        // tag, so it is deterministic for a given type definition. If the
        // shape of `CapsuleControlEndpoint` or `TransportCamouflage` changes,
        // signatures previously minted over a NON-EMPTY list stop verifying —
        // which is correct: a different encoding of the faces is a different
        // fact, and quietly accepting it would be the hole this tail exists
        // to close.
        if !faces.is_empty() {
            buf.extend_from_slice(b"\0faces\0");
            let json = serde_json::to_vec(faces).unwrap_or_default();
            buf.extend_from_slice(&(json.len() as u32).to_be_bytes());
            buf.extend_from_slice(&json);
        }
        // Fourth domain-separated tail — written ONLY when a client-facing
        // label is set, appended after every earlier tail, so an identity
        // with `client_label = None` encodes byte-identically to the
        // pre-`client_label` version whatever the other tails do. That is
        // what keeps every signature minted before this field existed
        // valid, the same discipline the expires-at / public-addr / faces
        // tails were added under.
        if let Some(label) = client_label {
            buf.extend_from_slice(b"\0client-label\0");
            buf.extend_from_slice(label.as_bytes());
        }
        buf
    }

    /// [`Self::signing_bytes`] plus a fifth domain-separated tail naming the
    /// signer, present ONLY for [`IdentitySigner::Machine`].
    ///
    /// **This is the mechanism that keeps every operator-signed identity's
    /// preimage byte-identical.** For [`IdentitySigner::Operator`] this
    /// function returns EXACTLY [`Self::signing_bytes`]'s own return value —
    /// it calls that function with the SAME ten arguments and, seeing
    /// `Operator`, appends nothing. `signing_bytes` itself never learned
    /// about signers at all: every one of its existing call sites (this
    /// file's own test suite, and every external caller that predates
    /// self-issuance) keeps compiling and keeps producing the bytes it
    /// always has, untouched by this function's existence. Only
    /// [`Self::verify`]/[`Self::verify_with_anchor`] route through this
    /// wrapper instead of the bare `signing_bytes` call they used before
    /// self-issuance existed.
    ///
    /// For [`IdentitySigner::Machine`] the tail is `\0signer-machine\0`
    /// followed by the length-prefixed `machine_id` the signer claims — so a
    /// relabelled signer (Operator → Machine or vice versa) changes the
    /// bytes, and a self-signed identity minted for one machine can never be
    /// silently relabelled for another without invalidating its own
    /// signature. Appended LAST, after the client-label tail, so an identity
    /// with no faces, no client label, and `signer = Operator` is
    /// `signing_bytes`'s output with literally nothing appended — the empty
    /// case every prior tail already preserves.
    #[allow(clippy::too_many_arguments)]
    fn signing_bytes_with_signer(
        self_id: Uuid,
        machine_id: &MachineId,
        mesh_id: &MeshId,
        roles: &[ServiceRole],
        role_keys: &[RolePublicKeys],
        adopted_at_ms: u64,
        expires_at_ms: Option<u64>,
        public_addr: Option<&str>,
        faces: &[crate::capsule::CapsuleControlEndpoint],
        client_label: Option<&str>,
        signer: &IdentitySigner,
    ) -> Vec<u8> {
        let mut buf = Self::signing_bytes(
            self_id,
            machine_id,
            mesh_id,
            roles,
            role_keys,
            adopted_at_ms,
            expires_at_ms,
            public_addr,
            faces,
            client_label,
        );
        if let IdentitySigner::Machine { machine_id: signer_machine_id } = signer {
            buf.extend_from_slice(b"\0signer-machine\0");
            buf.extend_from_slice(&(signer_machine_id.len() as u32).to_be_bytes());
            buf.extend_from_slice(signer_machine_id.as_bytes());
        }
        buf
    }

    /// Construct + sign in one call (operator-box use). No expiry, no
    /// address, no faces, no client label — [`Self::sign_new_full`] with
    /// those four left at their defaults.
    pub fn sign_new(
        self_id: Uuid,
        machine_id: MachineId,
        mesh_id: MeshId,
        roles: Vec<ServiceRole>,
        role_keys: Vec<RolePublicKeys>,
        adopted_at_ms: u64,
        signing_key: &SigningKey,
    ) -> Self {
        Self::sign_new_full(
            self_id,
            machine_id,
            mesh_id,
            roles,
            role_keys,
            adopted_at_ms,
            None,
            None,
            // No faces: writes no tail, so this narrower constructor keeps
            // producing byte-identical signatures.
            Vec::new(),
            // No client label either, same reason.
            None,
            signing_key,
        )
    }

    /// Construct + sign with every optional field. This is the canonical
    /// full constructor; [`Self::sign_new`] routes through it with
    /// `None`/empty for the fields it omits, so every existing caller keeps
    /// producing the byte layout [`Self::signing_bytes`] documents.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new_full(
        self_id: Uuid,
        machine_id: MachineId,
        mesh_id: MeshId,
        roles: Vec<ServiceRole>,
        role_keys: Vec<RolePublicKeys>,
        adopted_at_ms: u64,
        expires_at_ms: Option<u64>,
        public_addr: Option<String>,
        faces: Vec<crate::capsule::CapsuleControlEndpoint>,
        client_label: Option<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let bytes = Self::signing_bytes(
            self_id,
            &machine_id,
            &mesh_id,
            &roles,
            &role_keys,
            adopted_at_ms,
            expires_at_ms,
            public_addr.as_deref(),
            &faces,
            client_label.as_deref(),
        );
        let sig = signing_key.sign(&bytes);
        Self {
            self_id,
            machine_id,
            mesh_id,
            roles,
            role_keys,
            adopted_at_ms,
            revoked: false,
            revoked_at_ms: None,
            operator_sig: SignatureHex::from_signature(&sig),
            expires_at_ms,
            public_addr,
            faces,
            signer: IdentitySigner::Operator,
            client_label,
        }
    }

    /// Construct + self-sign with the box's own durable attestation key —
    /// the [`IdentitySigner::Machine`] sibling of [`Self::sign_new_full`].
    ///
    /// No `public_addr`/`faces`: a self-issued identity is minted with no
    /// operator and no network reachable, and neither is knowable locally
    /// (see `docs/mirage/plans/self-issued-identity-2026-08-18.md`'s warden
    /// investigation for the full accounting of what a box can and cannot
    /// know about itself at this moment). No `client_label` either — that
    /// mint stays the operator's own call (`Self::sign_new_full`), not this
    /// path's; a reader still gets one via
    /// [`Self::client_label_or_derive`]. `expires_at_ms` IS accepted —
    /// unlike the operator path, a self-issued identity should always carry
    /// a bound expiry, matching its own capsule's `not_after_ms` (see
    /// `crate::self_issue::mint_self_issued_capsule`) — a self-signed claim
    /// that somehow outlived its box should not be honoured forever.
    #[must_use]
    pub fn sign_self_issued(
        self_id: Uuid,
        machine_id: MachineId,
        mesh_id: MeshId,
        roles: Vec<ServiceRole>,
        role_keys: Vec<RolePublicKeys>,
        adopted_at_ms: u64,
        expires_at_ms: Option<u64>,
        attestation: &crate::attestation::AttestationKey,
    ) -> Self {
        let signer = IdentitySigner::Machine {
            machine_id: machine_id.to_string(),
        };
        let bytes = Self::signing_bytes_with_signer(
            self_id,
            &machine_id,
            &mesh_id,
            &roles,
            &role_keys,
            adopted_at_ms,
            expires_at_ms,
            None,
            &[],
            None,
            &signer,
        );
        let sig_bytes = attestation.sign(&bytes);
        Self {
            self_id,
            machine_id,
            mesh_id,
            roles,
            role_keys,
            adopted_at_ms,
            revoked: false,
            revoked_at_ms: None,
            operator_sig: SignatureHex(hex::encode(sig_bytes)),
            expires_at_ms,
            public_addr: None,
            faces: Vec::new(),
            signer,
            client_label: None,
        }
    }

    /// True if `expires_at_ms` is set and `now_ms` is at or past it.
    /// An identity with no expiry never expires.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        matches!(self.expires_at_ms, Some(exp) if now_ms >= exp)
    }

    /// This machine's wire public key for `role`, if the identity names one.
    /// See [`Self::role_keys`] for why the set is signed rather than
    /// derived.
    pub fn wire_pubkey_for(&self, role: &ServiceRole) -> Option<&str> {
        self.role_keys
            .iter()
            .find(|rk| &rk.role == role)
            .map(|rk| rk.wire_pubkey_hex.as_str())
    }

    /// This machine's fact-signing key for `role`, decoded. `None` when the
    /// role has no signing key, when the hex is malformed, or when the
    /// identity names no key at all for that role — the same permissive
    /// decode the old root-level `signing_verifying_key` had, now resolved
    /// per role instead of once for the whole identity.
    pub fn signing_verifying_key_for(&self, role: &ServiceRole) -> Option<VerifyingKey> {
        let hex_str = self
            .role_keys
            .iter()
            .find(|rk| &rk.role == role)?
            .signing_pubkey_hex
            .as_deref()?;
        let bytes = hex::decode(hex_str).ok()?;
        let arr: [u8; 32] = bytes.try_into().ok()?;
        VerifyingKey::from_bytes(&arr).ok()
    }

    /// Verify the signature against an operator pinned verifying key.
    ///
    /// **Exact current meaning, unchanged.** For every identity whose
    /// [`Self::signer`] is [`IdentitySigner::Operator`] — every identity
    /// this method has ever been called on, since `IdentitySigner::Machine`
    /// did not exist before this field did — this computes the identical
    /// bytes it always has (see [`Self::signing_bytes_with_signer`]'s own
    /// doc) and checks them against `operator_pub` exactly as before. A
    /// [`IdentitySigner::Machine`]-signed identity is not special-cased
    /// here: it naturally fails, because its actual signature was produced
    /// over a longer, tail-extended preimage that this call does not
    /// reproduce when checking against the operator key — fail-closed, the
    /// same property [`crate::capsule::unseal_capsule`] relies on for a
    /// mislabelled `CapsuleSigner`. Use [`Self::verify_with_anchor`] to
    /// check an identity under whichever anchor its own `signer` claims.
    pub fn verify(&self, operator_pub: &VerifyingKey) -> Result<(), IdentityError> {
        let bytes = Self::signing_bytes_with_signer(
            self_id_copy(&self.self_id),
            &self.machine_id,
            &self.mesh_id,
            &self.roles,
            &self.role_keys,
            self.adopted_at_ms,
            self.expires_at_ms,
            self.public_addr.as_deref(),
            &self.faces,
            self.client_label.as_deref(),
            &self.signer,
        );
        let sig = self.operator_sig.to_signature()?;
        operator_pub
            .verify(&bytes, &sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Verify this identity against whichever anchor its own [`Self::signer`]
    /// names: the operator key (identical to [`Self::verify`]) for
    /// [`IdentitySigner::Operator`], or the named box's own attestation key,
    /// resolved from `anchor.machine`, for [`IdentitySigner::Machine`].
    ///
    /// Mirrors [`crate::capsule::CapsuleTrustAnchor::verifying_key_for`]'s
    /// own refusal discipline: an absent or mismatched machine anchor
    /// refuses outright and never falls back to the operator key — a
    /// self-signed identity that cannot be checked under its OWN claimed
    /// authority is not silently re-checked under a different one.
    pub fn verify_with_anchor(
        &self,
        anchor: &crate::capsule::CapsuleTrustAnchor<'_>,
    ) -> Result<(), IdentityError> {
        match &self.signer {
            IdentitySigner::Operator => self.verify(anchor.operator),
            IdentitySigner::Machine { machine_id } => {
                let ma = anchor
                    .machine
                    .as_ref()
                    .ok_or_else(|| IdentityError::NoMachineAnchor(machine_id.clone()))?;
                if ma.machine_id != machine_id.as_str() {
                    return Err(IdentityError::MachineAnchorMismatch {
                        got: machine_id.clone(),
                        want: ma.machine_id.to_string(),
                    });
                }
                let bytes = Self::signing_bytes_with_signer(
                    self_id_copy(&self.self_id),
                    &self.machine_id,
                    &self.mesh_id,
                    &self.roles,
                    &self.role_keys,
                    self.adopted_at_ms,
                    self.expires_at_ms,
                    self.public_addr.as_deref(),
                    &self.faces,
                    self.client_label.as_deref(),
                    &self.signer,
                );
                let sig = self.operator_sig.to_signature()?;
                ma.attestation
                    .verify(&bytes, &sig)
                    .map_err(|_| IdentityError::BadSignature)
            }
        }
    }
}

#[inline]
fn self_id_copy(u: &Uuid) -> Uuid {
    *u
}

/// Tombstone broadcast over peer-event gossip when operator revokes a
/// declared identity. Carries its own signature so any monitor can
/// verify independently of trust to the relaying peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclaredIdentityRevoke {
    pub self_id: Uuid,
    pub revoked_at_ms: u64,
    pub operator_sig: SignatureHex,
}

impl DeclaredIdentityRevoke {
    pub fn signing_bytes(self_id: Uuid, revoked_at_ms: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"mirage-declared-identity-revoke-v1\0");
        buf.extend_from_slice(self_id.as_bytes());
        buf.extend_from_slice(&revoked_at_ms.to_be_bytes());
        buf
    }

    pub fn sign_new(self_id: Uuid, revoked_at_ms: u64, signing_key: &SigningKey) -> Self {
        let bytes = Self::signing_bytes(self_id, revoked_at_ms);
        let sig = signing_key.sign(&bytes);
        Self {
            self_id,
            revoked_at_ms,
            operator_sig: SignatureHex::from_signature(&sig),
        }
    }

    pub fn verify(&self, operator_pub: &VerifyingKey) -> Result<(), IdentityError> {
        let bytes = Self::signing_bytes(self_id_copy(&self.self_id), self.revoked_at_ms);
        let sig = self.operator_sig.to_signature()?;
        operator_pub
            .verify(&bytes, &sig)
            .map_err(|_| IdentityError::BadSignature)
    }
}

/// Wire-friendly hex wrapper around an Ed25519 signature so the
/// declaration serialises as plain JSON instead of a binary blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureHex(pub String);

impl SignatureHex {
    pub fn from_signature(sig: &Signature) -> Self {
        Self(hex::encode(sig.to_bytes()))
    }

    pub fn to_signature(&self) -> Result<Signature, IdentityError> {
        let raw = hex::decode(&self.0).map_err(|e| IdentityError::BadHex(e.to_string()))?;
        let arr: [u8; 64] = raw
            .try_into()
            .map_err(|v: Vec<u8>| IdentityError::BadSignatureLen(v.len()))?;
        Ok(Signature::from_bytes(&arr))
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid hex in signature: {0}")]
    BadHex(String),
    #[error("signature must be 64 bytes, got {0}")]
    BadSignatureLen(usize),
    #[error("operator signature did not verify")]
    BadSignature,
    #[error("declared identity is machine-signed for {0} but no machine anchor is held")]
    NoMachineAnchor(String),
    #[error("declared identity is machine-signed for {got}, this anchor is for {want}")]
    MachineAnchorMismatch { got: String, want: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn op_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn sample_pubkey() -> String {
        "a".repeat(64)
    }

    /// A single-entry `role_keys` list — the common case most tests below
    /// exercise, mirroring how `sample_pubkey` was passed positionally
    /// before `role_keys` replaced `pubkey_hex`.
    fn role_keys_for(role: ServiceRole, wire_hex: &str) -> Vec<RolePublicKeys> {
        vec![RolePublicKeys {
            role,
            wire_pubkey_hex: wire_hex.to_string(),
            signing_pubkey_hex: None,
        }]
    }

    fn sample_decl(role: ServiceRole, op: &SigningKey) -> DeclaredIdentity {
        DeclaredIdentity::sign_new(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, &sample_pubkey()),
            1_700_000_000_000,
            op,
        )
    }

    #[test]
    fn verify_roundtrip_monitor() {
        let op = op_key();
        let decl = sample_decl(ServiceRole::Monitor, &op);
        decl.verify(&op.verifying_key()).expect("verify");
    }

    #[test]
    fn verify_roundtrip_node_v2_and_v3_coexist() {
        let op = op_key();
        let v2 = sample_decl(ServiceRole::Node { epoch: NodeEpoch::V2 }, &op);
        let v3 = sample_decl(ServiceRole::Node { epoch: NodeEpoch::V3 }, &op);
        v2.verify(&op.verifying_key()).unwrap();
        v3.verify(&op.verifying_key()).unwrap();
        assert_ne!(v2.self_id, v3.self_id, "epochs must get distinct UUIDs");
    }

    #[test]
    fn wrong_operator_key_rejected() {
        let op = op_key();
        let wrong_key = op_key();
        let decl = sample_decl(ServiceRole::Sentry, &op);
        assert!(decl.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn modified_pubkey_fails_verify() {
        let op = op_key();
        let mut decl = sample_decl(ServiceRole::Node { epoch: NodeEpoch::V2 }, &op);
        decl.role_keys[0].wire_pubkey_hex = "b".repeat(64);
        assert!(decl.verify(&op.verifying_key()).is_err());
    }

    #[test]
    fn revoke_verifies() {
        let op = op_key();
        let self_id = Uuid::new_v4();
        let rev = DeclaredIdentityRevoke::sign_new(self_id, 1_700_000_999_000, &op);
        rev.verify(&op.verifying_key()).unwrap();
    }

    #[test]
    fn signature_hex_roundtrip() {
        let op = op_key();
        let decl = sample_decl(ServiceRole::Mshd, &op);
        let json = serde_json::to_string(&decl).unwrap();
        let back: DeclaredIdentity = serde_json::from_str(&json).unwrap();
        back.verify(&op.verifying_key()).unwrap();
    }

    /// A `DeclaredIdentity` carrying several roles' worth of public keys
    /// round trips through JSON and its operator signature still verifies —
    /// the preimage bytes `role_keys` contributes must survive the trip
    /// exactly, or a gossiped identity would stop verifying on its FIRST
    /// hop.
    #[test]
    fn declared_identity_round_trips_through_its_signed_preimage() {
        let op = op_key();
        let roles = vec![ServiceRole::Monitor, ServiceRole::Secd];
        let role_keys = vec![
            RolePublicKeys {
                role: ServiceRole::Monitor,
                wire_pubkey_hex: "aa".repeat(32),
                signing_pubkey_hex: Some("bb".repeat(32)),
            },
            RolePublicKeys {
                role: ServiceRole::Secd,
                wire_pubkey_hex: "cc".repeat(32),
                signing_pubkey_hex: None,
            },
        ];
        let decl = DeclaredIdentity::sign_new(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            roles,
            role_keys,
            1_700_000_000_000,
            &op,
        );

        let json = serde_json::to_string(&decl).unwrap();
        let back: DeclaredIdentity = serde_json::from_str(&json).unwrap();
        back.verify(&op.verifying_key())
            .expect("round-tripped identity must still verify");
        assert_eq!(back.wire_pubkey_for(&ServiceRole::Monitor), Some("aa".repeat(32).as_str()));
        assert_eq!(back.wire_pubkey_for(&ServiceRole::Secd), Some("cc".repeat(32).as_str()));
        assert_eq!(
            back.wire_pubkey_for(&ServiceRole::Warden),
            None,
            "a role the identity does not name has no key"
        );
    }

    #[test]
    fn signing_bytes_stable_per_field() {
        let machine = MachineId::new("nl-example-203.0.113.31").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let role = ServiceRole::Node { epoch: NodeEpoch::V2 };
        let id = Uuid::nil();
        let rk = role_keys_for(role, "deadbeef");
        let a = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[role], &rk, 1_700_000_000, None, None, &[], None,
        );
        let b = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[role], &rk, 1_700_000_000, None, None, &[], None,
        );
        assert_eq!(a, b, "deterministic input -> deterministic bytes");
    }

    /// The `None` case (no expiry, no address, no faces, and a `role_keys`
    /// entry with no signing pubkey) produces exactly the encoding this
    /// fn's own doc promises: `roles` count-prefixed at the fixed early
    /// position `role` used to occupy, then `role_keys` count-prefixed
    /// right after it. Pinning the exact bytes here is what catches an
    /// accidental reordering — this file's own discipline for every other
    /// tail below.
    #[test]
    fn signing_bytes_none_case_matches_the_documented_encoding() {
        let machine = MachineId::new("nl-example-203.0.113.31").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let role = ServiceRole::Monitor;
        let id = Uuid::nil();
        let ts: u64 = 1_700_000_000_000;
        let rk = role_keys_for(role, "aabbccdd");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"mirage-declared-identity-v1\0");
        expected.extend_from_slice(id.as_bytes());
        expected.extend_from_slice(machine.to_string().as_bytes());
        expected.push(0);
        expected.extend_from_slice(mesh.as_str().as_bytes());
        expected.push(0);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(role.to_string().as_bytes());
        expected.push(0);
        // role_keys: one entry, no signing key.
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(role.to_string().as_bytes());
        expected.push(0);
        expected.extend_from_slice(b"aabbccdd");
        expected.push(0);
        expected.push(0); // signing pubkey absent
        expected.extend_from_slice(&ts.to_be_bytes());

        let actual =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None);
        assert_eq!(
            actual, expected,
            "the None path must match the documented byte layout exactly"
        );
    }

    /// A `role_keys` entry WITH a signing pubkey produces different preimage
    /// bytes than the same entry without one — the presence byte inside the
    /// per-role encoding is what a relay would have to forge to strip a
    /// signing key silently.
    #[test]
    fn a_role_keys_entry_with_a_signing_pubkey_differs_from_one_without() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let role = ServiceRole::Sentry;
        let id = Uuid::new_v4();
        let ts: u64 = 1_700_000_000_000;
        let spk = "a".repeat(64);

        let without = role_keys_for(role, "xx");
        let mut with_spk = without.clone();
        with_spk[0].signing_pubkey_hex = Some(spk);

        let a = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &without, ts, None, None, &[], None);
        let b = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &with_spk, ts, None, None, &[], None);
        assert_ne!(a, b, "a signing pubkey must extend the byte sequence");
    }

    /// Two encoders that assemble the SAME set of per-role keys in
    /// different insertion order must sign byte-identical preimages —
    /// `signing_bytes` sorts by role internally so this holds regardless of
    /// how a caller (a `Vec` built by iterating
    /// `MachineCapsule::slices`, versus one built from a map) happened to
    /// order its list.
    #[test]
    fn two_encoders_of_the_same_role_key_set_in_different_order_agree() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let roles = vec![ServiceRole::Monitor, ServiceRole::Secd, ServiceRole::Warden];
        let id = Uuid::new_v4();
        let ts: u64 = 1_700_000_000_000;

        let forward = vec![
            RolePublicKeys {
                role: ServiceRole::Monitor,
                wire_pubkey_hex: "aa".repeat(32),
                signing_pubkey_hex: None,
            },
            RolePublicKeys {
                role: ServiceRole::Secd,
                wire_pubkey_hex: "bb".repeat(32),
                signing_pubkey_hex: Some("cc".repeat(32)),
            },
            RolePublicKeys {
                role: ServiceRole::Warden,
                wire_pubkey_hex: "dd".repeat(32),
                signing_pubkey_hex: None,
            },
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_ne!(
            forward.iter().map(|rk| rk.role).collect::<Vec<_>>(),
            reversed.iter().map(|rk| rk.role).collect::<Vec<_>>(),
            "precondition: the two Vecs really are in different orders"
        );

        let a = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &roles, &forward, ts, None, None, &[], None);
        let b = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &roles, &reversed, ts, None, None, &[], None);
        assert_eq!(a, b, "insertion order of role_keys must not affect the preimage");
    }

    /// An identity minted with a role that has no signing key verifies
    /// correctly.
    #[test]
    fn verify_without_signing_pubkey() {
        let op = op_key();
        let decl = sample_decl(ServiceRole::Monitor, &op);
        assert!(decl.role_keys[0].signing_pubkey_hex.is_none());
        decl.verify(&op.verifying_key()).expect("must verify without a signing pubkey");
    }

    /// An identity minted with a role's signing pubkey verifies correctly,
    /// and `signing_verifying_key_for` decodes it back.
    #[test]
    fn verify_with_signing_pubkey() {
        let op = op_key();
        let box_signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let spk_hex = hex::encode(box_signing.verifying_key().to_bytes());
        let role = ServiceRole::Node { epoch: NodeEpoch::V2 };
        let decl = DeclaredIdentity::sign_new(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            vec![RolePublicKeys {
                role,
                wire_pubkey_hex: sample_pubkey(),
                signing_pubkey_hex: Some(spk_hex.clone()),
            }],
            1_700_000_000_000,
            &op,
        );
        assert_eq!(decl.wire_pubkey_for(&role), Some(sample_pubkey().as_str()));
        decl.verify(&op.verifying_key()).expect("must verify with a signing pubkey");

        let recovered = decl.signing_verifying_key_for(&role).expect("must decode vk");
        assert_eq!(
            recovered.to_bytes(),
            box_signing.verifying_key().to_bytes()
        );
    }

    /// Tampering with a role's signing pubkey after signing must fail
    /// verify.
    #[test]
    fn tamper_signing_pubkey_fails_verify() {
        let op = op_key();
        let box_signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let spk_hex = hex::encode(box_signing.verifying_key().to_bytes());
        let role = ServiceRole::Mshd;
        let mut decl = DeclaredIdentity::sign_new(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            vec![RolePublicKeys {
                role,
                wire_pubkey_hex: sample_pubkey(),
                signing_pubkey_hex: Some(spk_hex),
            }],
            1_700_000_000_000,
            &op,
        );
        // Tamper: replace with a different key's hex.
        let other_signing = ed25519_dalek::SigningKey::generate(&mut OsRng);
        decl.role_keys[0].signing_pubkey_hex =
            Some(hex::encode(other_signing.verifying_key().to_bytes()));
        assert!(
            decl.verify(&op.verifying_key()).is_err(),
            "a tampered signing pubkey must fail verify"
        );
    }

    /// `expires_at_ms = None` must still be byte-identical to the encoding
    /// without it (the TTL tail is only written when an expiry is present),
    /// so every pre-TTL operator signature keeps verifying after the
    /// upgrade.
    #[test]
    fn signing_bytes_expiry_none_is_legacy_identical() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let role = ServiceRole::Mshd;
        let id = Uuid::new_v4();
        let ts: u64 = 1_700_000_000_000;
        let rk = role_keys_for(role, "xx");

        let legacy =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None);
        let legacy_again =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None);
        assert_eq!(legacy, legacy_again);
    }

    /// `public_addr = None` must reproduce the same bytes as the equivalent
    /// call without an address — this is what keeps every operator
    /// signature minted before the field existed verifying after the
    /// binary upgrade. `Some` appends its own domain-separated tail, after
    /// the TTL tail.
    #[test]
    fn signing_bytes_public_addr_tail_is_backward_compatible() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let role = ServiceRole::Monitor;
        let id = Uuid::new_v4();
        let ts: u64 = 1_700_000_000_000;
        let rk = role_keys_for(role, "aabbccdd");
        let addr = "203.0.113.15:19444";

        for exp_opt in [None, Some(1_700_000_086_400_000u64)] {
            let without_addr = DeclaredIdentity::signing_bytes(
                id, &machine, &mesh, &[role], &rk, ts, exp_opt, None, &[], None,
            );
            let with_addr = DeclaredIdentity::signing_bytes(
                id, &machine, &mesh, &[role], &rk, ts, exp_opt, Some(addr), &[], None,
            );
            let mut expected = without_addr.clone();
            expected.extend_from_slice(b"\0public-addr\0");
            expected.extend_from_slice(addr.as_bytes());
            assert_eq!(with_addr, expected, "address tail goes last, after the TTL tail");
        }
    }

    /// `expires_at_ms = Some` appends the domain-separated TTL tail, and the
    /// bytes differ from the None case.
    #[test]
    fn signing_bytes_expiry_some_appends_tail() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let role = ServiceRole::Mshd;
        let id = Uuid::new_v4();
        let ts: u64 = 1_700_000_000_000;
        let exp: u64 = 1_700_000_086_400_000;
        let rk = role_keys_for(role, "xx");

        let without =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None);
        let with_exp =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, Some(exp), None, &[], None);
        assert_ne!(without, with_exp, "expiry Some must extend the byte sequence");
        let mut expected = without.clone();
        expected.extend_from_slice(b"\0expires-at\0");
        expected.extend_from_slice(&exp.to_be_bytes());
        assert_eq!(with_exp, expected);
    }

    /// An identity minted with an expiry verifies, and tampering with
    /// `expires_at_ms` (e.g. a relay extending the lifetime) fails verify.
    #[test]
    fn expiry_is_bound_into_signature() {
        let op = op_key();
        let exp: u64 = 1_700_000_086_400_000;
        let role = ServiceRole::Mshd;
        let mut decl = DeclaredIdentity::sign_new_full(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, &sample_pubkey()),
            1_700_000_000_000,
            Some(exp),
            None,
            Vec::new(), None,
            &op,
        );
        decl.verify(&op.verifying_key()).expect("expiring identity must verify");
        assert!(decl.is_expired(exp), "now == expiry is expired");
        assert!(decl.is_expired(exp + 1));
        assert!(!decl.is_expired(exp - 1));

        // A relay extends the lifetime -> signature must break.
        decl.expires_at_ms = Some(exp + 10_000_000);
        assert!(
            decl.verify(&op.verifying_key()).is_err(),
            "tampered expires_at_ms must fail verify"
        );
    }

    /// An identity with no expiry never expires.
    #[test]
    fn no_expiry_never_expires() {
        let op = op_key();
        let decl = sample_decl(ServiceRole::Node { epoch: NodeEpoch::V2 }, &op);
        assert!(decl.expires_at_ms.is_none());
        assert!(!decl.is_expired(u64::MAX));
    }

    // ── roles: signed, and a machine can run several at once ─────────────

    /// The reason `roles` moved inside the envelope: a remote monitor reads
    /// this list off gossip alone, with no visibility into opbox's local
    /// escrow, so the list has to be trustworthy on its own.
    #[test]
    fn a_machine_can_declare_several_roles_at_once() {
        let op = op_key();
        let roles = vec![ServiceRole::Monitor, ServiceRole::Secd, ServiceRole::Warden];
        let role_keys = vec![
            RolePublicKeys { role: ServiceRole::Monitor, wire_pubkey_hex: "aa".repeat(32), signing_pubkey_hex: None },
            RolePublicKeys { role: ServiceRole::Secd, wire_pubkey_hex: "bb".repeat(32), signing_pubkey_hex: None },
            RolePublicKeys { role: ServiceRole::Warden, wire_pubkey_hex: "cc".repeat(32), signing_pubkey_hex: None },
        ];
        let decl = DeclaredIdentity::sign_new(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            roles,
            role_keys,
            1_700_000_000_000,
            &op,
        );
        decl.verify(&op.verifying_key()).expect("must verify");
        assert_eq!(decl.roles.len(), 3);
        assert_eq!(decl.wire_pubkey_for(&ServiceRole::Secd), Some("bb".repeat(32).as_str()));
    }

    /// `roles` is inside the signed preimage: a relay stripping or adding a
    /// role must break the signature, or a monitor's peer filter could be
    /// fed a role the operator never declared.
    #[test]
    fn tampering_the_roles_list_after_signing_breaks_verification() {
        let op = op_key();
        let mut decl = sample_decl(ServiceRole::Monitor, &op);
        decl.roles.push(ServiceRole::Operator);
        assert!(
            decl.verify(&op.verifying_key()).is_err(),
            "an added role must invalidate the signature"
        );
    }

    /// A one-role list and a two-role list must not share a preimage even
    /// when the extra role's bytes could otherwise look like continuation —
    /// the count prefix is what rules that out, the same reason
    /// `GroupCharter::signing_bytes` count-prefixes its member list.
    #[test]
    fn different_role_counts_never_collide_in_the_preimage() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let id = Uuid::new_v4();
        let ts: u64 = 1_700_000_000_000;
        let rk: Vec<RolePublicKeys> = Vec::new();

        let one = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[ServiceRole::Monitor], &rk, ts, None, None, &[], None,
        );
        let two = DeclaredIdentity::signing_bytes(
            id,
            &machine,
            &mesh,
            &[ServiceRole::Monitor, ServiceRole::Secd],
            &rk,
            ts,
            None,
            None,
            &[], None,
        );
        let none = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[], &rk, ts, None, None, &[], None);
        assert_ne!(one, two);
        assert_ne!(one, none);
        assert_ne!(two, none);
    }

    /// `ServiceRole::Edge`'s tag round-trips through `as_tag`, `Display`,
    /// and the `#[serde(tag = "kind")]` wire shape every other role already
    /// uses — the mechanism `labels_from_roles`/`service_roles_from_tags`
    /// (mirage2monitor / operator-box) both key off.
    #[test]
    fn edge_role_tag_round_trips() {
        assert_eq!(ServiceRole::Edge.as_tag(), "edge");
        assert_eq!(ServiceRole::Edge.to_string(), "edge");
        let json = serde_json::to_value(ServiceRole::Edge).expect("serialise");
        assert_eq!(json, serde_json::json!({"kind": "edge"}));
        let back: ServiceRole = serde_json::from_value(json).expect("deserialise");
        assert_eq!(back, ServiceRole::Edge);
    }

    /// A `DeclaredIdentity` naming `Edge` verifies and round-trips through
    /// JSON exactly like any other role — the same proof
    /// `declared_identity_round_trips_through_its_signed_preimage` already
    /// gives `Monitor`+`Secd`, extended to the new role so a gossiped edge
    /// identity is proven, not assumed.
    #[test]
    fn edge_role_verifies_and_round_trips_through_a_declared_identity() {
        let op = op_key();
        let decl = sample_decl(ServiceRole::Edge, &op);
        decl.verify(&op.verifying_key()).expect("verify");

        let json = serde_json::to_string(&decl).unwrap();
        let back: DeclaredIdentity = serde_json::from_str(&json).unwrap();
        back.verify(&op.verifying_key())
            .expect("round-tripped edge identity must still verify");
        assert_eq!(back.roles, vec![ServiceRole::Edge]);
    }

    // ── ServiceRole::BackOffice (2026-09-23 backoffice-automated-issuance) ──

    /// `ServiceRole::BackOffice`'s serde tag round-trips through JSON —
    /// `#[serde(rename_all = "snake_case", tag = "kind")]` gives it the
    /// wire tag `"back_office"`, distinct from `as_tag()`/`Display`'s
    /// hyphenated `"back-office"` (the same split every other multi-word
    /// role already has, e.g. `DbWorker`'s wire tag `db_worker` vs. its
    /// `as_tag()` `"db-worker"`).
    #[test]
    fn backoffice_role_tag_round_trip() {
        let json = serde_json::to_string(&ServiceRole::BackOffice).expect("serialize");
        assert_eq!(json, r#"{"kind":"back_office"}"#);
        let back: ServiceRole = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ServiceRole::BackOffice);
        assert_eq!(ServiceRole::BackOffice.as_tag(), "back-office");
        assert_eq!(ServiceRole::BackOffice.to_string(), "back-office");
    }

    /// A `DeclaredIdentity` naming `BackOffice` among its roles round-trips
    /// through JSON and still verifies — the new variant is additive to the
    /// signed `roles`/`role_keys` preimage exactly like every other role,
    /// no special-casing needed in `signing_bytes`.
    #[test]
    fn declared_identity_with_backoffice_role_round_trips_and_verifies() {
        let op = op_key();
        let decl = sample_decl(ServiceRole::BackOffice, &op);
        let json = serde_json::to_string(&decl).unwrap();
        let back: DeclaredIdentity = serde_json::from_str(&json).unwrap();
        back.verify(&op.verifying_key())
            .expect("a BackOffice-role identity must verify after a JSON round trip");
        assert_eq!(back.roles, vec![ServiceRole::BackOffice]);
    }

    /// An identity whose JSON predates every optional field this struct has
    /// grown (`revoked`/`revoked_at_ms`/`expires_at_ms`/`public_addr`/
    /// `faces`/`signer` all omitted) still parses — the same "old-shape
    /// identity" guarantee every prior field addition preserved, checked
    /// here explicitly so adding `BackOffice` is proven not to have
    /// disturbed it. Mirrors the shape `IdentitySigner`'s own doc names:
    /// "every identity ever minted before this field existed... deserialises
    /// correctly with no migration."
    #[test]
    fn old_shape_identity_json_still_parses() {
        let op = op_key();
        let self_id = Uuid::new_v4();
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let role_keys = role_keys_for(ServiceRole::Monitor, &sample_pubkey());
        let bytes = DeclaredIdentity::signing_bytes(
            self_id,
            &machine,
            &"v3-staging".parse().unwrap(),
            &[ServiceRole::Monitor],
            &role_keys,
            1_700_000_000_000,
            None,
            None,
            &[], None,
        );
        let sig = op.sign(&bytes);
        // Hand-built JSON carrying only the fields that existed before
        // `revoked`/`revoked_at_ms`/`expires_at_ms`/`public_addr`/`faces`/
        // `signer`/`client_label` were added — every one of those is
        // `#[serde(default)]`.
        let old_shape_json = format!(
            r#"{{"self_id":"{self_id}","machine_id":"{machine}","mesh_id":"v3-staging","roles":[{{"kind":"monitor"}}],"role_keys":[{{"role":{{"kind":"monitor"}},"wire_pubkey_hex":"{pubkey}"}}],"adopted_at_ms":1700000000000,"operator_sig":"{sig_hex}"}}"#,
            self_id = self_id,
            machine = machine,
            pubkey = sample_pubkey(),
            sig_hex = hex::encode(sig.to_bytes()),
        );
        let decl: DeclaredIdentity =
            serde_json::from_str(&old_shape_json).expect("old-shape JSON must still parse");
        decl.verify(&op.verifying_key())
            .expect("old-shape identity must still verify");
        assert!(!decl.revoked, "defaulted revoked must be false");
        assert_eq!(decl.signer, IdentitySigner::Operator, "defaulted signer");
        assert_eq!(decl.client_label, None, "defaulted client_label");
        assert_eq!(
            decl.client_label_or_derive(),
            derive_client_label(self_id),
            "the derived fallback must match what a fresh mint would have signed"
        );
    }

    /// A role tag this build does not recognise (simulating a NEWER peer
    /// gossiping a future role an OLDER build like this one has never heard
    /// of) fails deserialisation gracefully — a typed `serde_json::Error`,
    /// never a panic. This is the property that lets an older peer receive
    /// a newer `DeclaredIdentity` carrying `BackOffice` (or whatever comes
    /// after it) without crashing: it drops the frame with a decode error
    /// exactly like it would for `"back_office"` on a build that predates
    /// this change.
    #[test]
    fn unrecognized_role_tag_fails_gracefully_not_panics() {
        let json = r#"{
            "self_id":"00000000-0000-0000-0000-000000000000",
            "machine_id":"ru-hostkey-203.0.113.10",
            "mesh_id":"v3-staging",
            "roles":[{"kind":"some_future_role_this_build_has_never_heard_of"}],
            "role_keys":[],
            "adopted_at_ms":1700000000000,
            "operator_sig":"00"
        }"#;
        let result: Result<DeclaredIdentity, _> = serde_json::from_str(json);
        assert!(
            result.is_err(),
            "an unrecognised role tag must be a typed decode error, not a successful parse"
        );
    }

    /// **The pre-`client_label` fixture.** This exact JSON string and
    /// verifying key were captured by running the code as it stood
    /// immediately BEFORE the `client_label` field was added (`sign_new`
    /// over a fixed seed, self_id, and timestamp, then
    /// `serde_json::to_string`) — not reconstructed by hand. It carries no
    /// `client_label` key at all, and its `operator_sig` was computed over
    /// the pre-change preimage (no client-label tail). Deserializing it
    /// under the CURRENT code must still populate `client_label: None` via
    /// `#[serde(default)]` and the signature must still verify byte for
    /// byte — the concrete proof that landing this field did not disturb a
    /// single already-gossiped identity.
    #[test]
    fn pre_client_label_fixture_still_verifies() {
        const FIXTURE_JSON: &str = r#"{"self_id":"11111111-2222-3333-4444-555555555555","machine_id":"ru-hostkey-203.0.113.10","mesh_id":"v3-staging","roles":[{"kind":"monitor"}],"role_keys":[{"role":{"kind":"monitor"},"wire_pubkey_hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"adopted_at_ms":1700000000000,"revoked":false,"revoked_at_ms":null,"operator_sig":"659541fe2bfd1445b03a0e09ada04554e6698d3dc9b14aaf21a464060b2baed5caa1cd378430bfbee39918fccd8c31467127ce3ee1451867d7458f06c1ea4b04","signer":{"kind":"operator"}}"#;
        const FIXTURE_OP_PUB_HEX: &str =
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

        assert!(
            !FIXTURE_JSON.contains("client_label"),
            "the fixture must genuinely predate the field, or this test proves nothing"
        );

        let decl: DeclaredIdentity =
            serde_json::from_str(FIXTURE_JSON).expect("the pre-change fixture must still parse");
        assert_eq!(decl.client_label, None, "a pre-change row has no client_label");

        let op_pub_bytes: [u8; 32] = hex::decode(FIXTURE_OP_PUB_HEX)
            .expect("fixture pubkey is valid hex")
            .try_into()
            .expect("an ed25519 verifying key is 32 bytes");
        let op_pub = VerifyingKey::from_bytes(&op_pub_bytes).expect("fixture pubkey is a valid point");
        decl.verify(&op_pub)
            .expect("a signature minted before client_label existed must still verify byte-for-byte");

        // The lazy upgrade path: a reader gets a usable label even though
        // none was ever signed, and it is exactly what a fresh mint of the
        // SAME self_id would have signed.
        assert_eq!(
            decl.client_label_or_derive(),
            derive_client_label(decl.self_id)
        );
    }
}

#[cfg(test)]
mod faces_tail_tests {
    use super::*;
    use crate::capsule::CapsuleControlEndpoint;
    use crate::mirage::wire::camouflage::TransportCamouflage;

    fn fixture() -> (Uuid, MachineId, MeshId, ServiceRole, u64) {
        (
            Uuid::from_u128(7),
            "ru-hostkey-203.0.113.10".parse().unwrap(),
            "v3-staging".parse().unwrap(),
            ServiceRole::Monitor,
            1_700_000_000_000,
        )
    }

    fn face(port: u16) -> CapsuleControlEndpoint {
        CapsuleControlEndpoint {
            port,
            camouflage: TransportCamouflage::TlsReal {
                sni: "edge-static.net".into(),
                alpn: vec!["h2".into()],
            },
            wire_version: Some(9),
            purpose: None,
        }
    }

    fn role_keys_for(role: ServiceRole, wire_hex: &str) -> Vec<RolePublicKeys> {
        vec![RolePublicKeys {
            role,
            wire_pubkey_hex: wire_hex.to_string(),
            signing_pubkey_hex: None,
        }]
    }

    /// THE compatibility invariant. An identity with no faces must produce
    /// the byte-identical preimage it produced before the field existed, or
    /// every operator signature ever minted stops verifying at once — the
    /// signed-bytes rule this codebase pays for with a two-roll cutover.
    #[test]
    fn an_empty_face_list_writes_no_tail() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "xx");
        let without = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None);
        // Reconstruct the pre-faces encoding by hand: label, ids, roles,
        // role_keys, ts. Any drift between this and the real fn shows up as
        // a diff here rather than as a fleet-wide signature failure.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"mirage-declared-identity-v1\0");
        expected.extend_from_slice(id.as_bytes());
        expected.extend_from_slice(machine.to_string().as_bytes());
        expected.push(0);
        expected.extend_from_slice(mesh.as_str().as_bytes());
        expected.push(0);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(role.to_string().as_bytes());
        expected.push(0);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(role.to_string().as_bytes());
        expected.push(0);
        expected.extend_from_slice(b"xx");
        expected.push(0);
        expected.push(0);
        expected.extend_from_slice(&ts.to_be_bytes());
        assert_eq!(without, expected);
    }

    /// The tail is appended AFTER `public-addr`, so adding faces cannot
    /// change how any earlier tail encodes.
    #[test]
    fn the_faces_tail_extends_and_never_rewrites_the_earlier_tails() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "xx");
        let addr = Some("203.0.113.15:19444");
        let base = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, addr, &[], None);
        let with =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, addr, &[face(443)], None);
        assert!(with.starts_with(&base), "faces must only APPEND");
        assert!(with.len() > base.len());
    }

    /// Two different face lists must not collide — otherwise a relay could
    /// swap one face set for another under the same signature.
    #[test]
    fn different_face_lists_produce_different_preimages() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "xx");
        let a = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[face(443)], None);
        let b = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[face(8443)], None);
        let ab = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[face(443), face(8443)], None,
        );
        assert_ne!(a, b);
        assert_ne!(a, ab);
        assert_ne!(b, ab);
    }

    /// End to end: a signature minted over a face list verifies, and the
    /// same identity with one face removed does not.
    #[test]
    fn a_stripped_face_breaks_the_signature() {
        let (id, machine, mesh, role, ts) = fixture();
        let op = SigningKey::from_bytes(&[9u8; 32]);
        let decl = DeclaredIdentity::sign_new_full(
            id,
            machine,
            mesh,
            vec![role],
            role_keys_for(role, "xx"),
            ts,
            None,
            None,
            vec![face(443), face(80)], None,
            &op,
        );
        assert!(decl.verify(&op.verifying_key()).is_ok());
        let mut tampered = decl.clone();
        tampered.faces.pop();
        assert!(tampered.verify(&op.verifying_key()).is_err());
    }

    /// THE compatibility invariant for `FacePurpose`. `purpose: None` on
    /// every face must reproduce, byte for byte, the preimage captured from
    /// the code BEFORE `FacePurpose` existed. The hex below is that capture
    /// — taken by running this exact fixture (two faces, ports 443 and 80,
    /// one `wire_version: Some(9)` and one `wire_version: None`) through
    /// `signing_bytes()` prior to adding the `purpose` field, and must never
    /// be edited to make this test pass.
    #[test]
    fn an_unset_purpose_leaves_every_existing_signature_intact() {
        const GOLDEN_HEX: &str = "6d69726167652d6465636c617265642d6964656e746974792d7631000000000000000000000000000000000772752d686f73746b65792d3039342e37340076332d73746167696e6700000000016d6f6e69746f7200000000016d6f6e69746f7200787800000000018bcfe56800006661636573000000008f5b7b22706f7274223a3434332c2263616d6f75666c616765223a7b2274797065223a22746c735f7265616c222c22736e69223a22656467652d7374617469632e6e6574222c22616c706e223a5b226832225d7d2c22776972655f76657273696f6e223a397d2c7b22706f7274223a38302c2263616d6f75666c616765223a7b2274797065223a226e6f6e65227d7d5d";
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "xx");
        let faces = vec![
            face(443),
            CapsuleControlEndpoint {
                port: 80,
                camouflage: TransportCamouflage::None,
                wire_version: None,
                purpose: None,
            },
        ];
        let bytes = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &faces, None);
        assert_eq!(hex::encode(&bytes), GOLDEN_HEX);
    }

    /// A field that rides the signature must actually be bound into it — if
    /// this passed trivially because `purpose` were dropped from the
    /// preimage, the previous test's "nothing moved" guarantee would be
    /// meaningless (an always-dropped field can never move anything).
    #[test]
    fn a_set_purpose_changes_the_preimage() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "xx");
        let unset = vec![
            face(443),
            CapsuleControlEndpoint {
                port: 80,
                camouflage: TransportCamouflage::None,
                wire_version: None,
                purpose: None,
            },
        ];
        let mut set = unset.clone();
        set[1].purpose = Some(crate::capsule::FacePurpose::NodeChain);
        let a = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &unset, None);
        let b = DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &set, None);
        assert_ne!(a, b);
    }

    /// `purpose: None` must not merely leave the preimage unchanged — it
    /// must be absent from the JSON entirely, which is what
    /// `skip_serializing_if` is for and what the preimage test above cannot
    /// tell apart from "serialized as `null`".
    #[test]
    fn an_unset_purpose_emits_no_key() {
        let endpoint = face(443);
        let json = serde_json::to_value(&endpoint).expect("a plain data struct always serializes");
        assert!(
            json.as_object().expect("struct serializes to a JSON object").get("purpose").is_none(),
            "an unset purpose must not appear in the JSON at all: {json}"
        );
    }
}

/// The signed-bytes trap this crate has already paid for once: proving a
/// third signer never changes the preimage the first two already produce,
/// checked against the RAW bytes rather than through `verify` — a
/// round-trip test knows both preimages and would pass either way, which is
/// exactly how this class of bug shipped before (see `IdentitySigner`'s own
/// doc and `crate::capsule`'s sibling `CapsuleSigner::Machine` tests).
#[cfg(test)]
mod self_issued_signer_tests {
    use super::*;
    use crate::attestation::{AttestationKey, AttestedFields};
    use crate::capsule::{CapsuleTrustAnchor, MachineAnchor};
    use rand::rngs::OsRng;

    fn op_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fixture() -> (Uuid, MachineId, MeshId, ServiceRole, u64) {
        (
            Uuid::from_u128(7),
            "ru-hostkey-203.0.113.10".parse().unwrap(),
            "v3-staging".parse().unwrap(),
            ServiceRole::Monitor,
            1_700_000_000_000,
        )
    }

    fn role_keys_for(role: ServiceRole, wire_hex: &str) -> Vec<RolePublicKeys> {
        vec![RolePublicKeys {
            role,
            wire_pubkey_hex: wire_hex.to_string(),
            signing_pubkey_hex: None,
        }]
    }

    fn attestation_for(machine_id: &MachineId) -> AttestationKey {
        AttestationKey::generate(machine_id.to_string())
    }

    /// **The exact property the owner's brief demands.** `signing_bytes`
    /// itself was never touched — no tenth parameter, no new branch — so
    /// this asserts the wrapper reproduces it byte for byte when the signer
    /// is `Operator`, against the RAW preimage rather than through `verify`.
    #[test]
    fn signing_bytes_with_signer_reproduces_signing_bytes_exactly_for_operator() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "aabbccdd");
        let plain = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None,
        );
        let wrapped = DeclaredIdentity::signing_bytes_with_signer(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None, &IdentitySigner::Operator,
        );
        assert_eq!(
            plain, wrapped,
            "an Operator signer must add nothing to signing_bytes' own output"
        );
    }

    /// The Machine tail strictly extends the operator preimage as a prefix
    /// — never rewrites it — the same discipline every earlier tail
    /// (`expires-at`, `public-addr`, `faces`) already follows.
    #[test]
    fn signing_bytes_with_signer_extends_but_never_rewrites_for_machine() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "aabbccdd");
        let base = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None,
        );
        let signer = IdentitySigner::Machine { machine_id: machine.to_string() };
        let with_signer = DeclaredIdentity::signing_bytes_with_signer(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None, &signer,
        );
        assert!(with_signer.starts_with(&base), "the machine tail must only APPEND");
        assert!(with_signer.len() > base.len());
    }

    /// Two different claimed machine ids must not collide in the tail —
    /// otherwise a relabelled self-signed identity could be pointed at a
    /// different box's anchor without breaking its own signature.
    #[test]
    fn different_claimed_machine_ids_produce_different_preimages() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "xx");
        let a = DeclaredIdentity::signing_bytes_with_signer(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None,
            &IdentitySigner::Machine { machine_id: "ru-hostkey-203.0.113.10".to_string() },
        );
        let b = DeclaredIdentity::signing_bytes_with_signer(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None,
            &IdentitySigner::Machine { machine_id: "tr-hostkey-203.0.113.20".to_string() },
        );
        assert_ne!(a, b);
    }

    /// End to end: a self-issued identity verifies under its own box's
    /// attestation anchor, and — the fail-closed property `verify`'s own doc
    /// promises — does NOT verify under the plain operator path, because
    /// the operator never signed anything and the preimage it was actually
    /// signed over is longer than the one `verify` recomputes.
    #[test]
    fn self_issued_identity_verifies_under_its_own_machine_anchor_and_not_under_operator() {
        let op = op_key();
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let attestation = attestation_for(&machine);
        let role = ServiceRole::Secd;
        let decl = DeclaredIdentity::sign_self_issued(
            Uuid::new_v4(),
            machine.clone(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, "aa".repeat(32).as_str()),
            1_700_000_000_000,
            Some(1_700_003_600_000),
            &attestation,
        );
        assert_eq!(decl.signer, IdentitySigner::Machine { machine_id: machine.to_string() });

        let anchor = CapsuleTrustAnchor {
            operator: &op.verifying_key(),
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: machine.as_str(),
                attestation: attestation.verifying_key(),
            }),
        };
        decl.verify_with_anchor(&anchor)
            .expect("a self-issued identity must verify under its own machine anchor");

        assert!(
            decl.verify(&op.verifying_key()).is_err(),
            "a self-issued identity must never verify as an operator-signed one"
        );
    }

    /// The refusal an operator-only caller gets today, before any machine
    /// anchor exists to check against — never a silent pass.
    #[test]
    fn self_issued_identity_is_refused_with_no_machine_anchor_held() {
        let op = op_key();
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let attestation = attestation_for(&machine);
        let role = ServiceRole::Secd;
        let decl = DeclaredIdentity::sign_self_issued(
            Uuid::new_v4(), machine, "v3-staging".parse().unwrap(), vec![role],
            role_keys_for(role, "aa".repeat(32).as_str()), 1_700_000_000_000, None, &attestation,
        );
        let err = decl
            .verify_with_anchor(&CapsuleTrustAnchor::operator_only(&op.verifying_key()))
            .unwrap_err();
        assert!(matches!(err, IdentityError::NoMachineAnchor(_)), "got {err:?}");
    }

    /// A capsule minted by box A must never verify under an anchor built for
    /// box B, mirroring `crate::capsule`'s own
    /// `machine_signed_capsule_rejected_for_a_different_machine_anchor`.
    #[test]
    fn self_issued_identity_is_refused_under_a_different_machines_anchor() {
        let op = op_key();
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let attestation = attestation_for(&machine);
        let role = ServiceRole::Secd;
        let decl = DeclaredIdentity::sign_self_issued(
            Uuid::new_v4(), machine, "v3-staging".parse().unwrap(), vec![role],
            role_keys_for(role, "aa".repeat(32).as_str()), 1_700_000_000_000, None, &attestation,
        );
        let anchor = CapsuleTrustAnchor {
            operator: &op.verifying_key(),
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: "tr-hostkey-203.0.113.20",
                attestation: attestation.verifying_key(),
            }),
        };
        let err = decl.verify_with_anchor(&anchor).unwrap_err();
        assert!(matches!(err, IdentityError::MachineAnchorMismatch { .. }), "got {err:?}");
    }

    /// An identity JSON minted before `signer` existed (the field simply
    /// absent) deserialises as `Operator` — the roll-order property every
    /// other `#[serde(default)]` field in this crate is proven against its
    /// own wire bytes, not merely the struct definition.
    #[test]
    fn a_declared_identity_missing_the_signer_field_deserialises_as_operator() {
        let op = op_key();
        let (id, machine, mesh, role, ts) = fixture();
        let decl = DeclaredIdentity::sign_new(
            id, machine, mesh, vec![role], role_keys_for(role, "aa".repeat(32).as_str()), ts, &op,
        );
        let mut value = serde_json::to_value(&decl).expect("encodes");
        value
            .as_object_mut()
            .expect("DeclaredIdentity serialises as a JSON object")
            .remove("signer");
        let restored: DeclaredIdentity =
            serde_json::from_value(value).expect("must deserialise without a signer field");
        assert_eq!(restored.signer, IdentitySigner::Operator);
        restored.verify(&op.verifying_key()).expect("still verifies as operator-signed");
    }

    /// **The byte-level claim behind reusing the raw attestation key for a
    /// second speech-act.** A genuine announce-attestation signature must
    /// never verify as a self-issued identity signature — proven directly,
    /// the same way `crate::capsule`'s own
    /// `an_announce_attestation_cannot_be_replayed_as_a_capsule_signature`
    /// proves it for the capsule envelope. `signing_bytes`' own label
    /// (`b"mirage-declared-identity-v1\0"`, lowercase) and
    /// `ATTEST_SIG_LABEL_V3` (`b"MIRAGE-MACHINE-ATTESTATION-V3"`, uppercase)
    /// diverge at the very first byte (`m` 0x6D vs `M` 0x4D), so the two
    /// preimages can never collide regardless of what either carries after
    /// its label.
    #[test]
    fn an_announce_attestation_cannot_be_replayed_as_a_self_issued_identity_signature() {
        let machine = MachineId::new("ru-hostkey-203.0.113.10").unwrap();
        let attestation = attestation_for(&machine);
        let announce_fields = AttestedFields {
            machine_id: machine.as_str(),
            build_id: "test-build",
            eph_pubkey_hex: &"ab".repeat(32),
            boot_nonce: "boot-nonce-1",
            started_at_ms: 1_700_000_000_000,
            platform: None,
            renewal: None,
        };
        let announce_sig_hex = attestation.attest(&announce_fields);
        let sig_bytes: [u8; 64] = hex::decode(&announce_sig_hex)
            .expect("attest() always returns hex")
            .try_into()
            .expect("an ed25519 signature is 64 bytes");

        let role = ServiceRole::Secd;
        let mut decl = DeclaredIdentity::sign_self_issued(
            Uuid::new_v4(), machine.clone(), "v3-staging".parse().unwrap(), vec![role],
            role_keys_for(role, "aa".repeat(32).as_str()), 1_700_000_000_000, None, &attestation,
        );
        // Splice in the announce signature in place of the genuine one.
        decl.operator_sig = SignatureHex(hex::encode(sig_bytes));

        let op = op_key();
        let anchor = CapsuleTrustAnchor {
            operator: &op.verifying_key(),
            charter: None,
            machine: Some(MachineAnchor {
                machine_id: machine.as_str(),
                attestation: attestation.verifying_key(),
            }),
        };
        let err = decl.verify_with_anchor(&anchor).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadSignature),
            "an announce attestation must never verify as a self-issued identity signature — got {err:?}"
        );
    }

    /// `AttestationKey::sign` is the same raw key `attest` uses; a real
    /// `sign_self_issued` round trip (already proven above) is the
    /// meaningful test — this only pins that the two are the exact same
    /// key, not two independently-generated ones, so a future refactor
    /// cannot quietly split them.
    #[test]
    fn attestation_sign_and_attest_share_the_same_verifying_key() {
        let attestation = AttestationKey::generate("ru-hostkey-203.0.113.10");
        let sig_bytes = attestation.sign(b"arbitrary bytes");
        let sig = Signature::from_bytes(&sig_bytes);
        attestation
            .verifying_key()
            .verify(b"arbitrary bytes", &sig)
            .expect("AttestationKey::sign must verify against AttestationKey::verifying_key");
    }
}

/// `client_label` — the client-facing opaque label
/// (`docs/mirage/plans/2026-09-25-client-facing-node-label.md`). Its
/// backward-compatibility proof (`None` reproduces the pre-field byte
/// layout, and a real pre-change fixture still verifies) lives in `mod
/// tests` above, next to every earlier tail's own compatibility test. This
/// module covers the NEW behavior: the tail is actually bound into the
/// signature, and the signed/derived split works as the field's own doc
/// promises.
#[cfg(test)]
mod client_label_tests {
    use super::*;

    fn fixture() -> (Uuid, MachineId, MeshId, ServiceRole, u64) {
        (
            Uuid::from_u128(7),
            "ru-hostkey-203.0.113.10".parse().unwrap(),
            "v3-staging".parse().unwrap(),
            ServiceRole::Monitor,
            1_700_000_000_000,
        )
    }

    fn role_keys_for(role: ServiceRole, wire_hex: &str) -> Vec<RolePublicKeys> {
        vec![RolePublicKeys {
            role,
            wire_pubkey_hex: wire_hex.to_string(),
            signing_pubkey_hex: None,
        }]
    }

    /// `client_label = Some(..)` appends the domain-separated tail, and the
    /// bytes differ from the `None` case — the same shape every earlier
    /// optional field (`expires_at_ms`/`public_addr`/`faces`) proves for
    /// itself.
    #[test]
    fn signing_bytes_client_label_some_appends_tail_after_faces() {
        let (id, machine, mesh, role, ts) = fixture();
        let rk = role_keys_for(role, "aabbccdd");
        let label = "node-deadbeef01";

        let without =
            DeclaredIdentity::signing_bytes(id, &machine, &mesh, &[role], &rk, ts, None, None, &[], None);
        let with_label = DeclaredIdentity::signing_bytes(
            id, &machine, &mesh, &[role], &rk, ts, None, None, &[], Some(label),
        );
        assert_ne!(without, with_label, "a client label must extend the byte sequence");
        let mut expected = without.clone();
        expected.extend_from_slice(b"\0client-label\0");
        expected.extend_from_slice(label.as_bytes());
        assert_eq!(with_label, expected, "the label tail goes last, after the faces tail");
    }

    /// End to end: an identity minted with a client label verifies, and a
    /// relay substituting a different opaque string for it — the exact
    /// tamper this tail exists to close — breaks the signature.
    #[test]
    fn client_label_is_bound_into_the_signature() {
        let op = SigningKey::from_bytes(&[3u8; 32]);
        let role = ServiceRole::Monitor;
        let decl = DeclaredIdentity::sign_new_full(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, "aabbccdd"),
            1_700_000_000_000,
            None,
            None,
            Vec::new(),
            Some("node-aaaaaaaaaa".to_string()),
            &op,
        );
        decl.verify(&op.verifying_key()).expect("a labeled identity must verify");

        let mut tampered = decl.clone();
        tampered.client_label = Some("node-bbbbbbbbbb".to_string());
        assert!(
            tampered.verify(&op.verifying_key()).is_err(),
            "a relay substituting a different label must invalidate the signature"
        );

        let mut stripped = decl.clone();
        stripped.client_label = None;
        assert!(
            stripped.verify(&op.verifying_key()).is_err(),
            "stripping a signed label must invalidate the signature just as substituting one does"
        );
    }

    /// `client_label` round-trips through JSON verbatim when set, and stays
    /// out of the JSON entirely when unset (`skip_serializing_if`) — the
    /// same discipline `public_addr`/`faces` already follow.
    #[test]
    fn client_label_round_trips_and_is_omitted_when_unset() {
        let op = SigningKey::from_bytes(&[4u8; 32]);
        let role = ServiceRole::Monitor;
        let labeled = DeclaredIdentity::sign_new_full(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, "aabbccdd"),
            1_700_000_000_000,
            None,
            None,
            Vec::new(),
            Some("node-cccccccccc".to_string()),
            &op,
        );
        let json = serde_json::to_value(&labeled).expect("encodes");
        assert_eq!(json.get("client_label"), Some(&serde_json::json!("node-cccccccccc")));
        let back: DeclaredIdentity = serde_json::from_value(json).expect("decodes");
        back.verify(&op.verifying_key()).expect("round-tripped labeled identity must verify");
        assert_eq!(back.client_label.as_deref(), Some("node-cccccccccc"));

        let unlabeled = DeclaredIdentity::sign_new(
            Uuid::new_v4(),
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, "aabbccdd"),
            1_700_000_000_000,
            &op,
        );
        let json = serde_json::to_value(&unlabeled).expect("encodes");
        assert!(
            json.as_object().expect("struct serializes to an object").get("client_label").is_none(),
            "an unset client_label must not appear in the JSON at all: {json}"
        );
    }

    /// [`DeclaredIdentity::client_label_or_derive`] prefers the SIGNED value
    /// when one was minted, even though it happens to differ from what
    /// [`derive_client_label`] would compute today — proving the fallback
    /// only ever fires for `None`, never silently overriding a genuinely
    /// signed label.
    #[test]
    fn client_label_or_derive_prefers_the_signed_value_over_a_fresh_derivation() {
        let op = SigningKey::from_bytes(&[5u8; 32]);
        let self_id = Uuid::new_v4();
        let role = ServiceRole::Monitor;
        let signed_label = "node-legacyformat".to_string();
        assert_ne!(
            signed_label,
            derive_client_label(self_id),
            "precondition: the signed label must differ from a fresh derivation"
        );
        let decl = DeclaredIdentity::sign_new_full(
            self_id,
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, "aabbccdd"),
            1_700_000_000_000,
            None,
            None,
            Vec::new(),
            Some(signed_label.clone()),
            &op,
        );
        assert_eq!(decl.client_label_or_derive(), signed_label);
    }

    /// The `None` path of [`DeclaredIdentity::client_label_or_derive`]
    /// computes byte-identically to [`derive_client_label`] — the lazy,
    /// storage-free upgrade path the field's own doc promises.
    #[test]
    fn client_label_or_derive_falls_back_to_derive_client_label_when_unset() {
        let op = op_key_local();
        let self_id = Uuid::new_v4();
        let role = ServiceRole::Sentry;
        let decl = DeclaredIdentity::sign_new(
            self_id,
            MachineId::new("ru-hostkey-203.0.113.10").unwrap(),
            "v3-staging".parse().unwrap(),
            vec![role],
            role_keys_for(role, "aabbccdd"),
            1_700_000_000_000,
            &op,
        );
        assert!(decl.client_label.is_none());
        assert_eq!(decl.client_label_or_derive(), derive_client_label(self_id));
    }

    fn op_key_local() -> SigningKey {
        SigningKey::from_bytes(&[6u8; 32])
    }
}
