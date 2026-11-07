//! Anonymous-credential crypto primitives for data-plane untrusted-peer authz.
//!
//! Two arms:
//! - [`epoch_hmac`] — light arm (~1-3µs). Verifier-unlinkable, issuer-linkable.
//!   Deployable today. Symmetric: epoch secret used for both issue and verify.
//! - [`signed_capability`] — asymmetric arm. Issuer (opbox) holds the Ed25519
//!   signing key; nodes hold only the verifying key. An untrusted node
//!   cannot mint credentials. See module docs for the full trust model.
//!
//! Node-held state: [`CredentialParams`] carries the epoch secrets (gossip-delivered).
//! [`SpentSet`] tracks used credential ids per epoch to reject replays.

pub mod epoch_hmac;
pub mod role_signed;
pub mod signed_capability;
pub mod subscriber_set;

use std::collections::{HashMap, HashSet};
use std::sync::mpsc;

use serde::{Deserialize, Serialize};

use crate::error::{MirageError, Result};
use crate::mirage::wire::CredentialScheme;

use epoch_hmac::{verify_epoch_hmac, EpochHmacKey};
use signed_capability::{verify_signed_capability, CapabilityVerifyKey};

// ── CredentialId ─────────────────────────────────────────────────────────────

/// A fixed-size, Copy key used for spent-set dedup.
///
/// For EpochHmac: left-padded 16-byte nonce (bytes 16..32 = nonce).
/// For SignedCapability: the 32-byte `nonce` field of the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialId([u8; 32]);

impl CredentialId {
    /// Construct from a 16-byte EpochHmac nonce (zero-pads the upper 16 bytes).
    pub fn from_hmac_nonce(nonce: &[u8; 16]) -> Self {
        let mut id = [0u8; 32];
        id[16..32].copy_from_slice(nonce);
        Self(id)
    }

    /// Construct directly from a 32-byte value (SignedCapability nonce).
    pub fn from_bytes32(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<signed_capability::CapabilityToken> for CredentialId {
    fn from(t: signed_capability::CapabilityToken) -> Self {
        Self::from_bytes32(t.nonce)
    }
}

// ── AuthorityId ───────────────────────────────────────────────────────────────

/// Stable identifier for one credential-issuing authority within a mesh's trust set.
/// `0` = the mesh's primary operator. Additional roots (admin, ring) get distinct ids.
/// Numeric + Copy so it binds deterministically into the signing preimage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct AuthorityId(pub u32);

// ── Authority ─────────────────────────────────────────────────────────────────

/// One root of trust in a mesh's credential configuration.
///
/// A node accepts a presented token if it verifies under ANY authority whose
/// `scheme` matches the wire scheme byte. An authority holds only PUBLIC verify
/// material (per-epoch verifying key / HMAC secret / future ring root) — never a
/// minting key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Authority {
    #[serde(default)]
    pub authority_id: AuthorityId,
    #[serde(default)]
    pub scheme: CredentialScheme,
    #[serde(default)]
    pub epochs: Vec<EpochEntry>,
}

impl Authority {
    pub fn new(authority_id: AuthorityId, scheme: CredentialScheme, epochs: Vec<EpochEntry>) -> Self {
        Self { authority_id, scheme, epochs }
    }
}

// ── CredentialParams ──────────────────────────────────────────────────────────

/// Node-held credential configuration, gossip-delivered by the operator.
///
/// Serialisable so it can ride the gossip substrate. Add new fields as
/// `Option` / `#[serde(default)]` for forward-compat.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialParams {
    /// Monotonic generation counter. Nodes discard stale gossip with lower generation.
    #[serde(default)]
    pub generation: u64,
    /// Trust set: a presented token is accepted if it verifies under ANY authority
    /// whose `scheme` matches the wire scheme byte. A single-element vec reproduces
    /// the prior single-scheme behavior (backward-compatible).
    #[serde(default)]
    pub authorities: Vec<Authority>,
    /// Operator Ed25519 signature over the security-relevant fields (generation,
    /// the whole authority set incl. every epoch). Modification of generation is
    /// rejected at the node before apply. `#[serde(default)]` = forward-compat:
    /// old peers omit it, new nodes verify it.
    #[serde(default)]
    pub operator_sig: Option<crate::identity::SignatureHex>,
}

impl CredentialParams {
    /// Single-authority constructor (the common operated-mesh case; mirrors the
    /// prior single-scheme shape). `operator_sig` is left `None` — call `sign`.
    ///
    /// Credential enforcement is unconditional (no `require` toggle — see the
    /// arc3 mandatory-credentials excision): a mesh with any `CredentialParams`
    /// configured always rejects uncredentialed (scheme=0x00) dials at the exit.
    pub fn single(generation: u64, scheme: CredentialScheme, epochs: Vec<EpochEntry>) -> Self {
        Self {
            generation,
            authorities: vec![Authority::new(AuthorityId(0), scheme, epochs)],
            operator_sig: None,
        }
    }

    /// The primary authority's scheme (first in the set), or the default when empty.
    /// For logging / single-authority back-compat reads.
    pub fn primary_scheme(&self) -> CredentialScheme {
        self.authorities.first().map(|a| a.scheme).unwrap_or_default()
    }

    /// Total epoch count across all authorities (for logging / metrics).
    pub fn total_epochs(&self) -> usize {
        self.authorities.iter().map(|a| a.epochs.len()).sum()
    }

    /// Canonical signing preimage. EXCLUDES `operator_sig`. Binds every
    /// security-relevant field incl. epoch secrets and epoch public verify material
    /// (prevents both secret-substitution and pubkey-substitution).
    ///
    /// Label bumped v3→v4 (arc3 mandatory-credentials excision) — the `require`
    /// byte is REMOVED from the preimage: credential enforcement is now
    /// unconditional, so there is no toggle left to sign over. All
    /// signers/verifiers rebuild together (no mixed-version fleet; this is a
    /// deliberate signed-bytes/wire break, not additive).
    pub fn credential_signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"mirage-credential-params-v4\0");
        buf.extend_from_slice(&self.generation.to_be_bytes()); // 8B BE
        buf.extend_from_slice(&(self.authorities.len() as u32).to_be_bytes()); // 4B BE
        for a in &self.authorities {
            buf.extend_from_slice(&a.authority_id.0.to_be_bytes()); // 4B BE
            buf.push(a.scheme as u8);                                // 1B
            buf.extend_from_slice(&(a.epochs.len() as u32).to_be_bytes()); // 4B BE
            for e in &a.epochs {
                buf.extend_from_slice(&e.epoch_id.to_be_bytes());     // 4B BE
                buf.extend_from_slice(&e.not_after_ms.to_be_bytes()); // 8B BE
                buf.extend_from_slice(&e.secret);                     // 32B
                buf.extend_from_slice(&(e.verify_material.len() as u32).to_be_bytes()); // 4B BE len
                buf.extend_from_slice(&e.verify_material);
            }
        }
        buf
    }

    /// Operator-box use: sign in place, populating `operator_sig`.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let bytes = self.credential_signing_bytes();
        let sig = signing_key.sign(&bytes);
        self.operator_sig = Some(crate::identity::SignatureHex::from_signature(&sig));
    }

    /// Node/monitor use: verify `operator_sig` against the pinned operator key.
    /// Err on missing sig, bad encoding, or signature mismatch.
    pub fn verify(&self, operator_pub: &ed25519_dalek::VerifyingKey) -> crate::error::Result<()> {
        use ed25519_dalek::Verifier;
        let sig_hex = self.operator_sig.as_ref().ok_or_else(|| {
            crate::error::MirageError::Protocol(
                "credential params: missing operator signature".to_string(),
            )
        })?;
        let sig = sig_hex.to_signature().map_err(|e| {
            crate::error::MirageError::Protocol(format!(
                "credential params: bad signature encoding: {e}"
            ))
        })?;
        let bytes = self.credential_signing_bytes();
        operator_pub.verify(&bytes, &sig).map_err(|_| {
            crate::error::MirageError::Protocol(
                "credential params: operator signature verification failed".to_string(),
            )
        })
    }
}

/// A single epoch's secret material and expiry.
///
/// `secret` is zeroed on drop — it carries a fleet-wide gossip-delivered key
/// that should not linger in heap memory after the epoch is superseded.
///
/// ## Field overloading: `secret` vs `verify_material`
///
/// The `secret` field carries different material depending on the active scheme:
/// - `scheme = EpochHmac`: `secret` is the 32-byte HMAC-SHA256 key. Symmetric:
///   every verifier node holds the same secret and can both verify AND mint tokens.
/// - `scheme = SignedCapability`: `secret` is the 32-byte Ed25519 **verifying
///   key** (compressed Curve25519 public key). Asymmetric: nodes can only verify;
///   only opbox, which holds the signing key seed, can mint tokens. The verifying
///   key is integrity-protected by the operator's own signature over
///   `CredentialParams` — epoch-pubkey substitution is rejected
///   at the node before the params are applied.
/// - `scheme = BlindRsaBatch`: `secret` is unused (zero). The RSA-2048 public key
///   (DER-encoded, ~294 bytes) lives in `verify_material` — it is too large for
///   the 32-byte `secret` slot. `verify_material` is NOT zeroized (it is public
///   material). The preimage in `credential_signing_bytes` covers both fields so
///   substitution of either is rejected by the operator signature check.
///
/// `Debug` is hand-written to redact `secret` — the raw key bytes must never
/// appear in logs or debug output regardless of the active scheme.
#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
pub struct EpochEntry {
    /// Epoch identifier — carried in every credential token.
    #[zeroize(skip)]
    pub epoch_id: u32,
    /// Unix timestamp (ms) after which this epoch no longer accepts new credentials.
    #[zeroize(skip)]
    pub not_after_ms: u64,
    /// 32-byte secret material; semantics depend on the active scheme.
    /// See the struct-level doc for the scheme overloads.
    /// Gossip-delivered; never logged.
    pub secret: [u8; 32],
    /// Variable-length PUBLIC verify material for schemes that need more than the
    /// 32-byte `secret` slot. For `BlindRsaBatch` this is the issuer's RSA public
    /// key in DER (from `mirage_blindtoken::IssuerPublicKey::to_der`). Empty for
    /// `EpochHmac` / `SignedCapability` (which use `secret`). Public material — not
    /// zeroized.
    #[serde(default)]
    #[zeroize(skip)]
    pub verify_material: Vec<u8>,
}

impl EpochEntry {
    /// Epoch carrying a 32-byte secret (`EpochHmac` key / `SignedCapability` verify key).
    pub fn with_secret(epoch_id: u32, not_after_ms: u64, secret: [u8; 32]) -> Self {
        Self { epoch_id, not_after_ms, secret, verify_material: Vec::new() }
    }

    /// Epoch carrying variable-length public verify material (`BlindRsaBatch` RSA pubkey DER).
    pub fn with_verify_material(epoch_id: u32, not_after_ms: u64, verify_material: Vec<u8>) -> Self {
        Self { epoch_id, not_after_ms, secret: [0u8; 32], verify_material }
    }
}

impl std::fmt::Debug for EpochEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochEntry")
            .field("epoch_id", &self.epoch_id)
            .field("not_after_ms", &self.not_after_ms)
            .field("secret", &"<redacted 32B>")
            .field("verify_material_len", &self.verify_material.len())
            .finish()
    }
}

// ── verify_credential ─────────────────────────────────────────────────────────

/// Verify a raw credential blob presented during connection setup.
///
/// Returns a [`CredentialId`] on success — the caller must then call
/// `SpentSet::record_and_check` with this id and the epoch_id to reject replays.
///
/// `scheme_byte` comes from the wire (the client announces which scheme it used).
/// `credential` is the raw token bytes.
/// `now_ms` is the current Unix timestamp in milliseconds (monotonic).
///
/// Equivalent to [`verify_credential_bound`] with an empty dial context (no
/// per-dial binding). Kept for callers that don't bind a dial context.
pub fn verify_credential(
    params: &CredentialParams,
    scheme_byte: u8,
    credential: &[u8],
    now_ms: u64,
) -> Result<CredentialId> {
    verify_credential_bound(params, scheme_byte, credential, now_ms, &[])
}

/// Verify a credential, binding it to a per-dial context.
///
/// `dial_context` is mixed into the proof transcript for schemes that support
/// dial-context binding (currently RingMembership: the DLEQ challenge covers it).
/// The verifying node passes its OWN node_id here; the client mints the proof
/// against the EXIT hop's node_id. A credential minted for exit A therefore
/// fails verification at exit B — closing lateral replay by a malicious exit
/// that lifts a token and re-presents it to a different exit (each exit keeps a
/// separate SpentSet, so epoch-only binding would let one observed token buy a
/// dial at every other exit). Schemes that can't bind a dial context at mint
/// time (BlindRsaBatch issues offline batches, EpochHmac/SignedCapability)
/// ignore `dial_context` and rely on the SpentSet alone.
pub fn verify_credential_bound(
    params: &CredentialParams,
    scheme_byte: u8,
    credential: &[u8],
    now_ms: u64,
    dial_context: &[u8],
) -> Result<CredentialId> {
    let scheme = CredentialScheme::from_byte(scheme_byte)?;
    if scheme == CredentialScheme::Legacy {
        return Err(MirageError::Protocol(
            "credential required; legacy open-relay path rejected".to_string(),
        ));
    }
    // Try every authority whose scheme matches the wire byte; accept on the first
    // that verifies. SpentSet replay-check is the caller's responsibility.
    let mut last_err: Option<MirageError> = None;
    for authority in &params.authorities {
        if authority.scheme != scheme { continue; }
        match verify_under_authority(authority, scheme, credential, now_ms, dial_context) {
            Ok(id) => return Ok(id),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| MirageError::Protocol(format!(
        "credential: no configured authority for scheme {}", scheme.name()
    ))))
}

fn verify_under_authority(authority: &Authority, scheme: CredentialScheme, credential: &[u8], now_ms: u64, dial_context: &[u8]) -> Result<CredentialId> {
    match scheme {
        CredentialScheme::Legacy => unreachable!("Legacy filtered in verify_credential"),
        CredentialScheme::EpochHmac => {
            if credential.len() < 4 {
                return Err(MirageError::Protocol("epoch_hmac: token too short to read epoch_id".to_string()));
            }
            let epoch_id = u32::from_be_bytes(credential[0..4].try_into().expect("slice is 4 bytes"));
            let entry = find_epoch(&authority.epochs, epoch_id, now_ms)?;
            let key = EpochHmacKey::from_bytes(entry.secret);
            let parsed = verify_epoch_hmac(&key, credential)?;
            Ok(CredentialId::from_hmac_nonce(&parsed.nonce))
        }
        CredentialScheme::SignedCapability => {
            if credential.len() < 4 {
                return Err(MirageError::Protocol("signed_capability: token too short to read epoch_id".to_string()));
            }
            let epoch_id = u32::from_be_bytes(credential[0..4].try_into().expect("slice is 4 bytes"));
            let entry = find_epoch(&authority.epochs, epoch_id, now_ms)?;
            // EpochEntry.secret carries the Ed25519 verifying key (32-byte pubkey)
            // for the SignedCapability scheme — see EpochEntry doc for field overload.
            let vk = CapabilityVerifyKey::from_bytes(entry.secret);
            let parsed = verify_signed_capability(&vk, credential)?;
            Ok(CredentialId::from(parsed))
        }
        CredentialScheme::BlindRsaBatch => {
            // Wire token layout: [ 4B epoch_id BE | 32B token_msg | 32B randomizer | 256B signature ]
            // Total: 324 bytes.
            const OFF_MSG: usize = 4;
            const OFF_RAND: usize = OFF_MSG + mirage_blindtoken::MSG_LEN;        // 36
            const OFF_SIG: usize = OFF_RAND + mirage_blindtoken::RANDOMIZER_LEN; // 68
            const TOKEN_LEN: usize = OFF_SIG + mirage_blindtoken::SIG_LEN;       // 324
            if credential.len() != TOKEN_LEN {
                return Err(MirageError::Protocol(format!(
                    "blind_rsa_batch: token length {} != expected {TOKEN_LEN}",
                    credential.len()
                )));
            }
            let epoch_id = u32::from_be_bytes(credential[0..4].try_into().expect("4 bytes"));
            let entry = find_epoch(&authority.epochs, epoch_id, now_ms)?;
            if entry.verify_material.is_empty() {
                return Err(MirageError::Protocol(format!(
                    "blind_rsa_batch: epoch {epoch_id} has no issuer public key"
                )));
            }
            let pk = mirage_blindtoken::IssuerPublicKey::from_der(&entry.verify_material)
                .map_err(|e| MirageError::Protocol(format!("blind_rsa_batch: bad issuer pubkey: {e}")))?;
            let mut msg = [0u8; mirage_blindtoken::MSG_LEN];
            msg.copy_from_slice(&credential[OFF_MSG..OFF_RAND]);
            let mut randomizer = [0u8; mirage_blindtoken::RANDOMIZER_LEN];
            randomizer.copy_from_slice(&credential[OFF_RAND..OFF_SIG]);
            let mut sig = [0u8; mirage_blindtoken::SIG_LEN];
            sig.copy_from_slice(&credential[OFF_SIG..TOKEN_LEN]);
            mirage_blindtoken::verify(&pk, &msg, &randomizer, &sig)
                .map_err(|e| MirageError::Protocol(format!("blind_rsa_batch: verification failed: {e}")))?;
            // The token message doubles as the single-use CredentialId (SpentSet kills replay).
            Ok(CredentialId::from_bytes32(msg))
        }
        CredentialScheme::RingMembership => {
            // Transparent Merkle-membership token (mirage-ringmember wire body).
            // The token's first 4 bytes are the epoch_id (little-endian, matching
            // mirage_ringmember::MembershipToken::encode). EpochEntry.verify_material
            // holds the 32-byte Merkle root for this scheme (published by the
            // issuer; the field is overloaded the same way the RSA pubkey rides it
            // for BlindRsaBatch). The DLEQ nullifier returned doubles as the
            // single-use CredentialId — SpentSet kills replay, exactly like the
            // blind-token msg.
            //
            // proof_mode: this arm is the `merkle_reveal` regime. The reserved
            // `zk_inclusion` (full unlinkability) regime is a FUTURE scheme byte,
            // not a field here — keeping the one-byte-per-scheme seam avoids an
            // unbound authority field + a signing-preimage bump across opbox.
            if credential.len() < 4 {
                return Err(MirageError::Protocol(
                    "ring_membership: token too short to read epoch_id".to_string(),
                ));
            }
            let epoch_id = u32::from_le_bytes(credential[0..4].try_into().expect("4 bytes"));
            let entry = find_epoch(&authority.epochs, epoch_id, now_ms)?;
            // verify_material layout: 32B Merkle root, optionally followed by a
            // 4-byte little-endian `max_dials` (the per-epoch dial budget). A
            // bare 32-byte field is the legacy strict single-use form
            // (max_dials = 1) so older signed epochs keep verifying.
            let vm = &entry.verify_material;
            if vm.len() != 32 && vm.len() != 36 {
                return Err(MirageError::Protocol(format!(
                    "ring_membership: epoch {epoch_id} verify_material must be 32B root or 32B root||4B max_dials, got {} bytes",
                    vm.len()
                )));
            }
            let mut root = [0u8; 32];
            root.copy_from_slice(&vm[0..32]);
            let max_dials = if vm.len() == 36 {
                u32::from_le_bytes(vm[32..36].try_into().expect("4 bytes")).max(1)
            } else {
                1
            };
            // Transcript = epoch_id (LE) || dial_context. dial_context is the
            // verifying exit's node_id (empty for callers that don't bind it).
            // Binding the exit id into the DLEQ challenge means a proof minted
            // for exit A fails at exit B → a malicious exit cannot lift a token
            // and replay it laterally to other exits. The per-dial nullifier +
            // SpentSet additionally cap each (member, epoch, index) to one use.
            let mut transcript = epoch_id.to_le_bytes().to_vec();
            transcript.extend_from_slice(dial_context);
            let nullifier = mirage_ringmember::verify_membership(credential, &root, epoch_id, &transcript, max_dials)
                .map_err(|e| MirageError::Protocol(format!("ring_membership: verification failed: {e}")))?;
            Ok(CredentialId::from_bytes32(nullifier))
        }
        CredentialScheme::RoleSigned => {
            // Not authority-keyed: the credential holder IS the authority
            // (an operator/group-signed identity excerpt it presents about
            // itself), so there is no per-mesh `Authority`/`EpochEntry` to
            // verify against here — the check needs the pinned operator/group
            // pubkey and the exit's OWN node id instead, neither of which this
            // function's signature carries. Callers dispatch straight to
            // `role_signed::verify_role_signed` with that context — see that
            // function's own doc. Reaching this arm at all means a caller
            // routed a RoleSigned credential through the generic
            // authority-keyed path by mistake.
            Err(MirageError::Protocol(
                "role_signed: not an authority-keyed scheme — call \
                 crate::crypto::credential::role_signed::verify_role_signed directly, \
                 passing the operator/group pubkey and the exit's own node id"
                    .to_string(),
            ))
        }
    }
}

fn find_epoch<'a>(
    epochs: &'a [EpochEntry],
    epoch_id: u32,
    now_ms: u64,
) -> Result<&'a EpochEntry> {
    let entry = epochs
        .iter()
        .find(|e| e.epoch_id == epoch_id)
        .ok_or_else(|| {
            MirageError::Protocol(format!("credential: unknown epoch_id {epoch_id}"))
        })?;
    if now_ms > entry.not_after_ms {
        return Err(MirageError::Protocol(format!(
            "credential: epoch {epoch_id} expired (not_after_ms={}, now_ms={now_ms})",
            entry.not_after_ms
        )));
    }
    Ok(entry)
}

// ── SpentSet ──────────────────────────────────────────────────────────────────

/// Safety cap on the number of spent ids recorded per epoch.
///
/// Under the `SignedCapability` scheme tokens must be operator-signed, so the
/// legitimate per-epoch volume is bounded and this cap should never be hit in
/// normal operation. It is a **runaway guard only**: if a single epoch's set
/// reaches this limit, further fresh ids in that epoch are REJECTED (fail-
/// closed) rather than accepted-without-recording (which would allow replay)
/// or recorded unbounded (which risks OOM). A `warn!` fires once per epoch
/// when the threshold is first crossed.
pub const MAX_SPENT_PER_EPOCH: usize = 1_048_576; // 1 Mi entries ≈ 32 MiB per epoch

/// Per-epoch replay-detection set.
///
/// The node calls `record_and_check` on every accepted credential. On the
/// second presentation of the same `CredentialId` the call returns `false`.
///
/// Wrapping in `tokio::sync::Mutex` is the NODE's responsibility (this type
/// is sync + simple).
///
/// ## Persistence hook
///
/// Install a channel sender via [`SpentSet::with_persist_sender`]. Every
/// freshly-seen `(epoch_id, id_bytes)` pair is sent non-blocking over the
/// channel so the caller can persist it to disk and restore the set on restart
/// via [`SpentSet::load_entry`]. The hook fires only on fresh entries —
/// replays are NOT re-sent.
///
/// ## Per-epoch size cap
///
/// See [`MAX_SPENT_PER_EPOCH`]. When an epoch's set is already at the cap,
/// `record_and_check` returns `false` (fail-closed) and logs a `warn!` once
/// per epoch.
#[derive(Debug, Default)]
pub struct SpentSet {
    /// epoch_id → set of seen CredentialIds.
    inner: HashMap<u32, HashSet<CredentialId>>,
    /// Optional persistence channel. Non-blocking (`try_send` semantics via
    /// `send` on a disconnected sender → silently drops).
    persist_tx: Option<mpsc::Sender<(u32, [u8; 32])>>,
    /// Epochs for which the cap-exceeded warning has already been logged once.
    cap_warned: HashSet<u32>,
}

impl SpentSet {
    /// Create an empty SpentSet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a persistence sender.
    ///
    /// When set, every freshly-accepted `(epoch_id, id)` pair is forwarded to
    /// `tx` so the caller can write it to a durable store and re-feed the set
    /// on restart via [`SpentSet::load_entry`]. Sends are non-blocking — a
    /// full or disconnected receiver causes the entry to be silently dropped
    /// from the channel (the entry is still recorded in memory).
    pub fn with_persist_sender(mut self, tx: mpsc::Sender<(u32, [u8; 32])>) -> Self {
        self.persist_tx = Some(tx);
        self
    }

    /// Record `id` for `epoch_id`.
    ///
    /// Returns `true` if the credential is fresh (first presentation) and has
    /// been recorded successfully. Forwards `(epoch_id, *id.as_bytes())` to
    /// the persistence sender if one is installed.
    ///
    /// Returns `false` in two cases:
    /// - The id has been seen before (replay); no message is sent.
    /// - The epoch's set has reached [`MAX_SPENT_PER_EPOCH`] (fail-closed);
    ///   a `warn!` is logged once per epoch and the id is NOT recorded.
    ///   Accepting without recording would allow replay; this is the safe
    ///   choice between replay-window and OOM.
    pub fn record_and_check(&mut self, epoch_id: u32, id: CredentialId) -> bool {
        let epoch_set = self.inner.entry(epoch_id).or_default();

        // Cap guard: fail-closed when the epoch set is already at the limit.
        if epoch_set.len() >= MAX_SPENT_PER_EPOCH {
            if self.cap_warned.insert(epoch_id) {
                tracing::warn!(
                    epoch_id,
                    cap = MAX_SPENT_PER_EPOCH,
                    "SpentSet: per-epoch cap reached — rejecting further fresh credentials \
                     for this epoch (fail-closed); operator should rotate epoch"
                );
            }
            return false;
        }

        let fresh = epoch_set.insert(id);
        if fresh {
            if let Some(tx) = &self.persist_tx {
                let _ = tx.send((epoch_id, *id.as_bytes())); // non-blocking; drop on disconnect
            }
        }
        fresh
    }

    /// Load a single entry at boot time WITHOUT re-persisting.
    ///
    /// Used to restore the spent set from a durable store after a node
    /// restart. Does NOT fire the persistence sender — the entry is already
    /// on disk.
    pub fn load_entry(&mut self, epoch_id: u32, id: CredentialId) {
        self.inner.entry(epoch_id).or_default().insert(id);
    }

    /// Return all currently tracked `(epoch_id, id_bytes)` pairs.
    ///
    /// Used by the node to compact/rewrite its on-disk log after a
    /// [`SpentSet::prune`] removes expired epochs.
    pub fn iter_entries(&self) -> Vec<(u32, [u8; 32])> {
        let mut out = Vec::new();
        for (epoch_id, ids) in &self.inner {
            for id in ids {
                out.push((*epoch_id, *id.as_bytes()));
            }
        }
        out
    }

    /// Prune data for expired epochs to bound memory growth.
    ///
    /// Drops every epoch whose `not_after_ms` is strictly less than `now_ms`.
    /// Also clears the once-per-epoch cap warning state for pruned epochs so
    /// a recycled epoch_id (unlikely but possible) starts fresh.
    ///
    /// Keyed by `epoch_id` only. Invariant: epoch_ids are unique across
    /// authorities within one CredentialParams (the operator assigns them).
    /// Multi-authority epoch_id namespacing (key by (authority_id, epoch_id))
    /// is a later-phase concern once a second live authority exists.
    pub fn prune(&mut self, now_ms: u64, params: &CredentialParams) {
        let expired: Vec<u32> = params.authorities.iter()
            .flat_map(|a| a.epochs.iter())
            .filter(|e| e.not_after_ms < now_ms)
            .map(|e| e.epoch_id)
            .collect();
        for id in expired {
            self.inner.remove(&id);
            self.cap_warned.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epoch_hmac::{issue_epoch_hmac, random_nonce16};

    fn make_params(epoch_id: u32, not_after_ms: u64) -> CredentialParams {
        CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(epoch_id, not_after_ms, [0x42u8; 32])],
        )
    }

    #[test]
    fn verify_credential_legacy_rejects() {
        let params = make_params(1, u64::MAX);
        let result = verify_credential(&params, 0x00, b"anything", 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("credential required"));
    }

    #[test]
    fn verify_credential_expired_epoch_rejects() {
        let params = make_params(1, 1000); // expires at t=1000ms
        let key = epoch_hmac::EpochHmacKey::from_bytes([0x42u8; 32]);
        let nonce = random_nonce16();
        let token = issue_epoch_hmac(&key, 1, nonce);
        // now_ms=2000 > not_after_ms=1000
        let result = verify_credential(&params, 0x01, &token, 2000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn verify_credential_epoch_hmac_roundtrip() {
        let params = make_params(5, u64::MAX);
        let key = epoch_hmac::EpochHmacKey::from_bytes([0x42u8; 32]);
        let nonce = random_nonce16();
        let token = issue_epoch_hmac(&key, 5, nonce);
        let id = verify_credential(&params, 0x01, &token, 0).unwrap();
        // CredentialId encodes the nonce in bytes 16..32
        assert_eq!(&id.as_bytes()[16..32], &nonce);
    }

    #[test]
    fn spent_set_replay_rejected() {
        let mut spent = SpentSet::new();
        let id = CredentialId::from_hmac_nonce(&[0xABu8; 16]);
        assert!(spent.record_and_check(1, id), "first presentation must be accepted");
        assert!(!spent.record_and_check(1, id), "second presentation must be rejected");
    }

    #[test]
    fn spent_set_prune_removes_expired() {
        let mut spent = SpentSet::new();
        let id = CredentialId::from_hmac_nonce(&[0x01u8; 16]);
        spent.record_and_check(1, id);

        let params = CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(1, 500, [0u8; 32])],
        );

        // Before expiry, epoch 1 still present.
        spent.prune(400, &params);
        assert!(spent.inner.contains_key(&1));

        // After expiry, epoch 1 removed.
        spent.prune(600, &params);
        assert!(!spent.inner.contains_key(&1));
    }

    /// When the per-epoch cap is reached, fresh ids must be REJECTED (fail-closed)
    /// rather than accepted-without-recording (which would reopen a replay window).
    /// The test overrides the effective cap by filling a set to MAX_SPENT_PER_EPOCH
    /// via load_entry (which bypasses the cap guard intentionally — boot-reload) and
    /// then verifies that record_and_check returns false for new ids.
    ///
    /// Since MAX_SPENT_PER_EPOCH is 1 Mi, we test cap logic via a local wrapper that
    /// stuffs `n` synthetic ids into the set using load_entry (no cap check) to reach
    /// exactly the threshold, then calls record_and_check for one more new id.
    #[test]
    fn spent_set_cap_fail_closed() {
        let mut spent = SpentSet::new();
        // Fill epoch 42 to exactly the cap using load_entry (bypasses cap on load).
        for i in 0..MAX_SPENT_PER_EPOCH {
            let mut raw = [0u8; 32];
            // Spread i across bytes 0..4 to guarantee distinct ids.
            raw[0] = (i >> 24) as u8;
            raw[1] = (i >> 16) as u8;
            raw[2] = (i >> 8) as u8;
            raw[3] = i as u8;
            spent.load_entry(42, CredentialId::from_bytes32(raw));
        }
        assert_eq!(spent.inner[&42].len(), MAX_SPENT_PER_EPOCH, "setup: epoch set must be at cap");

        // A brand-new id must be rejected — the epoch set is full.
        let new_id = CredentialId::from_bytes32([0xFFu8; 32]);
        let result = spent.record_and_check(42, new_id);
        assert!(!result, "record_and_check must return false (reject) when epoch is at cap");

        // The id must NOT have been inserted (still at cap, not cap+1).
        assert_eq!(spent.inner[&42].len(), MAX_SPENT_PER_EPOCH, "cap must not grow beyond MAX_SPENT_PER_EPOCH");
    }

    /// A replay of an already-seen id must still return false even after the cap
    /// warning has been triggered (cap_warned set must not confuse replay logic).
    #[test]
    fn spent_set_cap_replay_still_rejected() {
        let mut spent = SpentSet::new();
        for i in 0..MAX_SPENT_PER_EPOCH {
            let mut raw = [0u8; 32];
            raw[0] = (i >> 24) as u8;
            raw[1] = (i >> 16) as u8;
            raw[2] = (i >> 8) as u8;
            raw[3] = i as u8;
            spent.load_entry(42, CredentialId::from_bytes32(raw));
        }
        // An already-recorded id also returns false (replay + cap).
        let existing_id = CredentialId::from_bytes32([0u8; 32]);
        assert!(!spent.record_and_check(42, existing_id), "replay at cap must still return false");
    }

    /// After prune removes an expired epoch, cap_warned must also be cleared so a
    /// recycled epoch_id (if the operator reuses it) starts fresh.
    #[test]
    fn spent_set_prune_clears_cap_warned() {
        let mut spent = SpentSet::new();
        // Trigger the cap warning on epoch 1.
        for i in 0..MAX_SPENT_PER_EPOCH {
            let mut raw = [0u8; 32];
            raw[0] = (i >> 24) as u8;
            raw[1] = (i >> 16) as u8;
            raw[2] = (i >> 8) as u8;
            raw[3] = i as u8;
            spent.load_entry(1, CredentialId::from_bytes32(raw));
        }
        // Force the warn path so cap_warned is populated.
        let _ = spent.record_and_check(1, CredentialId::from_bytes32([0xFFu8; 32]));
        assert!(spent.cap_warned.contains(&1), "cap_warned must be set before prune");

        let params = CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(1, 500, [0u8; 32])],
        );
        spent.prune(600, &params);
        assert!(!spent.cap_warned.contains(&1), "prune must clear cap_warned for expired epoch");
    }

    /// ZeroizeOnDrop must NOT break serde — gossip delivery round-trips through JSON.
    #[test]
    fn epoch_entry_serde_roundtrip_with_zeroize() {
        let params = make_params(7, 99_999_999);
        let json = serde_json::to_string(&params).expect("serialize");
        let restored: CredentialParams = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.authorities[0].epochs.len(), 1);
        let e = &restored.authorities[0].epochs[0];
        assert_eq!(e.epoch_id, 7);
        assert_eq!(e.not_after_ms, 99_999_999);
        assert_eq!(e.secret, [0x42u8; 32]);
    }

    /// verify_credential still works after adding ZeroizeOnDrop — regression guard.
    #[test]
    fn verify_credential_still_works_after_zeroize_derive() {
        let params = make_params(3, u64::MAX);
        let key = epoch_hmac::EpochHmacKey::from_bytes([0x42u8; 32]);
        let nonce = random_nonce16();
        let token = issue_epoch_hmac(&key, 3, nonce);
        let id = verify_credential(&params, 0x01, &token, 0).expect("verify must succeed");
        assert_eq!(&id.as_bytes()[16..32], &nonce);
    }

    // ── Persistence hook tests ───────────────────────────────────────────────

    #[test]
    fn persist_sender_fires_on_fresh_entry() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut spent = SpentSet::new().with_persist_sender(tx);
        let id = CredentialId::from_hmac_nonce(&[0xCCu8; 16]);

        // First presentation — fresh → sender fires.
        assert!(spent.record_and_check(2, id), "first must be fresh");
        let (epoch, bytes) = rx.try_recv().expect("persist_tx must have fired");
        assert_eq!(epoch, 2);
        assert_eq!(&bytes, id.as_bytes());

        // Replay — NOT fresh → sender stays silent.
        assert!(!spent.record_and_check(2, id), "second must be replay");
        assert!(
            rx.try_recv().is_err(),
            "replay must NOT send to persist channel"
        );
    }

    #[test]
    fn load_entry_does_not_send() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut spent = SpentSet::new().with_persist_sender(tx);
        let id = CredentialId::from_hmac_nonce(&[0xDDu8; 16]);

        // Boot-load — must not fire persist_tx.
        spent.load_entry(3, id);
        assert!(rx.try_recv().is_err(), "load_entry must not fire persist_tx");

        // Verify the entry was actually recorded (subsequent record returns false = replay).
        assert!(
            !spent.record_and_check(3, id),
            "loaded entry must act as already-seen"
        );
        // The replay in record_and_check also must not fire.
        assert!(rx.try_recv().is_err(), "replay must not fire persist_tx");
    }

    #[test]
    fn iter_entries_returns_loaded_entries() {
        let mut spent = SpentSet::new();
        let id_a = CredentialId::from_hmac_nonce(&[0x01u8; 16]);
        let id_b = CredentialId::from_hmac_nonce(&[0x02u8; 16]);

        spent.load_entry(5, id_a);
        spent.load_entry(5, id_b);
        spent.load_entry(7, id_a);

        let mut entries = spent.iter_entries();
        entries.sort(); // deterministic order for assertion
        assert_eq!(entries.len(), 3, "must return all 3 entries");

        // Verify each expected (epoch_id, bytes) is present.
        let has = |ep: u32, id: &CredentialId| entries.contains(&(ep, *id.as_bytes()));
        assert!(has(5, &id_a));
        assert!(has(5, &id_b));
        assert!(has(7, &id_a));
    }
}

/// Negative-path coverage for the anon-credential verify + reuse path (ZT-robustness P1).
#[cfg(test)]
mod negative_path_tests {
    use super::*;
    use epoch_hmac::{issue_epoch_hmac, random_nonce16, EpochHmacKey};

    const NOW: u64 = 1_000_000_000_000;
    const SECRET_A: [u8; 32] = [0x11u8; 32];
    const SECRET_B: [u8; 32] = [0x22u8; 32];

    fn mk_params(epoch_id: u32, secret: [u8; 32], not_after_ms: u64) -> CredentialParams {
        CredentialParams::single(
            1002,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(epoch_id, not_after_ms, secret)],
        )
    }

    fn mint(epoch_id: u32, secret: [u8; 32]) -> Vec<u8> {
        let key = EpochHmacKey::from_bytes(secret);
        issue_epoch_hmac(&key, epoch_id, random_nonce16()).to_vec()
    }

    // ── 1. Happy path ────────────────────────────────────────────────────────

    #[test]
    fn valid_token_accepts() {
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(2, SECRET_A);
        let result = verify_credential(&params, CredentialScheme::EpochHmac as u8, &token, NOW);
        assert!(result.is_ok(), "valid token must be accepted; got {:?}", result.err());
    }

    // ── 2. Scheme-byte rejections ────────────────────────────────────────────

    #[test]
    fn legacy_scheme_byte_rejected() {
        // Valid EpochHmac token presented with scheme_byte=0x00 (Legacy) must reject.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(2, SECRET_A);
        let result = verify_credential(&params, 0x00, &token, NOW);
        assert!(result.is_err(), "Legacy scheme_byte must be rejected even with a structurally valid token");
    }

    #[test]
    fn scheme_byte_out_of_range_rejected() {
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(2, SECRET_A);
        // 0x06 is unknown — 0x00..=0x05 are all assigned now (Legacy through
        // RoleSigned).
        let result = verify_credential(&params, 0x06, &token, NOW);
        assert!(result.is_err(), "Unknown scheme byte 0x06 must be rejected by from_byte");
    }

    #[test]
    fn role_signed_scheme_byte_has_no_configured_authority_here() {
        // 0x05 (RoleSigned) is a KNOWN scheme byte now, but this crate's
        // generic authority-keyed path has no arm that can verify it (see
        // `verify_under_authority`'s own RoleSigned arm) — an EpochHmac-only
        // `CredentialParams` correctly still rejects it, just not by
        // `from_byte` any more.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(2, SECRET_A);
        let result = verify_credential(&params, 0x05, &token, NOW);
        assert!(result.is_err(), "RoleSigned must not verify under an EpochHmac authority");
    }

    // ── 3. Epoch-lookup rejections ───────────────────────────────────────────

    #[test]
    fn unknown_epoch_rejected() {
        // params has epoch 2; token minted for epoch 99 — find_epoch must fail.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(99, SECRET_A);
        let result = verify_credential(&params, 0x01, &token, NOW);
        assert!(result.is_err(), "Unknown epoch_id 99 must be rejected");
    }

    #[test]
    fn expired_epoch_rejected() {
        // not_after_ms = NOW - 1 → already expired at NOW.
        let params = mk_params(2, SECRET_A, NOW - 1);
        let token = mint(2, SECRET_A);
        let result = verify_credential(&params, 0x01, &token, NOW);
        assert!(result.is_err(), "Expired epoch must be rejected");
    }

    // ── 4. Token-length rejections ───────────────────────────────────────────

    #[test]
    fn truncated_lt4_rejected() {
        // 3-byte blob: too short to read epoch_id (needs at least 4 bytes).
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let result = verify_credential(&params, 0x01, &[0u8; 3], NOW);
        assert!(result.is_err(), "Credential shorter than 4 bytes must be rejected");
    }

    #[test]
    fn truncated_ge4_lt52_rejected() {
        // 30-byte blob: epoch_id bytes parse to epoch 2, but token is too short for MAC verify.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let mut blob = vec![0u8; 30];
        blob[0..4].copy_from_slice(&2u32.to_be_bytes()); // epoch_id = 2
        let result = verify_credential(&params, 0x01, &blob, NOW);
        assert!(result.is_err(), "30-byte token (ge4 lt52) must be rejected by verify_epoch_hmac length check");
    }

    #[test]
    fn oversized_token_rejected() {
        // 60-byte blob: epoch_id = 2, but length != 52.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let mut blob = vec![0u8; 60];
        blob[0..4].copy_from_slice(&2u32.to_be_bytes());
        let result = verify_credential(&params, 0x01, &blob, NOW);
        assert!(result.is_err(), "60-byte token (oversized) must be rejected by verify_epoch_hmac length check");
    }

    // ── 5. MAC-integrity rejections ──────────────────────────────────────────

    #[test]
    fn invalid_mac_rejected() {
        // Valid epoch-2 token with one MAC byte flipped.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let mut token = mint(2, SECRET_A);
        token[25] ^= 0xFF;
        let result = verify_credential(&params, 0x01, &token, NOW);
        assert!(result.is_err(), "Flipped MAC byte must cause mac mismatch rejection");
    }

    #[test]
    fn wrong_secret_rejected() {
        // Token minted with SECRET_A, but params has SECRET_B for epoch 2.
        let params = mk_params(2, SECRET_B, NOW + 3_600_000);
        let token = mint(2, SECRET_A);
        let result = verify_credential(&params, 0x01, &token, NOW);
        assert!(result.is_err(), "Token minted with wrong secret must cause mac mismatch rejection");
    }

    // ── 6. Scheme-confusion rejection ────────────────────────────────────────

    #[test]
    fn scheme_confusion_voprf_byte_rejected() {
        // A valid EpochHmac token routed to the SignedCapability arm (scheme_byte=0x02)
        // must NOT accept. The EpochHmac token is 52 bytes; SignedCapability expects
        // exactly 100 bytes — the length check alone causes rejection. This test
        // verifies that the routing is correct and that no EpochHmac token can be
        // accepted under the SignedCapability scheme byte.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(2, SECRET_A);
        let result = verify_credential(&params, 0x02, &token, NOW);
        assert!(result.is_err(), "EpochHmac token presented with SignedCapability scheme_byte must be rejected");
    }

    #[test]
    fn scheme_confusion_hmac_token_on_signed_cap_byte_rejected() {
        // Same as above but explicit: EpochHmac 52-byte token → scheme_byte=0x02 → Err.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(2, SECRET_A); // 52 bytes
        assert_eq!(token.len(), 52);
        let result = verify_credential(&params, 0x02, &token, NOW);
        assert!(result.is_err(), "52-byte EpochHmac token must be rejected on scheme_byte=0x02 (wrong length)");
    }

    // ── 7. Cross-epoch rejection ─────────────────────────────────────────────

    #[test]
    fn cross_epoch_token_rejected() {
        // params has only epoch 2; token minted for epoch 3 must fail find_epoch.
        let params = mk_params(2, SECRET_A, NOW + 3_600_000);
        let token = mint(3, SECRET_A);
        let result = verify_credential(&params, 0x01, &token, NOW);
        assert!(result.is_err(), "Token for epoch 3 with params containing only epoch 2 must be rejected");
    }

    // ── 8. SpentSet replay tests ─────────────────────────────────────────────

    // NOTE (P1.3 finding): SpentSet is in-RAM only — see zt-substrate-robustness
    // backlog; a node restart forgets spent ids, reopening a replay window for
    // the live epoch.

    #[test]
    fn spent_set_replay_rejected() {
        let mut s = SpentSet::new();
        let id = CredentialId::from_hmac_nonce(&[7u8; 16]);
        assert!(s.record_and_check(2, id), "first presentation must be fresh (true)");
        assert!(!s.record_and_check(2, id), "second presentation must be replay (false)");
    }

    #[test]
    fn spent_set_distinct_ids_ok() {
        let mut s = SpentSet::new();
        let id_a = CredentialId::from_hmac_nonce(&[0x01u8; 16]);
        let id_b = CredentialId::from_hmac_nonce(&[0x02u8; 16]);
        assert!(s.record_and_check(2, id_a), "first distinct id must be fresh");
        assert!(s.record_and_check(2, id_b), "second distinct id must be fresh");
    }

    #[test]
    fn spent_set_per_epoch_keyed() {
        // Same id under epoch 2 and epoch 3 → both fresh.
        // The token's MAC binds epoch_id, so a single token cannot cross epochs:
        // a MAC issued for epoch 2 will fail verification when presented with
        // epoch 3's secret, making cross-epoch token reuse impossible at the
        // verify_credential level. SpentSet is nonetheless per-epoch keyed so
        // a spent id in epoch 2 does not block the same id pattern in epoch 3.
        let mut s = SpentSet::new();
        let id = CredentialId::from_hmac_nonce(&[0xAAu8; 16]);
        assert!(s.record_and_check(2, id), "fresh under epoch 2");
        assert!(s.record_and_check(3, id), "fresh under epoch 3 (per-epoch keyed)");
        // Confirming replay still blocked within each epoch:
        assert!(!s.record_and_check(2, id), "replay under epoch 2 must be rejected");
        assert!(!s.record_and_check(3, id), "replay under epoch 3 must be rejected");
    }
}

#[cfg(test)]
mod sig_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_signable_params() -> CredentialParams {
        CredentialParams::single(
            42,
            CredentialScheme::EpochHmac,
            vec![EpochEntry::with_secret(7, 99_999_999, [0xABu8; 32])],
        )
    }

    #[test]
    fn sign_then_verify_ok() {
        let key = SigningKey::generate(&mut OsRng);
        let mut params = make_signable_params();
        params.sign(&key);
        params.verify(&key.verifying_key()).expect("signature must verify");
    }

    #[test]
    fn modify_generation_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let mut params = make_signable_params();
        params.sign(&key);
        params.generation += 1;
        assert!(
            params.verify(&key.verifying_key()).is_err(),
            "modified generation must not verify"
        );
    }

    #[test]
    fn modify_secret_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let mut params = make_signable_params();
        params.sign(&key);
        params.authorities[0].epochs[0].secret[0] ^= 0xFF;
        assert!(
            params.verify(&key.verifying_key()).is_err(),
            "modified epoch secret must not verify"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = SigningKey::generate(&mut OsRng);
        let k2 = SigningKey::generate(&mut OsRng);
        let mut params = make_signable_params();
        params.sign(&k1);
        assert!(
            params.verify(&k2.verifying_key()).is_err(),
            "wrong verifying key must not verify"
        );
    }

    #[test]
    fn missing_sig_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let params = make_signable_params(); // operator_sig = None
        assert!(
            params.verify(&key.verifying_key()).is_err(),
            "missing signature must not verify"
        );
    }
}

/// Full coverage for the SignedCapability scheme through `verify_credential` +
/// direct API. Also covers cross-scheme confusion and replay via SpentSet.
#[cfg(test)]
mod signed_capability_tests {
    use super::*;
    use signed_capability::{
        generate_capability_keypair, mint_signed_capability, random_nonce32, CapabilityVerifyKey,
    };

    const NOW: u64 = 2_000_000_000_000;

    /// Build a `CredentialParams` with the SignedCapability scheme.
    /// `secret` holds the Ed25519 verifying key bytes.
    fn make_sc_params(
        epoch_id: u32,
        vk: &CapabilityVerifyKey,
        not_after_ms: u64,
    ) -> CredentialParams {
        CredentialParams::single(
            1,
            CredentialScheme::SignedCapability,
            vec![EpochEntry::with_secret(epoch_id, not_after_ms, vk.to_bytes())],
        )
    }

    // ── 1. Happy path ────────────────────────────────────────────────────────

    #[test]
    fn happy_path_mint_verify_ok() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        let params = make_sc_params(7, &vk, NOW + 3_600_000);
        let token = mint_signed_capability(&sk, 7, nonce);
        let result = verify_credential(&params, 0x02, &token, NOW);
        assert!(result.is_ok(), "valid SignedCapability token must verify; got {:?}", result.err());
    }

    #[test]
    fn credential_id_equals_nonce() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        let params = make_sc_params(5, &vk, NOW + 3_600_000);
        let token = mint_signed_capability(&sk, 5, nonce);
        let cred_id = verify_credential(&params, 0x02, &token, NOW).unwrap();
        assert_eq!(cred_id.as_bytes(), &nonce, "CredentialId must equal the token nonce");
    }

    // ── 2. Invalid signature ─────────────────────────────────────────────────

    #[test]
    fn invalid_signature_rejected() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        let params = make_sc_params(3, &vk, NOW + 3_600_000);
        let mut token = mint_signed_capability(&sk, 3, nonce);
        token[50] ^= 0xFF; // flip one byte in signature region
        let result = verify_credential(&params, 0x02, &token, NOW);
        assert!(result.is_err(), "flipped signature byte must be rejected");
    }

    // ── 3. Wrong epoch verify key ────────────────────────────────────────────

    #[test]
    fn wrong_epoch_key_rejected() {
        let (sk, _vk_a) = generate_capability_keypair();
        let (_sk_b, vk_b) = generate_capability_keypair();
        let nonce = random_nonce32();
        // Params carry vk_b, but token was minted with sk (matching vk_a).
        let params = make_sc_params(4, &vk_b, NOW + 3_600_000);
        let token = mint_signed_capability(&sk, 4, nonce);
        let result = verify_credential(&params, 0x02, &token, NOW);
        assert!(result.is_err(), "token minted with key A verified against key B must be rejected");
    }

    // ── 4. Token length rejections ───────────────────────────────────────────

    #[test]
    fn truncated_token_rejected() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        let params = make_sc_params(1, &vk, NOW + 3_600_000);
        let token = mint_signed_capability(&sk, 1, nonce);
        // 99 bytes — one short.
        let short = &token[..99];
        assert!(verify_credential(&params, 0x02, short, NOW).is_err(), "99-byte token must be rejected");
        // 3 bytes — well short.
        assert!(verify_credential(&params, 0x02, &token[..3], NOW).is_err(), "3-byte token must be rejected");
    }

    #[test]
    fn oversized_token_rejected() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        let params = make_sc_params(1, &vk, NOW + 3_600_000);
        let mut token = mint_signed_capability(&sk, 1, nonce);
        token.push(0x00); // 101 bytes
        assert!(verify_credential(&params, 0x02, &token, NOW).is_err(), "101-byte token must be rejected");
    }

    // ── 5. Cross-epoch rejection ─────────────────────────────────────────────

    #[test]
    fn cross_epoch_token_rejected() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        // Params only has epoch 2; token is minted for epoch 3.
        let params = make_sc_params(2, &vk, NOW + 3_600_000);
        let token = mint_signed_capability(&sk, 3, nonce);
        let result = verify_credential(&params, 0x02, &token, NOW);
        assert!(result.is_err(), "token for epoch 3 with params containing only epoch 2 must be rejected");
    }

    // ── 6. Scheme-confusion: EpochHmac token on SignedCapability byte ────────

    #[test]
    fn hmac_token_on_sc_scheme_byte_rejected() {
        use epoch_hmac::{issue_epoch_hmac, random_nonce16, EpochHmacKey};
        let (_sk, vk) = generate_capability_keypair();
        let params = make_sc_params(2, &vk, NOW + 3_600_000);
        // Mint a valid 52-byte EpochHmac token.
        let hmac_key = EpochHmacKey::from_bytes([0x42u8; 32]);
        let hmac_token = issue_epoch_hmac(&hmac_key, 2, random_nonce16());
        // Present it with scheme_byte=0x02 (SignedCapability).
        let result = verify_credential(&params, 0x02, &hmac_token, NOW);
        assert!(result.is_err(), "52-byte EpochHmac token must be rejected on SignedCapability scheme byte (wrong length)");
    }

    // ── 7. Scheme-confusion: SignedCapability token on EpochHmac byte ────────

    #[test]
    fn sc_token_on_hmac_scheme_byte_rejected() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        // EpochHmac params — secret is HMAC key, not a pubkey.
        let params = CredentialParams::single(
            1,
            CredentialScheme::EpochHmac,
            // pubkey bytes used as HMAC key (gibberish) — intentional scheme-confusion test
            vec![EpochEntry::with_secret(2, NOW + 3_600_000, vk.to_bytes())],
        );
        let token = mint_signed_capability(&sk, 2, nonce); // 100 bytes
        // Present a 100-byte SignedCapability token with scheme_byte=0x01 (EpochHmac).
        // EpochHmac expects exactly 52 bytes → length check fails.
        let result = verify_credential(&params, 0x01, &token, NOW);
        assert!(result.is_err(), "100-byte SignedCapability token must be rejected on EpochHmac scheme byte (wrong length)");
    }

    // ── 8. Replay via SpentSet ────────────────────────────────────────────────

    #[test]
    fn replay_via_spent_set_rejected() {
        let (sk, vk) = generate_capability_keypair();
        let nonce = random_nonce32();
        let params = make_sc_params(9, &vk, NOW + 3_600_000);
        let token = mint_signed_capability(&sk, 9, nonce);

        let cred_id = verify_credential(&params, 0x02, &token, NOW).unwrap();

        let mut spent = SpentSet::new();
        // First presentation: fresh.
        assert!(spent.record_and_check(9, cred_id), "first presentation must be accepted");
        // Second presentation (same nonce → same CredentialId): replay.
        assert!(!spent.record_and_check(9, cred_id), "second presentation must be rejected as replay");
    }
}

/// Full coverage for the `BlindRsaBatch` scheme (0x03) through `verify_credential`.
/// Tests also cover replay via `SpentSet`, multi-authority routing, and the
/// v3 preimage binding of `verify_material`.
#[cfg(test)]
mod blind_rsa_tests {
    use super::*;
    use mirage_blindtoken::{issuer_keygen, IssuerPublicKey, IssuerSecretKey};
    use signed_capability::{generate_capability_keypair, mint_signed_capability, random_nonce32};

    const NOW: u64 = 3_000_000_000_000;

    /// Assemble a 324-byte wire token from the blind token components.
    fn mint_blind_token(
        sk: &IssuerSecretKey,
        pk: &IssuerPublicKey,
        epoch_id: u32,
        msg: [u8; 32],
    ) -> Vec<u8> {
        let (blinded, state) = mirage_blindtoken::blind(pk, &msg).unwrap();
        let bsig = mirage_blindtoken::blind_sign(sk, &blinded).unwrap();
        let (sig, rand) = mirage_blindtoken::unblind(pk, &bsig, &state, &msg).unwrap();
        // Wire layout: epoch_id BE | msg | randomizer | signature
        let mut token = Vec::with_capacity(324);
        token.extend_from_slice(&epoch_id.to_be_bytes());
        token.extend_from_slice(&msg);
        token.extend_from_slice(&rand);
        token.extend_from_slice(&sig);
        token
    }

    fn blind_params(epoch_id: u32, not_after_ms: u64, pk: &IssuerPublicKey) -> CredentialParams {
        CredentialParams::single(
            1,
            CredentialScheme::BlindRsaBatch,
            vec![EpochEntry::with_verify_material(
                epoch_id,
                not_after_ms,
                pk.to_der().unwrap(),
            )],
        )
    }

    // ── 1. Happy path ────────────────────────────────────────────────────────

    #[test]
    fn blind_rsa_happy_path() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg = [0x55u8; 32];
        let params = blind_params(1, NOW + 3_600_000, &pk);
        let token = mint_blind_token(&sk, &pk, 1, msg);
        let cred_id = verify_credential(&params, 0x03, &token, NOW)
            .expect("valid blind token must verify");
        // The token message doubles as the CredentialId.
        assert_eq!(cred_id.as_bytes(), &msg, "CredentialId must equal token message");
    }

    // ── 2. Modified signature rejected ───────────────────────────────────────

    #[test]
    fn blind_rsa_wrong_msg_sig_rejected() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg = [0x11u8; 32];
        let params = blind_params(2, NOW + 3_600_000, &pk);
        let mut token = mint_blind_token(&sk, &pk, 2, msg);
        // Flip a byte in the signature region (bytes 68..324).
        token[100] ^= 0xFF;
        assert!(
            verify_credential(&params, 0x03, &token, NOW).is_err(),
            "flipped signature byte must be rejected"
        );
    }

    // ── 3. Unknown epoch rejected ────────────────────────────────────────────

    #[test]
    fn blind_rsa_unknown_epoch_rejected() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg = [0x22u8; 32];
        // params has epoch 1; token minted for epoch 99.
        let params = blind_params(1, NOW + 3_600_000, &pk);
        let token = mint_blind_token(&sk, &pk, 99, msg);
        assert!(
            verify_credential(&params, 0x03, &token, NOW).is_err(),
            "unknown epoch 99 must be rejected"
        );
    }

    // ── 4. Expired epoch rejected ────────────────────────────────────────────

    #[test]
    fn blind_rsa_expired_epoch_rejected() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg = [0x33u8; 32];
        // not_after_ms < NOW
        let params = blind_params(3, NOW - 1, &pk);
        let token = mint_blind_token(&sk, &pk, 3, msg);
        assert!(
            verify_credential(&params, 0x03, &token, NOW).is_err(),
            "expired epoch must be rejected"
        );
    }

    // ── 5. Wrong token length rejected ──────────────────────────────────────

    #[test]
    fn blind_rsa_wrong_length_rejected() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg = [0x44u8; 32];
        let params = blind_params(4, NOW + 3_600_000, &pk);
        let good_token = mint_blind_token(&sk, &pk, 4, msg);
        assert_eq!(good_token.len(), 324);

        // Truncated: 200 bytes.
        assert!(
            verify_credential(&params, 0x03, &good_token[..200], NOW).is_err(),
            "200-byte token must be rejected (too short)"
        );
        // Oversized: append one extra byte.
        let mut oversized = good_token.clone();
        oversized.push(0x00);
        assert!(
            verify_credential(&params, 0x03, &oversized, NOW).is_err(),
            "325-byte token must be rejected (too long)"
        );
    }

    // ── 6. Wrong issuer key rejected ─────────────────────────────────────────

    #[test]
    fn blind_rsa_wrong_issuer_rejected() {
        let (sk_a, pk_a) = issuer_keygen().unwrap();
        let (_sk_b, pk_b) = issuer_keygen().unwrap();
        let msg = [0x66u8; 32];
        // Token minted under issuer A; params carry issuer B's pubkey.
        let params = blind_params(5, NOW + 3_600_000, &pk_b);
        let token = mint_blind_token(&sk_a, &pk_a, 5, msg);
        assert!(
            verify_credential(&params, 0x03, &token, NOW).is_err(),
            "token minted under issuer A must be rejected when params carry issuer B"
        );
    }

    // ── 7. Replay via SpentSet ────────────────────────────────────────────────

    #[test]
    fn blind_rsa_replay_via_spent_set() {
        let (sk, pk) = issuer_keygen().unwrap();
        let msg = [0x77u8; 32];
        let params = blind_params(6, NOW + 3_600_000, &pk);
        let token = mint_blind_token(&sk, &pk, 6, msg);

        let cred_id = verify_credential(&params, 0x03, &token, NOW).unwrap();
        let mut spent = SpentSet::new();
        assert!(spent.record_and_check(6, cred_id), "first presentation must be accepted");
        assert!(!spent.record_and_check(6, cred_id), "second presentation must be rejected as replay");
    }

    // ── 8. Multi-authority routing ────────────────────────────────────────────

    #[test]
    fn blind_rsa_multi_authority() {
        // Two authorities in one CredentialParams:
        //   authority 0 — SignedCapability (Ed25519)
        //   authority 1 — BlindRsaBatch (RSA-2048)
        let (sc_sk, sc_vk) = generate_capability_keypair();
        let (rsa_sk, rsa_pk) = issuer_keygen().unwrap();

        let params = CredentialParams {
            generation: 1,
            authorities: vec![
                Authority::new(
                    AuthorityId(0),
                    CredentialScheme::SignedCapability,
                    vec![EpochEntry::with_secret(10, NOW + 3_600_000, sc_vk.to_bytes())],
                ),
                Authority::new(
                    AuthorityId(1),
                    CredentialScheme::BlindRsaBatch,
                    vec![EpochEntry::with_verify_material(
                        10,
                        NOW + 3_600_000,
                        rsa_pk.to_der().unwrap(),
                    )],
                ),
            ],
            operator_sig: None,
        };

        let sc_nonce = random_nonce32();
        let sc_token = mint_signed_capability(&sc_sk, 10, sc_nonce);
        let rsa_msg = [0x88u8; 32];
        let rsa_token = mint_blind_token(&rsa_sk, &rsa_pk, 10, rsa_msg);

        // SignedCapability token presented with scheme 0x02 → verifies under authority 0.
        assert!(
            verify_credential(&params, 0x02, &sc_token, NOW).is_ok(),
            "SignedCapability token must verify under authority 0"
        );
        // BlindRsaBatch token presented with scheme 0x03 → verifies under authority 1.
        assert!(
            verify_credential(&params, 0x03, &rsa_token, NOW).is_ok(),
            "BlindRsaBatch token must verify under authority 1"
        );
        // BlindRsaBatch token presented with scheme 0x02 → no BlindRsaBatch authority
        // matches scheme 0x02, the SignedCapability authority won't accept a 324-byte token.
        assert!(
            verify_credential(&params, 0x02, &rsa_token, NOW).is_err(),
            "BlindRsaBatch token on scheme 0x02 must be rejected (wrong length for SignedCapability)"
        );
        // SignedCapability token presented with scheme 0x03 → 100-byte token won't pass
        // the BlindRsaBatch 324-byte length check.
        assert!(
            verify_credential(&params, 0x03, &sc_token, NOW).is_err(),
            "SignedCapability token on scheme 0x03 must be rejected (wrong length for BlindRsaBatch)"
        );
    }

    // ── 9. preimage binds verify_material ─────────────────────────────────

    #[test]
    fn preimage_binds_verify_material() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let (_rsa_sk, rsa_pk) = issuer_keygen().unwrap();
        let mut params = blind_params(20, NOW + 3_600_000, &rsa_pk);

        let op_key = SigningKey::generate(&mut OsRng);
        params.sign(&op_key);

        // Freshly-signed params must verify.
        params.verify(&op_key.verifying_key()).expect("signature must verify over correct params");

        // Flip one byte in verify_material — preimage changes, signature breaks.
        params.authorities[0].epochs[0].verify_material[0] ^= 0xFF;
        assert!(
            params.verify(&op_key.verifying_key()).is_err(),
            "modified verify_material must cause signature verification to fail"
        );
    }
}

/// Coverage for the `RingMembership` scheme (0x04) through `verify_credential` —
/// the P2 wiring of the `mirage-ringmember` crate (Merkle root in
/// `verify_material`, DLEQ nullifier → CredentialId, SpentSet replay).
#[cfg(test)]
mod ring_membership_tests {
    use super::*;

    const NOW: u64 = 3_000_000_000_000;

    fn ring_params(epoch_id: u32, not_after_ms: u64, root: [u8; 32]) -> CredentialParams {
        CredentialParams::single(
            1,
            CredentialScheme::RingMembership,
            vec![EpochEntry::with_verify_material(epoch_id, not_after_ms, root.to_vec())],
        )
    }

    #[test]
    fn ring_membership_verify_and_replay() {
        let epoch_id = 7u32;
        let (sk0, pk0) = mirage_ringmember::member_keygen();
        let (_sk1, pk1) = mirage_ringmember::member_keygen();
        let (root, proofs) = mirage_ringmember::issuer_build_tree(&[pk0, pk1]).unwrap();
        let transcript = epoch_id.to_le_bytes();
        let token = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, 0).encode();

        let params = ring_params(epoch_id, NOW + 3_600_000, root);
        let cred_id = verify_credential(&params, 0x04, &token, NOW)
            .expect("ring membership token must verify");

        let mut spent = SpentSet::new();
        assert!(spent.record_and_check(epoch_id, cred_id), "first presentation accepted");
        assert!(!spent.record_and_check(epoch_id, cred_id), "replay (same nullifier) rejected");
    }

    #[test]
    fn ring_membership_wrong_root_rejected() {
        let epoch_id = 8u32;
        let (sk0, pk0) = mirage_ringmember::member_keygen();
        let (_root, proofs) = mirage_ringmember::issuer_build_tree(&[pk0]).unwrap();
        let transcript = epoch_id.to_le_bytes();
        let token = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, 0).encode();

        // Publish an unrelated root → Merkle check must fail.
        let (_osk, opk) = mirage_ringmember::member_keygen();
        let (other_root, _) = mirage_ringmember::issuer_build_tree(&[opk]).unwrap();
        let params = ring_params(epoch_id, NOW + 3_600_000, other_root);
        assert!(verify_credential(&params, 0x04, &token, NOW).is_err(), "wrong root must reject");
    }

    #[test]
    fn ring_membership_expired_epoch_rejected() {
        let epoch_id = 9u32;
        let (sk0, pk0) = mirage_ringmember::member_keygen();
        let (root, proofs) = mirage_ringmember::issuer_build_tree(&[pk0]).unwrap();
        let transcript = epoch_id.to_le_bytes();
        let token = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, 0).encode();
        // not_after in the past → find_epoch rejects.
        let params = ring_params(epoch_id, NOW - 1, root);
        assert!(verify_credential(&params, 0x04, &token, NOW).is_err(), "expired epoch must reject");
    }

    /// Bounded-budget: verify_material = root||max_dials admits nf_index up to
    /// max_dials, each producing a distinct nullifier (distinct SpentSet entry),
    /// while an index at the budget is rejected. This is the pooled-client case:
    /// N concurrent dials, N distinct nullifiers, no replay rejection.
    #[test]
    fn ring_membership_bounded_budget_indices() {
        let epoch_id = 21u32;
        let (sk0, pk0) = mirage_ringmember::member_keygen();
        let (_sk1, pk1) = mirage_ringmember::member_keygen();
        let (root, proofs) = mirage_ringmember::issuer_build_tree(&[pk0, pk1]).unwrap();
        let transcript = epoch_id.to_le_bytes();

        // Publish root || max_dials=3.
        let mut vm = root.to_vec();
        vm.extend_from_slice(&3u32.to_le_bytes());
        let params = CredentialParams::single(
            1,
            CredentialScheme::RingMembership,
            vec![EpochEntry::with_verify_material(epoch_id, NOW + 3_600_000, vm)],
        );

        let mut spent = SpentSet::new();
        // indices 0,1,2 all admitted, each a distinct nullifier → all accepted.
        for i in 0u32..3 {
            let tok = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, i).encode();
            let cred_id = verify_credential(&params, 0x04, &tok, NOW)
                .unwrap_or_else(|e| panic!("index {i} must verify within budget: {e}"));
            assert!(spent.record_and_check(epoch_id, cred_id), "index {i} distinct nullifier accepted");
        }
        // index 3 is at the budget → rejected.
        let over = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, 3).encode();
        assert!(
            verify_credential(&params, 0x04, &over, NOW).is_err(),
            "nf_index == max_dials must reject"
        );
    }

    /// Dial-context (exit-id) binding: a proof minted for exit A verifies at
    /// exit A but is rejected at exit B. Closes lateral replay by a malicious
    /// exit that lifts a token and re-presents it to a different exit.
    #[test]
    fn ring_membership_dial_context_binding() {
        let epoch_id = 31u32;
        let (sk0, pk0) = mirage_ringmember::member_keygen();
        let (_sk1, pk1) = mirage_ringmember::member_keygen();
        let (root, proofs) = mirage_ringmember::issuer_build_tree(&[pk0, pk1]).unwrap();
        let params = ring_params(epoch_id, NOW + 3_600_000, root);

        let exit_a = b"exit-node-A";
        let exit_b = b"exit-node-B";

        // Client mints against exit A: transcript = epoch_id_le || exit_a.
        let mut transcript = epoch_id.to_le_bytes().to_vec();
        transcript.extend_from_slice(exit_a);
        let token = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, 0).encode();

        // Verifies at exit A (matching dial_context).
        verify_credential_bound(&params, 0x04, &token, NOW, exit_a)
            .expect("ring token must verify at its intended exit");

        // Rejected at exit B (different dial_context → DLEQ challenge diverges).
        assert!(
            verify_credential_bound(&params, 0x04, &token, NOW, exit_b).is_err(),
            "ring token minted for exit A must be rejected at exit B (lateral replay)"
        );
    }

    #[test]
    fn ring_membership_bad_verify_material_len_rejected() {
        let epoch_id = 10u32;
        let (sk0, pk0) = mirage_ringmember::member_keygen();
        let (_root, proofs) = mirage_ringmember::issuer_build_tree(&[pk0]).unwrap();
        let transcript = epoch_id.to_le_bytes();
        let token = mirage_ringmember::prove_membership(&sk0, &proofs[0], epoch_id, &transcript, 0).encode();
        // verify_material that is not a 32-byte root → fail-closed.
        let params = CredentialParams::single(
            1,
            CredentialScheme::RingMembership,
            vec![EpochEntry::with_verify_material(epoch_id, NOW + 3_600_000, vec![0u8; 10])],
        );
        assert!(verify_credential(&params, 0x04, &token, NOW).is_err(), "non-32B root must reject");
    }
}
