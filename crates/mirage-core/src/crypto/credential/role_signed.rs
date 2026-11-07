//! `RoleSigned` (`CredentialScheme::RoleSigned = 0x05`) — the self-presented,
//! self-vouched credential an operator-admitted, non-relay role uses to dial
//! as itself.
//!
//! See `docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Credentials — the
//! exit admits an edge-owned chain by the edge's own operator-signed
//! identity". Every other scheme in this module's sibling arms
//! ([`super::epoch_hmac`], [`super::signed_capability`]) needs a THIRD party
//! (opbox) to mint the token a node presents; `RoleSigned` is for the case
//! where the credential HOLDER is also the authority that vouches for it —
//! today that is an Edge box dialling into the mesh as the owner of its own
//! onion chains, never as a relay hop.
//!
//! # Two signatures, never one
//!
//! 1. **`operator_sig`** — the operator/group's Ed25519 signature over a
//!    five-field identity excerpt (`self_id`, `mesh_id`, `role`,
//!    `signing_pubkey_hex`, `identity_not_after_ms`). Proves this excerpt was
//!    really issued to a [`ServiceRole::Edge`] box by the operator/group,
//!    with no dependency on the verifier holding a live copy of
//!    `declared_identities` — the same property
//!    [`crate::identity::DeclaredIdentity`] already has, just over a
//!    narrower, purpose-built preimage (see
//!    [`excerpt_signing_bytes`] — NOT the same bytes
//!    [`crate::identity::DeclaredIdentity::signing_bytes`] signs, which
//!    additionally covers `roles`, `role_keys`, `faces` and more that a
//!    dial's verifier has no business parsing).
//! 2. **`dial_sig`** — a per-dial Ed25519 signature by the excerpt's own
//!    `signing_pubkey_hex`, over `self_id || nonce || ts_ms || exit_node_id
//!    || mesh_id`. Proves THIS dial was made by the actual holder of that
//!    role's private signing key, bound to this specific exit's node id —
//!    mirroring the exact dial-context-binding reasoning
//!    [`super::verify_credential_bound`]'s own doc states for
//!    `RingMembership`: "closing lateral replay by a malicious exit that
//!    lifts a token and re-presents it to a different exit".
//!
//! `identity_not_after_ms` bounds how long a captured excerpt is usable —
//! **owner ruling 2026-09-24: the bound is the subscription.** It is the
//! customer's paid-through time; a renewed payment re-issues the excerpt, a
//! lapsed one lets it expire at the exit with no live revocation check.
//!
//! # Why `exit_node_id` rides the wire, not only the signature preimage
//!
//! [`RoleSignedToken::exit_node_id`] is carried in the clear (and is ALSO
//! folded into [`dial_signing_bytes`]'s preimage, so it cannot be edited
//! without invalidating `dial_sig`). This is deliberately one field, not
//! zero: without it, "this token was minted for a different exit" and "this
//! token's signature was tampered with" are cryptographically
//! indistinguishable — both fail the same `verify_strict` call. Carrying it
//! explicitly lets [`verify_role_signed`] reject a wrong-exit presentation
//! with [`RoleSignedError::WrongExitBinding`] as a cheap, named, pre-crypto
//! check, while the signature still refuses to trust an edited value that
//! was never signed for.
//!
//! # Replay protection
//!
//! Bounding `ts_ms` to [`ROLE_SIGNED_TS_WINDOW_MS`] is this module's whole
//! job. Turning "fresh" into "single-use" is a per-exit, TTL-bounded
//! seen-nonce cache — the node's job, a later step; [`verify_role_signed`]
//! hands back the token's `nonce` in [`RoleSignedVerified`] for exactly that
//! cache to key on.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;
use uuid::Uuid;

use crate::capsule::RoleSlice;
use crate::identity::{ServiceRole, SignatureHex};

// ── Constants ────────────────────────────────────────────────────────────

/// Domain label for [`excerpt_signing_bytes`]'s preimage.
const ROLE_SIGNED_EXCERPT_LABEL: &[u8] = b"mirage-role-signed-excerpt-v1\0";
/// Domain label for [`dial_signing_bytes`]'s preimage.
const ROLE_SIGNED_DIAL_LABEL: &[u8] = b"mirage-role-signed-dial-v1\0";

/// Half-width of the timestamp freshness window `verify_role_signed` checks
/// `ts_ms` against, in milliseconds. Proposed ±60s, per the plan.
pub const ROLE_SIGNED_TS_WINDOW_MS: u64 = 60_000;

// ── Errors ───────────────────────────────────────────────────────────────

/// Everything [`verify_role_signed`] (and the codec it rides on) can reject
/// a token for. Each variant is independently reachable and independently
/// testable — see this module's own test suite.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoleSignedError {
    /// The operator/group signature over the five-field identity excerpt
    /// does not verify — the excerpt was tampered with, or never really
    /// issued by the pinned operator/group key.
    #[error("role_signed: operator signature over the identity excerpt does not verify")]
    BadOperatorSig,
    /// `now_ms` is past `identity_not_after_ms` — the bound is the
    /// customer's subscription; see this module's own doc.
    #[error(
        "role_signed: identity excerpt expired (identity_not_after_ms={identity_not_after_ms}, now_ms={now_ms})"
    )]
    ExpiredIdentity { identity_not_after_ms: u64, now_ms: u64 },
    /// The excerpt names a role other than [`ServiceRole::Edge`] — the only
    /// role this scheme admits at an exit today.
    #[error("role_signed: excerpt names role {role}, the exit requires ServiceRole::Edge")]
    WrongRole { role: ServiceRole },
    /// The token was minted for a different exit's node id than the one
    /// verifying it — see this module's own doc on why this is a distinct,
    /// cheap, pre-crypto check.
    #[error(
        "role_signed: token names exit {token_exit}, this exit is {this_exit}"
    )]
    WrongExitBinding { token_exit: String, this_exit: String },
    /// `ts_ms` falls outside the `±`[`ROLE_SIGNED_TS_WINDOW_MS`] window
    /// around `now_ms`.
    #[error(
        "role_signed: ts_ms={ts_ms} is outside the ±{window_ms}ms window around now_ms={now_ms}"
    )]
    StaleTimestamp { ts_ms: u64, now_ms: u64, window_ms: u64 },
    /// The per-dial Ed25519 signature does not verify against the excerpt's
    /// own `signing_pubkey_hex`.
    #[error("role_signed: per-dial signature does not verify against the excerpt's signing key")]
    BadDialSig,
    /// The token's bytes are structurally malformed — truncated, an unknown
    /// role byte, invalid UTF-8, bad hex, or a mint-time precondition this
    /// module refuses to silently paper over (e.g. a role slice with no
    /// signing key).
    #[error("role_signed: {0}")]
    Malformed(String),
}

// ── Identity excerpt ─────────────────────────────────────────────────────

/// The operator/group-signed identity excerpt an Edge box presents at every
/// dial. Minted once, at provisioning, by whoever holds the operator/group
/// signing key ([`sign_role_signed_excerpt`]); the edge re-uses it for many
/// dials via [`mint_role_signed_token`] — only the per-dial `nonce`/`ts_ms`/
/// `dial_sig` change between dials.
#[derive(Debug, Clone)]
pub struct RoleSignedIdentityExcerpt {
    pub self_id: Uuid,
    pub mesh_id: String,
    pub role: ServiceRole,
    /// Hex-encoded Ed25519 public half of the role's own signing key — the
    /// SAME key [`crate::identity::RolePublicKeys::signing_pubkey_hex`]
    /// gossips for this role.
    pub signing_pubkey_hex: String,
    /// Unix-ms after which this excerpt must not be honoured. Bound to the
    /// customer's subscription paid-through time — see this module's own
    /// doc.
    pub identity_not_after_ms: u64,
    pub operator_sig: SignatureHex,
}

/// Operator/group side: mint a fresh identity excerpt for a role.
///
/// Signs exactly the five fields the exit checks — deliberately NOT
/// [`crate::identity::DeclaredIdentity::signing_bytes`]'s much larger
/// preimage, which also covers `roles`, `role_keys`, `faces` and more that a
/// dial's verifier never needs to parse. See this module's own doc, "Two
/// signatures, never one".
///
/// Fails only when `role` cannot be represented on this scheme's wire —
/// see [`role_to_wire_byte`].
pub fn sign_role_signed_excerpt(
    operator_signing_key: &SigningKey,
    self_id: Uuid,
    mesh_id: &str,
    role: ServiceRole,
    signing_pubkey_hex: &str,
    identity_not_after_ms: u64,
) -> Result<RoleSignedIdentityExcerpt, RoleSignedError> {
    let preimage = excerpt_signing_bytes(self_id, mesh_id, role, signing_pubkey_hex, identity_not_after_ms)?;
    let sig = operator_signing_key.sign(&preimage);
    Ok(RoleSignedIdentityExcerpt {
        self_id,
        mesh_id: mesh_id.to_string(),
        role,
        signing_pubkey_hex: signing_pubkey_hex.to_string(),
        identity_not_after_ms,
        operator_sig: SignatureHex::from_signature(&sig),
    })
}

// ── Token ────────────────────────────────────────────────────────────────

/// The per-dial token an Edge box presents in the V9 hello's credential slot
/// (`V9ClientHello.cred_scheme = CredentialScheme::RoleSigned as u8`,
/// followed by the `[2B len BE][token]` frame every scheme shares — see
/// `mirage_protocol::driver::ClientCredential`'s own doc).
///
/// Flattens [`RoleSignedIdentityExcerpt`]'s five fields with the per-dial
/// fields (`exit_node_id`, `nonce`, `ts_ms`, `dial_sig`) into one wire
/// struct — the excerpt is re-used across many dials in memory
/// ([`mint_role_signed_token`] takes it by reference), but what actually
/// rides the wire is one self-contained token per dial.
#[derive(Debug, Clone)]
pub struct RoleSignedToken {
    pub self_id: Uuid,
    pub mesh_id: String,
    pub role: ServiceRole,
    pub signing_pubkey_hex: String,
    pub identity_not_after_ms: u64,
    pub operator_sig: SignatureHex,
    /// The exit node id this dial is bound to — see this module's own doc,
    /// "Why `exit_node_id` rides the wire, not only the signature preimage".
    pub exit_node_id: String,
    pub nonce: [u8; 16],
    pub ts_ms: u64,
    /// `Ed25519(signing_privkey, self_id||nonce||ts_ms||exit_node_id||mesh_id)`.
    pub dial_sig: [u8; 64],
}

impl RoleSignedToken {
    /// Wire-encode. Fails only if `role` is not representable on this wire
    /// slot ([`role_to_wire_byte`]) or `operator_sig` is not valid hex for a
    /// 64-byte signature — both indicate a token that could never have come
    /// out of [`mint_role_signed_token`] in the first place.
    pub fn encode(&self) -> Result<Vec<u8>, RoleSignedError> {
        let role_byte = role_to_wire_byte(&self.role)
            .ok_or_else(|| RoleSignedError::WrongRole { role: self.role })?;
        let op_sig = self
            .operator_sig
            .to_signature()
            .map_err(|_| RoleSignedError::BadOperatorSig)?;

        let mut buf = Vec::new();
        buf.extend_from_slice(self.self_id.as_bytes());
        write_len_prefixed(&mut buf, self.mesh_id.as_bytes());
        buf.push(role_byte);
        write_len_prefixed(&mut buf, self.signing_pubkey_hex.as_bytes());
        buf.extend_from_slice(&self.identity_not_after_ms.to_be_bytes());
        buf.extend_from_slice(&op_sig.to_bytes());
        write_len_prefixed(&mut buf, self.exit_node_id.as_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.ts_ms.to_be_bytes());
        buf.extend_from_slice(&self.dial_sig);
        Ok(buf)
    }

    /// Wire-decode. Every short read or unrecognised role byte fails closed
    /// with [`RoleSignedError::Malformed`] — never a panic.
    pub fn decode(bytes: &[u8]) -> Result<Self, RoleSignedError> {
        let mut off = 0usize;

        let self_id_bytes = read_bytes(bytes, &mut off, 16)?;
        let self_id = Uuid::from_bytes(self_id_bytes.try_into().expect("16 bytes"));

        let mesh_id = read_len_prefixed_string(bytes, &mut off)?;

        let role_byte = read_u8(bytes, &mut off)?;
        let role = role_from_wire_byte(role_byte)
            .ok_or_else(|| RoleSignedError::Malformed(format!("unknown role byte 0x{role_byte:02x}")))?;

        let signing_pubkey_hex = read_len_prefixed_string(bytes, &mut off)?;
        let identity_not_after_ms = read_u64_be(bytes, &mut off)?;

        let op_sig_bytes = read_bytes(bytes, &mut off, 64)?;
        let op_sig_arr: [u8; 64] = op_sig_bytes.try_into().expect("64 bytes");
        let operator_sig = SignatureHex::from_signature(&Signature::from_bytes(&op_sig_arr));

        let exit_node_id = read_len_prefixed_string(bytes, &mut off)?;

        let nonce_bytes = read_bytes(bytes, &mut off, 16)?;
        let nonce: [u8; 16] = nonce_bytes.try_into().expect("16 bytes");

        let ts_ms = read_u64_be(bytes, &mut off)?;

        let dial_sig_bytes = read_bytes(bytes, &mut off, 64)?;
        let dial_sig: [u8; 64] = dial_sig_bytes.try_into().expect("64 bytes");

        Ok(Self {
            self_id,
            mesh_id,
            role,
            signing_pubkey_hex,
            identity_not_after_ms,
            operator_sig,
            exit_node_id,
            nonce,
            ts_ms,
            dial_sig,
        })
    }
}

/// Edge side: mint a fresh [`RoleSignedToken`] for one dial, given the
/// box's own [`RoleSlice`] (for the per-dial signing key) and the
/// operator-signed excerpt it already holds.
///
/// Fails if `slice`/`excerpt` do not name [`ServiceRole::Edge`], if `slice`
/// carries no signing key, or if `slice`'s signing key does not match the
/// public key the excerpt itself claims (a slice/excerpt pair that were
/// never issued together).
pub fn mint_role_signed_token(
    slice: &RoleSlice,
    excerpt: &RoleSignedIdentityExcerpt,
    exit_node_id: &str,
    ts_ms: u64,
) -> Result<RoleSignedToken, RoleSignedError> {
    if slice.role != ServiceRole::Edge {
        return Err(RoleSignedError::WrongRole { role: slice.role });
    }
    if excerpt.role != ServiceRole::Edge {
        return Err(RoleSignedError::WrongRole { role: excerpt.role });
    }

    let signing_secret = slice
        .signing_secret()
        .ok_or_else(|| RoleSignedError::Malformed("edge role slice carries no signing key".to_string()))?;
    let signing_key = SigningKey::from_bytes(&signing_secret);

    let actual_pub_hex = hex::encode(signing_key.verifying_key().to_bytes());
    if actual_pub_hex != excerpt.signing_pubkey_hex {
        return Err(RoleSignedError::Malformed(
            "role slice's signing pubkey does not match the excerpt it is dialling under".to_string(),
        ));
    }

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);

    let preimage = dial_signing_bytes(excerpt.self_id, &nonce, ts_ms, exit_node_id, &excerpt.mesh_id);
    let dial_sig = signing_key.sign(&preimage).to_bytes();

    Ok(RoleSignedToken {
        self_id: excerpt.self_id,
        mesh_id: excerpt.mesh_id.clone(),
        role: excerpt.role,
        signing_pubkey_hex: excerpt.signing_pubkey_hex.clone(),
        identity_not_after_ms: excerpt.identity_not_after_ms,
        operator_sig: excerpt.operator_sig.clone(),
        exit_node_id: exit_node_id.to_string(),
        nonce,
        ts_ms,
        dial_sig,
    })
}

// ── Verify ───────────────────────────────────────────────────────────────

/// What a successfully-verified token hands back to its caller — just
/// enough for the exit to build its own replay cache. See this module's own
/// doc, "Replay protection".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleSignedVerified {
    pub self_id: Uuid,
    pub nonce: [u8; 16],
}

/// Exit side: verify a presented [`RoleSignedToken`].
///
/// `operator_pub` is the pinned operator/group verifying key (the same
/// anchor every other operator-signed fact in the fleet checks against).
/// `exit_node_id` is the verifying exit's OWN node id — never taken from the
/// token. `now_ms` drives both the identity-expiry and the timestamp-window
/// checks.
///
/// Checks run in the order the plan's own "two signatures, never one"
/// section states: `operator_sig` first (nothing else in the excerpt can be
/// trusted before that holds), then the excerpt's own content (role,
/// expiry), then the per-dial context (exit binding, timestamp), then
/// `dial_sig` last — the only check that costs a second Ed25519 verify.
pub fn verify_role_signed(
    token: &RoleSignedToken,
    operator_pub: &VerifyingKey,
    exit_node_id: &str,
    now_ms: u64,
) -> Result<RoleSignedVerified, RoleSignedError> {
    let excerpt_bytes = excerpt_signing_bytes(
        token.self_id,
        &token.mesh_id,
        token.role,
        &token.signing_pubkey_hex,
        token.identity_not_after_ms,
    )?;
    let op_sig = token
        .operator_sig
        .to_signature()
        .map_err(|_| RoleSignedError::BadOperatorSig)?;
    operator_pub
        .verify_strict(&excerpt_bytes, &op_sig)
        .map_err(|_| RoleSignedError::BadOperatorSig)?;

    if token.role != ServiceRole::Edge {
        return Err(RoleSignedError::WrongRole { role: token.role });
    }

    if now_ms > token.identity_not_after_ms {
        return Err(RoleSignedError::ExpiredIdentity {
            identity_not_after_ms: token.identity_not_after_ms,
            now_ms,
        });
    }

    if token.exit_node_id != exit_node_id {
        return Err(RoleSignedError::WrongExitBinding {
            token_exit: token.exit_node_id.clone(),
            this_exit: exit_node_id.to_string(),
        });
    }

    let delta = now_ms.abs_diff(token.ts_ms);
    if delta > ROLE_SIGNED_TS_WINDOW_MS {
        return Err(RoleSignedError::StaleTimestamp {
            ts_ms: token.ts_ms,
            now_ms,
            window_ms: ROLE_SIGNED_TS_WINDOW_MS,
        });
    }

    let signing_pub = decode_signing_pubkey_hex(&token.signing_pubkey_hex)?;
    let dial_bytes = dial_signing_bytes(token.self_id, &token.nonce, token.ts_ms, &token.exit_node_id, &token.mesh_id);
    let dial_sig = Signature::from_bytes(&token.dial_sig);
    signing_pub
        .verify_strict(&dial_bytes, &dial_sig)
        .map_err(|_| RoleSignedError::BadDialSig)?;

    Ok(RoleSignedVerified {
        self_id: token.self_id,
        nonce: token.nonce,
    })
}

fn decode_signing_pubkey_hex(hex_str: &str) -> Result<VerifyingKey, RoleSignedError> {
    let bytes = hex::decode(hex_str).map_err(|_| RoleSignedError::BadDialSig)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| RoleSignedError::BadDialSig)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| RoleSignedError::BadDialSig)
}

// ── Preimages ────────────────────────────────────────────────────────────

/// `operator_sig`'s preimage — see this module's own doc, "Two signatures,
/// never one", item 1.
fn excerpt_signing_bytes(
    self_id: Uuid,
    mesh_id: &str,
    role: ServiceRole,
    signing_pubkey_hex: &str,
    identity_not_after_ms: u64,
) -> Result<Vec<u8>, RoleSignedError> {
    let role_byte = role_to_wire_byte(&role).ok_or(RoleSignedError::WrongRole { role })?;
    let mut buf = Vec::new();
    buf.extend_from_slice(ROLE_SIGNED_EXCERPT_LABEL);
    buf.extend_from_slice(self_id.as_bytes());
    write_len_prefixed(&mut buf, mesh_id.as_bytes());
    buf.push(role_byte);
    write_len_prefixed(&mut buf, signing_pubkey_hex.as_bytes());
    buf.extend_from_slice(&identity_not_after_ms.to_be_bytes());
    Ok(buf)
}

/// `dial_sig`'s preimage — see this module's own doc, "Two signatures,
/// never one", item 2.
fn dial_signing_bytes(self_id: Uuid, nonce: &[u8; 16], ts_ms: u64, exit_node_id: &str, mesh_id: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(ROLE_SIGNED_DIAL_LABEL);
    buf.extend_from_slice(self_id.as_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&ts_ms.to_be_bytes());
    write_len_prefixed(&mut buf, exit_node_id.as_bytes());
    write_len_prefixed(&mut buf, mesh_id.as_bytes());
    buf
}

// ── Role wire byte ───────────────────────────────────────────────────────
//
// A small, SEPARATE byte scheme scoped to this module's own wire slot — not
// `ServiceRole`'s own `as_tag()`/`Display`, because `ServiceRole::Node`
// carries a `NodeEpoch` this token has no field for, and every unit variant
// here needs a STABLE, forever-assigned byte the same way `CredentialScheme`
// itself does. Only `Edge` is ever legitimately minted today; the rest are
// assigned so the scheme reads honestly as "reusable by any future
// operator-admitted, non-relay role" (the plan's own words) without a wire
// break the day a second role needs it. `Node` is deliberately UNREPRESENTABLE
// here — see the doc above.

fn role_to_wire_byte(role: &ServiceRole) -> Option<u8> {
    match role {
        ServiceRole::Edge => Some(0x01),
        ServiceRole::Monitor => Some(0x02),
        ServiceRole::Sentry => Some(0x03),
        ServiceRole::Mshd => Some(0x04),
        ServiceRole::Sentinel => Some(0x05),
        ServiceRole::Secd => Some(0x06),
        ServiceRole::DbWorker => Some(0x07),
        ServiceRole::Warden => Some(0x08),
        ServiceRole::Operator => Some(0x09),
        ServiceRole::Perimeter => Some(0x0A),
        ServiceRole::BackOffice => Some(0x0B),
        ServiceRole::Node { .. } => None,
    }
}

fn role_from_wire_byte(byte: u8) -> Option<ServiceRole> {
    match byte {
        0x01 => Some(ServiceRole::Edge),
        0x02 => Some(ServiceRole::Monitor),
        0x03 => Some(ServiceRole::Sentry),
        0x04 => Some(ServiceRole::Mshd),
        0x05 => Some(ServiceRole::Sentinel),
        0x06 => Some(ServiceRole::Secd),
        0x07 => Some(ServiceRole::DbWorker),
        0x08 => Some(ServiceRole::Warden),
        0x09 => Some(ServiceRole::Operator),
        0x0A => Some(ServiceRole::Perimeter),
        0x0B => Some(ServiceRole::BackOffice),
        _ => None,
    }
}

// ── Byte-buffer codec helpers ────────────────────────────────────────────

fn write_len_prefixed(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_u8(buf: &[u8], off: &mut usize) -> Result<u8, RoleSignedError> {
    let b = buf
        .get(*off)
        .copied()
        .ok_or_else(|| RoleSignedError::Malformed("truncated: expected 1 more byte".to_string()))?;
    *off += 1;
    Ok(b)
}

fn read_bytes<'a>(buf: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8], RoleSignedError> {
    let end = off
        .checked_add(n)
        .ok_or_else(|| RoleSignedError::Malformed("length overflow".to_string()))?;
    let slice = buf
        .get(*off..end)
        .ok_or_else(|| RoleSignedError::Malformed(format!("truncated: expected {n} more bytes")))?;
    *off = end;
    Ok(slice)
}

fn read_u32_be(buf: &[u8], off: &mut usize) -> Result<u32, RoleSignedError> {
    let b = read_bytes(buf, off, 4)?;
    Ok(u32::from_be_bytes(b.try_into().expect("4 bytes")))
}

fn read_u64_be(buf: &[u8], off: &mut usize) -> Result<u64, RoleSignedError> {
    let b = read_bytes(buf, off, 8)?;
    Ok(u64::from_be_bytes(b.try_into().expect("8 bytes")))
}

fn read_len_prefixed_string(buf: &[u8], off: &mut usize) -> Result<String, RoleSignedError> {
    let len = read_u32_be(buf, off)? as usize;
    let b = read_bytes(buf, off, len)?;
    String::from_utf8(b.to_vec()).map_err(|_| RoleSignedError::Malformed("invalid utf-8".to_string()))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::RoleSlice;

    const EXIT_A: &str = "exit-node-a";
    const EXIT_B: &str = "exit-node-b";
    const NOW: u64 = 2_000_000_000_000;

    struct Fixture {
        operator_signing: SigningKey,
        edge_slice: RoleSlice,
        excerpt: RoleSignedIdentityExcerpt,
    }

    fn make_fixture(role: ServiceRole, identity_not_after_ms: u64) -> Fixture {
        let operator_signing = SigningKey::generate(&mut OsRng);
        let edge_signing = SigningKey::generate(&mut OsRng);
        let edge_signing_pub_hex = hex::encode(edge_signing.verifying_key().to_bytes());

        let edge_slice = RoleSlice {
            role,
            wire_privkey: [0x11u8; 32],
            signing_privkey: Some(edge_signing.to_bytes()),
            wire_pubkey_hex: "aa".repeat(32),
            signing_pubkey_hex: Some(edge_signing_pub_hex.clone()),
        };

        let excerpt = sign_role_signed_excerpt(
            &operator_signing,
            Uuid::new_v4(),
            "v3-staging",
            role,
            &edge_signing_pub_hex,
            identity_not_after_ms,
        )
        .expect("Edge role must be encodable");

        Fixture { operator_signing, edge_slice, excerpt }
    }

    fn valid_token(fixture: &Fixture) -> RoleSignedToken {
        mint_role_signed_token(&fixture.edge_slice, &fixture.excerpt, EXIT_A, NOW)
            .expect("mint must succeed for a properly matched slice/excerpt pair")
    }

    // ── Round-trip ───────────────────────────────────────────────────────

    #[test]
    fn encode_decode_roundtrip() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let token = valid_token(&fixture);

        let wire = token.encode().expect("encode must succeed");
        let decoded = RoleSignedToken::decode(&wire).expect("decode must succeed");

        assert_eq!(decoded.self_id, token.self_id);
        assert_eq!(decoded.mesh_id, token.mesh_id);
        assert_eq!(decoded.role, token.role);
        assert_eq!(decoded.signing_pubkey_hex, token.signing_pubkey_hex);
        assert_eq!(decoded.identity_not_after_ms, token.identity_not_after_ms);
        assert_eq!(decoded.exit_node_id, token.exit_node_id);
        assert_eq!(decoded.nonce, token.nonce);
        assert_eq!(decoded.ts_ms, token.ts_ms);
        assert_eq!(decoded.dial_sig, token.dial_sig);
        assert_eq!(
            decoded.operator_sig.to_signature().unwrap().to_bytes(),
            token.operator_sig.to_signature().unwrap().to_bytes()
        );

        // Re-encoding the decoded token must reproduce the exact same bytes.
        assert_eq!(decoded.encode().expect("re-encode"), wire);
    }

    #[test]
    fn decode_truncated_bytes_is_malformed_not_a_panic() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let token = valid_token(&fixture);
        let wire = token.encode().expect("encode");

        for cut in [0usize, 1, 16, 20, wire.len() - 1] {
            let result = RoleSignedToken::decode(&wire[..cut]);
            assert!(result.is_err(), "truncation at {cut} bytes must be rejected, not panic");
        }
    }

    // ── Happy path ───────────────────────────────────────────────────────

    #[test]
    fn a_valid_token_verifies() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let token = valid_token(&fixture);

        let verified = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW)
            .expect("a properly minted token must verify");

        assert_eq!(verified.self_id, fixture.excerpt.self_id);
        assert_eq!(verified.nonce, token.nonce);
    }

    #[test]
    fn a_valid_token_survives_the_wire_round_trip_and_still_verifies() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let token = valid_token(&fixture);
        let wire = token.encode().expect("encode");
        let decoded = RoleSignedToken::decode(&wire).expect("decode");

        verify_role_signed(&decoded, &fixture.operator_signing.verifying_key(), EXIT_A, NOW)
            .expect("the decoded token must still verify");
    }

    // ── Named failures ───────────────────────────────────────────────────

    #[test]
    fn tampered_excerpt_is_rejected_as_bad_operator_sig() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let mut token = valid_token(&fixture);
        token.mesh_id.push('!'); // any excerpt-covered field, post-signature

        let result = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW);
        assert_eq!(result, Err(RoleSignedError::BadOperatorSig));
    }

    #[test]
    fn expired_identity_is_rejected() {
        // not_after_ms in the past relative to NOW.
        let fixture = make_fixture(ServiceRole::Edge, NOW - 1);
        let token = valid_token(&fixture);

        let result = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW);
        assert_eq!(
            result,
            Err(RoleSignedError::ExpiredIdentity { identity_not_after_ms: NOW - 1, now_ms: NOW })
        );
    }

    #[test]
    fn role_other_than_edge_is_rejected() {
        // Monitor is encodable on this wire (role_to_wire_byte), but only
        // Edge is admitted at the exit — and mint_role_signed_token itself
        // already refuses to build a non-Edge token (see
        // mint_refuses_a_non_edge_slice), so this builds the token by hand
        // to exercise verify_role_signed's OWN role check independently.
        let fixture = make_fixture(ServiceRole::Monitor, NOW + 3_600_000);
        let edge_signing = SigningKey::from_bytes(
            &fixture.edge_slice.signing_privkey.expect("fixture always carries a signing key"),
        );
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let preimage = dial_signing_bytes(fixture.excerpt.self_id, &nonce, NOW, EXIT_A, &fixture.excerpt.mesh_id);
        let token = RoleSignedToken {
            self_id: fixture.excerpt.self_id,
            mesh_id: fixture.excerpt.mesh_id.clone(),
            role: fixture.excerpt.role,
            signing_pubkey_hex: fixture.excerpt.signing_pubkey_hex.clone(),
            identity_not_after_ms: fixture.excerpt.identity_not_after_ms,
            operator_sig: fixture.excerpt.operator_sig.clone(),
            exit_node_id: EXIT_A.to_string(),
            nonce,
            ts_ms: NOW,
            dial_sig: edge_signing.sign(&preimage).to_bytes(),
        };

        let result = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW);
        assert_eq!(result, Err(RoleSignedError::WrongRole { role: ServiceRole::Monitor }));
    }

    #[test]
    fn dial_signature_by_another_key_is_rejected() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let mut token = valid_token(&fixture);

        // Sign the dial preimage with an UNRELATED key, keeping every other
        // field (including exit_node_id) exactly as minted.
        let impostor = SigningKey::generate(&mut OsRng);
        let preimage = dial_signing_bytes(token.self_id, &token.nonce, token.ts_ms, &token.exit_node_id, &token.mesh_id);
        token.dial_sig = impostor.sign(&preimage).to_bytes();

        let result = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW);
        assert_eq!(result, Err(RoleSignedError::BadDialSig));
    }

    #[test]
    fn a_token_minted_for_another_exit_is_rejected_as_wrong_exit_binding() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        // Minted for EXIT_A, presented to EXIT_B.
        let token = mint_role_signed_token(&fixture.edge_slice, &fixture.excerpt, EXIT_A, NOW).expect("mint");

        let result = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_B, NOW);
        assert_eq!(
            result,
            Err(RoleSignedError::WrongExitBinding {
                token_exit: EXIT_A.to_string(),
                this_exit: EXIT_B.to_string(),
            })
        );
    }

    #[test]
    fn timestamp_outside_the_window_is_rejected() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        // Minted honestly, just far enough in the past to fall outside the
        // freshness window at verify time.
        let stale_ts = NOW - ROLE_SIGNED_TS_WINDOW_MS - 1;
        let token = mint_role_signed_token(&fixture.edge_slice, &fixture.excerpt, EXIT_A, stale_ts).expect("mint");

        let result = verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW);
        assert_eq!(
            result,
            Err(RoleSignedError::StaleTimestamp {
                ts_ms: stale_ts,
                now_ms: NOW,
                window_ms: ROLE_SIGNED_TS_WINDOW_MS,
            })
        );
    }

    #[test]
    fn timestamp_at_the_edge_of_the_window_still_verifies() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let edge_ts = NOW - ROLE_SIGNED_TS_WINDOW_MS;
        let token = mint_role_signed_token(&fixture.edge_slice, &fixture.excerpt, EXIT_A, edge_ts).expect("mint");

        verify_role_signed(&token, &fixture.operator_signing.verifying_key(), EXIT_A, NOW)
            .expect("exactly at the window boundary must still verify");
    }

    // ── Mint-side guards ─────────────────────────────────────────────────

    #[test]
    fn mint_refuses_a_slice_with_no_signing_key() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let mut headless = fixture.edge_slice.clone();
        headless.signing_privkey = None;

        let result = mint_role_signed_token(&headless, &fixture.excerpt, EXIT_A, NOW);
        assert!(matches!(result, Err(RoleSignedError::Malformed(_))));
    }

    #[test]
    fn mint_refuses_a_slice_excerpt_key_mismatch() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let mut mismatched = fixture.edge_slice.clone();
        let other = SigningKey::generate(&mut OsRng);
        mismatched.signing_privkey = Some(other.to_bytes());

        let result = mint_role_signed_token(&mismatched, &fixture.excerpt, EXIT_A, NOW);
        assert!(matches!(result, Err(RoleSignedError::Malformed(_))));
    }

    #[test]
    fn mint_refuses_a_non_edge_slice() {
        let fixture = make_fixture(ServiceRole::Edge, NOW + 3_600_000);
        let mut wrong_role = fixture.edge_slice.clone();
        wrong_role.role = ServiceRole::Sentry;

        let result = mint_role_signed_token(&wrong_role, &fixture.excerpt, EXIT_A, NOW);
        assert!(matches!(result, Err(RoleSignedError::WrongRole { role: ServiceRole::Sentry })));
    }

    // ── Wire byte stability ──────────────────────────────────────────────

    #[test]
    fn edge_role_wire_byte_is_stable() {
        // Forever-assigned, like every other byte in this module — a
        // regression here silently breaks every already-minted token.
        assert_eq!(role_to_wire_byte(&ServiceRole::Edge), Some(0x01));
        assert_eq!(role_from_wire_byte(0x01), Some(ServiceRole::Edge));
    }

    #[test]
    fn node_role_is_not_representable_on_this_wire() {
        let node = ServiceRole::Node { epoch: crate::ids::NodeEpoch::V2 };
        assert_eq!(role_to_wire_byte(&node), None);
    }
}
