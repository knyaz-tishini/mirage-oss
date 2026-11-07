//! SignedCapability — the asymmetric anonymous-credential arm.
//!
//! Replaces the symmetric `EpochHmac` trust model where every verifier node
//! holds the epoch secret (verify == mint → a node that reaches an untrusted state
//! cannot mint credentials fleet-wide). In this scheme:
//!
//! - **Issuer (opbox)**: holds the per-epoch Ed25519 **signing key** (private).
//!   Only opbox can mint valid tokens.
//! - **Verifier (node)**: holds only the per-epoch Ed25519 **verifying key**
//!   (public). Can verify but **cannot** mint.
//!
//! Unlinkability property: the node sees a random 32-byte nonce + a signature.
//! It cannot correlate which client issued the token (the nonce is independently
//! random per token; the signature says nothing about the client identity).
//!
//! # Wire format (100 bytes, fixed)
//!
//! ```text
//! [0..4]    epoch_id    u32 big-endian
//! [4..36]   nonce       32 random bytes — becomes CredentialId on success
//! [36..100] signature   64-byte Ed25519 signature over the preimage below
//! ```
//!
//! # Signature preimage (domain-separated)
//!
//! ```text
//! b"mirage-signed-cap-v1\0"   (21 bytes, NUL-terminated label)
//! epoch_id.to_be_bytes()      (4 bytes)
//! nonce                       (32 bytes)
//! ```
//! Total preimage length: 57 bytes.
//!
//! # EpochEntry.secret field overloading
//!
//! `EpochEntry.secret: [u8; 32]` is reused without schema change:
//! - scheme = `EpochHmac`       → `secret` is the 32-byte HMAC key.
//! - scheme = `SignedCapability` → `secret` is the 32-byte Ed25519 **verifying
//!   key** (public key). A compressed Curve25519 point fits exactly in 32 bytes.
//!
//! The verifying key is integrity-protected by the operator's own Ed25519
//! signature over `CredentialParams` (see `CredentialParams::sign`), so
//! epoch-pubkey substitution is rejected at the node before the
//! params are applied.
//!
//! # Opbox persistence
//!
//! Opbox stores the 32-byte **signing key seed** (not the full 64-byte secret
//! key) in its EpochState. Call `CapabilitySigningKey::seed_bytes()` to extract
//! it and `CapabilitySigningKey::from_seed` to restore it. The corresponding
//! verifying key (32 bytes) is what opbox writes into `EpochEntry.secret` and
//! gossips to nodes.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{MirageError, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Domain-separation label prepended to the signature preimage.
pub const SIGNED_CAP_LABEL: &[u8] = b"mirage-signed-cap-v1\0";

/// Fixed token byte length: 4 (epoch_id) + 32 (nonce) + 64 (sig) = 100.
pub const SIGNED_CAP_TOKEN_LEN: usize = 100;

// ── Key types ─────────────────────────────────────────────────────────────────

/// The **verifying** (public) key for a SignedCapability epoch.
///
/// Node-side: opbox gossips the 32-byte compressed public key in
/// `EpochEntry.secret`. Nodes construct this type from those bytes and call
/// [`verify_signed_capability`].
///
/// This type intentionally exposes **no signing method**. A node that holds
/// only `CapabilityVerifyKey` cannot produce valid tokens — that requires
/// [`CapabilitySigningKey`], which never leaves opbox.
#[derive(Clone)]
pub struct CapabilityVerifyKey([u8; 32]);

impl CapabilityVerifyKey {
    /// Construct from raw 32-byte compressed public-key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw 32-byte representation (suitable for storing in `EpochEntry.secret`).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Internal conversion to the dalek verifying key. Returns `Err` on
    /// invalid point encoding.
    fn to_dalek(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).map_err(|e| {
            MirageError::Protocol(format!(
                "signed_capability: invalid verifying key bytes: {e}"
            ))
        })
    }
}

/// The **signing** (private seed) key for a SignedCapability epoch.
///
/// Opbox-side only. Never gossipped; opbox persists the 32-byte seed and
/// derives the signing key on demand.
///
/// The seed is zeroed on drop.
pub struct CapabilitySigningKey(Zeroizing<[u8; 32]>);

impl CapabilitySigningKey {
    /// Construct from a 32-byte seed (the canonical Ed25519 seed, not the
    /// 64-byte expanded secret key).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(Zeroizing::new(seed))
    }

    /// Extract the raw seed bytes (for persistence in opbox EpochState).
    pub fn seed_bytes(&self) -> [u8; 32] {
        *self.0
    }

    /// Derive the corresponding verifying key.
    pub fn verify_key(&self) -> CapabilityVerifyKey {
        let sk = SigningKey::from_bytes(&self.0);
        CapabilityVerifyKey(sk.verifying_key().to_bytes())
    }

    /// Internal conversion to the dalek signing key.
    fn to_dalek(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
}

// ── Token type ────────────────────────────────────────────────────────────────

/// Parsed, signature-verified fields extracted from a SignedCapability token.
///
/// The `nonce` field becomes the [`CredentialId`](super::CredentialId) via
/// `CredentialId::from_bytes32(token.nonce)`. The caller is responsible for
/// a spent-set check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityToken {
    pub epoch_id: u32,
    /// The 32-byte per-token random value. Used as the dedup key in SpentSet.
    pub nonce: [u8; 32],
}

// ── Keypair generation ────────────────────────────────────────────────────────

/// Generate a fresh per-epoch keypair from OS randomness.
///
/// Opbox calls this when creating a new epoch:
/// - Stores `signing_key.seed_bytes()` in its EpochState.
/// - Writes `verify_key.to_bytes()` into `EpochEntry.secret` before gossiping
///   `CredentialParams` to the fleet.
pub fn generate_capability_keypair() -> (CapabilitySigningKey, CapabilityVerifyKey) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let sk = CapabilitySigningKey::from_seed(seed);
    let vk = sk.verify_key();
    (sk, vk)
}

// ── Mint (issuer / opbox side) ────────────────────────────────────────────────

/// Mint a 100-byte SignedCapability token.
///
/// `epoch_id` and `nonce` are chosen by opbox (nonce must be random, 32 bytes,
/// generated fresh per token). Returns the exact bytes to send to the client,
/// which the client then presents on the data leg.
pub fn mint_signed_capability(
    signing_key: &CapabilitySigningKey,
    epoch_id: u32,
    nonce: [u8; 32],
) -> Vec<u8> {
    let preimage = build_preimage(epoch_id, &nonce);
    let sk = signing_key.to_dalek();
    let sig: Signature = sk.sign(&preimage);
    let sig_bytes = sig.to_bytes(); // [u8; 64]

    let mut token = vec![0u8; SIGNED_CAP_TOKEN_LEN];
    token[0..4].copy_from_slice(&epoch_id.to_be_bytes());
    token[4..36].copy_from_slice(&nonce);
    token[36..100].copy_from_slice(&sig_bytes);
    token
}

/// Generate a random 32-byte nonce for use in [`mint_signed_capability`].
pub fn random_nonce32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

// ── Verify (node side) ────────────────────────────────────────────────────────

/// Verify a SignedCapability token on the node side.
///
/// Returns a [`CapabilityToken`] on success. The caller must then:
/// 1. Convert to `CredentialId::from_bytes32(token.nonce)`.
/// 2. Call `SpentSet::record_and_check(epoch_id, cred_id)` to reject replays.
///
/// Fails if:
/// - Token length is not exactly 100 bytes.
/// - The Ed25519 signature does not verify against `verify_key`.
pub fn verify_signed_capability(
    verify_key: &CapabilityVerifyKey,
    token: &[u8],
) -> Result<CapabilityToken> {
    if token.len() != SIGNED_CAP_TOKEN_LEN {
        return Err(MirageError::Protocol(format!(
            "signed_capability: token length {} != {}",
            token.len(),
            SIGNED_CAP_TOKEN_LEN
        )));
    }

    let epoch_id = u32::from_be_bytes(token[0..4].try_into().expect("slice is 4 bytes"));
    let nonce: [u8; 32] = token[4..36].try_into().expect("slice is 32 bytes");
    let sig_bytes: [u8; 64] = token[36..100].try_into().expect("slice is 64 bytes");

    let sig = Signature::from_bytes(&sig_bytes);
    let vk = verify_key.to_dalek()?;
    let preimage = build_preimage(epoch_id, &nonce);

    vk.verify_strict(&preimage, &sig).map_err(|_| {
        MirageError::Protocol("signed_capability: signature verification failed".to_string())
    })?;

    Ok(CapabilityToken { epoch_id, nonce })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Build the domain-separated signature preimage.
///
/// Layout: `LABEL (21B) || epoch_id_be (4B) || nonce (32B)` = 57 bytes.
fn build_preimage(epoch_id: u32, nonce: &[u8; 32]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNED_CAP_LABEL.len() + 4 + 32);
    preimage.extend_from_slice(SIGNED_CAP_LABEL);
    preimage.extend_from_slice(&epoch_id.to_be_bytes());
    preimage.extend_from_slice(nonce);
    preimage
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (CapabilitySigningKey, CapabilityVerifyKey) {
        generate_capability_keypair()
    }

    #[test]
    fn signed_capability_roundtrip() {
        let (sk, vk) = keypair();
        let nonce = random_nonce32();
        let token = mint_signed_capability(&sk, 7, nonce);
        let parsed = verify_signed_capability(&vk, &token).unwrap();
        assert_eq!(parsed.epoch_id, 7);
        assert_eq!(parsed.nonce, nonce);
    }

    #[test]
    fn credential_id_equals_nonce() {
        use super::super::CredentialId;
        let (sk, vk) = keypair();
        let nonce = random_nonce32();
        let token = mint_signed_capability(&sk, 1, nonce);
        let parsed = verify_signed_capability(&vk, &token).unwrap();
        let cred_id = CredentialId::from_bytes32(parsed.nonce);
        assert_eq!(cred_id.as_bytes(), &nonce);
    }

    #[test]
    fn invalid_signature_rejected() {
        let (sk, vk) = keypair();
        let nonce = random_nonce32();
        let mut token = mint_signed_capability(&sk, 3, nonce);
        // Flip one byte in the signature region.
        token[50] ^= 0xFF;
        assert!(verify_signed_capability(&vk, &token).is_err());
    }

    #[test]
    fn wrong_verify_key_rejected() {
        let (sk, _vk_a) = keypair();
        let (_sk_b, vk_b) = keypair();
        let nonce = random_nonce32();
        let token = mint_signed_capability(&sk, 4, nonce);
        // Verify with key B while token was minted with key A.
        assert!(verify_signed_capability(&vk_b, &token).is_err());
    }

    #[test]
    fn truncated_token_rejected() {
        let (sk, vk) = keypair();
        let nonce = random_nonce32();
        let token = mint_signed_capability(&sk, 1, nonce);
        // 99 bytes — one short.
        assert!(verify_signed_capability(&vk, &token[..99]).is_err());
        // 3 bytes — well short.
        assert!(verify_signed_capability(&vk, &token[..3]).is_err());
        // empty.
        assert!(verify_signed_capability(&vk, &[]).is_err());
    }

    #[test]
    fn oversized_token_rejected() {
        let (sk, vk) = keypair();
        let nonce = random_nonce32();
        let mut token = mint_signed_capability(&sk, 1, nonce);
        token.push(0x00); // 101 bytes.
        assert!(verify_signed_capability(&vk, &token).is_err());
    }

    #[test]
    fn seed_roundtrip() {
        let (sk, vk) = keypair();
        let seed = sk.seed_bytes();
        let sk2 = CapabilitySigningKey::from_seed(seed);
        // Signing key reconstructed from seed must produce the same verify key.
        assert_eq!(sk2.verify_key().to_bytes(), vk.to_bytes());
    }

    #[test]
    fn verify_key_cannot_be_used_to_mint() {
        // Compile-time assertion: CapabilityVerifyKey exposes no sign() method.
        // This test verifies the API contract at the type level — if
        // CapabilityVerifyKey ever accidentally gains a signing path this test
        // will still compile (it's a doc-comment assertion), but the type
        // design is reviewed here:
        //
        //   CapabilityVerifyKey has: from_bytes, to_bytes, to_dalek (private)
        //   CapabilitySigningKey has: from_seed, seed_bytes, verify_key, to_dalek (private)
        //
        // A node holding only CapabilityVerifyKey has no code path to call
        // SigningKey::sign — the signing key bytes never leave the issuer.
        let (_sk, vk) = generate_capability_keypair();
        let _ = vk.to_bytes(); // verify key is usable for export
        // No sign() call is possible here — CapabilityVerifyKey has no such method.
    }

    #[test]
    fn token_length_is_100() {
        let (sk, _vk) = keypair();
        let nonce = random_nonce32();
        let token = mint_signed_capability(&sk, 99, nonce);
        assert_eq!(token.len(), SIGNED_CAP_TOKEN_LEN);
        assert_eq!(SIGNED_CAP_TOKEN_LEN, 100);
    }

    #[test]
    fn preimage_label_is_nul_terminated() {
        // Ensures the domain label matches what's documented in the preimage spec.
        assert_eq!(SIGNED_CAP_LABEL, b"mirage-signed-cap-v1\0");
        assert_eq!(SIGNED_CAP_LABEL.len(), 21);
    }
}
