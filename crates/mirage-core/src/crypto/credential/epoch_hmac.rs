//! EpochHmac — the light anonymous-credential arm.
//!
//! Token wire layout (52 bytes, fixed):
//! ```text
//! [0..4]   epoch_id   (u32 big-endian)
//! [4..20]  nonce      ([u8;16], random per dial)
//! [20..52] mac        ([u8;32] = HMAC-SHA256(epoch_secret, LABEL || epoch_id_be || nonce))
//! ```
//!
//! Properties: ~1-3µs verify. Verifier-unlinkable (the node never sees which
//! client issued the token — only that a valid epoch secret was used).
//! Issuer-linkable (opbox, which holds the epoch secret, can correlate).

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{MirageError, Result};

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label prepended to every HMAC input.
pub const EPOCH_HMAC_LABEL: &[u8] = b"MIRAGE-CRED-EPOCHHMAC-V1";

/// Fixed token byte length.
pub const EPOCH_HMAC_TOKEN_LEN: usize = 52;

/// A zeroizing newtype over the 32-byte epoch HMAC key.
///
/// The inner bytes are zeroed on drop. Intentionally no `Debug` / `Display`
/// implementation — the secret must not be printed.
pub struct EpochHmacKey(Zeroizing<[u8; 32]>);

impl EpochHmacKey {
    /// Construct from raw key bytes. Caller is responsible for the source's
    /// entropy quality (e.g. HKDF output from the operator-delivered epoch secret).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Read-only access to the raw bytes (e.g. for serialisation to gossip).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The parsed, MAC-verified fields extracted from an EpochHmac token.
///
/// The caller is responsible for a spent-set check using `nonce` as the
/// dedup key (see `SpentSet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochHmacToken {
    pub epoch_id: u32,
    pub nonce: [u8; 16],
}

/// Issue an EpochHmac credential token.
///
/// The caller supplies a fresh random `nonce` (see `random_nonce16`) and the
/// current `epoch_id`. Returns the 52-byte token suitable for on-wire
/// transmission.
pub fn issue_epoch_hmac(key: &EpochHmacKey, epoch_id: u32, nonce: [u8; 16]) -> [u8; EPOCH_HMAC_TOKEN_LEN] {
    let mac = compute_mac(key, epoch_id, &nonce);
    let mut token = [0u8; EPOCH_HMAC_TOKEN_LEN];
    token[0..4].copy_from_slice(&epoch_id.to_be_bytes());
    token[4..20].copy_from_slice(&nonce);
    token[20..52].copy_from_slice(&mac);
    token
}

/// Verify an EpochHmac token, returning the parsed fields on success.
///
/// Only MAC integrity and token length are checked here. The caller must:
/// - Check `token.epoch_id` against the live `CredentialParams.epochs` list
///   (existence + expiry).
/// - Pass `token.nonce` to `SpentSet::record_and_check` to reject replays.
pub fn verify_epoch_hmac(key: &EpochHmacKey, token: &[u8]) -> Result<EpochHmacToken> {
    if token.len() != EPOCH_HMAC_TOKEN_LEN {
        return Err(MirageError::Protocol(format!(
            "epoch_hmac: token length {} != {}",
            token.len(),
            EPOCH_HMAC_TOKEN_LEN
        )));
    }

    let epoch_id = u32::from_be_bytes(token[0..4].try_into().expect("slice is 4 bytes"));
    let nonce: [u8; 16] = token[4..20].try_into().expect("slice is 16 bytes");
    let presented_mac: &[u8; 32] = token[20..52].try_into().expect("slice is 32 bytes");

    let expected_mac = compute_mac(key, epoch_id, &nonce);

    // Constant-time comparison — never use `==` on secrets.
    if presented_mac.ct_eq(&expected_mac).into() {
        Ok(EpochHmacToken { epoch_id, nonce })
    } else {
        Err(MirageError::Protocol(
            "credential mac mismatch".to_string(),
        ))
    }
}

/// Generate a cryptographically random 16-byte nonce.
pub fn random_nonce16() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn compute_mac(key: &EpochHmacKey, epoch_id: u32, nonce: &[u8; 16]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(EPOCH_HMAC_LABEL);
    mac.update(&epoch_id.to_be_bytes());
    mac.update(nonce);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EpochHmacKey {
        EpochHmacKey::from_bytes([0x42u8; 32])
    }

    fn other_key() -> EpochHmacKey {
        EpochHmacKey::from_bytes([0xFFu8; 32])
    }

    #[test]
    fn epoch_hmac_roundtrip() {
        let key = test_key();
        let nonce = random_nonce16();
        let epoch_id = 7u32;
        let token = issue_epoch_hmac(&key, epoch_id, nonce);
        let parsed = verify_epoch_hmac(&key, &token).unwrap();
        assert_eq!(parsed.epoch_id, epoch_id);
        assert_eq!(parsed.nonce, nonce);
    }

    #[test]
    fn epoch_hmac_wrong_key_rejects() {
        let key = test_key();
        let nonce = random_nonce16();
        let token = issue_epoch_hmac(&key, 1, nonce);
        let err = verify_epoch_hmac(&other_key(), &token);
        assert!(err.is_err());
    }

    #[test]
    fn epoch_hmac_modified_rejects() {
        let key = test_key();
        let nonce = random_nonce16();
        let mut token = issue_epoch_hmac(&key, 1, nonce);
        token[25] ^= 0xFF; // flip a byte in the mac region
        let err = verify_epoch_hmac(&key, &token);
        assert!(err.is_err());
    }

    #[test]
    fn epoch_hmac_bad_len_rejects() {
        let key = test_key();
        let short = vec![0u8; 51];
        let long = vec![0u8; 53];
        assert!(verify_epoch_hmac(&key, &short).is_err());
        assert!(verify_epoch_hmac(&key, &long).is_err());
    }
}
