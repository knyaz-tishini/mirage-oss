//! DK network delivery — seal the SQLCipher master key (DK) to a db-worker's
//! boot-ephemeral X25519 key so it never rests on disk (custody W8).
//!
//! opbox seals ([`seal_dk`]) the escrowed 32-byte DK to the worker's
//! boot-ephemeral pubkey using **ephemeral-ephemeral** X25519 ECDH →
//! HKDF-SHA256 → ChaCha20-Poly1305, and signs the whole envelope with the
//! pinned operator Ed25519 key. db-worker unseals ([`unseal_dk`]) with its
//! RAM-only ephemeral secret after verifying the operator signature +
//! freshness + worker/boot binding.
//!
//! The seal target is the **ephemeral** key (never persisted), not the baked
//! identity (which rests on disk inside the binary) — so a disk snapshot of a
//! captured [`KeyRelease`] blob yields nothing: the only key that unwraps it
//! lived in RAM for one boot.
//!
//! Binding (defence in depth, three independent layers):
//! - the operator Ed25519 signature authenticates the envelope came from opbox;
//! - the AEAD AAD is `worker_id ‖ boot_nonce`, so a release sealed for worker A
//!   / boot N cannot be replayed to worker B or a later boot (AEAD fails);
//! - a freshness window on `ts_ms` bounds the replay horizon.
//!
//! The signing preimage is a fixed length-prefixed byte layout (never a JSON
//! hash) so the signature is over typed, unambiguous bytes.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{derive_key, shared_secret, AeadCipher, AeadSuite, KeyPair};

/// HKDF `info` label — domain-separates the seal key from every other key
/// derived off an X25519 shared secret in this codebase.
const SEAL_INFO: &[u8] = b"mirage-dk-seal-v1";

/// Ed25519 signing-preimage domain label.
const SIG_LABEL: &[u8] = b"MIRAGE-DK-RELEASE-V1";

/// A sealed DK release. Opaque to the monitor that relays it; only the
/// db-worker holding the matching boot-ephemeral secret can unseal it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRelease {
    /// opbox's per-release ephemeral X25519 public key (hex, 64 chars).
    pub op_eph_pubkey_hex: String,
    /// AEAD nonce (hex, 24 chars = 12 bytes).
    pub nonce_hex: String,
    /// Sealed DK: ChaCha20-Poly1305 ciphertext ‖ 16-byte tag (hex).
    pub ciphertext_hex: String,
    /// The db-worker this release is bound to (also the AEAD AAD).
    pub worker_id: String,
    /// The worker's per-boot nonce this release answers (also AEAD AAD) —
    /// ties the release to exactly one boot, defeating replay across reboots.
    pub boot_nonce: String,
    /// Opaque lease id for the operator's audit/hold bookkeeping.
    pub lease_id: String,
    /// opbox seal timestamp (unix ms) — freshness-checked on unseal.
    pub ts_ms: u64,
    /// Ed25519 signature by the pinned operator key over the fixed preimage.
    pub operator_sig_hex: String,
}

#[derive(Debug, Error)]
pub enum DkError {
    #[error("malformed key release field: {0}")]
    Malformed(String),
    #[error("operator signature invalid")]
    SigInvalid,
    #[error("key release stale: |now - ts| exceeds the freshness window")]
    Stale,
    #[error("key release bound to a different worker/boot than expected")]
    BindingMismatch,
    #[error("DK unseal failed (AEAD auth) — wrong ephemeral key, tampered blob, or AAD mismatch")]
    Unseal,
}

/// Length-prefix `bytes` (u32-LE length) into `out`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The AEAD additional-authenticated-data: binds the ciphertext to a specific
/// worker + boot. Built identically on seal and unseal (unseal uses the
/// *expected* values, so a mismatched binding fails the AEAD tag).
fn seal_aad(worker_id: &str, boot_nonce: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(worker_id.len() + boot_nonce.len() + 8);
    push_lp(&mut aad, worker_id.as_bytes());
    push_lp(&mut aad, boot_nonce.as_bytes());
    aad
}

/// Deterministic Ed25519 signing preimage — a fixed, length-prefixed layout
/// over every field the signature must cover. Never a JSON hash.
#[allow(clippy::too_many_arguments)]
fn sig_preimage(
    op_eph_pub: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    worker_id: &str,
    boot_nonce: &str,
    lease_id: &str,
    ts_ms: u64,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(SIG_LABEL.len() + 32 + 12 + ciphertext.len() + 128);
    p.extend_from_slice(SIG_LABEL);
    push_lp(&mut p, op_eph_pub);
    push_lp(&mut p, nonce);
    push_lp(&mut p, ciphertext);
    push_lp(&mut p, worker_id.as_bytes());
    push_lp(&mut p, boot_nonce.as_bytes());
    push_lp(&mut p, lease_id.as_bytes());
    p.extend_from_slice(&ts_ms.to_le_bytes());
    p
}

/// **opbox side.** Seal `dk` to the worker's boot-ephemeral pubkey and sign the
/// envelope with the operator Ed25519 key. `nonce` is drawn from `OsRng`.
#[allow(clippy::too_many_arguments)]
pub fn seal_dk(
    dk: &[u8; 32],
    worker_eph_pubkey: &[u8; 32],
    worker_id: &str,
    boot_nonce: &str,
    lease_id: &str,
    ts_ms: u64,
    operator_signing_key: &SigningKey,
) -> KeyRelease {
    // Fresh per-release ephemeral for opbox — neither side's ECDH key persists.
    let op_eph = KeyPair::generate();
    let op_eph_pub = op_eph.public.to_bytes();

    let worker_pub = PublicKey::from(*worker_eph_pubkey);
    let shared = shared_secret(&op_eph.secret, &worker_pub);
    let seal_key = derive_key(&shared, b"", SEAL_INFO);

    let mut nonce = [0u8; 12];
    use rand::{rngs::OsRng, RngCore};
    OsRng.fill_bytes(&mut nonce);

    let aad = seal_aad(worker_id, boot_nonce);
    let ciphertext = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &seal_key)
        .encrypt(&nonce, dk, &aad)
        .expect("ChaCha20-Poly1305 seal of a 32-byte DK is always valid");

    let preimage = sig_preimage(
        &op_eph_pub,
        &nonce,
        &ciphertext,
        worker_id,
        boot_nonce,
        lease_id,
        ts_ms,
    );
    let sig = operator_signing_key.sign(&preimage);

    KeyRelease {
        op_eph_pubkey_hex: hex::encode(op_eph_pub),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(&ciphertext),
        worker_id: worker_id.to_string(),
        boot_nonce: boot_nonce.to_string(),
        lease_id: lease_id.to_string(),
        ts_ms,
        operator_sig_hex: hex::encode(sig.to_bytes()),
    }
}

/// **db-worker side.** Verify the operator signature + freshness + worker/boot
/// binding, then ECDH-unseal the DK with the RAM-only boot-ephemeral secret.
/// Returns the 32-byte DK in a `Zeroizing` buffer.
#[allow(clippy::too_many_arguments)]
pub fn unseal_dk(
    release: &KeyRelease,
    worker_eph_secret: &[u8; 32],
    expected_worker_id: &str,
    expected_boot_nonce: &str,
    operator_pubkey: &VerifyingKey,
    now_ms: u64,
    max_skew_ms: u64,
) -> Result<Zeroizing<[u8; 32]>, DkError> {
    // 1. Binding — reject before any crypto if it's not addressed to us.
    if release.worker_id != expected_worker_id || release.boot_nonce != expected_boot_nonce {
        return Err(DkError::BindingMismatch);
    }

    // 2. Freshness — bound the replay window (absolute skew, either direction).
    let skew = now_ms.abs_diff(release.ts_ms);
    if skew > max_skew_ms {
        return Err(DkError::Stale);
    }

    // 3. Parse the wire fields.
    let op_eph_pub = decode_32(&release.op_eph_pubkey_hex, "op_eph_pubkey")?;
    let nonce = decode_12(&release.nonce_hex)?;
    let ciphertext = hex::decode(&release.ciphertext_hex)
        .map_err(|e| DkError::Malformed(format!("ciphertext hex: {e}")))?;
    let sig_bytes = decode_64(&release.operator_sig_hex)?;

    // 4. Verify the operator signature over the fixed preimage BEFORE decrypt.
    let preimage = sig_preimage(
        &op_eph_pub,
        &nonce,
        &ciphertext,
        &release.worker_id,
        &release.boot_nonce,
        &release.lease_id,
        release.ts_ms,
    );
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    operator_pubkey
        .verify(&preimage, &sig)
        .map_err(|_| DkError::SigInvalid)?;

    // 5. ECDH + HKDF + AEAD unseal. AAD is rebuilt from the EXPECTED
    //    worker/boot, so a release sealed for anyone else fails the tag.
    let worker_secret = StaticSecret::from(*worker_eph_secret);
    let op_pub = PublicKey::from(op_eph_pub);
    let shared = shared_secret(&worker_secret, &op_pub);
    let seal_key = derive_key(&shared, b"", SEAL_INFO);
    let aad = seal_aad(expected_worker_id, expected_boot_nonce);

    let pt = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &seal_key)
        .decrypt(&nonce, &ciphertext, &aad)
        .map_err(|_| DkError::Unseal)?;

    if pt.len() != 32 {
        return Err(DkError::Malformed(format!(
            "unsealed DK must be 32 bytes, got {}",
            pt.len()
        )));
    }
    let mut dk = Zeroizing::new([0u8; 32]);
    dk.copy_from_slice(&pt);
    Ok(dk)
}

fn decode_32(hex_str: &str, field: &str) -> Result<[u8; 32], DkError> {
    let v = hex::decode(hex_str).map_err(|e| DkError::Malformed(format!("{field} hex: {e}")))?;
    v.try_into()
        .map_err(|_| DkError::Malformed(format!("{field} must be 32 bytes")))
}

fn decode_12(hex_str: &str) -> Result<[u8; 12], DkError> {
    let v = hex::decode(hex_str).map_err(|e| DkError::Malformed(format!("nonce hex: {e}")))?;
    v.try_into()
        .map_err(|_| DkError::Malformed("nonce must be 12 bytes".to_string()))
}

fn decode_64(hex_str: &str) -> Result<[u8; 64], DkError> {
    let v = hex::decode(hex_str).map_err(|e| DkError::Malformed(format!("sig hex: {e}")))?;
    v.try_into()
        .map_err(|_| DkError::Malformed("signature must be 64 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    struct Fixture {
        op_sign: SigningKey,
        op_verify: VerifyingKey,
        worker_eph: KeyPair,
        dk: [u8; 32],
        worker_id: String,
        boot_nonce: String,
        ts_ms: u64,
    }

    fn fixture() -> Fixture {
        let op_sign = SigningKey::generate(&mut OsRng);
        let op_verify = op_sign.verifying_key();
        let worker_eph = KeyPair::generate();
        let mut dk = [0u8; 32];
        for (i, b) in dk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        Fixture {
            op_sign,
            op_verify,
            worker_eph,
            dk,
            worker_id: "worker-abc".to_string(),
            boot_nonce: "boot-nonce-xyz".to_string(),
            ts_ms: 1_000_000,
        }
    }

    fn seal(f: &Fixture) -> KeyRelease {
        seal_dk(
            &f.dk,
            &f.worker_eph.public.to_bytes(),
            &f.worker_id,
            &f.boot_nonce,
            "lease-1",
            f.ts_ms,
            &f.op_sign,
        )
    }

    #[test]
    fn roundtrip_recovers_dk() {
        let f = fixture();
        let rel = seal(&f);
        let dk = unseal_dk(
            &rel,
            &f.worker_eph.secret.to_bytes(),
            &f.worker_id,
            &f.boot_nonce,
            &f.op_verify,
            f.ts_ms + 500,
            60_000,
        )
        .expect("unseal");
        assert_eq!(*dk, f.dk);
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let f = fixture();
        let mut rel = seal(&f);
        // Flip a byte in the ciphertext, then re-sign so the sig check passes
        // and the failure is proven to come from the AEAD tag, not the sig.
        let mut ct = hex::decode(&rel.ciphertext_hex).unwrap();
        ct[0] ^= 0xff;
        rel.ciphertext_hex = hex::encode(&ct);
        let op_eph_pub = decode_32(&rel.op_eph_pubkey_hex, "x").unwrap();
        let nonce = decode_12(&rel.nonce_hex).unwrap();
        let preimage = sig_preimage(
            &op_eph_pub, &nonce, &ct, &rel.worker_id, &rel.boot_nonce, &rel.lease_id, rel.ts_ms,
        );
        rel.operator_sig_hex = hex::encode(f.op_sign.sign(&preimage).to_bytes());
        let err = unseal_dk(
            &rel, &f.worker_eph.secret.to_bytes(), &f.worker_id, &f.boot_nonce,
            &f.op_verify, f.ts_ms, 60_000,
        )
        .unwrap_err();
        assert!(matches!(err, DkError::Unseal), "got {err:?}");
    }

    #[test]
    fn wrong_ephemeral_secret_fails() {
        let f = fixture();
        let rel = seal(&f);
        let attacker = KeyPair::generate();
        let err = unseal_dk(
            &rel, &attacker.secret.to_bytes(), &f.worker_id, &f.boot_nonce,
            &f.op_verify, f.ts_ms, 60_000,
        )
        .unwrap_err();
        assert!(matches!(err, DkError::Unseal), "got {err:?}");
    }

    #[test]
    fn forged_signature_rejected() {
        let f = fixture();
        let rel = seal(&f);
        let other_key = SigningKey::generate(&mut OsRng).verifying_key();
        let err = unseal_dk(
            &rel, &f.worker_eph.secret.to_bytes(), &f.worker_id, &f.boot_nonce,
            &other_key, f.ts_ms, 60_000,
        )
        .unwrap_err();
        assert!(matches!(err, DkError::SigInvalid), "got {err:?}");
    }

    #[test]
    fn stale_release_rejected() {
        let f = fixture();
        let rel = seal(&f);
        let err = unseal_dk(
            &rel, &f.worker_eph.secret.to_bytes(), &f.worker_id, &f.boot_nonce,
            &f.op_verify, f.ts_ms + 120_000, 60_000,
        )
        .unwrap_err();
        assert!(matches!(err, DkError::Stale), "got {err:?}");
    }

    #[test]
    fn wrong_worker_binding_rejected() {
        let f = fixture();
        let rel = seal(&f);
        // Different expected worker_id → rejected at the binding gate.
        let err = unseal_dk(
            &rel, &f.worker_eph.secret.to_bytes(), "worker-OTHER", &f.boot_nonce,
            &f.op_verify, f.ts_ms, 60_000,
        )
        .unwrap_err();
        assert!(matches!(err, DkError::BindingMismatch), "got {err:?}");
    }
}
