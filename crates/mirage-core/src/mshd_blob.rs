//! Zero-trust encrypted blob delivery for mshd.
//!
//! # Design
//!
//! Operator encrypts a file under the target mshd's X25519 public key and
//! stages the ciphertext on a monitor (which never sees the plaintext).
//! The mshd pulls the ciphertext over its existing V9 wire, decrypts locally,
//! and writes the result to `dest_path`.
//!
//! ## Key exchange
//!
//! ```text
//! shared = X25519(op_mesh_priv, mshd_pub)     # operator side
//! shared = X25519(mshd_priv,    op_mesh_pub)   # mshd side  (identical)
//! key    = HKDF-SHA256(shared, salt=blob_id.as_bytes(), info=b"mirage-mshd-blob-v1")
//! ```
//!
//! ## Per-chunk AEAD
//!
//! Each chunk is encrypted with ChaCha20-Poly1305:
//! - nonce: 12 random bytes, unique per chunk
//! - AAD: `blob_id.as_bytes() || idx.to_le_bytes()` (binds chunk to blob + position)
//!
//! ## Authenticity
//!
//! The operator signs the manifest (all fields except `op_sig`) with the same
//! Ed25519 `SigningKey` used to sign `DeclaredIdentity`. The mshd verifies
//! against its pinned operator verifying key before any decryption occurs.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MshdBlobError {
    #[error("operator signature did not verify")]
    BadSignature,
    #[error("chunk decryption failed (AEAD tag mismatch or corrupt ciphertext)")]
    DecryptFailed,
    #[error("reassembled plaintext SHA-256 does not match manifest")]
    HashMismatch,
    #[error("chunk {0} is missing (total expected {1})")]
    MissingChunk(u32, u32),
    #[error("malformed blob: {0}")]
    Malformed(String),
}

// ── Wire types ────────────────────────────────────────────────────────────────

/// Manifest describing one encrypted blob staged on a monitor.
///
/// `op_sig` covers the canonical signing bytes of every other field.
/// Serialised `plain_sha256` is a 64-char lowercase hex string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MshdBlobManifest {
    /// UUID v4 uniquely identifying this blob.
    pub blob_id: String,
    /// UUID of the target mshd (must match the mshd that pulls it).
    pub mshd_id: String,
    /// Destination path on the mshd's box (absolute or relative to cwd).
    pub dest_path: String,
    /// Total plaintext size in bytes.
    pub total_bytes: u64,
    /// Chunk size used during sealing (bytes, excluding AEAD tag).
    pub chunk_size: u32,
    /// Number of chunks.
    pub chunk_count: u32,
    /// SHA-256 of the original plaintext (verified after full reassembly).
    #[serde(with = "crate::hex_fixed::hex32")]
    pub plain_sha256: [u8; 32],
    /// Hex-encoded X25519 public key of the operator mesh identity used to
    /// seal this blob. The mshd uses this to derive the shared ECDH secret.
    pub op_mesh_pub_hex: String,
    /// Unix timestamp (ms) when the blob was sealed.
    pub created_at_ms: u64,
    /// Ed25519 signature over [`MshdBlobManifest::signing_bytes`].
    /// Encoded as a 128-char lowercase hex string.
    pub op_sig: String,
}

impl MshdBlobManifest {
    /// Canonical byte form signed by the operator. Stable: new fields MUST be
    /// appended at the end so existing signatures keep verifying.
    pub fn signing_bytes(
        blob_id: &str,
        mshd_id: &str,
        dest_path: &str,
        total_bytes: u64,
        chunk_size: u32,
        chunk_count: u32,
        plain_sha256: &[u8; 32],
        op_mesh_pub_hex: &str,
        created_at_ms: u64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"mirage-mshd-blob-manifest-v1\0");
        buf.extend_from_slice(blob_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(mshd_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(dest_path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&total_bytes.to_be_bytes());
        buf.extend_from_slice(&chunk_size.to_be_bytes());
        buf.extend_from_slice(&chunk_count.to_be_bytes());
        buf.extend_from_slice(plain_sha256);
        buf.extend_from_slice(op_mesh_pub_hex.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&created_at_ms.to_be_bytes());
        buf
    }

    fn signing_bytes_self(&self) -> Vec<u8> {
        Self::signing_bytes(
            &self.blob_id,
            &self.mshd_id,
            &self.dest_path,
            self.total_bytes,
            self.chunk_size,
            self.chunk_count,
            &self.plain_sha256,
            &self.op_mesh_pub_hex,
            self.created_at_ms,
        )
    }

    /// Verify the operator signature against `op_sign_pub`.
    pub fn verify_signature(&self, op_sign_pub: &VerifyingKey) -> Result<(), MshdBlobError> {
        let sig_bytes = hex::decode(&self.op_sig)
            .map_err(|_| MshdBlobError::Malformed("op_sig is not valid hex".into()))?;
        let arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| MshdBlobError::Malformed("op_sig must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&arr);
        let bytes = self.signing_bytes_self();
        op_sign_pub
            .verify(&bytes, &sig)
            .map_err(|_| MshdBlobError::BadSignature)
    }
}

/// One encrypted chunk of a blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MshdBlobChunk {
    /// Must match `MshdBlobManifest::blob_id`.
    pub blob_id: String,
    /// Zero-based chunk index.
    pub idx: u32,
    /// 12-byte random nonce used to encrypt this chunk.
    #[serde(with = "crate::hex_fixed::hex12")]
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 ciphertext (plaintext_chunk + 16-byte AEAD tag).
    /// Base64 in JSON — a raw `Vec<u8>` serialises as a number array (~4×
    /// bloat); base64 (~1.33×) keeps the manifest+chunks body and the gossip
    /// events compact. (The V9 wire no longer caps a single write — `send`
    /// fragments — so this is a serialisation-size choice, not a wire limit.)
    /// Shim lives in [`crate::b64_serde`] — shared with `mirage_protocol`'s
    /// mshd RPC channel rather than duplicated per module.
    #[serde(with = "crate::b64_serde::b64_vec")]
    pub ct: Vec<u8>,
}

// ── Opbox → monitor staging request ──────────────────────────────────────────

/// Body for both `POST /relay/mshd/{id}/blob` (opbox → monitor stage) and
/// `GET /relay/mshd/blob/{blob_id}` (monitor → mshd fetch).
///
/// Carries the full manifest plus every encrypted chunk in ONE request. The
/// V9 wire is a byte stream (`Tunnel::send` fragments), so the whole blob
/// rides a single connection in each direction — no per-chunk handshakes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobStageRequest {
    pub manifest: MshdBlobManifest,
    pub chunks: Vec<MshdBlobChunk>,
}

/// Response body for `GET /relay/mshd/{id}/blob/pending`.
///
/// Returns manifests of all blobs staged for this mshd that have not yet
/// been acknowledged. The mshd uses these to know which blobs to pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobPendingResponse {
    pub blobs: Vec<MshdBlobManifest>,
}

/// Request body for `POST /relay/mshd/blob/{blob_id}/ack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobAckRequest {
    /// Must match the blob_id in the URL path.
    pub blob_id: String,
}

// ── Crypto primitives ─────────────────────────────────────────────────────────

/// Default chunk size (1 MiB). The whole blob ships in one request now, so
/// chunking only governs per-chunk AEAD granularity, store-row count, resume
/// granularity, and gossip-event size. 1 MiB keeps a 60 MB blob at ~60 rows /
/// gossip events (vs ~1900 at the old 32 KiB) while bounding each gossip
/// event. (Previously 32 KiB to fit one chunk under the u16 wire frame cap —
/// that constraint is gone; `Tunnel::send` fragments.)
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// HKDF info label — fixed for this protocol version.
const HKDF_INFO: &[u8] = b"mirage-mshd-blob-v1";

/// Derive the per-blob ChaCha20-Poly1305 key.
///
/// `shared` = `X25519(op_mesh_priv, mshd_pub)` (32 bytes).
/// `blob_id` is used as the HKDF salt to bind the key to this specific blob.
fn derive_blob_key(shared: &[u8; 32], blob_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(blob_id.as_bytes()), shared);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF expand with 32-byte output is always valid");
    out
}

/// Build the per-chunk AAD: `blob_id_bytes || idx_le_bytes`.
fn chunk_aad(blob_id: &str, idx: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(blob_id.len() + 4);
    aad.extend_from_slice(blob_id.as_bytes());
    aad.extend_from_slice(&idx.to_le_bytes());
    aad
}

/// Seal `file_bytes` into an encrypted manifest + chunk list.
///
/// # Parameters
///
/// - `file_bytes` — the plaintext file content.
/// - `mshd_id` — UUID of the target mshd.
/// - `dest_path` — where the mshd should write the decrypted file.
/// - `op_mesh_priv` — operator's X25519 mesh static private key (32 bytes).
/// - `mshd_pub` — mshd's X25519 static public key (32 bytes).
/// - `op_sign_key` — operator's Ed25519 signing key (signs the manifest).
/// - `chunk_size` — plaintext bytes per chunk (use [`DEFAULT_CHUNK_SIZE`]).
///
/// # Returns
///
/// `(manifest, chunks)` — both must be delivered to the monitor together.
pub fn seal_blob(
    file_bytes: &[u8],
    mshd_id: &str,
    dest_path: &str,
    op_mesh_priv: &[u8; 32],
    mshd_pub: &[u8; 32],
    op_sign_key: &SigningKey,
    chunk_size: u32,
) -> (MshdBlobManifest, Vec<MshdBlobChunk>) {
    // ── blob_id ───────────────────────────────────────────────────────────────
    let blob_id = uuid::Uuid::new_v4().to_string();

    // ── ECDH shared secret ────────────────────────────────────────────────────
    let op_secret = StaticSecret::from(*op_mesh_priv);
    let mshd_public = X25519Public::from(*mshd_pub);
    let shared = op_secret.diffie_hellman(&mshd_public).to_bytes();

    // ── per-blob key ──────────────────────────────────────────────────────────
    let key_bytes = derive_blob_key(&shared, &blob_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    // ── plaintext SHA-256 ─────────────────────────────────────────────────────
    let plain_sha256 = sha256(file_bytes);

    // ── chunk encryption ──────────────────────────────────────────────────────
    let chunk_size_usize = chunk_size as usize;
    let chunk_count = file_bytes
        .chunks(chunk_size_usize)
        .count()
        .max(1) as u32; // at least 1 chunk even for empty input

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for (idx, plain_chunk) in file_bytes.chunks(chunk_size_usize).enumerate() {
        // Random 12-byte nonce per chunk.
        let nonce_arr: [u8; 12] = ChaCha20Poly1305::generate_nonce(&mut OsRng).into();
        let nonce = Nonce::from_slice(&nonce_arr);

        let aad = chunk_aad(&blob_id, idx as u32);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plain_chunk,
                    aad: &aad,
                },
            )
            .expect("ChaCha20Poly1305 encrypt is infallible for valid key+nonce");

        chunks.push(MshdBlobChunk {
            blob_id: blob_id.clone(),
            idx: idx as u32,
            nonce: nonce_arr,
            ct,
        });
    }

    // Handle empty input: generate one empty encrypted chunk.
    if chunks.is_empty() {
        let nonce_arr: [u8; 12] = ChaCha20Poly1305::generate_nonce(&mut OsRng).into();
        let nonce = Nonce::from_slice(&nonce_arr);
        let aad = chunk_aad(&blob_id, 0);
        let ct = cipher
            .encrypt(nonce, Payload { msg: &[], aad: &aad })
            .expect("ChaCha20Poly1305 encrypt is infallible");
        chunks.push(MshdBlobChunk {
            blob_id: blob_id.clone(),
            idx: 0,
            nonce: nonce_arr,
            ct,
        });
    }

    // ── operator mesh pubkey (derived from priv) ───────────────────────────────
    let op_mesh_pub_bytes = X25519Public::from(&op_secret).to_bytes();
    let op_mesh_pub_hex = hex::encode(op_mesh_pub_bytes);

    let total_bytes = file_bytes.len() as u64;
    let created_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // ── operator signature over manifest header ────────────────────────────────
    let signing_input = MshdBlobManifest::signing_bytes(
        &blob_id,
        mshd_id,
        dest_path,
        total_bytes,
        chunk_size,
        chunk_count,
        &plain_sha256,
        &op_mesh_pub_hex,
        created_at_ms,
    );
    let sig: Signature = op_sign_key.sign(&signing_input);
    let op_sig = hex::encode(sig.to_bytes());

    let manifest = MshdBlobManifest {
        blob_id,
        mshd_id: mshd_id.to_owned(),
        dest_path: dest_path.to_owned(),
        total_bytes,
        chunk_size,
        chunk_count,
        plain_sha256,
        op_mesh_pub_hex,
        created_at_ms,
        op_sig,
    };

    (manifest, chunks)
}

/// Decrypt and verify a blob sealed by [`seal_blob`].
///
/// # Verification order
///
/// 1. Verify `op_sig` against `op_sign_pub` — reject before any decryption.
/// 2. Derive `shared = X25519(mshd_priv, op_mesh_pub)` and the per-blob key.
/// 3. Decrypt each chunk (AEAD tag + AAD check).
/// 4. Reassemble in `idx` order, verify `plain_sha256`.
///
/// # Errors
///
/// - [`MshdBlobError::BadSignature`] — operator signature invalid.
/// - [`MshdBlobError::MissingChunk`] — a chunk index is absent.
/// - [`MshdBlobError::DecryptFailed`] — AEAD authentication failed on a chunk.
/// - [`MshdBlobError::HashMismatch`] — reassembled plaintext SHA-256 mismatch.
/// - [`MshdBlobError::Malformed`] — manifest fields are structurally invalid.
pub fn open_blob(
    manifest: &MshdBlobManifest,
    chunks: &[MshdBlobChunk],
    mshd_priv: &[u8; 32],
    op_mesh_pub: &[u8; 32],
    op_sign_pub: &VerifyingKey,
) -> Result<Vec<u8>, MshdBlobError> {
    // Step 1: verify operator signature FIRST — reject before any decryption.
    manifest.verify_signature(op_sign_pub)?;

    // Validate manifest.op_mesh_pub_hex matches the supplied op_mesh_pub.
    let expected_hex = hex::encode(op_mesh_pub);
    if manifest.op_mesh_pub_hex != expected_hex {
        return Err(MshdBlobError::Malformed(
            "op_mesh_pub_hex in manifest does not match supplied op_mesh_pub".into(),
        ));
    }

    // Step 2: derive shared secret and per-blob key.
    let mshd_secret = StaticSecret::from(*mshd_priv);
    let op_public = X25519Public::from(*op_mesh_pub);
    let shared = mshd_secret.diffie_hellman(&op_public).to_bytes();
    let key_bytes = derive_blob_key(&shared, &manifest.blob_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    // Build an index of chunks keyed by idx for O(1) lookup.
    let mut chunk_map: std::collections::HashMap<u32, &MshdBlobChunk> =
        std::collections::HashMap::new();
    for c in chunks {
        chunk_map.insert(c.idx, c);
    }

    // Step 3: decrypt each chunk in order.
    let mut plaintext = Vec::with_capacity(manifest.total_bytes as usize);
    for idx in 0..manifest.chunk_count {
        let chunk = chunk_map
            .get(&idx)
            .ok_or(MshdBlobError::MissingChunk(idx, manifest.chunk_count))?;

        let nonce = Nonce::from_slice(&chunk.nonce);
        let aad = chunk_aad(&manifest.blob_id, idx);
        let plain_chunk = cipher
            .decrypt(nonce, Payload { msg: &chunk.ct, aad: &aad })
            .map_err(|_| MshdBlobError::DecryptFailed)?;
        plaintext.extend_from_slice(&plain_chunk);
    }

    // Step 4: verify SHA-256 of reassembled plaintext.
    let got_hash = sha256(&plaintext);
    if got_hash != manifest.plain_sha256 {
        return Err(MshdBlobError::HashMismatch);
    }

    Ok(plaintext)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    use rand::rngs::OsRng as RandOsRng;
    use x25519_dalek::StaticSecret as X25519Secret;

    fn gen_x25519() -> ([u8; 32], [u8; 32]) {
        let secret = X25519Secret::random_from_rng(RandOsRng);
        let public = X25519Public::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    fn gen_ed25519() -> Ed25519SigningKey {
        Ed25519SigningKey::generate(&mut RandOsRng)
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        rand::RngCore::fill_bytes(&mut RandOsRng, &mut buf);
        buf
    }

    #[test]
    fn roundtrip_1mb() {
        let (op_mesh_priv, op_mesh_pub) = gen_x25519();
        let (mshd_priv, mshd_pub) = gen_x25519();
        let op_sign_key = gen_ed25519();
        let op_sign_pub = op_sign_key.verifying_key();

        let original = random_bytes(1_024 * 1_024); // 1 MiB

        let (manifest, chunks) = seal_blob(
            &original,
            "test-mshd-id",
            "/tmp/test_output",
            &op_mesh_priv,
            &mshd_pub,
            &op_sign_key,
            DEFAULT_CHUNK_SIZE,
        );

        assert_eq!(manifest.chunk_count, chunks.len() as u32);
        assert_eq!(manifest.total_bytes, original.len() as u64);

        let recovered = open_blob(&manifest, &chunks, &mshd_priv, &op_mesh_pub, &op_sign_pub)
            .expect("open_blob must succeed");

        assert_eq!(recovered, original, "recovered bytes must equal original");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (op_mesh_priv, op_mesh_pub) = gen_x25519();
        let (mshd_priv, mshd_pub) = gen_x25519();
        let op_sign_key = gen_ed25519();
        let op_sign_pub = op_sign_key.verifying_key();

        let original = random_bytes(512 * 1024);

        let (manifest, mut chunks) = seal_blob(
            &original,
            "mshd-tamper-test",
            "/tmp/out",
            &op_mesh_priv,
            &mshd_pub,
            &op_sign_key,
            DEFAULT_CHUNK_SIZE,
        );

        // Flip one byte in the first chunk's ciphertext.
        chunks[0].ct[0] ^= 0xFF;

        let result = open_blob(&manifest, &chunks, &mshd_priv, &op_mesh_pub, &op_sign_pub);
        assert!(
            matches!(result, Err(MshdBlobError::DecryptFailed)),
            "tampered ciphertext must yield DecryptFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn wrong_op_sign_pub_fails() {
        let (op_mesh_priv, op_mesh_pub) = gen_x25519();
        let (_mshd_priv, mshd_pub) = gen_x25519();
        let (mshd_priv2, _) = gen_x25519();
        let op_sign_key = gen_ed25519();
        let wrong_sign_pub = gen_ed25519().verifying_key();

        let original = random_bytes(1024);

        let (manifest, chunks) = seal_blob(
            &original,
            "mshd-sig-test",
            "/tmp/out",
            &op_mesh_priv,
            &mshd_pub,
            &op_sign_key,
            DEFAULT_CHUNK_SIZE,
        );

        let result = open_blob(&manifest, &chunks, &mshd_priv2, &op_mesh_pub, &wrong_sign_pub);
        assert!(
            matches!(result, Err(MshdBlobError::BadSignature)),
            "wrong verifying key must yield BadSignature, got: {:?}",
            result
        );
    }

    #[test]
    fn wrong_mshd_priv_fails() {
        let (op_mesh_priv, op_mesh_pub) = gen_x25519();
        let (_mshd_priv, mshd_pub) = gen_x25519();
        let (wrong_mshd_priv, _) = gen_x25519();
        let op_sign_key = gen_ed25519();
        let op_sign_pub = op_sign_key.verifying_key();

        let original = random_bytes(1024);

        let (manifest, chunks) = seal_blob(
            &original,
            "mshd-wrong-priv-test",
            "/tmp/out",
            &op_mesh_priv,
            &mshd_pub,
            &op_sign_key,
            DEFAULT_CHUNK_SIZE,
        );

        let result = open_blob(&manifest, &chunks, &wrong_mshd_priv, &op_mesh_pub, &op_sign_pub);
        assert!(
            matches!(result, Err(MshdBlobError::DecryptFailed)),
            "wrong mshd_priv must yield DecryptFailed, got: {:?}",
            result
        );
    }

    #[test]
    fn manifest_signing_bytes_stable() {
        // Deterministic input → deterministic canonical bytes.
        let sha = [0xABu8; 32];
        let a = MshdBlobManifest::signing_bytes(
            "blob-id", "mshd-id", "/tmp/x", 1024, 256, 4, &sha, "deadbeef", 1_700_000_000_000,
        );
        let b = MshdBlobManifest::signing_bytes(
            "blob-id", "mshd-id", "/tmp/x", 1024, 256, 4, &sha, "deadbeef", 1_700_000_000_000,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn empty_file_roundtrip() {
        let (op_mesh_priv, op_mesh_pub) = gen_x25519();
        let (mshd_priv, mshd_pub) = gen_x25519();
        let op_sign_key = gen_ed25519();
        let op_sign_pub = op_sign_key.verifying_key();

        let (manifest, chunks) = seal_blob(
            &[],
            "mshd-empty-test",
            "/tmp/empty",
            &op_mesh_priv,
            &mshd_pub,
            &op_sign_key,
            DEFAULT_CHUNK_SIZE,
        );

        let recovered = open_blob(&manifest, &chunks, &mshd_priv, &op_mesh_pub, &op_sign_pub)
            .expect("empty file roundtrip");
        assert!(recovered.is_empty());
    }

    #[test]
    fn serde_roundtrip() {
        let (op_mesh_priv, _op_mesh_pub) = gen_x25519();
        let (_mshd_priv, mshd_pub) = gen_x25519();
        let op_sign_key = gen_ed25519();

        let (manifest, chunks) = seal_blob(
            b"hello world",
            "mshd-serde-test",
            "/tmp/hello",
            &op_mesh_priv,
            &mshd_pub,
            &op_sign_key,
            DEFAULT_CHUNK_SIZE,
        );

        let req = BlobStageRequest { manifest, chunks };
        let json = serde_json::to_string(&req).unwrap();
        let back: BlobStageRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.manifest.blob_id, back.manifest.blob_id);
        assert_eq!(req.chunks.len(), back.chunks.len());
    }
}
