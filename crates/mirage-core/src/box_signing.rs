//! Box-side Ed25519 signing-key manager.
//!
//! Each Mirage VPS self-generates a signing keypair distinct from its X25519
//! wire key.  The operator captures the verifying key at adopt-time, embeds it
//! in the box's [`crate::identity::DeclaredIdentity`] (in the entry for this
//! role inside [`crate::identity::DeclaredIdentity::role_keys`]), and gossips
//! the declaration fleet-wide so any monitor can verify facts signed by that
//! box.
//!
//! ## On-disk format
//!
//! Mirrors `db-key.raw`: 64 lowercase hex chars encoding the 32-byte Ed25519
//! seed, stored at a caller-supplied path (e.g.
//! `<state_dir>/box-signing-key.raw`), mode 0600 on Unix.  Plaintext by
//! design — NOT sealed under a device fingerprint (that scheme was killed for
//! being reboot-fragile).
//!
//! ## Cross-platform
//!
//! The file-permissions set is guarded by `#[cfg(unix)]` so this module
//! compiles and functions on Windows (where the OS enforces ACLs via NTFS, not
//! mode bits).

use std::fs;
use std::io;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::identity::SignatureHex;

/// Canonical filename for the box-side Ed25519 signing seed, relative to
/// `<state_dir>`.  Same on-disk shape as the retired operator-delivered
/// `db-key.raw` (64 lowercase hex chars, mode 0600).
pub const BOX_SIGNING_KEY_FILENAME: &str = "box-signing-key.raw";

/// Box-side Ed25519 signing keypair.
///
/// Loaded from or generated to a caller-supplied path via
/// [`load_or_generate`].  The public half is registered with the operator at
/// adopt-time and bound into this role's entry in
/// [`crate::identity::DeclaredIdentity::role_keys`].
#[derive(Clone)]
pub struct BoxSigningKey {
    signing: SigningKey,
}

impl BoxSigningKey {
    /// Load the seed from `path` if it exists, otherwise generate a fresh
    /// keypair, write the seed, and return it.
    ///
    /// Atomic write on generation: seed is written to `<path>.new`, chmod
    /// 0600 on Unix, then renamed to `path` so a partial write never
    /// corrupts a live key.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` on any I/O failure.  A malformed seed file
    /// (wrong length, non-hex) is surfaced as `io::ErrorKind::InvalidData`.
    pub fn load_or_generate(path: &Path) -> io::Result<Self> {
        if path.exists() {
            load_from_path(path)
        } else {
            generate_and_write(path)
        }
    }

    /// Build a [`BoxSigningKey`] directly from a 32-byte Ed25519 seed —
    /// no file I/O. For entities whose signing key is operator-baked into
    /// the binary at issue time (`bootstrap.rs` const) rather than
    /// generated on first boot and persisted to `box-signing-key.raw`.
    pub fn from_signing_key_bytes(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Hex-encode the 32-byte Ed25519 verifying (public) key.
    ///
    /// This is the value the operator stores in this role's entry in
    /// [`crate::identity::DeclaredIdentity::role_keys`].
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Return the raw [`VerifyingKey`] for direct cryptographic use.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign `msg` and wrap the result in the existing [`SignatureHex`] type.
    pub fn sign(&self, msg: &[u8]) -> SignatureHex {
        let sig = self.signing.sign(msg);
        SignatureHex::from_signature(&sig)
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

fn load_from_path(path: &Path) -> io::Result<BoxSigningKey> {
    let raw = fs::read_to_string(path)?;
    let hex_str = raw.trim();
    if hex_str.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "box-signing-key.raw must contain 64 hex chars, got {}",
                hex_str.len()
            ),
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("box-signing-key.raw contains non-hex chars: {e}"),
        )
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "hex-decoded seed must be 32 bytes, got {}",
                v.len()
            ),
        )
    })?;
    Ok(BoxSigningKey {
        signing: SigningKey::from_bytes(&arr),
    })
}

fn generate_and_write(path: &Path) -> io::Result<BoxSigningKey> {
    let signing = SigningKey::generate(&mut OsRng);
    let seed_hex = hex::encode(signing.to_bytes());

    // Atomic write: write to <path>.new, set perms, rename.
    let tmp_path = {
        let mut p = path.to_path_buf();
        let mut name = p
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no filename"))?
            .to_os_string();
        name.push(".new");
        p.set_file_name(name);
        p
    };

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&tmp_path, seed_hex.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::rename(&tmp_path, path)?;

    Ok(BoxSigningKey { signing })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use uuid::Uuid;

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mirage-core-box-signing-{label}-{}-{}.raw",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        p
    }

    #[test]
    fn generate_then_load_same_pubkey() {
        let path = tmp_path("gen-load");
        // First call: generates and writes.
        let first = BoxSigningKey::load_or_generate(&path).expect("generate");
        let first_hex = first.verifying_key_hex();
        // Second call: loads from disk.
        let second = BoxSigningKey::load_or_generate(&path).expect("load");
        let second_hex = second.verifying_key_hex();
        assert_eq!(
            first_hex, second_hex,
            "loaded key must match generated key"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sign_and_verify() {
        let path = tmp_path("sign-verify");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate");
        let msg = b"mirage-test-payload";
        let sig_hex = key.sign(msg);
        let sig = sig_hex.to_signature().expect("decode sig");
        let vk = key.verifying_key();
        vk.verify(msg, &sig).expect("signature must verify");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sign_wrong_message_fails() {
        let path = tmp_path("sign-wrong");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate");
        let sig_hex = key.sign(b"correct-message");
        let sig = sig_hex.to_signature().expect("decode sig");
        let vk = key.verifying_key();
        assert!(
            vk.verify(b"wrong-message", &sig).is_err(),
            "wrong message must not verify"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn verifying_key_hex_is_64_chars() {
        let path = tmp_path("vk-hex-len");
        let key = BoxSigningKey::load_or_generate(&path).expect("generate");
        assert_eq!(key.verifying_key_hex().len(), 64);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn from_signing_key_bytes_matches_manual_signingkey() {
        let seed: [u8; 32] = [7u8; 32];
        let baked = BoxSigningKey::from_signing_key_bytes(seed);
        let manual = SigningKey::from_bytes(&seed);
        assert_eq!(baked.verifying_key_hex(), hex::encode(manual.verifying_key().to_bytes()));

        let msg = b"baked-signing-key-payload";
        let sig_hex = baked.sign(msg);
        let sig = sig_hex.to_signature().expect("decode sig");
        baked.verifying_key().verify(msg, &sig).expect("signature must verify");
    }
}
