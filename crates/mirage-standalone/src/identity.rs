//! `ServerIdentity` — the four keys a standalone box owns, plus its mesh id.
//!
//! A standalone box is its own island: there is no monitor to escrow keys to
//! and no fleet to borrow an identity from. Everything the box needs to
//! authenticate itself, to issue subscriber credentials, and to serve one
//! customer is minted **once**, on first run, and then lives in
//! `<dir>/identity.json` for the life of the box.
//!
//! # The four keys
//!
//! | key | algorithm | what it is for |
//! |---|---|---|
//! | `node_wire` | X25519 | the box's own wire identity — its public half is published in the artefact as `server_pubkey_hex` and is what the client verifies the server by |
//! | `operator` | Ed25519 | signs this box's credential parameters and verifies role-signed credentials presented to it |
//! | `subscriber_issuer` | Ed25519 | signs the subscriber allowlist (`subscriber.set`) the box enforces |
//! | `subscriber` | X25519 | the customer's device key — the secret half goes into the artefact, the public half into the subscriber allowlist |
//!
//! The `operator` key is the one whose *placement* is still open in the wider
//! fleet: the node binary currently carries a compile-time constant for it
//! (`core::bootstrap::operator_pubkey()`). This crate does not change the
//! node. It only fixes the **storage and hand-out** side: the operator key
//! lives in `identity.json`, is loaded with the rest of the identity, and is
//! handed out through [`ServerIdentity::operator_signing_key`] /
//! [`ServerIdentity::operator_pubkey_hex`], so a later change of the node's
//! compile-time constant to a file-loaded key is a call-site change only.
//!
//! # `mesh_id`
//!
//! The `mesh_id` is a **personal identifier of the subscriber**, minted once
//! per box and reused unchanged. It is folded into the V9 handshake's confirm
//! label where the fleet's real mesh id would go; both sides must fold in the
//! same bytes. It names nothing beyond the one subscriber it was minted for —
//! no mesh, no monitor, no node and no chain is reachable from it — which is
//! exactly what a standalone box needs, since it has no fleet to name.
//!
//! # Secrets
//!
//! Private halves are held in [`zeroize::Zeroizing`] buffers and are never
//! printed — not in a log line, not in an error message, not in a `Debug`
//! rendering. Errors name the file and the shape of the problem only.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mirage_core::crypto::KeyPair;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::fsio;

/// File name of the on-disk identity, inside the box's data directory.
pub const IDENTITY_FILE_NAME: &str = "identity.json";

/// Schema version of `identity.json`.
pub const IDENTITY_FILE_VERSION: u32 = 1;

/// Raw length of every key this module stores, in bytes.
const KEY_LEN: usize = 32;

/// Length of a minted `mesh_id`, in hex characters.
pub const MESH_ID_HEX_LEN: usize = 64;

/// Everything that can go wrong while loading, minting or persisting a box's
/// identity.
///
/// No variant carries key material — only the file's path and a short
/// description of what was wrong with it.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// The identity file could not be read.
    #[error("identity: cannot read {path}")]
    Read {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// The identity file could not be written.
    #[error("identity: cannot write {path}")]
    Write {
        /// The file that could not be written.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },

    /// The file exists but is not a usable identity.
    #[error("identity: {path} is not a usable identity file ({reason})")]
    Malformed {
        /// The offending file.
        path: PathBuf,
        /// Why it was rejected — a fixed phrase, never a value.
        reason: &'static str,
    },

    /// The identity could not be encoded for writing.
    #[error("identity: cannot encode the identity ({reason})")]
    Encode {
        /// Why encoding failed.
        reason: String,
    },
}

/// A standalone box's own identity: four keys and a personal mesh id.
///
/// Build one with [`ServerIdentity::load_or_mint`] — the read-or-create path
/// a box uses on every start — or with [`ServerIdentity::load`] when reading
/// must never create anything. [`ServerIdentity::mint`] is the raw mint, for
/// callers that persist the result themselves.
pub struct ServerIdentity {
    /// The box's own X25519 wire key.
    node_wire: Zeroizing<[u8; KEY_LEN]>,
    /// The operator key — signs this box's credential parameters.
    operator: Zeroizing<[u8; KEY_LEN]>,
    /// The subscriber-issuer key — signs the subscriber allowlist.
    subscriber_issuer: Zeroizing<[u8; KEY_LEN]>,
    /// The customer's X25519 device key.
    subscriber: Zeroizing<[u8; KEY_LEN]>,
    /// The personal mesh id, minted once and reused unchanged.
    mesh_id: String,
}

impl fmt::Debug for ServerIdentity {
    /// Prints the non-secret shape only — never a key, never a secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("mesh_id", &self.mesh_id)
            .field("node_wire_pubkey_hex", &self.node_wire_pubkey_hex())
            .field("operator_pubkey_hex", &self.operator_pubkey_hex())
            .field("subscriber_issuer_pubkey_hex", &self.subscriber_issuer_pubkey_hex())
            .field("subscriber_pubkey_hex", &self.subscriber_pubkey_hex())
            .finish_non_exhaustive()
    }
}

/// The on-disk shape of `identity.json`.
///
/// Private halves are stored hex-encoded so the file stays plain JSON — the
/// box's data directory is a volume that operators copy around, and a
/// readable-but-obfuscated file is easier to reason about than an opaque
/// binary blob. The file itself is mode 0600 on Unix.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    /// Schema version of this file.
    v: u32,
    /// The box's X25519 wire secret, hex.
    node_wire_secret_hex: String,
    /// The operator Ed25519 seed, hex.
    operator_secret_hex: String,
    /// The subscriber-issuer Ed25519 seed, hex.
    subscriber_issuer_secret_hex: String,
    /// The customer's X25519 device secret, hex.
    subscriber_secret_hex: String,
    /// The personal mesh id.
    mesh_id: String,
}

impl ServerIdentity {
    /// Load this box's identity from `dir`, minting one on first use.
    ///
    /// Idempotent by construction: when `identity.json` exists it is read and
    /// the existing keys are returned unchanged — a restart never re-mints, and
    /// never invalidates a `client.link` the customer already holds. When it
    /// does not exist, a fresh identity is minted and written atomically with
    /// mode 0600 (Unix).
    ///
    /// # Errors
    ///
    /// Fails if the file exists but cannot be parsed, or if it cannot be
    /// written.
    pub fn load_or_mint(dir: &Path) -> Result<Self, IdentityError> {
        let path = identity_path(dir);
        match fs::read(&path) {
            Ok(raw) => Self::from_json_bytes(&raw, &path),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let identity = Self::mint();
                identity.write_to(dir)?;
                Ok(identity)
            }
            Err(source) => Err(IdentityError::Read { path, source }),
        }
    }

    /// Load this box's identity from `dir` — and never mint one.
    ///
    /// This is the read-only half of [`ServerIdentity::load_or_mint`]: a
    /// health check must be able to say "there is no identity here" without
    /// creating one as a side effect.
    pub fn load(dir: &Path) -> Result<Self, IdentityError> {
        let path = identity_path(dir);
        let raw = fs::read(&path).map_err(|source| IdentityError::Read {
            path: path.clone(),
            source,
        })?;
        Self::from_json_bytes(&raw, &path)
    }

    /// Mint a brand-new identity — four fresh keys and a fresh mesh id.
    ///
    /// This does not touch the disk; use [`ServerIdentity::write_to`] for
    /// that, or [`ServerIdentity::load_or_mint`] for the usual "read or
    /// create" behaviour.
    pub fn mint() -> Self {
        Self {
            node_wire: Zeroizing::new(random_key()),
            operator: Zeroizing::new(random_key()),
            subscriber_issuer: Zeroizing::new(random_key()),
            subscriber: Zeroizing::new(random_key()),
            mesh_id: hex::encode(random_key()),
        }
    }

    /// Use the **chain's** mesh id instead of this box's own.
    ///
    /// The boxes of one chain share a mesh id. The leg's credential carries
    /// it, and the hop that receives the leg compares it with its own, byte
    /// for byte — so a chain whose boxes disagree on the mesh id does not
    /// work at all.
    ///
    /// The id that is published to the customer must be the SAME one: the
    /// customer's link carries it, and the customer folds it into the
    /// handshake. That is why the override replaces the box's own id rather
    /// than sitting beside it.
    ///
    /// The file on disk keeps the box's own id: the override comes from the
    /// configuration, and the configuration is what says which chain the box
    /// stands in.
    pub fn with_mesh_id(mut self, mesh_id: &str) -> Self {
        self.mesh_id = mesh_id.to_owned();
        self
    }

    /// The path of this box's identity file inside `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        fsio::path_in(dir, IDENTITY_FILE_NAME)
    }

    /// The box's own X25519 wire key pair.
    ///
    /// The public half is what the artefact publishes as `server_pubkey_hex`
    /// and what the client verifies the server by.
    pub fn node_wire(&self) -> KeyPair {
        KeyPair::from_secret(*self.node_wire)
    }

    /// The box's own X25519 wire public key, lower-case hex.
    pub fn node_wire_pubkey_hex(&self) -> String {
        hex::encode(self.node_wire().public.as_bytes())
    }

    /// The operator signing key — signs this box's credential parameters.
    ///
    /// The node binary currently pins the operator key as a compile-time
    /// constant; this accessor is the storage side of the same key, ready for
    /// the node to read it from here instead.
    pub fn operator_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.operator)
    }

    /// The operator public key, lower-case hex.
    pub fn operator_pubkey_hex(&self) -> String {
        hex::encode(self.operator_signing_key().verifying_key().to_bytes())
    }

    /// The subscriber-issuer signing key — signs the subscriber allowlist.
    pub fn subscriber_issuer_signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.subscriber_issuer)
    }

    /// The subscriber-issuer public key, lower-case hex.
    ///
    /// This is the key an edge pins to decide whether a subscriber allowlist
    /// is trustworthy.
    pub fn subscriber_issuer_pubkey_hex(&self) -> String {
        hex::encode(self.subscriber_issuer_signing_key().verifying_key().to_bytes())
    }

    /// The subscriber-issuer public key as a verifying key.
    pub fn subscriber_issuer_verifying_key(&self) -> VerifyingKey {
        self.subscriber_issuer_signing_key().verifying_key()
    }

    /// The customer's X25519 device key pair.
    ///
    /// The secret half is what the artefact hands to the client; the public
    /// half is what the subscriber allowlist admits.
    pub fn subscriber(&self) -> KeyPair {
        KeyPair::from_secret(*self.subscriber)
    }

    /// The customer's X25519 device public key, lower-case hex.
    pub fn subscriber_pubkey_hex(&self) -> String {
        hex::encode(self.subscriber().public.as_bytes())
    }

    /// The customer's X25519 device secret, lower-case hex.
    ///
    /// This is the artefact's `private_key_hex`. It is returned here only so
    /// the artefact builder can embed it — it is never logged.
    pub fn subscriber_secret_hex(&self) -> String {
        hex::encode(*self.subscriber)
    }

    /// The personal mesh id — the subscriber's own identifier.
    ///
    /// Minted once per box and reused unchanged, exactly as the fleet's
    /// per-subscriber mesh id is: both sides fold the same bytes into the
    /// handshake, and it names nothing beyond this one subscriber.
    pub fn mesh_id(&self) -> &str {
        &self.mesh_id
    }

    /// Write this identity into `dir`, atomically and privately.
    ///
    /// The file is replaced as a whole: a reader either sees the previous
    /// identity or this one, never a half-written mixture.
    pub fn write_to(&self, dir: &Path) -> Result<PathBuf, IdentityError> {
        let path = Self::path_in(dir);
        let file = IdentityFile {
            v: IDENTITY_FILE_VERSION,
            node_wire_secret_hex: hex::encode(*self.node_wire),
            operator_secret_hex: hex::encode(*self.operator),
            subscriber_issuer_secret_hex: hex::encode(*self.subscriber_issuer),
            subscriber_secret_hex: hex::encode(*self.subscriber),
            mesh_id: self.mesh_id.clone(),
        };
        let json = serde_json::to_vec_pretty(&file)
            .map_err(|e| IdentityError::Encode { reason: e.to_string() })?;
        fsio::write_atomic(&path, &json).map_err(|source| IdentityError::Write { path: path.clone(), source })?;
        Ok(path)
    }

    /// Rebuild an identity from the bytes of an `identity.json`.
    fn from_json_bytes(raw: &[u8], path: &Path) -> Result<Self, IdentityError> {
        let file: IdentityFile =
            serde_json::from_slice(raw).map_err(|_| IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "not valid JSON",
            })?;
        if file.v != IDENTITY_FILE_VERSION {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "unsupported file version",
            });
        }
        if file.mesh_id.trim().is_empty() {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "mesh id is empty",
            });
        }
        Ok(Self {
            node_wire: Zeroizing::new(decode_key(&file.node_wire_secret_hex).map_err(
                |reason| IdentityError::Malformed { path: path.to_path_buf(), reason },
            )?),
            operator: Zeroizing::new(decode_key(&file.operator_secret_hex).map_err(
                |reason| IdentityError::Malformed { path: path.to_path_buf(), reason },
            )?),
            subscriber_issuer: Zeroizing::new(decode_key(&file.subscriber_issuer_secret_hex).map_err(
                |reason| IdentityError::Malformed { path: path.to_path_buf(), reason },
            )?),
            subscriber: Zeroizing::new(decode_key(&file.subscriber_secret_hex).map_err(
                |reason| IdentityError::Malformed { path: path.to_path_buf(), reason },
            )?),
            mesh_id: file.mesh_id,
        })
    }
}

/// The path of the identity file inside `dir`.
fn identity_path(dir: &Path) -> PathBuf {
    ServerIdentity::path_in(dir)
}

/// 32 random bytes from the OS entropy source.
fn random_key() -> [u8; KEY_LEN] {
    let mut bytes = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Decode one hex-encoded key into raw bytes.
///
/// The failure reason is a fixed phrase — the offending value never appears
/// in an error message.
fn decode_key(hex_str: &str) -> Result<[u8; KEY_LEN], &'static str> {
    let raw = hex::decode(hex_str).map_err(|_| "a key is not valid hex")?;
    if raw.len() != KEY_LEN {
        return Err("a key has the wrong length");
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway directory, removed when the test ends.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mirage-standalone-{}-{}-{}",
                tag,
                std::process::id(),
                unique_counter()
            ));
            fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn unique_counter() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    #[test]
    fn minting_produces_four_distinct_keys_and_a_mesh_id() {
        let id = ServerIdentity::mint();
        assert_ne!(id.node_wire_pubkey_hex(), id.subscriber_pubkey_hex());
        assert_ne!(id.operator_pubkey_hex(), id.subscriber_issuer_pubkey_hex());
        assert_eq!(id.node_wire_pubkey_hex().len(), 64);
        assert_eq!(id.subscriber_pubkey_hex().len(), 64);
        assert_eq!(id.mesh_id().len(), MESH_ID_HEX_LEN);
    }

    #[test]
    fn load_or_mint_is_idempotent() {
        let dir = TempDir::new("idempotent");
        let first = ServerIdentity::load_or_mint(dir.path()).expect("first mint");
        let second = ServerIdentity::load_or_mint(dir.path()).expect("second load");

        assert_eq!(first.node_wire_pubkey_hex(), second.node_wire_pubkey_hex());
        assert_eq!(first.operator_pubkey_hex(), second.operator_pubkey_hex());
        assert_eq!(
            first.subscriber_issuer_pubkey_hex(),
            second.subscriber_issuer_pubkey_hex()
        );
        assert_eq!(first.subscriber_pubkey_hex(), second.subscriber_pubkey_hex());
        assert_eq!(first.mesh_id(), second.mesh_id());
    }

    #[test]
    fn the_secret_survives_a_reload() {
        let dir = TempDir::new("secret");
        let first = ServerIdentity::load_or_mint(dir.path()).expect("mint");
        let second = ServerIdentity::load_or_mint(dir.path()).expect("load");
        assert_eq!(first.subscriber_secret_hex(), second.subscriber_secret_hex());
    }

    #[test]
    fn the_identity_file_exists_after_minting() {
        let dir = TempDir::new("exists");
        ServerIdentity::load_or_mint(dir.path()).expect("mint");
        let path = ServerIdentity::path_in(dir.path());
        assert!(path.is_file());
    }

    #[test]
    fn a_corrupt_identity_file_is_refused_by_name() {
        let dir = TempDir::new("corrupt");
        fs::write(ServerIdentity::path_in(dir.path()), b"{not json").expect("write");
        let err = ServerIdentity::load_or_mint(dir.path()).expect_err("must refuse");
        assert!(matches!(err, IdentityError::Malformed { .. }));
        let text = err.to_string();
        assert!(text.contains("identity.json"));
        assert!(!text.contains('{'));
    }

    #[test]
    fn a_short_key_is_refused() {
        let dir = TempDir::new("short");
        let raw = serde_json::json!({
            "v": IDENTITY_FILE_VERSION,
            "node_wire_secret_hex": "aa",
            "operator_secret_hex": hex::encode([7u8; 32]),
            "subscriber_issuer_secret_hex": hex::encode([8u8; 32]),
            "subscriber_secret_hex": hex::encode([9u8; 32]),
            "mesh_id": "abc",
        });
        fs::write(ServerIdentity::path_in(dir.path()), raw.to_string()).expect("write");
        let err = ServerIdentity::load_or_mint(dir.path()).expect_err("must refuse");
        assert!(matches!(err, IdentityError::Malformed { .. }));
    }

    #[test]
    fn debug_never_shows_a_secret() {
        let id = ServerIdentity::mint();
        let text = format!("{:?}", id);
        assert!(!text.contains(&id.subscriber_secret_hex()));
        assert!(!text.contains(&hex::encode(*id.operator)));
        assert!(text.contains("mesh_id"));
    }

    #[cfg(unix)]
    #[test]
    fn the_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        ServerIdentity::load_or_mint(dir.path()).expect("mint");
        let mode = fs::metadata(ServerIdentity::path_in(dir.path()))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
