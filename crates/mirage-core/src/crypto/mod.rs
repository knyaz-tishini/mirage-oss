// This file converts `src/crypto.rs` into `src/crypto/mod.rs`.
// All content from the former crypto.rs lives here; the credential
// sub-module is added alongside.

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{MirageError, Result};

// ── Re-exports so `use mirage_core::crypto::*` keeps working ─────────────────

/// `AeadSuite` — canonical home is `mirage::wire`. Re-exported here for
/// crypto-callsite convenience (matches V9 import pattern).
pub use crate::mirage::wire::AeadSuite;

/// `CredentialScheme` — canonical home is `mirage::wire`. Re-exported here
/// so consumers can `use mirage_core::crypto::CredentialScheme`.
pub use crate::mirage::wire::CredentialScheme;

pub mod credential;
pub use credential::{
    Authority, AuthorityId, CredentialId, CredentialParams, EpochEntry, SpentSet,
    epoch_hmac::{
        issue_epoch_hmac, random_nonce16, verify_epoch_hmac, EpochHmacKey, EpochHmacToken,
        EPOCH_HMAC_LABEL, EPOCH_HMAC_TOKEN_LEN,
    },
    verify_credential,
    verify_credential_bound,
    signed_capability::{
        generate_capability_keypair, mint_signed_capability, random_nonce32,
        verify_signed_capability, CapabilitySigningKey, CapabilityVerifyKey, CapabilityToken,
        SIGNED_CAP_LABEL, SIGNED_CAP_TOKEN_LEN,
    },
};

// ── Existing crypto API (unchanged) ──────────────────────────────────────────

/// An X25519 key pair (secret + public).
pub struct KeyPair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a fresh key pair using the OS random source.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct a key pair from a raw 32-byte secret.
    pub fn from_secret(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl Clone for KeyPair {
    fn clone(&self) -> Self {
        // StaticSecret does not implement Clone; reconstruct from raw bytes.
        Self::from_secret(self.secret.to_bytes())
    }
}

/// Perform an X25519 Diffie-Hellman exchange and return the 32-byte shared secret.
pub fn shared_secret(our_secret: &StaticSecret, their_public: &PublicKey) -> [u8; 32] {
    our_secret.diffie_hellman(their_public).to_bytes()
}

/// Derive a 32-byte key from `shared_secret` using HKDF-SHA256 with `salt` and `info`.
pub fn derive_key(shared_secret: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut out = [0u8; 32];
    // HKDF expand only fails if the output length exceeds 255 * hash-len; 32 bytes is always safe.
    hk.expand(info, &mut out)
        .expect("HKDF expand with 32-byte output is always valid");
    out
}

/// Hash arbitrary data with BLAKE3 and return the 32-byte digest.
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// AEAD wrapper holding one concrete suite. Variant chosen at construction
/// from a negotiated `AeadSuite`; encrypt/decrypt dispatch via match.
///
/// V7: `AeadCipher::new()` is removed — every callsite must supply an explicit
/// `AeadSuite` via `AeadCipher::with_suite(suite, key)`.
pub enum AeadCipher {
    ChaCha20(ChaCha20Poly1305),
    Aes256(Aes256Gcm),
    Aes128(Aes128Gcm),
}

impl AeadCipher {
    /// V7 constructor: pick the suite explicitly. `key` MUST be at least
    /// `suite.key_len()` bytes; for AES-128 we slice to 16, for the others
    /// we use all 32.
    pub fn with_suite(suite: AeadSuite, key: &[u8; 32]) -> Self {
        match suite {
            AeadSuite::ChaCha20Poly1305 => {
                AeadCipher::ChaCha20(ChaCha20Poly1305::new(Key::from_slice(key)))
            }
            AeadSuite::Aes256Gcm => {
                use aes_gcm::aead::generic_array::GenericArray;
                AeadCipher::Aes256(Aes256Gcm::new(GenericArray::from_slice(key)))
            }
            AeadSuite::Aes128Gcm => {
                use aes_gcm::aead::generic_array::GenericArray;
                AeadCipher::Aes128(Aes128Gcm::new(GenericArray::from_slice(&key[..16])))
            }
        }
    }

    /// Which suite this cipher embeds — for logging / diagnostics.
    pub fn suite(&self) -> AeadSuite {
        match self {
            AeadCipher::ChaCha20(_) => AeadSuite::ChaCha20Poly1305,
            AeadCipher::Aes256(_) => AeadSuite::Aes256Gcm,
            AeadCipher::Aes128(_) => AeadSuite::Aes128Gcm,
        }
    }

    /// Encrypt `plaintext` with the given 12-byte nonce and optional additional data.
    /// Returns ciphertext || 16-byte tag.
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadCipher::ChaCha20(c) => {
                use chacha20poly1305::aead::Payload;
                let n = Nonce::from_slice(nonce);
                c.encrypt(n, Payload { msg: plaintext, aad })
                    .map_err(|e| MirageError::Crypto(e.to_string()))
            }
            AeadCipher::Aes256(c) => {
                use aes_gcm::aead::{generic_array::GenericArray, Payload as GcmPayload};
                let n = GenericArray::from_slice(nonce);
                c.encrypt(n, GcmPayload { msg: plaintext, aad })
                    .map_err(|e| MirageError::Crypto(e.to_string()))
            }
            AeadCipher::Aes128(c) => {
                use aes_gcm::aead::{generic_array::GenericArray, Payload as GcmPayload};
                let n = GenericArray::from_slice(nonce);
                c.encrypt(n, GcmPayload { msg: plaintext, aad })
                    .map_err(|e| MirageError::Crypto(e.to_string()))
            }
        }
    }

    /// Decrypt and authenticate `ciphertext` (includes the 16-byte tag).
    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadCipher::ChaCha20(c) => {
                use chacha20poly1305::aead::Payload;
                let n = Nonce::from_slice(nonce);
                c.decrypt(n, Payload { msg: ciphertext, aad })
                    .map_err(|_| MirageError::AuthFailed)
            }
            AeadCipher::Aes256(c) => {
                use aes_gcm::aead::{generic_array::GenericArray, Payload as GcmPayload};
                let n = GenericArray::from_slice(nonce);
                c.decrypt(n, GcmPayload { msg: ciphertext, aad })
                    .map_err(|_| MirageError::AuthFailed)
            }
            AeadCipher::Aes128(c) => {
                use aes_gcm::aead::{generic_array::GenericArray, Payload as GcmPayload};
                let n = GenericArray::from_slice(nonce);
                c.decrypt(n, GcmPayload { msg: ciphertext, aad })
                    .map_err(|_| MirageError::AuthFailed)
            }
        }
    }
}

/// Derive new per-direction session keys after a rekey exchange.
///
/// Uses HKDF-SHA256 where:
/// - IKM = new ECDH shared secret (32 bytes, fresh ephemeral exchange)
/// - salt = old write key (chains the old key material into the new one)
/// - info = `b"mirage-rekey-v1"` + direction tag
///
/// Returns `(new_send_key, new_recv_key)` from the perspective of the caller.
/// Both sides call this function with the same arguments in opposite order:
/// the client passes `(ecdh_ss, old_client_write, old_server_write)` while the
/// server also passes `(ecdh_ss, old_client_write, old_server_write)` — they
/// agree because neither side is "send" or "recv" at the key-derivation layer.
pub fn rekey_derive_keys(
    ecdh_shared: &[u8; 32],
    old_client_write: &[u8; 32],
    old_server_write: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let new_client = derive_key(ecdh_shared, old_client_write, b"mirage-rekey-v7-client");
    let new_server = derive_key(ecdh_shared, old_server_write, b"mirage-rekey-v7-server");
    (new_client, new_server)
}

/// Symmetric keys derived from a shared DH secret, one write key per direction.
///
/// `client_write_key` and `server_write_key` are wrapped in [`Zeroizing`] so
/// the 32-byte key material is wiped from memory when the struct is dropped.
/// The nonce counters are plain `u64` — they are not secret.
pub struct SessionKeys {
    pub client_write_key: Zeroizing<[u8; 32]>,
    pub server_write_key: Zeroizing<[u8; 32]>,
    pub client_nonce_counter: u64,
    pub server_nonce_counter: u64,
    /// Negotiated AEAD suite — carried on the struct so downstream codec
    /// instantiations read `keys.suite` without an extra parameter.
    pub suite: AeadSuite,
}

impl SessionKeys {
    /// Derive session keys from the raw shared secret using HKDF-SHA256.
    ///
    /// `salt` should be a session-unique value (e.g. handshake hash).
    /// `suite` is the negotiated AEAD suite from the V7 handshake.
    ///
    /// V7 labels (`mirage-client-write-key-v7` / `mirage-server-write-key-v7`)
    /// replace the V6 labels — a V6 peer computes different session keys
    /// and fails AEAD on the first frame.
    pub fn derive(shared: &[u8], salt: &[u8], suite: AeadSuite) -> Self {
        let mut client_write_key = Zeroizing::new([0u8; 32]);
        let mut server_write_key = Zeroizing::new([0u8; 32]);
        let hk = Hkdf::<Sha256>::new(Some(salt), shared);
        hk.expand(b"mirage-client-write-key-v7", client_write_key.as_mut())
            .expect("HKDF expand with 32-byte output is always valid");
        hk.expand(b"mirage-server-write-key-v7", server_write_key.as_mut())
            .expect("HKDF expand with 32-byte output is always valid");
        Self {
            client_write_key,
            server_write_key,
            client_nonce_counter: 0,
            server_nonce_counter: 0,
            suite,
        }
    }

    /// Derive V9 session keys from the ephemeral×ephemeral shared secret.
    ///
    /// IKM = `ecdh_ee` (ephemeral×ephemeral). Forward secrecy holds.
    /// Labels: `mirage-client-write-key-v9` / `mirage-server-write-key-v9`.
    ///
    /// Both `ecdh_ee` and the returned write keys are wrapped in [`Zeroizing`]
    /// so key material is zeroed on drop.
    pub fn derive_v9(
        ecdh_ee: &Zeroizing<[u8; 32]>,
        transcript_0: &[u8; 32],
        suite: AeadSuite,
    ) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(transcript_0), ecdh_ee.as_ref());
        let mut client_write_key = Zeroizing::new([0u8; 32]);
        let mut server_write_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"mirage-client-write-key-v9", client_write_key.as_mut())
            .expect("HKDF expand with 32-byte output is always valid");
        hk.expand(b"mirage-server-write-key-v9", server_write_key.as_mut())
            .expect("HKDF expand with 32-byte output is always valid");
        Self {
            client_write_key,
            server_write_key,
            client_nonce_counter: 0,
            server_nonce_counter: 0,
            suite,
        }
    }
}
