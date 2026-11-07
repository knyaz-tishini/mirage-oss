//! Camouflage layer — Reality-style handshake authentication.
//!
//! Client injects X25519 auth into the first 96 bytes of the TCP stream:
//!
//! ```text
//! [e_pub (32B)] [encrypted session_id (40B = 24B ciphertext + 16B tag)] [padding (24B)]
//! ```
//!
//! Session id layout (plaintext, 24 bytes):
//! ```text
//! [0..3]  version = [0, 1, 0]
//! [3]     reserved = 0x00
//! [4..8]  unix timestamp (big-endian u32)
//! [8..24] short_id (16 bytes, pre-shared)
//! ```
//!
//! Server validates: decrypts session_id via HKDF-derived key, checks short_id and
//! timestamp window.  If valid, signals success via a 32-byte confirm; if invalid,
//! returns `Ok(None)` — the caller may forward the stream to a fallback destination.
//!
//! After handshake, the stream is returned to the caller **as-is** — the inner Mirage
//! handshake runs on plain TCP bytes.  Reality is an outer auth layer only, not a
//! per-frame wrapper.
//!
//! This is our imitation of xtls/reality; it is **not wire-compatible with xray-core**.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mirage_core::{
    crypto::{derive_key, hash_blake3, shared_secret, AeadCipher, AeadSuite, KeyPair},
    error::MirageError,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::debug;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::{private, CamouflageLayer};
use crate::decode_hex;

// ─────────────────────────────────────────────────────────────────────────────
// Constants — identical to those used in l2/tcp/mirage_reality.rs
// ─────────────────────────────────────────────────────────────────────────────

/// Total size of the Reality client handshake message in bytes.
const HS_MSG_LEN: usize = 96;

/// Size of the plaintext session_id.
const SESSION_ID_LEN: usize = 24;

/// Size of the encrypted session_id (plaintext + 16B AEAD tag).
const ENC_SESSION_ID_LEN: usize = SESSION_ID_LEN + 16;

/// Protocol version embedded in session_id[0..3].
const REALITY_VERSION: [u8; 3] = [0, 1, 0];

/// Confirmation tag appended to the shared secret before hashing.
const REALITY_OK_TAG: &[u8] = b"REALITY-OK";

/// Length of the short_id field in the plaintext session_id.
const SHORT_ID_LEN: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
// Shared helper
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the 32-byte server confirmation: `BLAKE3(ss || "REALITY-OK")`.
fn reality_confirm(ss: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + REALITY_OK_TAG.len());
    input.extend_from_slice(ss);
    input.extend_from_slice(REALITY_OK_TAG);
    hash_blake3(&input)
}

/// Decode a hex `short_id` string into a `[u8; 16]` array.
fn decode_short_id(hex: &str) -> Result<[u8; SHORT_ID_LEN], MirageError> {
    let raw = decode_hex(hex)
        .map_err(|e| MirageError::Config(format!("invalid short_id hex '{hex}': {e}")))?;
    raw.try_into().map_err(|_| {
        MirageError::Config(format!(
            "short_id '{hex}' must decode to exactly {SHORT_ID_LEN} bytes"
        ))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// RealityClientCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// Reality-style camouflage — **client** side.
///
/// The client performs the 96-byte Reality auth handshake against the server's
/// static X25519 public key, then returns the raw `TcpStream` to the caller for
/// the inner Mirage ECDH handshake.
///
/// # Fields
/// - `server_static_pub` — server's 32-byte X25519 public key (pre-shared).
/// - `short_id` — 16-byte session identifier (pre-shared with the server).
pub struct RealityClientCamouflage {
    server_static_pub: [u8; 32],
    short_id: [u8; SHORT_ID_LEN],
}

impl RealityClientCamouflage {
    /// Create a new client-side Reality camouflage layer.
    ///
    /// * `server_static_pub` — server's 32-byte X25519 public key.
    /// * `short_id_hex` — hex-encoded 16-byte short ID (32 hex chars).
    pub fn new(
        server_static_pub: [u8; 32],
        short_id_hex: impl AsRef<str>,
    ) -> Result<Self, MirageError> {
        let short_id = decode_short_id(short_id_hex.as_ref())?;
        Ok(Self {
            server_static_pub,
            short_id,
        })
    }
}

impl private::Sealed for RealityClientCamouflage {}

#[async_trait]
impl CamouflageLayer for RealityClientCamouflage {
    type Stream = TcpStream;

    async fn wrap_client(
        &self,
        mut stream: TcpStream,
        _sni: &str,
    ) -> Result<TcpStream, MirageError> {
        // ── Ephemeral key generation ──────────────────────────────────────────
        let e_priv = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let e_pub = PublicKey::from(&e_priv);
        let e_pub_bytes = e_pub.to_bytes();

        // ── Derive shared secret and Reality handshake key ────────────────────
        let server_pk = PublicKey::from(self.server_static_pub);
        let ss_bytes = e_priv.diffie_hellman(&server_pk).to_bytes();
        let reality_key = derive_key(&ss_bytes, &[], b"REALITY");

        // ── Build plaintext session_id (24 bytes) ─────────────────────────────
        let mut session_id = [0u8; SESSION_ID_LEN];
        session_id[0..3].copy_from_slice(&REALITY_VERSION);
        session_id[3] = 0x00;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ts_bytes = (now_secs as u32).to_be_bytes();
        session_id[4..8].copy_from_slice(&ts_bytes);
        session_id[8..24].copy_from_slice(&self.short_id);

        // ── Derive 12-byte nonce from BLAKE3(e_pub) ───────────────────────────
        let pub_hash = hash_blake3(&e_pub_bytes);
        let nonce: [u8; 12] = pub_hash[..12]
            .try_into()
            .expect("BLAKE3 output is 32 bytes, slice of 12 is always valid");

        // ── Encrypt session_id ────────────────────────────────────────────────
        // Reality camouflage cipher: ChaCha20-Poly1305 hardcoded per the Reality spec —
        // this encrypts the TLS ClientHello session_id field, not session traffic.
        let cipher = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &reality_key);
        let enc_session_id = cipher.encrypt(&nonce, &session_id, &[])?;

        // ── Build and send 96-byte handshake message ──────────────────────────
        // Layout: [32B e_pub][40B enc_session_id+tag][24B padding zeros]
        let mut hs_msg = [0u8; HS_MSG_LEN];
        hs_msg[..32].copy_from_slice(&e_pub_bytes);
        hs_msg[32..32 + ENC_SESSION_ID_LEN].copy_from_slice(&enc_session_id);
        stream.write_all(&hs_msg).await?;

        // ── Receive server confirmation (32 bytes) ────────────────────────────
        let mut confirm_buf = [0u8; 32];
        stream.read_exact(&mut confirm_buf).await?;

        // ── Verify confirmation ───────────────────────────────────────────────
        let expected_confirm = reality_confirm(&ss_bytes);
        if expected_confirm != confirm_buf {
            return Err(MirageError::Handshake(
                "reality: server confirmation mismatch".into(),
            ));
        }

        debug!("reality: client handshake complete");
        Ok(stream)
    }

    async fn wrap_server(&self, _stream: TcpStream) -> Result<Option<TcpStream>, MirageError> {
        Err(MirageError::Config(
            "RealityClientCamouflage cannot be used on the server side; use RealityServerCamouflage".into(),
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RealityServerCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// Reality-style camouflage — **server** side.
///
/// Reads the 96-byte Reality handshake from the client, validates the
/// encrypted session_id and short_id, then returns the raw `TcpStream` for
/// the inner Mirage ECDH handshake.  On invalid auth, returns `Ok(None)` so
/// the caller can forward the connection to a fallback destination.
///
/// # Fields
/// - `keypair` — server's static X25519 keypair.
/// - `short_ids` — accepted 16-byte short IDs (at least one must match).
/// - `max_time_diff` — maximum accepted clock skew in seconds.
pub struct RealityServerCamouflage {
    keypair: KeyPair,
    short_ids: Vec<[u8; SHORT_ID_LEN]>,
    max_time_diff: u64,
}

impl RealityServerCamouflage {
    /// Create a new server-side Reality camouflage layer.
    ///
    /// * `keypair` — server's static X25519 keypair.
    /// * `short_ids_hex` — list of hex-encoded 16-byte short IDs.
    /// * `max_time_diff` — clock skew tolerance in seconds.
    pub fn new(
        keypair: KeyPair,
        short_ids_hex: &[impl AsRef<str>],
        max_time_diff: u64,
    ) -> Result<Self, MirageError> {
        let short_ids = short_ids_hex
            .iter()
            .map(|s| decode_short_id(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            keypair,
            short_ids,
            max_time_diff,
        })
    }
}

impl private::Sealed for RealityServerCamouflage {}

#[async_trait]
impl CamouflageLayer for RealityServerCamouflage {
    type Stream = TcpStream;

    async fn wrap_client(
        &self,
        _stream: TcpStream,
        _sni: &str,
    ) -> Result<TcpStream, MirageError> {
        Err(MirageError::Config(
            "RealityServerCamouflage cannot be used on the client side; use RealityClientCamouflage".into(),
        ))
    }

    async fn wrap_server(&self, mut stream: TcpStream) -> Result<Option<TcpStream>, MirageError> {
        // ── Read full 96-byte handshake message ───────────────────────────────
        let mut hs_msg = [0u8; HS_MSG_LEN];
        stream.read_exact(&mut hs_msg).await?;

        let e_pub_bytes: [u8; 32] = hs_msg[..32]
            .try_into()
            .expect("slice is exactly 32 bytes");
        let enc_session_id = &hs_msg[32..32 + ENC_SESSION_ID_LEN];

        // ── Derive shared secret and Reality handshake key ────────────────────
        let client_pub = PublicKey::from(e_pub_bytes);
        let ss_bytes = shared_secret(&self.keypair.secret, &client_pub);
        let reality_key = derive_key(&ss_bytes, &[], b"REALITY");

        // ── Derive nonce ──────────────────────────────────────────────────────
        let pub_hash = hash_blake3(&e_pub_bytes);
        let nonce: [u8; 12] = pub_hash[..12]
            .try_into()
            .expect("BLAKE3 output is 32 bytes, slice of 12 is always valid");

        // ── Attempt decryption — failure means unauthenticated probe ──────────
        // Reality camouflage cipher: ChaCha20-Poly1305 hardcoded per the Reality spec —
        // this decrypts the TLS ClientHello session_id field, not session traffic.
        let cipher = AeadCipher::with_suite(AeadSuite::ChaCha20Poly1305, &reality_key);
        let session_id = match cipher.decrypt(&nonce, enc_session_id, &[]) {
            Ok(pt) => pt,
            Err(_) => {
                debug!("reality: AEAD decrypt failed — not a valid Reality handshake");
                return Ok(None);
            }
        };

        if session_id.len() < SESSION_ID_LEN {
            return Ok(None);
        }

        // ── Verify timestamp ──────────────────────────────────────────────────
        let ts_bytes: [u8; 4] = session_id[4..8]
            .try_into()
            .expect("slice is exactly 4 bytes");
        let client_ts = u32::from_be_bytes(ts_bytes) as u64;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let diff = now_secs.abs_diff(client_ts);
        if diff > self.max_time_diff {
            debug!(
                diff,
                max = self.max_time_diff,
                "reality: timestamp out of range"
            );
            return Ok(None);
        }

        // ── Verify short_id ───────────────────────────────────────────────────
        let client_short_id: [u8; SHORT_ID_LEN] = session_id[8..24]
            .try_into()
            .expect("slice is exactly 16 bytes");

        let id_valid = self.short_ids.iter().any(|id| *id == client_short_id);
        if !id_valid {
            debug!("reality: short_id not recognized");
            return Ok(None);
        }

        // ── Send confirmation ─────────────────────────────────────────────────
        let confirm = reality_confirm(&ss_bytes);
        stream.write_all(&confirm).await?;

        debug!("reality: server handshake complete");
        Ok(Some(stream))
    }
}
