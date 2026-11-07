//! Wire frame types for V9-FS forward-secret onion handshake.
//!
//! V9-FS uses a telescopic (incremental) circuit construction where each hop
//! returns its own ephemeral public key, allowing the client to derive
//! per-hop session keys without using any node static key.
//!
//! Wire version bytes for FS onion frames:
//! - `0x0A` — legacy (no credential field); still accepted on decode for interop.
//! - `0x0B` — current; appends `[1B scheme][2B len BE][N B cred]` after the
//!   fixed fields.  Encoder always writes 0x0B.  Decoder accepts both.
//!
//! Frame type constants:
//! - `WIRE_VERSION_FS = 0x0B` — first byte written by encoder for `FsInitFrame`.
//! - `WIRE_VERSION_FS_LEGACY = 0x0A` — accepted on decode, treated as scheme=0x00.
//! - `MSG_FS_CREATED = 0x90` — server → client after handshake per hop.
//! - `MSG_FS_EXTEND = 0x91` — client → hop i (encrypted through keys 0..i-1).
//! - `MSG_FS_RELAY_INIT = 0x92` — entry/middle relays to next hop.

use mirage_core::{crypto::AeadSuite, error::MirageError};

/// Wire version byte written by the encoder for V9-FS onion frames (0x0B).
pub const WIRE_VERSION_FS: u8 = 0x0B;

/// Legacy wire version byte (0x0A) — accepted on decode, treated as scheme=0x00.
pub const WIRE_VERSION_FS_LEGACY: u8 = 0x0A;

/// `FsCreatedFrame` message type — sent by node after completing its hop handshake.
pub const MSG_FS_CREATED: u8 = 0x90;

/// `FsExtendFrame` message type — sent by client (encrypted) to extend circuit.
pub const MSG_FS_EXTEND: u8 = 0x91;

/// `FsRelayInitFrame` message type — sent by relay hops toward the next hop.
pub const MSG_FS_RELAY_INIT: u8 = 0x92;

/// FS handshake status codes returned in `FsCreatedFrame`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsCreatedStatus {
    Ok = 0,
    BadVersion = 1,
    NoCommonSuite = 2,
    AeadFail = 3,
    PeerTableMiss = 4,
    SuitePolicyViolation = 5,
    /// The exit node rejected the connection because the credential was
    /// absent, invalid, or replayed.  Clients should present a valid
    /// EpochHmac credential (scheme=0x01) and retry with a fresh nonce.
    CredentialRejected = 6,
    Unknown = 0xFFFF_FFFF,
}

impl FsCreatedStatus {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => FsCreatedStatus::Ok,
            1 => FsCreatedStatus::BadVersion,
            2 => FsCreatedStatus::NoCommonSuite,
            3 => FsCreatedStatus::AeadFail,
            4 => FsCreatedStatus::PeerTableMiss,
            5 => FsCreatedStatus::SuitePolicyViolation,
            6 => FsCreatedStatus::CredentialRejected,
            _ => FsCreatedStatus::Unknown,
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            FsCreatedStatus::Ok => 0,
            FsCreatedStatus::BadVersion => 1,
            FsCreatedStatus::NoCommonSuite => 2,
            FsCreatedStatus::AeadFail => 3,
            FsCreatedStatus::PeerTableMiss => 4,
            FsCreatedStatus::SuitePolicyViolation => 5,
            FsCreatedStatus::CredentialRejected => 6,
            FsCreatedStatus::Unknown => 0xFFFF_FFFF,
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, FsCreatedStatus::Ok)
    }

    pub fn name(self) -> &'static str {
        match self {
            FsCreatedStatus::Ok => "OK",
            FsCreatedStatus::BadVersion => "BAD_VERSION",
            FsCreatedStatus::NoCommonSuite => "NO_COMMON_SUITE",
            FsCreatedStatus::AeadFail => "AEAD_FAIL",
            FsCreatedStatus::PeerTableMiss => "PEER_TABLE_MISS",
            FsCreatedStatus::SuitePolicyViolation => "SUITE_POLICY_VIOLATION",
            FsCreatedStatus::CredentialRejected => "CREDENTIAL_REJECTED",
            FsCreatedStatus::Unknown => "UNKNOWN",
        }
    }
}

/// `FsInitFrame` — Client → Hop 0 (first message on wire).
///
/// Wire layout (version 0x0B, current):
/// ```text
/// [1B  wire_version = WIRE_VERSION_FS = 0x0B]
/// [2B  mesh_id_len BE][N B mesh_id]
/// [2B  chain_id_len BE][N B chain_id]
/// [1B  chain_length]
/// [1B  chain_position]               ← 0 for entry hop
/// [1B  client_suites_count]
/// [N B client_suite_ids]
/// [32B client_eph_pub]               ← per-hop client ephemeral X25519 public key
/// [8B  expected_peer_table_generation BE u64]
/// [1B  credential_scheme]            ← 0x00 = none, 0x01 = EpochHmac
/// [2B  credential_len BE]            ← 0 when scheme=0x00
/// [N B credential_bytes]             ← 52 bytes for EpochHmac
/// ```
///
/// Legacy version 0x0A is accepted on decode and produces `credential_scheme=0x00`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInitFrame {
    pub mesh_id: Vec<u8>,
    pub chain_id: Vec<u8>,
    pub chain_length: u8,
    pub chain_position: u8,
    pub client_suites: Vec<AeadSuite>,
    pub client_eph_pub: [u8; 32],
    pub expected_peer_table_generation: u64,
    /// Credential scheme byte: 0x00 = no credential, 0x01 = EpochHmac.
    pub credential_scheme: u8,
    /// Raw credential bytes.  Empty when `credential_scheme == 0x00`.
    /// 52 bytes for EpochHmac: `[4B epoch_id BE][16B nonce][32B mac]`.
    pub credential: Vec<u8>,
    /// Per-hop selector token — the high-entropy name of the listener this
    /// frame addresses. Empty means "not sent", which is a legitimate state
    /// during rollout and forever for a peer that has none.
    ///
    /// **Why it exists.** A hop must name a listener before it can pick the
    /// keys that decode the frame, and until now that name was derived:
    /// `{chain_id}-h{position}`. `chain_id` is `auto-{8hex}` from a `u32` —
    /// 32 bits, and its own doc says it was sized "short enough to scan logs
    /// by eye". It became a secret the moment the selector replaced the bind
    /// port as the address, and nothing re-sized it for that job. Two
    /// identifiers, two jobs: this is the address, `chain_id` stays the
    /// human handle in logs.
    ///
    /// **Why a trailer.** Written only when non-empty, so a writer with no
    /// token emits byte-for-byte the frame this format already had, and a
    /// reader that ends here treats it as absent — the same shape the
    /// credential trailer above uses, and the reason this half of item 11
    /// needs no flag day.
    pub selector_token: Vec<u8>,
}

impl FsInitFrame {
    pub fn encode(&self) -> Result<Vec<u8>, MirageError> {
        if self.client_suites.is_empty() {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: client_suites must be non-empty".into(),
            ));
        }
        if self.client_suites.len() > 255 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: client_suites must fit in u8".into(),
            ));
        }
        if self.mesh_id.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: mesh_id too long".into(),
            ));
        }
        if self.chain_id.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: chain_id too long".into(),
            ));
        }
        if self.credential.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: credential too long".into(),
            ));
        }

        let mut out = Vec::with_capacity(
            1 + 2 + self.mesh_id.len()
                + 2
                + self.chain_id.len()
                + 1
                + 1
                + 1
                + self.client_suites.len()
                + 32
                + 8
                + 1 + 2 + self.credential.len(),
        );
        // Always write version 0x0B (credential-capable).
        out.push(WIRE_VERSION_FS);
        out.extend_from_slice(&(self.mesh_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mesh_id);
        out.extend_from_slice(&(self.chain_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.chain_id);
        out.push(self.chain_length);
        out.push(self.chain_position);
        out.push(self.client_suites.len() as u8);
        for s in &self.client_suites {
            out.push(s.id());
        }
        out.extend_from_slice(&self.client_eph_pub);
        out.extend_from_slice(&self.expected_peer_table_generation.to_be_bytes());
        // Credential trailer (only present in 0x0B).
        out.push(self.credential_scheme);
        out.extend_from_slice(&(self.credential.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.credential);
        // Selector trailer — written only when present, so a frame without a
        // token is byte-identical to the format that predates it.
        if !self.selector_token.is_empty() {
            if self.selector_token.len() > u8::MAX as usize {
                return Err(MirageError::Protocol(
                    "v9-fs: selector_token too long".into(),
                ));
            }
            out.push(self.selector_token.len() as u8);
            out.extend_from_slice(&self.selector_token);
        }
        Ok(out)
    }

    /// Returns `(frame, bytes_consumed)`.
    ///
    /// Accepts both wire version 0x0A (legacy, no credential) and 0x0B (current).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), MirageError> {
        if buf.is_empty() {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: buffer empty".into(),
            ));
        }
        let wire_ver = buf[0];
        if wire_ver != WIRE_VERSION_FS && wire_ver != WIRE_VERSION_FS_LEGACY {
            return Err(MirageError::Protocol(format!(
                "v9-fs FsInitFrame: wrong wire version 0x{:02x} (expected 0x{:02x} or 0x{:02x})",
                wire_ver, WIRE_VERSION_FS, WIRE_VERSION_FS_LEGACY
            )));
        }
        let mut off = 1usize;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated mesh_id len".into(),
            ));
        }
        let mesh_id_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if buf.len() < off + mesh_id_len {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated mesh_id".into(),
            ));
        }
        let mesh_id = buf[off..off + mesh_id_len].to_vec();
        off += mesh_id_len;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated chain_id len".into(),
            ));
        }
        let chain_id_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if buf.len() < off + chain_id_len {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated chain_id".into(),
            ));
        }
        let chain_id = buf[off..off + chain_id_len].to_vec();
        off += chain_id_len;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated chain_length/chain_position".into(),
            ));
        }
        let chain_length = buf[off];
        off += 1;
        let chain_position = buf[off];
        off += 1;

        if buf.len() < off + 1 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated suite count".into(),
            ));
        }
        let suite_count = buf[off] as usize;
        off += 1;
        if suite_count == 0 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: empty client_suites".into(),
            ));
        }
        if buf.len() < off + suite_count {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated client_suites".into(),
            ));
        }
        let mut client_suites = Vec::with_capacity(suite_count);
        for i in 0..suite_count {
            client_suites.push(AeadSuite::from_byte(buf[off + i])?);
        }
        off += suite_count;

        if buf.len() < off + 32 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated client_eph_pub".into(),
            ));
        }
        let mut client_eph_pub = [0u8; 32];
        client_eph_pub.copy_from_slice(&buf[off..off + 32]);
        off += 32;

        if buf.len() < off + 8 {
            return Err(MirageError::Protocol(
                "v9-fs FsInitFrame: truncated expected_peer_table_generation".into(),
            ));
        }
        let expected_peer_table_generation = u64::from_be_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        off += 8;

        // Credential trailer — present in 0x0B, absent in legacy 0x0A.
        let (credential_scheme, credential) = if wire_ver == WIRE_VERSION_FS {
            if buf.len() < off + 3 {
                return Err(MirageError::Protocol(
                    "v9-fs FsInitFrame: truncated credential trailer".into(),
                ));
            }
            let scheme = buf[off];
            off += 1;
            let cred_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
            off += 2;
            if buf.len() < off + cred_len {
                return Err(MirageError::Protocol(
                    "v9-fs FsInitFrame: truncated credential bytes".into(),
                ));
            }
            let cred = buf[off..off + cred_len].to_vec();
            off += cred_len;
            (scheme, cred)
        } else {
            // Legacy 0x0A: no credential.
            (0x00u8, Vec::new())
        };

        // Selector trailer — absent when the buffer ends here.
        let selector_token: Vec<u8> = if buf.len() > off {
            let tok_len = buf[off] as usize;
            off += 1;
            if buf.len() < off + tok_len {
                return Err(MirageError::Protocol(
                    "v9-fs FsInitFrame: truncated selector token".into(),
                ));
            }
            let tok = buf[off..off + tok_len].to_vec();
            off += tok_len;
            tok
        } else {
            Vec::new()
        };

        Ok((
            FsInitFrame {
                mesh_id,
                chain_id,
                chain_length,
                chain_position,
                client_suites,
                client_eph_pub,
                expected_peer_table_generation,
                credential_scheme,
                credential,
                selector_token,
            },
            off,
        ))
    }
}

/// `FsCreatedFrame` — Node → Client (response to `FsInitFrame` or `FsExtendFrame`).
///
/// Wire layout (fixed 103 bytes):
/// ```text
/// [1B  type = MSG_FS_CREATED = 0x90]
/// [1B  chain_position]
/// [1B  chosen_suite_id]
/// [4B  status BE u32]
/// [32B server_eph_pub]    ← node's per-session ephemeral X25519 public key
/// [32B transcript_hash]
/// [32B auth_tag]          ← key-confirmation tag (all-zeros when status != Ok)
/// ```
///
/// `server_eph_pub` and `auth_tag` are all-zeros when `status != Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsCreatedFrame {
    pub chain_position: u8,
    pub suite: AeadSuite,
    pub status: FsCreatedStatus,
    pub server_eph_pub: [u8; 32],
    pub transcript_hash: [u8; 32],
    /// Key-confirmation tag: `BLAKE3_keyed(layer_key, "mirage-onion-fs-keyconfirm-v1" || transcript_i || server_eph_pub)`.
    /// All-zeros when `status != Ok`.
    pub auth_tag: [u8; 32],
}

impl FsCreatedFrame {
    pub const ENCODED_LEN: usize = 1 + 1 + 1 + 4 + 32 + 32 + 32;

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = MSG_FS_CREATED;
        out[1] = self.chain_position;
        out[2] = self.suite.id();
        out[3..7].copy_from_slice(&self.status.as_u32().to_be_bytes());
        out[7..39].copy_from_slice(&self.server_eph_pub);
        out[39..71].copy_from_slice(&self.transcript_hash);
        out[71..103].copy_from_slice(&self.auth_tag);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, MirageError> {
        if buf.len() < Self::ENCODED_LEN {
            return Err(MirageError::Protocol(format!(
                "v9-fs FsCreatedFrame: need {} bytes, got {}",
                Self::ENCODED_LEN,
                buf.len()
            )));
        }
        if buf[0] != MSG_FS_CREATED {
            return Err(MirageError::Protocol(format!(
                "v9-fs FsCreatedFrame: wrong msg type 0x{:02x} (expected 0x{:02x})",
                buf[0], MSG_FS_CREATED
            )));
        }
        let chain_position = buf[1];
        let suite = AeadSuite::from_byte(buf[2])?;
        let status = FsCreatedStatus::from_u32(u32::from_be_bytes([
            buf[3], buf[4], buf[5], buf[6],
        ]));
        let mut server_eph_pub = [0u8; 32];
        server_eph_pub.copy_from_slice(&buf[7..39]);
        let mut transcript_hash = [0u8; 32];
        transcript_hash.copy_from_slice(&buf[39..71]);
        let mut auth_tag = [0u8; 32];
        auth_tag.copy_from_slice(&buf[71..103]);
        Ok(FsCreatedFrame {
            chain_position,
            suite,
            status,
            server_eph_pub,
            transcript_hash,
            auth_tag,
        })
    }
}

/// `FsExtendFrame` — Client → Hop i (inner, encrypted through keys 0..i-1).
///
/// After decryption by entry hop, this is forwarded as `FsRelayInitFrame` to hop i.
///
/// Wire layout:
/// ```text
/// [1B  type = MSG_FS_EXTEND = 0x91]
/// [1B  chain_position]               ← i
/// [2B  next_hop_addr_len BE]
/// [N B next_hop_addr_utf8]           ← "host:port" for hop i
/// [32B client_eph_pub]               ← client's per-hop ephemeral X25519 public key
/// [8B  expected_peer_table_generation BE u64]
/// [1B  client_suites_count]
/// [N B client_suite_ids]
/// [32B prev_transcript]              ← transcript_{i-1} for hop i's key derivation
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsExtendFrame {
    pub chain_position: u8,
    pub next_hop_addr: String,
    pub client_eph_pub: [u8; 32],
    pub expected_peer_table_generation: u64,
    pub client_suites: Vec<AeadSuite>,
    /// Transcript from the previous hop (transcript_{i-1}).
    /// Included so hop i can compute transcript_i = extend_fs_transcript(prev_transcript, ...).
    /// Secure: this field is encrypted through keys 0..i-1 before transmission.
    pub prev_transcript: [u8; 32],
    /// Per-hop selector token addressed to hop `chain_position`. See
    /// [`FsInitFrame::selector_token`] for what it is and why it rides as a
    /// trailer. Encrypted through layers 0..i-1 like the rest of this frame,
    /// so a hop learns only the token meant for the hop it forwards to.
    pub selector_token: Vec<u8>,
}

impl FsExtendFrame {
    pub fn encode(&self) -> Result<Vec<u8>, MirageError> {
        if self.next_hop_addr.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: next_hop_addr too long".into(),
            ));
        }
        if self.client_suites.is_empty() {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: client_suites must be non-empty".into(),
            ));
        }
        if self.client_suites.len() > 255 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: client_suites must fit in u8".into(),
            ));
        }

        let addr_bytes = self.next_hop_addr.as_bytes();
        let mut out = Vec::with_capacity(
            1 + 1 + 2 + addr_bytes.len() + 32 + 8 + 1 + self.client_suites.len() + 32,
        );
        out.push(MSG_FS_EXTEND);
        out.push(self.chain_position);
        out.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(addr_bytes);
        out.extend_from_slice(&self.client_eph_pub);
        out.extend_from_slice(&self.expected_peer_table_generation.to_be_bytes());
        out.push(self.client_suites.len() as u8);
        for s in &self.client_suites {
            out.push(s.id());
        }
        out.extend_from_slice(&self.prev_transcript);
        // Selector trailer — written only when present, so a frame without a
        // token is byte-identical to the format that predates it.
        if !self.selector_token.is_empty() {
            if self.selector_token.len() > u8::MAX as usize {
                return Err(MirageError::Protocol(
                    "v9-fs FsExtendFrame: selector_token too long".into(),
                ));
            }
            out.push(self.selector_token.len() as u8);
            out.extend_from_slice(&self.selector_token);
        }
        Ok(out)
    }

    /// Returns `(frame, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), MirageError> {
        if buf.len() < 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: buffer too short".into(),
            ));
        }
        if buf[0] != MSG_FS_EXTEND {
            return Err(MirageError::Protocol(format!(
                "v9-fs FsExtendFrame: wrong msg type 0x{:02x} (expected 0x{:02x})",
                buf[0], MSG_FS_EXTEND
            )));
        }
        let chain_position = buf[1];
        let mut off = 2usize;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated next_hop_addr len".into(),
            ));
        }
        let addr_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if buf.len() < off + addr_len {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated next_hop_addr".into(),
            ));
        }
        let next_hop_addr = std::str::from_utf8(&buf[off..off + addr_len])
            .map_err(|_| MirageError::Protocol("v9-fs FsExtendFrame: next_hop_addr not UTF-8".into()))?
            .to_owned();
        off += addr_len;

        if buf.len() < off + 32 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated client_eph_pub".into(),
            ));
        }
        let mut client_eph_pub = [0u8; 32];
        client_eph_pub.copy_from_slice(&buf[off..off + 32]);
        off += 32;

        if buf.len() < off + 8 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated expected_peer_table_generation".into(),
            ));
        }
        let expected_peer_table_generation = u64::from_be_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        off += 8;

        if buf.len() < off + 1 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated suite count".into(),
            ));
        }
        let suite_count = buf[off] as usize;
        off += 1;
        if suite_count == 0 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: empty client_suites".into(),
            ));
        }
        if buf.len() < off + suite_count {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated client_suites".into(),
            ));
        }
        let mut client_suites = Vec::with_capacity(suite_count);
        for i in 0..suite_count {
            client_suites.push(AeadSuite::from_byte(buf[off + i])?);
        }
        off += suite_count;

        if buf.len() < off + 32 {
            return Err(MirageError::Protocol(
                "v9-fs FsExtendFrame: truncated prev_transcript".into(),
            ));
        }
        let mut prev_transcript = [0u8; 32];
        prev_transcript.copy_from_slice(&buf[off..off + 32]);
        off += 32;

        // Selector trailer — absent when the buffer ends here.
        let selector_token: Vec<u8> = if buf.len() > off {
            let tok_len = buf[off] as usize;
            off += 1;
            if buf.len() < off + tok_len {
                return Err(MirageError::Protocol(
                    "v9-fs FsExtendFrame: truncated selector token".into(),
                ));
            }
            let tok = buf[off..off + tok_len].to_vec();
            off += tok_len;
            tok
        } else {
            Vec::new()
        };

        Ok((
            FsExtendFrame {
                chain_position,
                next_hop_addr,
                client_eph_pub,
                expected_peer_table_generation,
                client_suites,
                prev_transcript,
                selector_token,
            },
            off,
        ))
    }
}

/// `FsRelayInitFrame` — Entry/Middle relays to next hop after decryption.
///
/// Allows hop i to behave identically whether it is the entry hop (receives
/// `FsInitFrame` directly from client) or a deeper hop (receives this frame
/// relayed by the entry hop after decryption of `FsExtendFrame`).
///
/// Wire layout:
/// ```text
/// [1B  type = MSG_FS_RELAY_INIT = 0x92]
/// [2B  mesh_id_len BE][N B mesh_id]       ← copied from original FsInitFrame by entry
/// [2B  chain_id_len BE][N B chain_id]
/// [1B  chain_length]
/// [1B  chain_position]                    ← i (this hop's position)
/// [1B  client_suites_count]
/// [N B client_suite_ids]
/// [32B client_eph_pub]                    ← from FsExtendFrame
/// [8B  expected_peer_table_generation BE u64]
/// [32B prev_transcript]                   ← transcript_{i-1} from FsExtendFrame
/// [1B  credential_scheme]                 ← 0x00 = none, 0x01 = EpochHmac
/// [2B  credential_len BE]                 ← 0 when scheme=0x00
/// [N B credential_bytes]                  ← 52 bytes for EpochHmac
/// ```
///
/// The credential is copied verbatim from the original `FsInitFrame` by the
/// entry relay (chain_position == 0) and forwarded to every subsequent hop
/// including the exit.  Relays do NOT verify credentials.  Only the exit verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsRelayInitFrame {
    pub mesh_id: Vec<u8>,
    pub chain_id: Vec<u8>,
    pub chain_length: u8,
    pub chain_position: u8,
    pub client_suites: Vec<AeadSuite>,
    pub client_eph_pub: [u8; 32],
    pub expected_peer_table_generation: u64,
    pub prev_transcript: [u8; 32],
    /// Credential scheme byte: 0x00 = no credential, 0x01 = EpochHmac.
    pub credential_scheme: u8,
    /// Raw credential bytes.  Empty when `credential_scheme == 0x00`.
    pub credential: Vec<u8>,
    /// Per-hop selector token for the hop this frame is forwarded TO. The
    /// relay copies it out of the `FsExtendFrame` it peeled; see
    /// [`FsInitFrame::selector_token`].
    pub selector_token: Vec<u8>,
}

impl FsRelayInitFrame {
    pub fn encode(&self) -> Result<Vec<u8>, MirageError> {
        if self.client_suites.is_empty() {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: client_suites must be non-empty".into(),
            ));
        }
        if self.client_suites.len() > 255 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: client_suites must fit in u8".into(),
            ));
        }
        if self.mesh_id.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: mesh_id too long".into(),
            ));
        }
        if self.chain_id.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: chain_id too long".into(),
            ));
        }
        if self.credential.len() > u16::MAX as usize {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: credential too long".into(),
            ));
        }

        let mut out = Vec::with_capacity(
            1 + 2 + self.mesh_id.len()
                + 2
                + self.chain_id.len()
                + 1
                + 1
                + 1
                + self.client_suites.len()
                + 32
                + 8
                + 32
                + 1 + 2 + self.credential.len(),
        );
        out.push(MSG_FS_RELAY_INIT);
        out.extend_from_slice(&(self.mesh_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mesh_id);
        out.extend_from_slice(&(self.chain_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.chain_id);
        out.push(self.chain_length);
        out.push(self.chain_position);
        out.push(self.client_suites.len() as u8);
        for s in &self.client_suites {
            out.push(s.id());
        }
        out.extend_from_slice(&self.client_eph_pub);
        out.extend_from_slice(&self.expected_peer_table_generation.to_be_bytes());
        out.extend_from_slice(&self.prev_transcript);
        // Credential trailer.
        out.push(self.credential_scheme);
        out.extend_from_slice(&(self.credential.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.credential);
        // Selector trailer — written only when present, so a frame without a
        // token is byte-identical to the format that predates it.
        if !self.selector_token.is_empty() {
            if self.selector_token.len() > u8::MAX as usize {
                return Err(MirageError::Protocol(
                    "v9-fs FsRelayInitFrame: selector_token too long".into(),
                ));
            }
            out.push(self.selector_token.len() as u8);
            out.extend_from_slice(&self.selector_token);
        }
        Ok(out)
    }

    /// Returns `(frame, bytes_consumed)`.
    ///
    /// The credential trailer (`[1B scheme][2B len][N bytes]`) is always
    /// present.  Old frames without the trailer decode with `credential_scheme=0x00`
    /// if the buffer ends exactly at `prev_transcript` (legacy compat).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), MirageError> {
        if buf.is_empty() {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: buffer empty".into(),
            ));
        }
        if buf[0] != MSG_FS_RELAY_INIT {
            return Err(MirageError::Protocol(format!(
                "v9-fs FsRelayInitFrame: wrong msg type 0x{:02x} (expected 0x{:02x})",
                buf[0], MSG_FS_RELAY_INIT
            )));
        }
        let mut off = 1usize;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated mesh_id len".into(),
            ));
        }
        let mesh_id_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if buf.len() < off + mesh_id_len {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated mesh_id".into(),
            ));
        }
        let mesh_id = buf[off..off + mesh_id_len].to_vec();
        off += mesh_id_len;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated chain_id len".into(),
            ));
        }
        let chain_id_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
        if buf.len() < off + chain_id_len {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated chain_id".into(),
            ));
        }
        let chain_id = buf[off..off + chain_id_len].to_vec();
        off += chain_id_len;

        if buf.len() < off + 2 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated chain_length/chain_position".into(),
            ));
        }
        let chain_length = buf[off];
        off += 1;
        let chain_position = buf[off];
        off += 1;

        if buf.len() < off + 1 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated suite count".into(),
            ));
        }
        let suite_count = buf[off] as usize;
        off += 1;
        if suite_count == 0 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: empty client_suites".into(),
            ));
        }
        if buf.len() < off + suite_count {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated client_suites".into(),
            ));
        }
        let mut client_suites = Vec::with_capacity(suite_count);
        for i in 0..suite_count {
            client_suites.push(AeadSuite::from_byte(buf[off + i])?);
        }
        off += suite_count;

        if buf.len() < off + 32 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated client_eph_pub".into(),
            ));
        }
        let mut client_eph_pub = [0u8; 32];
        client_eph_pub.copy_from_slice(&buf[off..off + 32]);
        off += 32;

        if buf.len() < off + 8 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated expected_peer_table_generation".into(),
            ));
        }
        let expected_peer_table_generation = u64::from_be_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
            buf[off + 4],
            buf[off + 5],
            buf[off + 6],
            buf[off + 7],
        ]);
        off += 8;

        if buf.len() < off + 32 {
            return Err(MirageError::Protocol(
                "v9-fs FsRelayInitFrame: truncated prev_transcript".into(),
            ));
        }
        let mut prev_transcript = [0u8; 32];
        prev_transcript.copy_from_slice(&buf[off..off + 32]);
        off += 32;

        // Credential trailer — optional for legacy compat (old relay → new exit).
        // If the buffer ends exactly here, treat as no-credential.
        let (credential_scheme, credential) = if buf.len() > off {
            if buf.len() < off + 3 {
                return Err(MirageError::Protocol(
                    "v9-fs FsRelayInitFrame: truncated credential trailer".into(),
                ));
            }
            let scheme = buf[off];
            off += 1;
            let cred_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
            off += 2;
            if buf.len() < off + cred_len {
                return Err(MirageError::Protocol(
                    "v9-fs FsRelayInitFrame: truncated credential bytes".into(),
                ));
            }
            let cred = buf[off..off + cred_len].to_vec();
            off += cred_len;
            (scheme, cred)
        } else {
            (0x00u8, Vec::new())
        };

        // Selector trailer — absent when the buffer ends here.
        let selector_token: Vec<u8> = if buf.len() > off {
            let tok_len = buf[off] as usize;
            off += 1;
            if buf.len() < off + tok_len {
                return Err(MirageError::Protocol(
                    "v9-fs FsRelayInitFrame: truncated selector token".into(),
                ));
            }
            let tok = buf[off..off + tok_len].to_vec();
            off += tok_len;
            tok
        } else {
            Vec::new()
        };

        Ok((
            FsRelayInitFrame {
                mesh_id,
                chain_id,
                chain_length,
                chain_position,
                client_suites,
                client_eph_pub,
                expected_peer_table_generation,
                prev_transcript,
                credential_scheme,
                credential,
                selector_token,
            },
            off,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FsInitFrame ──────────────────────────────────────────────────────────

    #[test]
    fn fs_init_frame_roundtrip() {
        let f = FsInitFrame {
            mesh_id: b"staging-v2".to_vec(),
            chain_id: b"c-fs-test".to_vec(),
            chain_length: 3,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm],
            client_eph_pub: [0xABu8; 32],
            expected_peer_table_generation: 42,
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        let (decoded, consumed) = FsInitFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
        assert_eq!(consumed, bytes.len());
        assert_eq!(bytes[0], WIRE_VERSION_FS);
    }

    #[test]
    fn fs_init_frame_roundtrip_empty_ids() {
        let f = FsInitFrame {
            mesh_id: vec![],
            chain_id: vec![],
            chain_length: 1,
            chain_position: 0,
            client_suites: vec![AeadSuite::Aes128Gcm],
            client_eph_pub: [0x01u8; 32],
            expected_peer_table_generation: 0,
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        let (decoded, _) = FsInitFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn fs_init_frame_with_epoch_hmac_credential_roundtrip() {
        // EpochHmac credential: epoch_id[4] + nonce[16] + mac[32] = 52 bytes.
        let mut cred = vec![0u8; 52];
        // epoch_id = 0x0000_0007
        cred[0] = 0x00; cred[1] = 0x00; cred[2] = 0x00; cred[3] = 0x07;
        // fill nonce + mac with distinct patterns
        for i in 4..20 { cred[i] = 0xAA; }
        for i in 20..52 { cred[i] = 0xBB; }

        let f = FsInitFrame {
            mesh_id: b"staging-v2".to_vec(),
            chain_id: b"c-cred-test".to_vec(),
            chain_length: 3,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0xCCu8; 32],
            expected_peer_table_generation: 99,
            credential_scheme: 0x01,
            credential: cred.clone(),
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        assert_eq!(bytes[0], WIRE_VERSION_FS, "encoder must write 0x0B");
        let (decoded, consumed) = FsInitFrame::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.credential_scheme, 0x01);
        assert_eq!(decoded.credential, cred);
    }

    #[test]
    fn fs_init_frame_legacy_0x0a_decode_no_credential() {
        // Build a valid 0x0A frame by hand (encode a 0x0B frame, patch byte 0).
        let f = FsInitFrame {
            mesh_id: b"m".to_vec(),
            chain_id: b"c".to_vec(),
            chain_length: 2,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0x11u8; 32],
            expected_peer_table_generation: 5,
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let mut bytes = f.encode().unwrap();
        // Strip the credential trailer (last 3 bytes: [scheme=0x00][len_hi=0x00][len_lo=0x00])
        // and patch version to 0x0A to simulate a legacy frame.
        let trailer_len = 3; // 1B scheme + 2B len + 0B cred
        bytes.truncate(bytes.len() - trailer_len);
        bytes[0] = WIRE_VERSION_FS_LEGACY;

        let (decoded, consumed) = FsInitFrame::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.credential_scheme, 0x00, "legacy decode must produce scheme=0x00");
        assert!(decoded.credential.is_empty(), "legacy decode must produce empty credential");
        assert_eq!(decoded.mesh_id, b"m".to_vec());
        assert_eq!(decoded.expected_peer_table_generation, 5);
    }

    #[test]
    fn fs_init_frame_rejects_wrong_version() {
        let f = FsInitFrame {
            mesh_id: b"m".to_vec(),
            chain_id: b"c".to_vec(),
            chain_length: 1,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0u8; 32],
            expected_peer_table_generation: 1,
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let mut bytes = f.encode().unwrap();
        bytes[0] = 0x09; // neither 0x0A nor 0x0B
        let err = FsInitFrame::decode(&bytes).unwrap_err();
        assert!(format!("{err:?}").contains("wrong wire version"));
    }

    #[test]
    fn fs_init_frame_rejects_truncated() {
        let err = FsInitFrame::decode(&[WIRE_VERSION_FS, 0x00]).unwrap_err();
        assert!(format!("{err:?}").contains("truncated"));
    }

    #[test]
    fn fs_init_frame_rejects_empty_suites() {
        let f = FsInitFrame {
            mesh_id: vec![],
            chain_id: vec![],
            chain_length: 1,
            chain_position: 0,
            client_suites: vec![],
            client_eph_pub: [0u8; 32],
            expected_peer_table_generation: 0,
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        assert!(f.encode().is_err());
    }

    // ── FsCreatedFrame ───────────────────────────────────────────────────────

    #[test]
    fn fs_created_frame_roundtrip_ok() {
        let f = FsCreatedFrame {
            chain_position: 1,
            suite: AeadSuite::Aes256Gcm,
            status: FsCreatedStatus::Ok,
            server_eph_pub: [0xCDu8; 32],
            transcript_hash: [0xEFu8; 32],
            auth_tag: [0xA5u8; 32],
        };
        let bytes = f.encode();
        assert_eq!(bytes.len(), FsCreatedFrame::ENCODED_LEN);
        assert_eq!(FsCreatedFrame::ENCODED_LEN, 103);
        assert_eq!(bytes[0], MSG_FS_CREATED);
        let decoded = FsCreatedFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
        assert!(decoded.status.is_ok());
    }

    #[test]
    fn fs_created_frame_roundtrip_aead_fail() {
        let f = FsCreatedFrame {
            chain_position: 0,
            suite: AeadSuite::ChaCha20Poly1305,
            status: FsCreatedStatus::AeadFail,
            server_eph_pub: [0u8; 32], // all-zeros when status != Ok
            transcript_hash: [0u8; 32],
            auth_tag: [0u8; 32], // all-zeros when status != Ok
        };
        let bytes = f.encode();
        let decoded = FsCreatedFrame::decode(&bytes).unwrap();
        assert_eq!(decoded.status, FsCreatedStatus::AeadFail);
        assert_eq!(decoded.status.name(), "AEAD_FAIL");
        assert!(!decoded.status.is_ok());
    }

    #[test]
    fn fs_created_frame_roundtrip_all_status_variants() {
        let variants = [
            FsCreatedStatus::Ok,
            FsCreatedStatus::BadVersion,
            FsCreatedStatus::NoCommonSuite,
            FsCreatedStatus::AeadFail,
            FsCreatedStatus::PeerTableMiss,
            FsCreatedStatus::SuitePolicyViolation,
            FsCreatedStatus::CredentialRejected,
        ];
        for v in variants {
            let roundtripped = FsCreatedStatus::from_u32(v.as_u32());
            assert_eq!(roundtripped, v);
        }
        // Unknown catches unrecognised values.
        assert_eq!(FsCreatedStatus::from_u32(999), FsCreatedStatus::Unknown);
        assert_eq!(FsCreatedStatus::Unknown.as_u32(), 0xFFFF_FFFF);
    }

    #[test]
    fn fs_created_frame_rejects_wrong_type() {
        let mut bytes = FsCreatedFrame {
            chain_position: 0,
            suite: AeadSuite::ChaCha20Poly1305,
            status: FsCreatedStatus::Ok,
            server_eph_pub: [0u8; 32],
            transcript_hash: [0u8; 32],
            auth_tag: [0u8; 32],
        }
        .encode();
        bytes[0] = 0x80;
        assert!(FsCreatedFrame::decode(&bytes).is_err());
    }

    #[test]
    fn fs_created_frame_rejects_truncated() {
        let bytes = [MSG_FS_CREATED; 10]; // too short (need 103)
        let err = FsCreatedFrame::decode(&bytes).unwrap_err();
        assert!(format!("{err:?}").contains("need"));
    }

    // ── FsExtendFrame ────────────────────────────────────────────────────────

    #[test]
    fn fs_extend_frame_roundtrip() {
        let f = FsExtendFrame {
            chain_position: 1,
            next_hop_addr: "10.0.0.2:9000".into(),
            client_eph_pub: [0x12u8; 32],
            expected_peer_table_generation: 7,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            prev_transcript: [0x99u8; 32],
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        assert_eq!(bytes[0], MSG_FS_EXTEND);
        let (decoded, consumed) = FsExtendFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn fs_extend_frame_roundtrip_multi_suite() {
        let f = FsExtendFrame {
            chain_position: 2,
            next_hop_addr: "192.168.1.100:4321".into(),
            client_eph_pub: [0xAAu8; 32],
            expected_peer_table_generation: 100,
            client_suites: vec![
                AeadSuite::Aes256Gcm,
                AeadSuite::ChaCha20Poly1305,
                AeadSuite::Aes128Gcm,
            ],
            prev_transcript: [0x55u8; 32],
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        let (decoded, _) = FsExtendFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn fs_extend_frame_rejects_wrong_type() {
        let f = FsExtendFrame {
            chain_position: 0,
            next_hop_addr: "127.0.0.1:1234".into(),
            client_eph_pub: [0u8; 32],
            expected_peer_table_generation: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            prev_transcript: [0u8; 32],
            selector_token: Vec::new(),
        };
        let mut bytes = f.encode().unwrap();
        bytes[0] = 0x00;
        assert!(FsExtendFrame::decode(&bytes).is_err());
    }

    #[test]
    fn fs_extend_frame_rejects_truncated() {
        let err = FsExtendFrame::decode(&[MSG_FS_EXTEND]).unwrap_err();
        assert!(format!("{err:?}").contains("truncated") || format!("{err:?}").contains("short"));
    }

    // ── FsRelayInitFrame ─────────────────────────────────────────────────────

    #[test]
    fn fs_relay_init_frame_roundtrip() {
        let f = FsRelayInitFrame {
            mesh_id: b"staging-v2".to_vec(),
            chain_id: b"c-fs-relay".to_vec(),
            chain_length: 3,
            chain_position: 1,
            client_suites: vec![AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0x77u8; 32],
            expected_peer_table_generation: 99,
            prev_transcript: [0x33u8; 32],
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        assert_eq!(bytes[0], MSG_FS_RELAY_INIT);
        let (decoded, consumed) = FsRelayInitFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn fs_relay_init_frame_with_epoch_hmac_credential_roundtrip() {
        let mut cred = vec![0u8; 52];
        cred[0] = 0x00; cred[1] = 0x00; cred[2] = 0x00; cred[3] = 0x03;
        for i in 4..20 { cred[i] = 0xDE; }
        for i in 20..52 { cred[i] = 0xAD; }

        let f = FsRelayInitFrame {
            mesh_id: b"staging-v2".to_vec(),
            chain_id: b"c-cred-relay".to_vec(),
            chain_length: 3,
            chain_position: 2,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0x55u8; 32],
            expected_peer_table_generation: 7,
            prev_transcript: [0x22u8; 32],
            credential_scheme: 0x01,
            credential: cred.clone(),
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        let (decoded, consumed) = FsRelayInitFrame::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded.credential_scheme, 0x01);
        assert_eq!(decoded.credential, cred);
    }

    #[test]
    fn fs_relay_init_frame_roundtrip_empty_ids() {
        let f = FsRelayInitFrame {
            mesh_id: vec![],
            chain_id: vec![],
            chain_length: 2,
            chain_position: 1,
            client_suites: vec![AeadSuite::Aes128Gcm],
            client_eph_pub: [0x00u8; 32],
            expected_peer_table_generation: 0,
            prev_transcript: [0u8; 32],
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let bytes = f.encode().unwrap();
        let (decoded, _) = FsRelayInitFrame::decode(&bytes).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn fs_relay_init_frame_rejects_wrong_type() {
        let f = FsRelayInitFrame {
            mesh_id: b"m".to_vec(),
            chain_id: b"c".to_vec(),
            chain_length: 1,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [0u8; 32],
            expected_peer_table_generation: 0,
            prev_transcript: [0u8; 32],
            credential_scheme: 0x00,
            credential: vec![],
            selector_token: Vec::new(),
        };
        let mut bytes = f.encode().unwrap();
        bytes[0] = MSG_FS_EXTEND; // wrong type
        assert!(FsRelayInitFrame::decode(&bytes).is_err());
    }

    #[test]
    fn fs_relay_init_frame_rejects_truncated() {
        let err = FsRelayInitFrame::decode(&[MSG_FS_RELAY_INIT]).unwrap_err();
        assert!(format!("{err:?}").contains("truncated"));
    }

    #[test]
    fn fs_created_status_credential_rejected_roundtrip() {
        let v = FsCreatedStatus::CredentialRejected;
        assert_eq!(v.as_u32(), 6);
        assert_eq!(FsCreatedStatus::from_u32(6), FsCreatedStatus::CredentialRejected);
        assert_eq!(v.name(), "CREDENTIAL_REJECTED");
        assert!(!v.is_ok());
    }
}
#[cfg(test)]
mod selector_trailer_tests {
    use super::*;

    fn init(token: Vec<u8>) -> FsInitFrame {
        FsInitFrame {
            mesh_id: b"MESH1".to_vec(),
            chain_id: b"auto-deadbeef".to_vec(),
            chain_length: 3,
            chain_position: 0,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [7u8; 32],
            expected_peer_table_generation: 42,
            credential_scheme: 0x02,
            credential: vec![9u8; 20],
            selector_token: token,
        }
    }

    /// The whole reason this half of item 11 needs no flag day: a writer with
    /// no token emits exactly the bytes the format had before the field
    /// existed. If this ever fails, the rollout stops being soft.
    #[test]
    fn an_absent_token_changes_not_one_byte() {
        let without = init(Vec::new()).encode().expect("encode");
        let with = init(vec![0xAB; 16]).encode().expect("encode");
        assert_eq!(&with[..without.len()], &without[..]);
        assert_eq!(with.len(), without.len() + 1 + 16);
    }

    /// A reader that runs out of buffer where the trailer would start reads
    /// "absent", not an error — that is an old writer talking to a new reader.
    #[test]
    fn a_frame_that_ends_before_the_trailer_decodes_as_absent() {
        let bytes = init(Vec::new()).encode().expect("encode");
        let (decoded, used) = FsInitFrame::decode(&bytes).expect("decode");
        assert!(decoded.selector_token.is_empty());
        assert_eq!(used, bytes.len());
    }

    #[test]
    fn a_token_round_trips_on_all_three_frames() {
        let tok = vec![0x5Au8; 16];

        let (d, _) = FsInitFrame::decode(&init(tok.clone()).encode().expect("e"))
            .expect("init decode");
        assert_eq!(d.selector_token, tok);

        let ext = FsExtendFrame {
            chain_position: 2,
            next_hop_addr: "10.0.0.2:9000".into(),
            client_eph_pub: [1u8; 32],
            expected_peer_table_generation: 7,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            prev_transcript: [2u8; 32],
            selector_token: tok.clone(),
        };
        let (d, _) = FsExtendFrame::decode(&ext.encode().expect("e")).expect("extend decode");
        assert_eq!(d.selector_token, tok);

        let relay = FsRelayInitFrame {
            mesh_id: b"MESH1".to_vec(),
            chain_id: b"auto-deadbeef".to_vec(),
            chain_length: 3,
            chain_position: 1,
            client_suites: vec![AeadSuite::ChaCha20Poly1305],
            client_eph_pub: [3u8; 32],
            expected_peer_table_generation: 8,
            prev_transcript: [4u8; 32],
            credential_scheme: 0x02,
            credential: vec![5u8; 20],
            selector_token: tok.clone(),
        };
        let (d, _) = FsRelayInitFrame::decode(&relay.encode().expect("e"))
            .expect("relay decode");
        assert_eq!(d.selector_token, tok);
    }

    /// A length that runs past the buffer is a malformed frame, not an absent
    /// token — the two must not be confused, or a truncation reads as a
    /// peer that simply has no token.
    #[test]
    fn a_truncated_token_is_an_error_not_an_absence() {
        let mut bytes = init(vec![0xAB; 16]).encode().expect("encode");
        bytes.truncate(bytes.len() - 4);
        assert!(FsInitFrame::decode(&bytes).is_err());
    }
}
