//! Wire V9 — ephemeral-ephemeral forward-secret + mutual-auth handshake.
//!
//! # Wire layout
//!
//! **ClientHello (97 bytes):**
//! ```text
//! [1B  protocol_version = 0x09]
//! [3B  client_suites: [suite_id, 0x00, 0x00]]
//! [32B e_pub_c]
//! [8B  ts_ms big-endian]
//! [16B client_proof_mac]
//! [32B client_static_pub]
//! [1B  cred_scheme (0x00 = legacy/no-credential)]
//! [1B  target_hint (0x00 = legacy/no-preference; see `TargetHint`)]
//! [3B  reserved zeros]
//! ```
//!
//! `target_hint` was carved out of the four-byte reserved tail
//! (`docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md`,
//! Stage 2). `0x00` decodes byte-identically to every hello minted before
//! this field existed — those bytes were already required all-zero — so an
//! old peer's hello, and every sender in this codebase today (none of which
//! sets a non-zero value yet — see [`TargetHint`]'s own doc), verifies
//! exactly as it did before this field was carved out.
//!
//! **ServerHello (81 bytes):**
//! ```text
//! [1B  chosen_suite]
//! [32B e_pub_s]
//! [32B server_proof]
//! [16B reserved zeros]
//! ```
//!
//! # Proof formulas (§2.2)
//!
//! ```text
//! client_proof = BLAKE3("MIRAGE-HS-V9-CLIENT-AUTH"
//!                || static_shared          // X25519(client_static_priv, server_static_pub)
//!                || e_pub_c
//!                || server_static_pub
//!                || mesh_id
//!                || ts_ms)[..16]
//!
//! transcript_0 = BLAKE3("MIRAGE-HS-V9-T0"
//!                || e_pub_c || e_pub_s
//!                || mesh_id || suite_id(1B)
//!                || ts_ms)
//!
//! server_proof = BLAKE3("MIRAGE-HS-V9-SERVER-AUTH"
//!                || ecdh_ee
//!                || transcript_0
//!                || server_static_pubkey_hex)
//! ```

use mirage_core::{
    crypto::{hash_blake3, AeadSuite, SessionKeys},
    error::MirageError,
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Wire constants (§2.3)
// ─────────────────────────────────────────────────────────────────────────────

/// First byte of every V9 ClientHello — used as the version probe.
pub const WIRE_VERSION_V9: u8 = 0x09;

/// Single-byte VersionReject signal sent by a server that does not support the
/// requested version. V8 client-hello first byte is a random curve point byte
/// and is never 0xFF, so there is no ambiguity.
pub const VERSION_REJECT: u8 = 0xFF;

pub const HS_V9_TRANSCRIPT_LABEL: &[u8] = b"MIRAGE-HS-V9-T0";
pub const HS_V9_CLIENT_AUTH_LABEL: &[u8] = b"MIRAGE-HS-V9-CLIENT-AUTH";
pub const HS_V9_SERVER_AUTH_LABEL: &[u8] = b"MIRAGE-HS-V9-SERVER-AUTH";
pub const HS_V9_CLIENT_WRITE: &[u8] = b"mirage-client-write-key-v9";
pub const HS_V9_SERVER_WRITE: &[u8] = b"mirage-server-write-key-v9";

pub const CLIENT_HELLO_LEN: usize = 97;
pub const SERVER_HELLO_LEN: usize = 81;

// ─────────────────────────────────────────────────────────────────────────────
// Wire message types (§2.4)
// ─────────────────────────────────────────────────────────────────────────────

/// 97-byte ClientHello for V9 handshake.
///
/// ## Wire byte layout
/// ```text
/// [0]      version = 0x09
/// [1..4]   suite_ids: [id, 0x00, 0x00]
/// [4..36]  e_pub_c  (32B)
/// [36..44] ts_ms    (8B big-endian)
/// [44..60] client_proof (16B)
/// [60..92] client_static_pub (32B) — used by server to verify client_proof
/// [92]     cred_scheme — credential scheme byte (0x00 = legacy/no-credential)
/// [93]     target_hint — see [`TargetHint`] (0x00 = legacy/no-preference)
/// [94..97] reserved zeros (3B)
/// ```
///
/// A legacy client sends `cred_scheme = 0x00` (the byte was previously a
/// reserved zero) ⇒ **byte-identical to pre-Phase-B wire**. Same story one
/// byte later: `target_hint = 0x00` is byte-identical to every hello minted
/// before Stage 2 of
/// `docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md` — see
/// [`TargetHint::Legacy`].
pub struct V9ClientHello {
    /// Always `WIRE_VERSION_V9` (0x09).
    pub version: u8,
    /// Up to 3 preferred suite IDs; unused slots are 0x00.
    pub suite_ids: [u8; 3],
    /// Client ephemeral X25519 public key.
    pub e_pub_c: [u8; 32],
    /// Millisecond UTC timestamp for replay protection.
    pub ts_ms: u64,
    /// 16-byte truncated BLAKE3 client proof (see module doc).
    pub client_proof: [u8; 16],
    /// Client's static X25519 public key — allows the server to verify `client_proof`
    /// without the client needing to transmit the corresponding private key.
    pub client_static_pub: [u8; 32],
    /// Credential scheme byte at wire position 92.
    ///
    /// `0x00` = no credential / legacy (no credential frame follows the hello).
    /// Non-zero = a `[2B len BE][len bytes]` credential frame follows the 97B hello
    /// on the server path (read by `run_server_handshake_v9_inner`).
    pub cred_scheme: u8,
    /// Target-hint byte at wire position 93 — see [`TargetHint`].
    ///
    /// Stored raw, exactly like `cred_scheme` above: this type only carries
    /// wire bytes, it does not validate them. Shape validation (is this byte
    /// one of the recognised [`TargetHint`] values) is
    /// `mirage-perimeter::classify::classify_v9_hello`'s job, the same
    /// crate that already validates every other shape fact about a hello.
    pub target_hint: u8,
}

impl V9ClientHello {
    /// Serialise to the 97-byte wire format.
    pub fn to_wire(&self) -> [u8; CLIENT_HELLO_LEN] {
        let mut buf = [0u8; CLIENT_HELLO_LEN];
        buf[0] = self.version;
        buf[1] = self.suite_ids[0];
        buf[2] = self.suite_ids[1];
        buf[3] = self.suite_ids[2];
        buf[4..36].copy_from_slice(&self.e_pub_c);
        buf[36..44].copy_from_slice(&self.ts_ms.to_be_bytes());
        buf[44..60].copy_from_slice(&self.client_proof);
        buf[60..92].copy_from_slice(&self.client_static_pub);
        buf[92] = self.cred_scheme;
        buf[93] = self.target_hint;
        // bytes 94..97 remain zero (reserved)
        buf
    }

    /// Deserialise from the 97-byte wire format.
    pub fn from_wire(buf: &[u8; CLIENT_HELLO_LEN]) -> Result<Self, MirageError> {
        if buf[0] != WIRE_VERSION_V9 {
            return Err(MirageError::Handshake(format!(
                "V9ClientHello: expected version 0x09, got 0x{:02x}",
                buf[0]
            )));
        }
        let suite_ids = [buf[1], buf[2], buf[3]];
        let e_pub_c: [u8; 32] = buf[4..36].try_into().expect("length checked");
        let ts_ms = u64::from_be_bytes(buf[36..44].try_into().expect("length checked"));
        let client_proof: [u8; 16] = buf[44..60].try_into().expect("length checked");
        let client_static_pub: [u8; 32] = buf[60..92].try_into().expect("length checked");
        let cred_scheme = buf[92];
        let target_hint = buf[93];
        Ok(Self {
            version: WIRE_VERSION_V9,
            suite_ids,
            e_pub_c,
            ts_ms,
            client_proof,
            client_static_pub,
            cred_scheme,
            target_hint,
        })
    }
}

/// Which inward destination the dialer wants this hello routed to, carried
/// in `V9ClientHello`'s wire byte 93 (see that type's own doc).
///
/// # Why `Legacy` is not merely "no preference"
///
/// Byte 93 sat inside the four-byte reserved tail before Stage 2 of
/// `docs/mirage/plans/every-persona-face-carries-both-2026-09-17.md`, and
/// every hello ever minted — by every sender in this codebase today, and by
/// every peer that predates this field entirely — already carries `0x00`
/// there, because the whole tail was required all-zero. `Legacy` is what
/// that same zero byte decodes to now, and its effect on routing is defined
/// to be identical to what a zero reserved-tail byte did before this type
/// existed: the perimeter routes on the face's own declared purpose
/// (`mirage-core::capsule::FacePurpose`), exactly as it always has (see
/// `mirage-perimeter::face::inward_target`). This type deliberately does not
/// depend on that one — `mirage-perimeter` is the crate that knows both
/// vocabularies and maps between them. This is what makes the field safe to
/// read fleet-wide before any sender emits anything else — see this module's
/// `to_wire`/`from_wire` doc.
///
/// # Variants are visible at every callsite, not hidden behind a trait
///
/// Same discipline this crate already applies to `AeadSuite`
/// (`suite_to_id`/`id_to_suite` below): a wire-selected axis is an enum with
/// explicit `to_byte`/`from_byte` conversions, never a `Box<dyn Trait>`, so
/// a third variant is a compile error at every match site rather than a
/// silent fall-through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetHint {
    /// Wire byte `0x00` — no preference stated. The perimeter routes this
    /// connection on the face's own declared purpose, exactly as it did
    /// before this field existed. This is the value every sender in this
    /// codebase emits today.
    Legacy,
    /// Wire byte `0x01` — route to the co-located monitor regardless of the
    /// face's declared purpose. Not yet emitted by any sender in this
    /// codebase — see this type's own doc.
    Monitor,
    /// Wire byte `0x02` — route to the co-located node regardless of the
    /// face's declared purpose. Not yet emitted by any sender in this
    /// codebase — see this type's own doc.
    Node,
}

impl TargetHint {
    /// Encode to the wire byte at `V9ClientHello`'s position 93.
    pub fn to_byte(self) -> u8 {
        match self {
            TargetHint::Legacy => 0x00,
            TargetHint::Monitor => 0x01,
            TargetHint::Node => 0x02,
        }
    }

    /// Decode wire byte 93. `None` for any value outside the three
    /// recognised ones — the caller (`mirage-perimeter::classify::
    /// classify_v9_hello`) treats that identically to a non-zero byte in
    /// the old, fully-reserved tail: not a valid hello shape.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(TargetHint::Legacy),
            0x01 => Some(TargetHint::Monitor),
            0x02 => Some(TargetHint::Node),
            _ => None,
        }
    }
}

/// 81-byte ServerHello for V9 handshake.
pub struct V9ServerHello {
    /// Negotiated AEAD suite ID.
    pub chosen_suite: u8,
    /// Server ephemeral X25519 public key.
    pub e_pub_s: [u8; 32],
    /// 32-byte BLAKE3 server proof (see module doc).
    pub server_proof: [u8; 32],
    /// Reserved for future use — must be zeros on send, ignored on recv.
    pub _reserved: [u8; 16],
}

impl V9ServerHello {
    /// Serialise to the 81-byte wire format.
    pub fn to_wire(&self) -> [u8; SERVER_HELLO_LEN] {
        let mut buf = [0u8; SERVER_HELLO_LEN];
        buf[0] = self.chosen_suite;
        buf[1..33].copy_from_slice(&self.e_pub_s);
        buf[33..65].copy_from_slice(&self.server_proof);
        // bytes 65..81 remain zero (_reserved)
        buf
    }

    /// Deserialise from the 81-byte wire format.
    pub fn from_wire(buf: &[u8; SERVER_HELLO_LEN]) -> Result<Self, MirageError> {
        let chosen_suite = buf[0];
        let e_pub_s: [u8; 32] = buf[1..33].try_into().expect("length checked");
        let server_proof: [u8; 32] = buf[33..65].try_into().expect("length checked");
        let _reserved: [u8; 16] = buf[65..81].try_into().expect("length checked");
        Ok(Self {
            chosen_suite,
            e_pub_s,
            server_proof,
            _reserved,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof computation helpers (§2.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute `transcript_0` — the session transcript hash binding both ephemeral
/// keys, mesh_id, negotiated suite, and timestamp.
///
/// ```text
/// BLAKE3("MIRAGE-HS-V9-T0" || e_pub_c || e_pub_s || mesh_id || suite_id(1B) || ts_ms)
/// ```
pub fn compute_transcript_0(
    e_pub_c: &[u8; 32],
    e_pub_s: &[u8; 32],
    mesh_id: &[u8],
    suite_id: u8,
    ts_ms: u64,
) -> [u8; 32] {
    let ts_bytes = ts_ms.to_be_bytes();
    let mut input = Vec::with_capacity(
        HS_V9_TRANSCRIPT_LABEL.len() + 32 + 32 + mesh_id.len() + 1 + 8,
    );
    input.extend_from_slice(HS_V9_TRANSCRIPT_LABEL);
    input.extend_from_slice(e_pub_c);
    input.extend_from_slice(e_pub_s);
    input.extend_from_slice(mesh_id);
    input.push(suite_id);
    input.extend_from_slice(&ts_bytes);
    hash_blake3(&input)
}

/// Compute the 16-byte `client_proof` MAC sent in ClientHello.
///
/// ```text
/// client_proof = BLAKE3("MIRAGE-HS-V9-CLIENT-AUTH"
///                || X25519(client_static_priv, server_static_pub)   // static_shared
///                || e_pub_c
///                || server_static_pub
///                || mesh_id
///                || suite_ids   // 3 bytes — offered AEAD suite list, as sent at ClientHello[1..4]
///                || ts_ms)[..16]
/// ```
///
/// The proof is bound to `server_static_pub` (not `e_pub_s` which is unknown at
/// ClientHello time), preventing impersonation of a specific server identity.
/// Session-uniqueness is provided by `ts_ms` (5-minute replay window recommended).
/// `suite_ids` binds the offered AEAD suite list so an on-path party cannot strip strong
/// suites from the offer to force a weaker negotiated suite.
pub fn compute_client_proof(
    client_static_priv: &[u8; 32],
    server_static_pub: &[u8; 32],
    e_pub_c: &[u8; 32],
    mesh_id: &[u8],
    suite_ids: &[u8; 3],
    ts_ms: u64,
) -> [u8; 16] {
    // Zeroize static_shared after use.
    let client_secret = StaticSecret::from(*client_static_priv);
    let server_pk = PublicKey::from(*server_static_pub);
    let static_shared = Zeroizing::new(client_secret.diffie_hellman(&server_pk).to_bytes());

    let ts_bytes = ts_ms.to_be_bytes();
    let mut input = Vec::with_capacity(
        HS_V9_CLIENT_AUTH_LABEL.len()
            + 32   // static_shared
            + 32   // e_pub_c
            + 32   // server_static_pub
            + mesh_id.len()
            + 3    // suite_ids
            + 8,   // ts_ms
    );
    input.extend_from_slice(HS_V9_CLIENT_AUTH_LABEL);
    input.extend_from_slice(&*static_shared);
    input.extend_from_slice(e_pub_c);
    input.extend_from_slice(server_static_pub);
    input.extend_from_slice(mesh_id);
    input.extend_from_slice(suite_ids);
    input.extend_from_slice(&ts_bytes);

    let full = hash_blake3(&input);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Verify the `client_proof` received in ClientHello.
///
/// The server does NOT have access to `client_static_priv` directly; instead it
/// computes the same `static_shared = X25519(server_static_priv, client_static_pub)`.
/// Both sides arrive at the same DH shared secret by commutativity of X25519.
///
/// `suite_ids` must be the 3-byte offered list from ClientHello[1..4] — exactly
/// as received on the wire and exactly as the client signed it.
///
/// Returns `Ok(())` on success, `Err(MirageError::AuthFailed)` on mismatch.
pub fn verify_client_proof(
    server_static_priv: &StaticSecret,
    client_static_pub: &[u8; 32],
    e_pub_c: &[u8; 32],
    server_static_pub: &[u8; 32],
    mesh_id: &[u8],
    suite_ids: &[u8; 3],
    ts_ms: u64,
    received_proof: &[u8; 16],
) -> Result<(), MirageError> {
    // static_shared = X25519(server_static_priv, client_static_pub)
    // This equals X25519(client_static_priv, server_static_pub) by DH commutativity.
    let client_pk = PublicKey::from(*client_static_pub);
    let static_shared = Zeroizing::new(server_static_priv.diffie_hellman(&client_pk).to_bytes());

    let ts_bytes = ts_ms.to_be_bytes();
    let mut input = Vec::with_capacity(
        HS_V9_CLIENT_AUTH_LABEL.len() + 32 + 32 + 32 + mesh_id.len() + 3 + 8,
    );
    input.extend_from_slice(HS_V9_CLIENT_AUTH_LABEL);
    input.extend_from_slice(&*static_shared);
    input.extend_from_slice(e_pub_c);
    input.extend_from_slice(server_static_pub);
    input.extend_from_slice(mesh_id);
    input.extend_from_slice(suite_ids);
    input.extend_from_slice(&ts_bytes);

    let expected_full = hash_blake3(&input);
    let expected: [u8; 16] = expected_full[..16].try_into().expect("length checked");

    // Constant-time comparison to prevent timing-based probing.
    use subtle::ConstantTimeEq;
    if expected.ct_eq(received_proof).into() {
        Ok(())
    } else {
        Err(MirageError::AuthFailed)
    }
}

/// Compute the `server_proof` included in ServerHello.
///
/// ```text
/// server_proof = BLAKE3("MIRAGE-HS-V9-SERVER-AUTH"
///                || ecdh_ee
///                || transcript_0
///                || server_static_pubkey_hex)
/// ```
///
/// Binds the ecdh_ee (forward-secret session secret) to the transcript and the
/// server's declared operator-signed identity, proving the server holds the
/// corresponding static private key.
pub fn compute_server_proof(
    ecdh_ee: &Zeroizing<[u8; 32]>,
    transcript_0: &[u8; 32],
    server_static_pub: &[u8; 32],
) -> [u8; 32] {
    let server_pubkey_hex = hex::encode(server_static_pub);
    let mut input = Vec::with_capacity(
        HS_V9_SERVER_AUTH_LABEL.len() + 32 + 32 + server_pubkey_hex.len(),
    );
    input.extend_from_slice(HS_V9_SERVER_AUTH_LABEL);
    input.extend_from_slice(ecdh_ee.as_ref());
    input.extend_from_slice(transcript_0);
    input.extend_from_slice(server_pubkey_hex.as_bytes());
    hash_blake3(&input)
}

/// Verify the `server_proof` received in ServerHello.
///
/// Returns `Ok(())` on success, `Err(MirageError::AuthFailed)` on mismatch.
pub fn verify_server_proof(
    ecdh_ee: &Zeroizing<[u8; 32]>,
    transcript_0: &[u8; 32],
    server_static_pub: &[u8; 32],
    received_proof: &[u8; 32],
) -> Result<(), MirageError> {
    let expected = compute_server_proof(ecdh_ee, transcript_0, server_static_pub);

    use subtle::ConstantTimeEq;
    if expected.ct_eq(received_proof).into() {
        Ok(())
    } else {
        Err(MirageError::AuthFailed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Session key derivation (§2.2 / §4.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Derive V9 session keys from the ephemeral×ephemeral shared secret.
///
/// IKM = `ecdh_ee` (ephemeral×ephemeral). Neither static key appears in the IKM.
/// Forward secrecy holds: disclosure of static keys does not decrypt past sessions.
///
/// ```text
/// client_write = HKDF-SHA256(ecdh_ee, salt=transcript_0, info="mirage-client-write-key-v9")
/// server_write = HKDF-SHA256(ecdh_ee, salt=transcript_0, info="mirage-server-write-key-v9")
/// ```
pub fn derive_v9_keys(
    ecdh_ee: &Zeroizing<[u8; 32]>,
    transcript_0: &[u8; 32],
    suite: AeadSuite,
) -> SessionKeys {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(transcript_0), ecdh_ee.as_ref());

    let mut client_write_key = Zeroizing::new([0u8; 32]);
    hk.expand(HS_V9_CLIENT_WRITE, client_write_key.as_mut())
        .expect("HKDF expand with 32-byte output is always valid");

    let mut server_write_key = Zeroizing::new([0u8; 32]);
    hk.expand(HS_V9_SERVER_WRITE, server_write_key.as_mut())
        .expect("HKDF expand with 32-byte output is always valid");

    SessionKeys {
        client_write_key,
        server_write_key,
        client_nonce_counter: 0,
        server_nonce_counter: 0,
        suite,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AeadSuite ↔ suite_id byte helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode an [`AeadSuite`] to its 1-byte wire ID.
pub fn suite_to_id(suite: AeadSuite) -> u8 {
    match suite {
        AeadSuite::ChaCha20Poly1305 => 0x01,
        AeadSuite::Aes256Gcm => 0x02,
        AeadSuite::Aes128Gcm => 0x03,
    }
}

/// Decode a 1-byte wire ID to an [`AeadSuite`].
///
/// Returns `None` for unknown / padding zeros.
pub fn id_to_suite(id: u8) -> Option<AeadSuite> {
    match id {
        0x01 => Some(AeadSuite::ChaCha20Poly1305),
        0x02 => Some(AeadSuite::Aes256Gcm),
        0x03 => Some(AeadSuite::Aes128Gcm),
        _ => None,
    }
}

/// Pick the first suite from `server_prefs` that appears in `client_ids`.
///
/// Returns `None` if there is no overlap.
pub fn negotiate_suite(server_prefs: &[AeadSuite], client_ids: &[u8; 3]) -> Option<AeadSuite> {
    for &suite in server_prefs {
        let id = suite_to_id(suite);
        if client_ids.contains(&id) {
            return Some(suite);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Generate ephemeral key (re-exported for handshake.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a fresh ephemeral X25519 key pair, returning `(secret, pub_bytes)`.
pub fn gen_ephemeral() -> (EphemeralSecret, [u8; 32]) {
    use rand::rngs::OsRng;
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public.to_bytes())
}

/// Write the 97-byte opening a chain FACE requires, for a dial that will
/// carry an onion envelope rather than a real V9 handshake.
///
/// **Why this exists at all.** A node's chain face is fronted by the
/// perimeter, whose classifier will not call a connection wire until
/// [`CLIENT_HELLO_LEN`] bytes that parse as a [`V9ClientHello`] have arrived.
/// Below it, `chain_splice` reads the perimeter's preamble and then skips
/// exactly [`CLIENT_HELLO_LEN`] bytes before reading the length-prefixed
/// envelope. So every dial into a chain face owes those bytes, whether or not
/// anything reads them: without them the perimeter waits, times out its peek,
/// and holds the connection — which is silent to the dialer and looks exactly
/// like an unreachable box.
///
/// **Why it is one function.** A hop dialing the next hop's face and a CLIENT
/// dialing the entry hop's face are the same act, and the whole point of the
/// face is that the two are not separable on the wire. Two implementations of
/// this hello would be two distributions, and the difference between them is
/// precisely what an observer wants. The node's relay path had one of these
/// and the client had none; that asymmetry is what this function removes.
///
/// **Why every field is real.** Nothing validates any of it — the classifier
/// checks the version, the suite ids and the reserved tail, and the node
/// discards the hello whole — so the temptation is to zero the fields nobody
/// reads. That would put 48 bytes of zeros at fixed offsets in the middle of
/// every chain-face opening and nowhere else, which is a landmark for anyone
/// who ever sees this plaintext: a perimeter, a future log path, an operator
/// holding the face's TLS key. Both keypairs are freshly generated per dial
/// and the proof is a truncated BLAKE3, because that is what a real one is.
/// Two X25519 keygens and a hash is what indistinguishability costs here.
///
/// Carriage-neutral by construction: this builds the 97 bytes and nothing
/// else, so a caller that needs them without an `AsyncWrite` — a UDP
/// datagram carries the same hello as one whole `send`, not a stream write —
/// reuses [`build_face_hello_bytes`] directly instead of re-deriving this
/// construction a second time. [`write_face_hello`] below is exactly that
/// reuse: a thin `stream.write_all` wrapper around it.
pub fn build_face_hello_bytes() -> [u8; CLIENT_HELLO_LEN] {
    let (_ephemeral_secret, e_pub_c) = gen_ephemeral();
    let (_static_secret, client_static_pub) = gen_ephemeral();
    let mut client_proof = [0u8; 16];
    client_proof.copy_from_slice(&hash_blake3(&[e_pub_c, client_static_pub].concat())[..16]);
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        // Slot 0 must name a suite the classifier recognises; slots 1-2 are
        // legitimately empty padding. The suite named here binds nothing.
        suite_ids: [suite_to_id(AeadSuite::ChaCha20Poly1305), 0x00, 0x00],
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme: 0x00,
        // This hello is chaff — the node discards it whole (see this
        // function's own doc) — so a target hint would route nothing even
        // if set. `Legacy` regardless, per `TargetHint`'s own doc: no
        // sender in this codebase emits a non-legacy hint yet.
        target_hint: TargetHint::Legacy.to_byte(),
    };
    hello.to_wire()
}

/// See [`build_face_hello_bytes`] for what is written and why every field is
/// real; this function is now only the carriage (writing those bytes to a
/// stream).
pub async fn write_face_hello<W>(stream: &mut W) -> Result<(), MirageError>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use tokio::io::AsyncWriteExt;

    let wire = build_face_hello_bytes();
    debug_assert_eq!(wire.len(), CLIENT_HELLO_LEN);
    stream.write_all(&wire).await.map_err(MirageError::Io)?;
    stream.flush().await.map_err(MirageError::Io)
}

#[cfg(test)]
mod face_hello_extraction_tests {
    //! `build_face_hello_bytes` was pulled out of `write_face_hello`'s body
    //! with no change to a single line of the construction itself — only the
    //! `stream.write_all` moved to the (now thin) caller. What is checkable
    //! about that claim without a socket is the fixed wire layout the
    //! perimeter's classifier actually reads (`mirage-perimeter`'s
    //! `classify.rs`: version, plausible suite ids, zeroed reserved tail) —
    //! everything else in the hello (`e_pub_c`, `client_static_pub`,
    //! `client_proof`, `ts_ms`) is freshly random per call by design (see the
    //! doc above), so byte-for-byte equality between two calls is neither
    //! possible nor the property that matters here.

    use super::*;

    /// The fixed offsets a future edit to the builder must not be able to
    /// move without this test catching it: version at byte 0, the
    /// classifier-recognised suite in slot 0 with slots 1-2 legitimately
    /// zero, `cred_scheme` at byte 92 zero for the no-flag case, `target_hint`
    /// at byte 93 `Legacy` (0x00), and the still-reserved tail (bytes 94..97)
    /// zero. This is exactly the fixed wire layout `V9ClientHello::to_wire`
    /// documents, unchanged by the extraction.
    #[test]
    fn build_face_hello_bytes_matches_the_fixed_wire_layout() {
        let wire = build_face_hello_bytes();

        assert_eq!(wire.len(), CLIENT_HELLO_LEN);
        assert_eq!(wire[0], WIRE_VERSION_V9, "byte 0 is the version the classifier probes");
        assert_eq!(
            wire[1],
            suite_to_id(AeadSuite::ChaCha20Poly1305),
            "slot 0 must name a suite the classifier recognises as plausible"
        );
        assert_eq!(wire[2..4], [0x00, 0x00], "suite slots 1-2 are legitimately empty padding");
        assert_eq!(wire[92], 0x00, "cred_scheme is 0x00 — legacy/no-credential — with no flag set");
        assert_eq!(
            wire[93],
            TargetHint::Legacy.to_byte(),
            "target_hint is Legacy (0x00) — no sender in this codebase emits anything else yet"
        );
        assert_eq!(wire[94..97], [0x00, 0x00, 0x00], "the still-reserved tail the classifier expects zeroed");
    }

    /// `write_face_hello` must still produce exactly what
    /// `build_face_hello_bytes` produces — it is now defined as nothing more
    /// than writing that array — so the same fixed-layout properties must
    /// hold on what actually goes out over a stream, not only on the pure
    /// builder in isolation.
    #[tokio::test]
    async fn write_face_hello_sends_exactly_what_the_builder_produces() {
        let (mut client, mut server) = tokio::io::duplex(CLIENT_HELLO_LEN);
        let write_task = tokio::spawn(async move {
            write_face_hello(&mut client).await.expect("write_face_hello must succeed on a live duplex pipe")
        });

        use tokio::io::AsyncReadExt;
        let mut received = [0u8; CLIENT_HELLO_LEN];
        server.read_exact(&mut received).await.expect("the full hello must arrive");
        write_task.await.expect("write task must not panic");

        assert_eq!(received[0], WIRE_VERSION_V9);
        assert_eq!(received[1], suite_to_id(AeadSuite::ChaCha20Poly1305));
        assert_eq!(received[2..4], [0x00, 0x00]);
        assert_eq!(received[92], 0x00);
        assert_eq!(received[93], TargetHint::Legacy.to_byte());
        assert_eq!(received[94..97], [0x00, 0x00, 0x00]);
    }

    /// The wire round-trip [`TargetHint`] promises: every recognised value
    /// survives `to_byte` → `from_byte` unchanged, and no value outside the
    /// three recognised ones decodes to `Some`.
    #[test]
    fn target_hint_round_trips_and_rejects_unrecognised_bytes() {
        for hint in [TargetHint::Legacy, TargetHint::Monitor, TargetHint::Node] {
            assert_eq!(TargetHint::from_byte(hint.to_byte()), Some(hint));
        }
        assert_eq!(TargetHint::Legacy.to_byte(), 0x00);
        assert_eq!(TargetHint::Monitor.to_byte(), 0x01);
        assert_eq!(TargetHint::Node.to_byte(), 0x02);
        for byte in 0x03..=0xFFu8 {
            assert_eq!(
                TargetHint::from_byte(byte),
                None,
                "byte 0x{byte:02x} names no recognised target hint"
            );
        }
    }

    /// `V9ClientHello::to_wire`/`from_wire` must round-trip `target_hint`
    /// exactly like every other field — built by serialising a real value
    /// and mutating one field, per this workspace's own method note
    /// (`docs/mirage/plans/chain-data-plane-over-faces-2026-09-02.md`,
    /// "Method note — how a format-pinning test is built"), not from a
    /// hand-written literal.
    #[test]
    fn client_hello_round_trips_a_non_legacy_target_hint() {
        let mut hello = V9ClientHello {
            version: WIRE_VERSION_V9,
            suite_ids: [suite_to_id(AeadSuite::ChaCha20Poly1305), 0x00, 0x00],
            e_pub_c: [0xAA; 32],
            ts_ms: 1_700_000_000_000,
            client_proof: [0xBB; 16],
            client_static_pub: [0xCC; 32],
            cred_scheme: 0x00,
            target_hint: TargetHint::Legacy.to_byte(),
        };
        hello.target_hint = TargetHint::Node.to_byte();

        let wire = hello.to_wire();
        assert_eq!(wire[93], TargetHint::Node.to_byte(), "byte 93 carries the mutated hint");

        let parsed = V9ClientHello::from_wire(&wire).expect("a well-formed hello always parses");
        assert_eq!(parsed.target_hint, TargetHint::Node.to_byte());
        assert_eq!(
            TargetHint::from_byte(parsed.target_hint),
            Some(TargetHint::Node),
            "the round-tripped byte still decodes to the hint that was set"
        );
    }
}
