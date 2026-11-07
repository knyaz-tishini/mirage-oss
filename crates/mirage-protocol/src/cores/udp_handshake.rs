//! V9 handshake — datagram carriage.
//!
//! Same cryptographic construction as [`crate::core::handshake`]'s stream V9
//! path: the same `V9ClientHello` / `V9ServerHello` wire bodies, the same
//! proof computations, the same `derive_v9_keys`. Only the carriage changes —
//! `send` / `recv` on a [`UdpPeerSocket`] instead of `AsyncRead` / `AsyncWrite`
//! on a byte stream. There is exactly one cryptographic construction; this
//! module does not invent a second one.
//!
//! ClientHello (97 bytes) and ServerHello (81 bytes) each fit in one datagram,
//! so there is no framing to add on top of the wire bodies themselves.
//!
//! # Reliability — and its exact limit
//!
//! The exchange is one request and one reply. Reliability exists to get that
//! one round trip to land and dies with it:
//!
//! - Client: send `ClientHello`, wait for `ServerHello` with a per-attempt
//!   timeout, retransmit the identical `ClientHello` (same ephemeral key,
//!   same timestamp, same proof) on timeout, up to a bounded number of
//!   attempts. A `VERSION_REJECT` reply fails fast — it is never retried.
//! - Server: [`run_server_handshake_v9_datagram`] processes one already-read
//!   `ClientHello` datagram per call against an already-bound
//!   [`UdpPeerSocket`] (via `UdpPeerSocket::bind_server_ephemeral`). A
//!   [`ServerHelloCache`] keyed by the client's ephemeral public key lets a
//!   caller that sees the same `ClientHello` again (a retransmit, because the
//!   client never got the first reply) resend the identical `ServerHello`
//!   bytes instead of deriving a second set of keys from fresh ephemerals.
//!
//! No sequence numbers, no ack frames, no window, no congestion control —
//! once `derive_v9_keys` has run on both sides, this layer is gone and the
//! data phase is bare datagrams with loss and reordering intact.
//!
//! # Credential carriage
//!
//! The stream V9 path frames its credential as a follow-on read: `[2B len
//! BE][len bytes]` after the 97-byte hello, because a byte stream has no
//! built-in message boundary and needs one. A UDP datagram already **is** one
//! message boundary, so this module does not reinvent that framing — the
//! credential, when present, rides appended directly after the 97-byte
//! `ClientHello` in the same datagram: `[97B ClientHello][credential bytes]`.
//! The server tells them apart from `hello_bytes.len()` alone (everything
//! past byte 97 is the credential); no length prefix is needed or sent.
//!
//! This keeps the handshake to exactly one datagram each way — no second
//! message, no extra retransmit state, and the [`ServerHelloCache`] still
//! keys on `e_pub_c` exactly as it does today, so a retransmitted
//! hello-plus-credential datagram still returns the identical `ServerHello`.
//!
//! `cred_scheme == 0x00` (no credential) works exactly as before: the
//! datagram is the bare 97-byte hello, nothing follows it, and the server's
//! `client_auth` closure sees an empty `credential` slice.
//!
//! Credential *verification* is not duplicated here — [`run_server_handshake_v9_datagram`]
//! builds the identical [`ClientAuthContext`] the stream path builds and
//! hands it to the same caller-supplied `client_auth` closure. Only the
//! carriage (how the bytes get from client to server) differs between the
//! two paths; the scheme dispatch and the verification live entirely in the
//! caller's closure, once, for both.
//!
//! See `MAX_CREDENTIAL_LEN` (reused from `crate::core::handshake`) and
//! `SAFE_UDP_HANDSHAKE_PAYLOAD_LEN` below for the size bound and where it
//! comes from, and [`run_client_handshake_v9_datagram_with_credential`]'s own
//! doc for what the client proof does and does not cover.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use mirage_core::{
    crypto::{AeadSuite, KeyPair},
    error::MirageError,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::auth::v9::{
    compute_client_proof, compute_server_proof, compute_transcript_0, derive_v9_keys,
    gen_ephemeral, id_to_suite, negotiate_suite, suite_to_id, verify_client_proof,
    verify_server_proof, TargetHint, V9ClientHello, V9ServerHello, CLIENT_HELLO_LEN,
    SERVER_HELLO_LEN, VERSION_REJECT, WIRE_VERSION_V9,
};
use crate::core::dgram_chain_addr::{
    DatagramChainAddress, CHAIN_ADDRESSED_FLAG, MAX_ENCODED_BLOCK_LEN,
};
use crate::cores::handshake::{
    current_ts_ms, ts_within_window, ClientAuthContext, ClientHandshakeResult,
    ServerHandshakeResult, MAX_CREDENTIAL_LEN,
};
use crate::transport::udp::UdpPeerSocket;

// ─────────────────────────────────────────────────────────────────────────────
// Credential size bound — named, not magic
// ─────────────────────────────────────────────────────────────────────────────

/// Conservative "never needs IP fragmentation" UDP payload ceiling.
///
/// 1200 bytes is the floor QUIC (RFC 9000) settled on for exactly this
/// reason: IPv6 guarantees a minimum path MTU of 1280 bytes, and
/// `1280 - 40 (IPv6 header) - 8 (UDP header) = 1232` bytes is the largest UDP
/// payload provably deliverable, unfragmented, over every real IPv6 path;
/// 1200 leaves headroom for any on-path encapsulation on top of that. This
/// handshake's whole premise is one datagram per message with no
/// fragmentation, so this is the number to stay under.
///
/// `pub`: the datagram FS-chain client (`mirage-dial-core`'s
/// `OnionFsUdpTunnel::connect`, U5 design Slice 3) reuses this exact constant
/// by name for its own per-hop frame size guard rather than duplicating the
/// 1200 as a second, unnamed magic number in a different crate — see that
/// module's doc for why the guard has to be a runtime check rather than a
/// compile-time one.
pub const SAFE_UDP_HANDSHAKE_PAYLOAD_LEN: usize = 1200;

// Compile-time proof that reusing the stream path's own `MAX_CREDENTIAL_LEN`
// cap for datagram carriage (rather than inventing a second number for the
// same kind of data) is actually safe: the worst-case ClientHello+credential
// datagram this module can produce must still fit under the ceiling above.
const _: () = assert!(CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN <= SAFE_UDP_HANDSHAKE_PAYLOAD_LEN);

/// Width of the length prefix in front of a chain block. Two bytes because
/// the block itself is variable and the credential follows it — the reader
/// needs to know where one ends and the other begins, and a datagram
/// boundary can only mark ONE such edge (it already marks the credential's).
pub const CHAIN_BLOCK_LEN_PREFIX: usize = 2;

// The same proof again for the widest datagram this module can now produce:
// hello, length prefix, a chain block at its cap, and a credential at its
// cap. Both caps are chosen so this holds; the chain-address caps were
// tightened from 64 to 32 bytes when this assertion first failed, rather
// than raising the ceiling, because the ceiling is a property of IPv6 paths
// and not something this code gets to pick.
const _: () = assert!(
    CLIENT_HELLO_LEN + CHAIN_BLOCK_LEN_PREFIX + MAX_ENCODED_BLOCK_LEN + MAX_CREDENTIAL_LEN
        <= SAFE_UDP_HANDSHAKE_PAYLOAD_LEN
);

/// Public alias for the datagram-carriage credential cap — for a caller that
/// needs to size a credential, or a receive buffer for a
/// [`V9ClientHello`]-plus-credential datagram, before calling
/// [`run_client_handshake_v9_datagram_with_credential`] or
/// [`run_server_handshake_v9_datagram`]. Identical to the stream path's own
/// cap; see the reuse note on `MAX_CREDENTIAL_LEN` above for why this module
/// does not define a second number for the same kind of data.
pub const MAX_CREDENTIAL_LEN_DATAGRAM: usize = MAX_CREDENTIAL_LEN;

// ─────────────────────────────────────────────────────────────────────────────
// FS-chain classifier-token hello — a second, disjoint bit in cred_scheme
// ─────────────────────────────────────────────────────────────────────────────

/// Set in a datagram `ClientHello`'s `cred_scheme` byte (bit 6) when this
/// hello is a throwaway classifier token for a multi-hop FS chain: its
/// content is never parsed, never authenticated, and a raw
/// `FsInitFrame`/`FsRelayInitFrame` follows as a SEPARATE datagram (see
/// `docs/mirage/plans/u5-datagram-telescopic-design-2026-09-09.md`, Slice 1).
///
/// Distinct from [`CHAIN_ADDRESSED_FLAG`] (bit 7) **on purpose** — the two
/// answer different questions about the same byte and must never be allowed
/// to collide:
/// - [`CHAIN_ADDRESSED_FLAG`] marks a hello that IS parsed and IS
///   authenticated by a real V9 handshake, whose chain block names *which
///   single-hop listener* the (still real) handshake addresses.
/// - [`FS_CHAIN_HELLO_FLAG`] marks a hello that is never parsed past the one
///   length-and-bit peek [`is_fs_chain_hello`] performs — it answers *is a
///   raw FS frame coming next, unauthenticated, on its own datagram* for a
///   chain whose hop identity, position and length the frame that follows
///   already carries authoritatively.
///
/// Forcing one bit to serve both would mean either declaring a real
/// `chain_id`/`chain_position` on an FS-chain hello that nothing downstream
/// reads (a placeholder that looks load-bearing and is not — the exact
/// pattern `write_face_hello`'s own doc argues against for zeroed fields), or
/// redefining what the flag means depending on context, which is worse. Two
/// different questions get two different bits.
pub const FS_CHAIN_HELLO_FLAG: u8 = 0x40;

// The two flags must never collide: if a future edit ever picks the same bit
// for both, an on-path party (or a stale build) could no longer tell "which
// single-hop listener" from "throwaway token, raw frame follows" apart, and
// [`is_fs_chain_hello`] would start misclassifying real chain-addressed
// hellos as FS-chain tokens or vice versa. Caught here, at compile time,
// rather than as a hard-to-reproduce routing bug on the wire.
const _: () = assert!(FS_CHAIN_HELLO_FLAG & CHAIN_ADDRESSED_FLAG == 0);

/// Cheap, allocation-free, zero-crypto peek: is `datagram` shaped like an
/// FS-chain classifier-token hello? Checked BEFORE [`parse_datagram_hello`]
/// or any handshake attempt — a byte-offset peek, not a parse, the same
/// texture as the stream side's own `body[0]` dispatch peek before it commits
/// to decoding a frame.
///
/// Total by construction: a datagram of the wrong length is exactly as much
/// "not this" as one of the right length with the bit clear, so this never
/// panics and never errors — this path's contract (see the design doc's
/// error-handling section) is that every rejection is silence, and silence
/// has no error channel to hand a `Result` to.
pub fn is_fs_chain_hello(datagram: &[u8]) -> bool {
    datagram.len() == CLIENT_HELLO_LEN && datagram[92] & FS_CHAIN_HELLO_FLAG != 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Retransmit bounds — named, not magic
// ─────────────────────────────────────────────────────────────────────────────

/// Per-attempt wait for a `ServerHello` before retransmitting the
/// `ClientHello`. Well above a same-host or LAN round trip (single-digit
/// milliseconds) so a healthy peer is never spuriously retried, while short
/// enough that a genuinely lost datagram is retried promptly.
const CLIENT_HELLO_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum number of `ClientHello` retransmits after the initial send (so up
/// to `CLIENT_HELLO_MAX_RETRANSMITS + 1` sends total). Bounds the handshake's
/// worst-case wall-clock cost to `CLIENT_HELLO_RETRANSMIT_TIMEOUT *
/// (CLIENT_HELLO_MAX_RETRANSMITS + 1)` — 3 seconds at the timeout above —
/// against an unreachable or silently dropping peer, instead of retrying
/// forever.
const CLIENT_HELLO_MAX_RETRANSMITS: u32 = 5;

// ─────────────────────────────────────────────────────────────────────────────
// Client side
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the client side of the V9 handshake over a [`UdpPeerSocket`],
/// with no credential appended (`cred_scheme = 0x00`) — unchanged from
/// before credential carriage existed.
///
/// See [`run_client_handshake_v9_datagram_with_credential`] for the general
/// form and for what the client proof does and does not cover; this is a
/// thin wrapper over it with an empty credential.
pub async fn run_client_handshake_v9_datagram(
    socket: &mut UdpPeerSocket,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
) -> Result<ClientHandshakeResult, MirageError> {
    run_client_handshake_v9_datagram_with_credential(
        socket,
        server_static_pub,
        client_static_priv,
        mesh_id,
        suite_prefs,
        0x00,
        &[],
    )
    .await
}

/// Perform the client side of the V9 handshake over a [`UdpPeerSocket`],
/// with a credential of `cred_scheme` appended to the `ClientHello` in the
/// same datagram: `[97B ClientHello][credential bytes]`. Pass
/// `cred_scheme = 0x00` and an empty `credential` for the no-credential case
/// (also available as the plain [`run_client_handshake_v9_datagram`]).
///
/// Sends the resulting datagram and waits for the 81-byte `ServerHello`,
/// retransmitting the identical datagram — same ephemeral key, same
/// timestamp, same proof, same credential bytes — on timeout (see the module
/// docs for the exact bound). The reply legitimately arrives from the
/// server's fresh ephemeral port rather than the address dialled —
/// `UdpPeerSocket::recv_handshake_from_host` is used instead of `recv` for
/// exactly that reason, and adopts the reply's source as the socket's new
/// `remote` before this function returns.
///
/// Crypto is byte-for-byte the same as [`crate::core::handshake::run_client_handshake_v9`]:
/// same hello bodies, same proofs, same `derive_v9_keys`.
///
/// # The client proof does not cover the credential
///
/// `client_proof` (via `compute_client_proof`) and `transcript_0` bind
/// `e_pub_c`, `server_static_pub`, `mesh_id`, the offered `suite_ids` and
/// `ts_ms` — never the credential bytes, on the stream path or here. That is
/// unchanged by this function: it calls the identical `compute_client_proof`
/// with the identical arguments the no-credential path always used. An
/// on-path party can therefore strip or swap the credential without
/// invalidating the proof; whatever protects against that must come from the
/// credential scheme itself (e.g. a token that already commits to context
/// the verifier checks), not from this handshake layer. This is a
/// pre-existing property of the live stream V9 path, not something this
/// function introduces — see the crate's credential-binding note in the
/// test module for the check that demonstrates it.
///
/// # Errors
///
/// Returns `Err(MirageError::Handshake(_))` **before sending anything** if
/// `credential.len()` exceeds the cap this module enforces for datagram
/// carriage (see `MAX_CREDENTIAL_LEN` / `SAFE_UDP_HANDSHAKE_PAYLOAD_LEN`) —
/// this handshake never fragments a datagram, so an oversized credential is
/// a hard failure rather than something to split or truncate.
pub async fn run_client_handshake_v9_datagram_with_credential(
    socket: &mut UdpPeerSocket,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    cred_scheme: u8,
    credential: &[u8],
) -> Result<ClientHandshakeResult, MirageError> {
    run_client_handshake_v9_datagram_with_chain(
        socket,
        server_static_pub,
        client_static_priv,
        mesh_id,
        suite_prefs,
        None,
        cred_scheme,
        credential,
    )
    .await
}

/// The general form: the same handshake, optionally naming which chain hop
/// this datagram session is addressing.
///
/// With `chain_address = None` this is byte-for-byte what
/// [`run_client_handshake_v9_datagram_with_credential`] always sent. With
/// `Some(_)`, [`CHAIN_ADDRESSED_FLAG`] is set in the hello's `cred_scheme`
/// and the length-prefixed block rides between the hello and the credential
/// — see [`parse_datagram_hello`] for the layout and
/// [`crate::core::dgram_chain_addr`] for why the addressing goes here rather
/// than into the tunnel's data phase.
///
/// # The flag is not covered by the client proof either
///
/// `cred_scheme` sits at wire byte 92 and `compute_client_proof` binds
/// `e_pub_c`, the server's static key, `mesh_id`, the offered suites and
/// `ts_ms` — not that byte, and not the credential. So an on-path party can
/// clear the flag or rewrite the block exactly as it can strip the
/// credential, and the result is a session that reaches the wrong listener
/// or none: a denial, not an escalation, since the hop it does reach still
/// runs the full proof and credential check against its own keys. Closing
/// this means the proof formula covering the whole datagram, which is a
/// fleet-wide wire change and is not what this carriage is.
#[allow(clippy::too_many_arguments)]
pub async fn run_client_handshake_v9_datagram_with_chain(
    socket: &mut UdpPeerSocket,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    chain_address: Option<&DatagramChainAddress>,
    cred_scheme: u8,
    credential: &[u8],
) -> Result<ClientHandshakeResult, MirageError> {
    if cred_scheme & CHAIN_ADDRESSED_FLAG != 0 {
        return Err(MirageError::Handshake(format!(
            "V9 datagram: cred_scheme 0x{cred_scheme:02x} has the chain-addressed bit set; that              bit is this carriage's own and is set from `chain_address`, so a caller passing it              in the scheme would be declaring a block that may not be there"
        )));
    }
    if credential.len() > MAX_CREDENTIAL_LEN {
        return Err(MirageError::Handshake(format!(
            "V9 datagram: credential is {actual} bytes but datagram carriage caps a credential at \
             {cap} bytes (the same cap the stream path uses) so that a {hello}-byte ClientHello plus \
             a full-cap credential — {total} bytes total — stays under the {safe}-byte safe UDP \
             payload ceiling this handshake never fragments across; the credential cannot be split \
             across more than one datagram",
            actual = credential.len(),
            cap = MAX_CREDENTIAL_LEN,
            hello = CLIENT_HELLO_LEN,
            total = CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN,
            safe = SAFE_UDP_HANDSHAKE_PAYLOAD_LEN,
        )));
    }

    // Generate client ephemeral key pair — fixed for the whole handshake
    // attempt, including every retransmit, so a retransmit is byte-identical
    // to the original send and the server can recognise it as the same
    // attempt via e_pub_c.
    let (e_priv_c, e_pub_c) = gen_ephemeral();

    let ts_ms = current_ts_ms();

    let mut suite_ids = [0u8; 3];
    for (i, &s) in suite_prefs.iter().take(3).enumerate() {
        suite_ids[i] = suite_to_id(s);
    }

    let client_proof = compute_client_proof(
        client_static_priv,
        server_static_pub,
        &e_pub_c,
        mesh_id,
        &suite_ids,
        ts_ms,
    );

    let client_static_pub = {
        let secret = StaticSecret::from(*client_static_priv);
        PublicKey::from(&secret).to_bytes()
    };

    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        // The flag says where the bytes are, not what the credential means —
        // the server clears it again before the scheme reaches verification.
        cred_scheme: match chain_address {
            Some(_) => cred_scheme | CHAIN_ADDRESSED_FLAG,
            None => cred_scheme,
        },
        // No sender in this codebase sets a non-legacy target hint yet — see
        // `TargetHint`'s own doc. Routing stays exactly what the face's
        // declared purpose says, precisely as it did before this field
        // existed.
        target_hint: TargetHint::Legacy.to_byte(),
    };

    // The chain block and the credential ride appended to the hello in the
    // same datagram — one buffer, built once, sent unchanged on every
    // retransmit (see the module docs: the whole point is no second message
    // and no new reliability state).
    let datagram = build_client_datagram(&hello, chain_address, credential)?;

    let mut retransmits = 0u32;
    let server_hello = loop {
        socket.send(&datagram).await?;

        let mut buf = [0u8; SERVER_HELLO_LEN];
        let recv_result = tokio::time::timeout(
            CLIENT_HELLO_RETRANSMIT_TIMEOUT,
            socket.recv_handshake_from_host(&mut buf),
        )
        .await;

        match recv_result {
            Ok(Ok(n)) if n == 1 && buf[0] == VERSION_REJECT => {
                // Fail fast — a version rejection is never retried.
                return Err(MirageError::Handshake(
                    "V9 datagram: server rejected version (VersionReject 0xFF)".into(),
                ));
            }
            Ok(Ok(n)) if n == SERVER_HELLO_LEN => {
                break V9ServerHello::from_wire(&buf)?;
            }
            Ok(Ok(n)) => {
                return Err(MirageError::Handshake(format!(
                    "V9 datagram: ServerHello datagram had unexpected length {n}"
                )));
            }
            Ok(Err(e)) => return Err(e),
            Err(_elapsed) => {
                retransmits += 1;
                if retransmits > CLIENT_HELLO_MAX_RETRANSMITS {
                    return Err(MirageError::HandshakeTimedOut(format!(
                        "V9 datagram: no ServerHello after {CLIENT_HELLO_MAX_RETRANSMITS} retransmits"
                    )));
                }
                // Retransmit the identical ClientHello and wait again.
                continue;
            }
        }
    };

    let suite = id_to_suite(server_hello.chosen_suite).ok_or_else(|| {
        MirageError::Handshake(format!(
            "V9 datagram: unknown suite_id 0x{:02x} in ServerHello",
            server_hello.chosen_suite
        ))
    })?;

    let e_pub_s = PublicKey::from(server_hello.e_pub_s);
    let ecdh_ee = Zeroizing::new(e_priv_c.diffie_hellman(&e_pub_s).to_bytes());

    let transcript_0 = compute_transcript_0(
        &e_pub_c,
        &server_hello.e_pub_s,
        mesh_id,
        server_hello.chosen_suite,
        ts_ms,
    );

    verify_server_proof(&ecdh_ee, &transcript_0, server_static_pub, &server_hello.server_proof)?;

    let session_keys = derive_v9_keys(&ecdh_ee, &transcript_0, suite);

    Ok(ClientHandshakeResult {
        session_keys,
        remote_s_pub: *server_static_pub,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// What a datagram ClientHello carries past its fixed 97 bytes
// ─────────────────────────────────────────────────────────────────────────────

/// The variable tail of a datagram `ClientHello`, split into its parts.
///
/// Produced by [`parse_datagram_hello`], which is the single place that knows
/// the layout — both the server handshake below and a caller that must read
/// the chain address BEFORE the handshake (to pick which listener's spec
/// serves this session) go through it, so there is one parser and not two
/// that can drift.
pub struct DatagramHello<'a> {
    /// The fixed 97-byte hello, parsed.
    pub hello: V9ClientHello,
    /// The chain hop this session addresses, when the hello declared one by
    /// setting [`CHAIN_ADDRESSED_FLAG`]. `None` is a datagram addressed the
    /// only way this plane could be addressed before: not at all.
    pub chain_address: Option<DatagramChainAddress>,
    /// `hello.cred_scheme` with [`CHAIN_ADDRESSED_FLAG`] cleared — the scheme
    /// a credential verifier should dispatch on. The flag says where the
    /// bytes are, never what the credential means, so it must not reach that
    /// dispatch.
    pub cred_scheme: u8,
    /// The credential bytes, chain block already removed.
    pub credential: &'a [u8],
}

/// Split a received datagram into hello, chain address and credential.
///
/// Layout, per [`crate::core::dgram_chain_addr`]:
///
/// ```text
/// flag clear: [97B ClientHello][credential bytes]
/// flag set:   [97B ClientHello][2B block_len BE][chain block][credential bytes]
/// ```
///
/// # Every malformed tail is an error, never an absence
///
/// A datagram whose hello sets the flag and then does not carry a
/// well-formed block is refused by name. Reading it as "no chain address"
/// would send it to whatever listener the mesh-id fallback happens to
/// resolve — which is precisely the unaddressed behaviour the chain block
/// exists to replace, reachable by corrupting two bytes.
///
/// # This runs before the client is authenticated, and that is deliberate
///
/// The stream chain plane resolves a hop only after the frame authenticates,
/// because there a miss and an authentication failure must be made
/// indistinguishable and the ordering itself would otherwise be the tell.
/// The datagram plane cannot do that: the AEAD suite the handshake
/// negotiates is read off the resolved listener's spec, so the address must
/// be known first. What makes that safe here is that the datagram server
/// answers a rejection with *nothing at all* — no reply, no reset, no close.
/// A miss and a failed proof produce the same silence, and the timing of a
/// datagram that is never sent is not observable to whoever sent the probe.
/// So this parser must stay total and allocation-bounded: it reads at most
/// [`MAX_ENCODED_BLOCK_LEN`] bytes of block, and the whole datagram is
/// already bounded by the receive buffer of whoever read it.
pub fn parse_datagram_hello(datagram: &[u8]) -> Result<DatagramHello<'_>, MirageError> {
    if datagram.len() < CLIENT_HELLO_LEN {
        return Err(MirageError::Handshake(format!(
            "V9 datagram: {} bytes is shorter than the {CLIENT_HELLO_LEN}-byte ClientHello",
            datagram.len()
        )));
    }
    let hello_fixed: [u8; CLIENT_HELLO_LEN] = datagram[..CLIENT_HELLO_LEN]
        .try_into()
        .expect("slice is exactly CLIENT_HELLO_LEN bytes by construction of the range above");
    let hello = V9ClientHello::from_wire(&hello_fixed)?;
    let tail = &datagram[CLIENT_HELLO_LEN..];

    if hello.cred_scheme & CHAIN_ADDRESSED_FLAG == 0 {
        return Ok(DatagramHello {
            cred_scheme: hello.cred_scheme,
            hello,
            chain_address: None,
            credential: tail,
        });
    }

    if tail.len() < CHAIN_BLOCK_LEN_PREFIX {
        return Err(MirageError::Handshake(format!(
            "V9 datagram: hello declares a chain block but only {} bytes follow it, fewer than              the {CHAIN_BLOCK_LEN_PREFIX}-byte length prefix",
            tail.len()
        )));
    }
    let block_len = u16::from_be_bytes([tail[0], tail[1]]) as usize;
    if block_len > MAX_ENCODED_BLOCK_LEN {
        return Err(MirageError::Handshake(format!(
            "V9 datagram: chain block claims {block_len} bytes, over the              {MAX_ENCODED_BLOCK_LEN}-byte maximum an admissible address can encode to"
        )));
    }
    let rest = &tail[CHAIN_BLOCK_LEN_PREFIX..];
    if rest.len() < block_len {
        return Err(MirageError::Handshake(format!(
            "V9 datagram: chain block claims {block_len} bytes but only {} follow the prefix",
            rest.len()
        )));
    }
    let chain_address = DatagramChainAddress::decode(&rest[..block_len])?;

    Ok(DatagramHello {
        cred_scheme: hello.cred_scheme & !CHAIN_ADDRESSED_FLAG,
        hello,
        chain_address: Some(chain_address),
        credential: &rest[block_len..],
    })
}

/// Build the datagram a chain-addressed client sends: the hello with
/// [`CHAIN_ADDRESSED_FLAG`] set in its `cred_scheme`, the length-prefixed
/// chain block, then the credential.
///
/// Kept beside [`parse_datagram_hello`] on purpose — a writer and a reader of
/// one layout that live apart drift apart.
fn build_client_datagram(
    hello: &V9ClientHello,
    chain_address: Option<&DatagramChainAddress>,
    credential: &[u8],
) -> Result<Vec<u8>, MirageError> {
    let block = match chain_address {
        None => None,
        Some(addr) => Some(addr.encode()?),
    };
    let block_len = block.as_ref().map(|b| CHAIN_BLOCK_LEN_PREFIX + b.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(CLIENT_HELLO_LEN + block_len + credential.len());
    out.extend_from_slice(&hello.to_wire());
    if let Some(block) = block {
        // `encode` cannot exceed MAX_ENCODED_BLOCK_LEN, which the module's
        // compile-time budget assertion covers, so this cast cannot truncate.
        out.extend_from_slice(&(block.len() as u16).to_be_bytes());
        out.extend_from_slice(&block);
    }
    out.extend_from_slice(credential);
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Server side
// ─────────────────────────────────────────────────────────────────────────────

/// Cache of already-answered V9 datagram handshakes, keyed by the client's
/// ephemeral public key (`e_pub_c`).
///
/// A retransmitted `ClientHello` carries the same `e_pub_c` as the original
/// (the client fixes its ephemeral key for the whole retry loop — see
/// [`run_client_handshake_v9_datagram`]). Looking the key up here lets
/// [`run_server_handshake_v9_datagram`] answer a retransmit with the exact
/// bytes already sent instead of generating a fresh server ephemeral and
/// deriving a second, different set of session keys for what is really one
/// handshake attempt.
///
/// Entries are inserted only after a `ClientHello` has passed proof
/// verification, so an unauthenticated peer cannot grow this map — there is
/// deliberately no eviction beyond that; a caller that owns one of these for
/// the lifetime of a listener is expected to size that lifetime accordingly.
pub struct ServerHelloCache {
    inner: Mutex<HashMap<[u8; 32], Vec<u8>>>,
}

impl ServerHelloCache {
    /// Construct an empty cache.
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    fn insert(&self, key: [u8; 32], value: Vec<u8>) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, value);
    }
}

impl Default for ServerHelloCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Perform the server side of the V9 handshake for one already-received
/// `ClientHello` datagram.
///
/// `socket` must already be bound to the client's address (the caller reads
/// the datagram — e.g. off a fixed rendezvous socket in front of many peers —
/// and calls `UdpPeerSocket::bind_server_ephemeral(client_addr)` before
/// calling this function; binding a fresh per-peer socket for every
/// `ClientHello`, retransmit or not, is the caller's responsibility and is
/// not performed here). `hello_bytes` is the datagram exactly as received:
/// the 97-byte `ClientHello`, optionally followed by a credential appended
/// directly after it (`[97B ClientHello][credential bytes]` — see the
/// module docs). A shorter-than-97-byte datagram is rejected as malformed.
///
/// Returns `Ok(Some(_))` once, for the `ClientHello` that first authenticates
/// for a given `e_pub_c` — `ServerHello` is sent and the reply is recorded in
/// `cache`. A later call with the same `e_pub_c` (a retransmit) resends the
/// cached bytes and returns `Ok(None)` without deriving anything new.
/// `Ok(None)` also covers every rejection path (malformed hello, stale
/// timestamp, bad proof, an oversized or malformed credential, `client_auth`
/// returning `false`, or no suite overlap) — exactly as the stream V9 server
/// never replies on rejection, no `ServerHello` is sent here either.
///
/// The `client_auth` closure receives a [`ClientAuthContext`] built exactly
/// as the stream path builds it — same fields, same `credential` bytes when
/// present — so a caller's closure written against the stream path needs no
/// change to also accept credentialed datagram clients.
///
/// # INVARIANT: parser never reached until `Ok(Some(_))` is returned.
#[must_use = "caller must check Option — None means no new handshake result, do not proceed as if there were one"]
pub async fn run_server_handshake_v9_datagram<F>(
    socket: &mut UdpPeerSocket,
    keypair: &KeyPair,
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    client_auth: F,
    hello_bytes: &[u8],
    cache: &ServerHelloCache,
) -> Result<Option<ServerHandshakeResult>, MirageError>
where
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool,
{
    // One parser for the whole datagram — hello, optional chain block,
    // credential. A caller that had to read the chain address before this
    // call (to pick which listener serves the session) went through the same
    // function, so the split it acted on and the split used here cannot
    // disagree.
    let parsed = match parse_datagram_hello(hello_bytes) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "[HS-V9-DGRAM] server refused: ClientHello did not parse");
            return Ok(None);
        }
    };
    // `chain_address` is deliberately not read here: WHICH listener serves
    // this session was decided by the caller before it chose the `keypair`
    // and `suite_prefs` passed in, and re-deciding it inside the handshake
    // would be a second answer to a settled question.
    let DatagramHello { hello, cred_scheme, credential, .. } = parsed;

    // Retransmit of an already-answered attempt — resend the identical bytes
    // rather than starting a second handshake with fresh ephemerals. Keyed
    // on e_pub_c alone, exactly as before credential carriage existed: the
    // client fixes the whole datagram (hello + credential) for every
    // retransmit, so a second copy of the same e_pub_c means a retransmit of
    // the same attempt, credential included.
    if let Some(cached_wire) = cache.get(&hello.e_pub_c) {
        socket.send(&cached_wire).await?;
        return Ok(None);
    }

    let suite = match negotiate_suite(suite_prefs, &hello.suite_ids) {
        Some(s) => s,
        None => {
            let _ = socket.send(&[VERSION_REJECT]).await;
            tracing::warn!(
                offered = ?hello.suite_ids,
                "[HS-V9-DGRAM] server refused: no AEAD suite in common with the client"
            );
            return Ok(None);
        }
    };
    let suite_id = suite_to_id(suite);

    let (e_priv_s, e_pub_s) = gen_ephemeral();

    let e_pub_c_pk = PublicKey::from(hello.e_pub_c);
    let ecdh_ee = Zeroizing::new(e_priv_s.diffie_hellman(&e_pub_c_pk).to_bytes());

    let transcript_0 = compute_transcript_0(&hello.e_pub_c, &e_pub_s, mesh_id, suite_id, hello.ts_ms);

    let client_static_pub = hello.client_static_pub;

    if !ts_within_window(current_ts_ms(), hello.ts_ms) {
        tracing::warn!(
            client_ts_ms = hello.ts_ms,
            client_static_pub = %hex::encode(&hello.client_static_pub[..8]),
            "[HS-V9-DGRAM] server refused: ClientHello timestamp outside the accepted window"
        );
        return Ok(None);
    }

    if verify_client_proof(
        &keypair.secret,
        &client_static_pub,
        &hello.e_pub_c,
        &keypair.public.to_bytes(),
        mesh_id,
        &hello.suite_ids,
        hello.ts_ms,
        &hello.client_proof,
    )
    .is_err()
    {
        tracing::warn!(
            client_static_pub = %hex::encode(&client_static_pub[..8]),
            "[HS-V9-DGRAM] server refused: client proof did not verify"
        );
        return Ok(None);
    }

    // Credential shape/size check — placed after proof verification, exactly
    // where the stream path (`handshake.rs`) reads its own credential frame,
    // so an unauthenticated peer (one that fails client_proof) never reaches
    // it.
    match cred_scheme {
        0x00 => {
            if !credential.is_empty() {
                // A legacy hello never has bytes past byte 97 — trailing
                // bytes here are either a malformed sender or an attempt to
                // smuggle data past a caller that only checks scheme_byte.
                // Reject rather than silently ignore them.
                tracing::warn!(
                    trailing = credential.len(),
                    "[HS-V9-DGRAM] server refused: cred_scheme=0x00 but trailing bytes follow the hello"
                );
                return Ok(None);
            }
        }
        _ => {
            if credential.len() > MAX_CREDENTIAL_LEN {
                tracing::warn!(
                    len = credential.len(),
                    cap = MAX_CREDENTIAL_LEN,
                    "[HS-V9-DGRAM] server refused: credential over the cap"
                );
                return Ok(None);
            }
        }
    }

    let ctx = ClientAuthContext {
        static_pub: &client_static_pub,
        ts_ms: hello.ts_ms,
        e_pub_c: &hello.e_pub_c,
        // Flag-stripped: a verifier dispatches on what the credential IS,
        // and the chain-addressed bit says only where in the datagram the
        // credential started.
        scheme_byte: cred_scheme,
        credential,
    };
    if !client_auth(&ctx) {
        tracing::warn!(
            client_static_pub = %hex::encode(&client_static_pub[..8]),
            "[HS-V9-DGRAM] server refused: the caller's client_auth closure rejected this client"
        );
        return Ok(None);
    }

    let server_static_pub = keypair.public.to_bytes();
    let server_proof = compute_server_proof(&ecdh_ee, &transcript_0, &server_static_pub);

    let server_hello = V9ServerHello {
        chosen_suite: suite_id,
        e_pub_s,
        server_proof,
        _reserved: [0u8; 16],
    };
    let wire = server_hello.to_wire();
    socket.send(&wire).await?;
    cache.insert(hello.e_pub_c, wire.to_vec());

    let session_keys = derive_v9_keys(&ecdh_ee, &transcript_0, suite);

    Ok(Some(ServerHandshakeResult {
        session_keys,
        remote_e_pub: client_static_pub,
    }))
}

#[cfg(test)]
mod carriage_tests {
    //! What the chain-addressed datagram layout must hold, without a socket
    //! or a handshake: the writer and the reader agree, the flag never
    //! reaches credential dispatch, and a hello that CLAIMS a block and does
    //! not carry one is refused rather than read as an unaddressed datagram.

    use super::*;

    fn hello(cred_scheme: u8) -> V9ClientHello {
        V9ClientHello {
            version: WIRE_VERSION_V9,
            suite_ids: [0x01, 0x00, 0x00],
            e_pub_c: [7u8; 32],
            ts_ms: 1_700_000_000_000,
            client_proof: [9u8; 16],
            client_static_pub: [3u8; 32],
            cred_scheme,
            target_hint: TargetHint::Legacy.to_byte(),
        }
    }

    fn address() -> DatagramChainAddress {
        DatagramChainAddress {
            chain_id: b"auto-deadbeef".to_vec(),
            chain_position: 2,
            chain_length: 4,
            selector_token: vec![0x5Au8; 16],
        }
    }

    #[test]
    fn an_unaddressed_datagram_is_byte_identical_to_what_this_module_always_sent() {
        let h = hello(0x02);
        let cred = b"a credential".to_vec();
        let built = build_client_datagram(&h, None, &cred).expect("build");

        let mut expected = h.to_wire().to_vec();
        expected.extend_from_slice(&cred);
        assert_eq!(built, expected, "adding chain carriage must not move an existing byte");

        let parsed = parse_datagram_hello(&built).expect("parse");
        assert!(parsed.chain_address.is_none());
        assert_eq!(parsed.cred_scheme, 0x02);
        assert_eq!(parsed.credential, &cred[..]);
    }

    #[test]
    fn an_addressed_datagram_round_trips_and_hides_the_flag_from_the_credential_scheme() {
        let addr = address();
        let cred = b"a credential".to_vec();
        let mut h = hello(0x02);
        h.cred_scheme |= CHAIN_ADDRESSED_FLAG;
        let built = build_client_datagram(&h, Some(&addr), &cred).expect("build");

        let parsed = parse_datagram_hello(&built).expect("parse");
        assert_eq!(parsed.chain_address.as_ref(), Some(&addr));
        // The scheme a verifier dispatches on is the one the caller asked
        // for. If the flag leaked through here, every chain-addressed client
        // would be refused by a credential verifier that has never heard of
        // scheme 0x82.
        assert_eq!(parsed.cred_scheme, 0x02);
        assert_eq!(parsed.hello.cred_scheme, 0x02 | CHAIN_ADDRESSED_FLAG);
        assert_eq!(parsed.credential, &cred[..]);
    }

    /// The whole point of putting the signal in `cred_scheme`: a datagram
    /// that claims a block must never be read as one that carries none. If
    /// it were, corrupting two bytes would drop a chain-addressed session
    /// back onto whatever the unaddressed fallback resolves to.
    #[test]
    fn a_claimed_block_that_is_not_there_is_refused_not_ignored() {
        let addr = address();
        let mut h = hello(0x02);
        h.cred_scheme |= CHAIN_ADDRESSED_FLAG;
        let built = build_client_datagram(&h, Some(&addr), b"cred").expect("build");

        // Cut anywhere inside the prefix or the block itself.
        let block_end = CLIENT_HELLO_LEN + CHAIN_BLOCK_LEN_PREFIX + addr.encode().expect("encode").len();
        for cut in CLIENT_HELLO_LEN..block_end {
            assert!(
                parse_datagram_hello(&built[..cut]).is_err(),
                "a datagram cut to {cut} bytes parsed instead of failing"
            );
        }

        // And a length prefix that describes more than the datagram holds.
        let mut lying = built.clone();
        lying[CLIENT_HELLO_LEN] = 0x00;
        lying[CLIENT_HELLO_LEN + 1] = MAX_ENCODED_BLOCK_LEN as u8;
        assert!(parse_datagram_hello(&lying).is_err());
    }

    /// The flag belongs to the carriage, not to the caller's scheme space.
    /// A caller that could pass it in `cred_scheme` would be declaring a
    /// block the writer was never given — the reader would then fail on a
    /// datagram the writer thought was well-formed.
    #[tokio::test]
    async fn a_caller_cannot_set_the_carriage_flag_through_the_credential_scheme() {
        let mut sock = UdpPeerSocket::bind_client("127.0.0.1:1".parse().expect("addr"))
            .await
            .expect("bind a client socket");
        // `expect_err` is not available here on purpose: the Ok variant
        // carries session keys and does not implement Debug, which is the
        // right call for a type holding key material.
        let outcome = run_client_handshake_v9_datagram_with_chain(
            &mut sock,
            &[1u8; 32],
            &[2u8; 32],
            b"MESH1",
            &[AeadSuite::ChaCha20Poly1305],
            None,
            0x02 | CHAIN_ADDRESSED_FLAG,
            b"cred",
        )
        .await;
        match outcome {
            Ok(_) => panic!("a scheme carrying the carriage flag must be refused"),
            Err(err) => assert!(
                err.to_string().contains("chain-addressed bit"),
                "the refusal must name what it refused: {err}"
            ),
        }
    }
}

#[cfg(test)]
mod fs_chain_hello_tests {
    //! [`is_fs_chain_hello`] is a peek, not a parse: it must recognise the
    //! flag when it is genuinely there, reject everything else — including
    //! a real hello that never set it — and never panic on a buffer of the
    //! wrong shape. `FS_CHAIN_HELLO_FLAG` and `CHAIN_ADDRESSED_FLAG` sharing
    //! no bit is enforced at compile time by the `const _: () = assert!(...)`
    //! next to the flag's own definition; nothing further to check for that
    //! here at runtime.

    use super::*;
    use crate::auth::v9::build_face_hello_bytes;

    /// A caller that wants an FS-chain classifier token takes exactly what
    /// [`build_face_hello_bytes`] (Slice 1's other artifact) already
    /// produces and ORs the flag into byte 92 — the pattern the design doc's
    /// Q3 names for the relay's own outbound dial. What is built that way
    /// must be exactly what gets recognised.
    #[test]
    fn the_flag_round_trips_through_build_and_recognise() {
        let mut wire = build_face_hello_bytes();
        assert!(!is_fs_chain_hello(&wire), "no caller has set the flag yet");
        wire[92] |= FS_CHAIN_HELLO_FLAG;
        assert!(is_fs_chain_hello(&wire), "the flag this module just set must be the one read back");
    }

    /// A real V9 hello built the ordinary way — [`build_face_hello_bytes`]
    /// with nothing OR'd into byte 92 — must never be mistaken for an
    /// FS-chain classifier token. If it were, every existing single-hop
    /// dial would start being routed down the FS-chain branch the moment
    /// this function shipped.
    #[test]
    fn a_real_v9_hello_built_without_the_flag_is_not_an_fs_chain_hello() {
        let wire = build_face_hello_bytes();
        assert!(!is_fs_chain_hello(&wire));
    }

    /// Below [`crate::auth::v9::CLIENT_HELLO_LEN`], byte 92 either does not
    /// exist or is not the byte this function means to read — a short
    /// buffer must be refused by the length check alone, before any
    /// indexing, or this function panics instead of returning `false` on
    /// exactly the kind of input a hostile or truncated sender would send.
    #[test]
    fn a_too_short_buffer_is_not_an_fs_chain_hello() {
        let mut wire = build_face_hello_bytes();
        wire[92] |= FS_CHAIN_HELLO_FLAG;
        let truncated = &wire[..CLIENT_HELLO_LEN - 1];
        assert!(!is_fs_chain_hello(truncated));
    }

    /// A datagram longer than the fixed hello — e.g. one that also carries a
    /// credential or a chain block after it, per [`parse_datagram_hello`]'s
    /// own layout — is never a classifier token by construction: the whole
    /// point of the classifier token is that NOTHING follows it in that
    /// datagram, because a separate raw FS frame is the next datagram, not
    /// more of this one.
    #[test]
    fn a_too_long_buffer_is_not_an_fs_chain_hello() {
        let mut wire = build_face_hello_bytes()[..].to_vec();
        wire[92] |= FS_CHAIN_HELLO_FLAG;
        wire.push(0xAA);
        assert!(!is_fs_chain_hello(&wire));
    }
}
