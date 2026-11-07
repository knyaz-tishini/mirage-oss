//! Client-side V9-FS forward-secret onion tunnel (telescopic circuit setup).
//!
//! # Connection lifecycle
//!
//! For an N-hop FS circuit:
//!
//! 1. Connect TCP to `hops[0]` (with optional camouflage — identical to `OnionTunnel`).
//! 2. Write byte_cipher skin prefix if present (identical to `OnionTunnel`).
//! 3. Compute `transcript_base = compute_fs_transcript_base(mesh_id, chain_id)`.
//! 4. For each hop `i` in `0..hops.len()`:
//!    - Generate `client_eph_i: EphemeralSecret`.
//!    - If `i == 0`: encode and send `FsInitFrame` prefixed by `[4B BE len]`.
//!    - If `i > 0`: encode `FsExtendFrame` (contains `client_eph_i_pub`,
//!      `prev_transcript`, `next_hop_addr[i]`), then wrap/encrypt through
//!      already-established layers `0..i-1` using `wrap_layer_v7` applied
//!      innermost-last (entry key outermost), and send `[4B BE len][ciphertext]`.
//!    - Read `FsCreatedFrame` (71 bytes) with 15 s timeout.
//!    - Verify `status.is_ok()`, `chain_position == i`, and `suite == chosen_suite_i`.
//!    - Compute `transcript_i = extend_fs_transcript(prev, i, node_id_i, c_pub_i, s_pub_i, suite)`.
//!    - Compute `shared_i = client_eph_i × server_eph_pub_i`.
//!    - Compute `key_i = derive_layer_key_v9_fs(&shared_i, i, &transcript_i, suite_i)`.
//!    - Store `key_i`, `client_eph_pub_i`, `server_eph_pub_i`, `transcript_i`.
//!    - Zeroize `shared_i` (via `Zeroizing`).
//! 5. Send initial `user_data` wrapped in all N layer keys (exit key innermost,
//!    entry key outermost).
//! 6. Return the `OnionFsTunnel` ready for bidirectional data transfer.
//!
//! After setup, data travels identically to `OnionTunnel` — forward direction is
//! raw bytes (no further wrapping on send), reply direction is framed
//! `[4B BE len][N-layer AEAD]` (unwrapped by `OnionFsSession::unwrap_reply`).
//!
//! # Forward data after setup
//!
//! Once the circuit is established, the entry hop already has a key for this
//! session. Data sent by the client travels raw (the client does not re-encrypt
//! it again here — it is the relay hops that peel/relay). This mirrors the V8
//! path exactly: after the envelope is accepted and the ack received, `send`
//! writes raw bytes and `recv` reads the N-layer AEAD reply.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use mirage_core::{
    config::{ChainConfig, HopConfig},
    crypto::AeadSuite,
    error::MirageError,
};
use mirage_protocol::camouflage::pipeline::{wrap_tcp_client, BidiStream};
use mirage_protocol::driver::ClientCredential;
use mirage_protocol::onion::{
    builder::{
        compute_fs_auth_tag, compute_fs_transcript_base, derive_layer_key_v9_fs,
        extend_fs_transcript, OnionFsSession, PeerSuitePreference,
    },
    fs_frame::{FsCreatedFrame, FsExtendFrame, FsInitFrame},
    layer::NextHop,
};
use mirage_protocol::traits::{TransportInfo, Tunnel};
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Client-side V9-FS forward-secret onion tunnel.
///
/// Established by `OnionFsTunnel::connect` via the telescopic N-RTT loop.
/// After construction, implements [`Tunnel`] identically to `OnionTunnel` —
/// raw forward writes, N-layer AEAD reply unwrap via `OnionFsSession`.
pub struct OnionFsTunnel {
    stream: Box<dyn BidiStream>,
    session: OnionFsSession,
    info: TransportInfo,
    recv_buf: Vec<u8>,
    plaintext_buf: Vec<u8>,
    /// When `true`, `recv` passes bytes through without AEAD unwrap (mux raw mode).
    pub raw_mode: bool,
}


/// The bytes of a hop's selector token, or empty when the monitor sent none.
///
/// Absent is legitimate — an older monitor mints no token and both sides fall
/// back to the derived `{chain_id}-h{position}`. Malformed is NOT: a token
/// that will not decode means the monitor and the client disagree about what
/// this hop is called, and quietly sending nothing would swap the real
/// selector for the 32-bit one this replaces, which is the failure this whole
/// change exists to remove. So it is an error, named.
pub(crate) fn hop_selector_token(
    chain_id: &str,
    hop_index: usize,
    hex_opt: Option<&str>,
) -> Result<Vec<u8>, MirageError> {
    match hex_opt {
        None => Ok(Vec::new()),
        Some(h) => {
            if h.len() % 2 != 0 {
                return Err(MirageError::Config(format!(
                    "chain {chain_id}: hop[{hop_index}] selector_token_hex has an odd                      length ({})",
                    h.len()
                )));
            }
            let mut out = Vec::with_capacity(h.len() / 2);
            for i in (0..h.len()).step_by(2) {
                out.push(u8::from_str_radix(&h[i..i + 2], 16).map_err(|e| {
                    MirageError::Config(format!(
                        "chain {chain_id}: hop[{hop_index}] selector_token_hex is not hex: {e}"
                    ))
                })?);
            }
            Ok(out)
        }
    }
}


/// The eight hex characters a hop's own journal prints for this selector.
///
/// A hop that will not serve us says nothing back, on purpose: a selector miss
/// and a refused credential leave through the same hold-then-close with the
/// same timing, because answering either question answers both for anyone
/// probing. That property is for the PEER, and it stays. It should never have
/// cost US the answer too.
///
/// The hop already writes the cause it chose — `not-authenticated` or
/// `no-such-listener` — into its own log, keyed by this digest of the selector
/// rather than the selector itself, so the journal never carries the map of
/// which chains ran through that box. Printing the same digest on our side
/// turns a bare fifteen-second timeout into one an operator can join against
/// the hop's own line and read the real cause off. Nothing new reaches the
/// wire and nothing new reaches the peer.
///
/// Must stay byte-identical to `chain_splice::selector_hash` in mirage2node:
/// BLAKE3 of the selector's bytes, first four, hex. Two spellings of one
/// digest would silently stop joining, which is the failure this is meant to
/// remove.
pub(crate) fn selector_digest(selector: &[u8]) -> String {
    let d = mirage_core::crypto::hash_blake3(selector);
    hex_lower(&d[..4])
}

/// Lowercase hex, small and local — this crate has no hex dependency and one
/// four-byte digest does not earn one.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// The selector bytes this dial addresses hop `position` by — the minted token
/// when the binding carried one, else the derived `{chain_id}-h{position}`
/// every hop answered to before tokens existed. Mirrors
/// `ChainSelector::from_frame` on the node side.
pub(crate) fn selector_for_hop(chain_id: &str, position: usize, token: &[u8]) -> Vec<u8> {
    if !token.is_empty() {
        return token.to_vec();
    }
    let mut out = Vec::with_capacity(chain_id.len() + 4);
    out.extend_from_slice(chain_id.as_bytes());
    out.extend_from_slice(b"-h");
    out.extend_from_slice(position.to_string().as_bytes());
    out
}

impl OnionFsTunnel {
    /// Test-only constructor: run the telescopic handshake loop over a
    /// caller-supplied stream (e.g. `tokio::io::DuplexStream`) instead of
    /// opening a TCP connection.  Production behaviour is unchanged; this
    /// method exists solely to enable in-process integration tests.
    ///
    /// `fake_peer_addr` is stored in `TransportInfo` — use any loopback addr.
    #[cfg(test)]
    pub async fn connect_with_stream(
        stream: Box<dyn mirage_protocol::camouflage::pipeline::BidiStream>,
        fake_peer_addr: std::net::SocketAddr,
        chain: &ChainConfig,
        initial_user_data: &[u8],
        mesh_id: &[u8],
        client_offered_suites: Vec<AeadSuite>,
        peer_suite_prefs: &[mirage_protocol::onion::builder::PeerSuitePreference],
        peer_table_generation: u64,
    ) -> Result<Self, MirageError> {
        if chain.hops.is_empty() {
            return Err(MirageError::Config(
                "v9-fs connect_with_stream: hops is empty".into(),
            ));
        }
        if client_offered_suites.is_empty() {
            return Err(MirageError::Config(
                "v9-fs connect_with_stream: client_offered_suites is empty".into(),
            ));
        }

        // Re-use the same suite negotiation + telescopic loop as `connect`.
        // We skip TCP setup and the byte_cipher prefix (no camouflage in tests).
        let chosen_suites = compute_chosen_suites_fs(
            &chain.hops,
            &client_offered_suites,
            peer_suite_prefs,
            &chain.chain_id,
        )?;

        let mut stream: Box<dyn mirage_protocol::camouflage::pipeline::BidiStream> = stream;

        let mut layer_keys: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut layer_aead_suites: Vec<AeadSuite> = Vec::with_capacity(chain.hops.len());
        let mut client_eph_pubs: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut server_eph_pubs: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut transcripts: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());

        let mut prev_transcript =
            mirage_protocol::onion::builder::compute_fs_transcript_base(
                mesh_id,
                chain.chain_id.as_bytes(),
            );

        for i in 0..chain.hops.len() {
            let hop = &chain.hops[i];
            let suite = chosen_suites[i];

            // Resolve hop's certified static pubkey — required for ntor authentication.
            let hop_static_pub = hop.public_key.as_deref()
                .ok_or_else(|| MirageError::Protocol(format!(
                    "v9-fs: hop[{i}] missing certified node static pubkey (FS onion requires authenticated hops)"
                )))
                .and_then(|hex| decode_hex_pubkey_fs(hex))?;

            // Use StaticSecret (throwaway per-dial) so we can do two DHs from the same key.
            let client_eph = StaticSecret::random_from_rng(OsRng);
            let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph).to_bytes();

            let wire_bytes = if i == 0 {
                let frame = FsInitFrame {
                    mesh_id: mesh_id.to_vec(),
                    chain_id: chain.chain_id.as_bytes().to_vec(),
                    chain_length: chain.hops.len() as u8,
                    chain_position: 0,
                    client_suites: client_offered_suites.clone(),
                    client_eph_pub,
                    expected_peer_table_generation: peer_table_generation,
                    credential_scheme: 0x00,
                    credential: vec![],
                    selector_token: hop_selector_token(
                        &chain.chain_id,
                        i,
                        hop.selector_token_hex.as_deref(),
                    )?,
                };
                frame.encode().map_err(|e| {
                    warn!(error = %e, "v9-fs test: FsInitFrame encode failed");
                    e
                })?
            } else {
                let next_hop_addr = hop.addr.clone();
                let extend = FsExtendFrame {
                    chain_position: i as u8,
                    next_hop_addr,
                    client_eph_pub,
                    expected_peer_table_generation: peer_table_generation,
                    client_suites: client_offered_suites.clone(),
                    prev_transcript,
                    selector_token: hop_selector_token(
                        &chain.chain_id,
                        i,
                        hop.selector_token_hex.as_deref(),
                    )?,
                };
                let extend_bytes = extend.encode().map_err(|e| {
                    warn!(hop = i, error = %e, "v9-fs test: FsExtendFrame encode failed");
                    e
                })?;
                encrypt_extend_through_layers(
                    &extend_bytes,
                    &layer_keys[..i],
                    &layer_aead_suites[..i],
                )?
            };

            let len_be = (wire_bytes.len() as u32).to_be_bytes();
            stream.write_all(&len_be).await.map_err(MirageError::Io)?;
            stream.write_all(&wire_bytes).await.map_err(MirageError::Io)?;
            stream.flush().await.map_err(MirageError::Io)?;

            let mut created_buf = [0u8; FsCreatedFrame::ENCODED_LEN];
            tokio::time::timeout(
                Duration::from_secs(15),
                read_exact_fs(&mut stream, &mut created_buf),
            )
            .await
            .map_err(|_| {
                MirageError::Protocol(format!(
                    "v9-fs test hop[{i}]: FsCreatedFrame read timed out"
                ))
            })
            .and_then(|r| r)?;

            let created = FsCreatedFrame::decode(&created_buf).map_err(|e| {
                warn!(hop = i, error = %e, "v9-fs test: FsCreatedFrame decode failed");
                e
            })?;

            if !created.status.is_ok() {
                return Err(MirageError::Protocol(format!(
                    "v9-fs test hop[{i}]: {} (code {})",
                    created.status.name(),
                    created.status.as_u32()
                )));
            }
            if created.chain_position as usize != i {
                return Err(MirageError::Protocol(format!(
                    "v9-fs test hop[{i}]: chain_position={} expected {i}",
                    created.chain_position
                )));
            }
            if created.suite != suite {
                return Err(MirageError::Protocol(format!(
                    "v9-fs test hop[{i}]: suite mismatch {:?} vs {:?}",
                    created.suite, suite
                )));
            }

            let node_id = hop
                .node_id
                .as_deref()
                .or(hop.display_name.as_deref())
                .unwrap_or("");
            let transcript_i = extend_fs_transcript(
                &prev_transcript,
                i as u8,
                node_id,
                &client_eph_pub,
                &created.server_eph_pub,
                &hop_static_pub,
                suite,
            );

            if created.transcript_hash != transcript_i {
                return Err(MirageError::Protocol(format!(
                    "v9-fs test hop[{i}]: transcript hash mismatch"
                )));
            }

            // ntor: two DHs from client's per-hop throwaway key.
            let ee = Zeroizing::new(
                client_eph.diffie_hellman(&PublicKey::from(created.server_eph_pub)).to_bytes(),
            );
            let es = Zeroizing::new(
                client_eph.diffie_hellman(&PublicKey::from(hop_static_pub)).to_bytes(),
            );
            let key_i = derive_layer_key_v9_fs(&ee, &es, i as u8, &transcript_i, suite);

            // Verify key-confirmation auth_tag.
            let expected_auth = compute_fs_auth_tag(&key_i, &transcript_i, &created.server_eph_pub);
            if created.auth_tag != expected_auth {
                return Err(MirageError::Protocol(format!(
                    "v9-fs test hop[{i}]: key-confirmation auth_tag mismatch (possible on-path party / wrong node identity)"
                )));
            }

            layer_keys.push(key_i);
            layer_aead_suites.push(suite);
            client_eph_pubs.push(client_eph_pub);
            server_eph_pubs.push(created.server_eph_pub);
            transcripts.push(transcript_i);
            prev_transcript = transcript_i;
        }

        if !initial_user_data.is_empty() {
            // Single exit-layer wrap (same forward convention as the real
            // `connect` + `send`: forward data is exit-terminal encryption,
            // NOT a multi-layer onion). Mirrors lines ~648-659.
            let n = layer_keys.len();
            let wrapped = mirage_protocol::onion::layer::wrap_reply_layer_v7(
                layer_aead_suites[n - 1],
                &layer_keys[n - 1],
                initial_user_data,
            )?;
            let len_be = (wrapped.len() as u32).to_be_bytes();
            stream.write_all(&len_be).await.map_err(MirageError::Io)?;
            stream.write_all(&wrapped).await.map_err(MirageError::Io)?;
            stream.flush().await.map_err(MirageError::Io)?;
        }

        let info = TransportInfo::tcp_raw(fake_peer_addr);
        let session = OnionFsSession {
            layer_keys,
            layer_aead_suites,
            client_eph_pubs,
            server_eph_pubs,
            transcripts,
        };

        Ok(OnionFsTunnel {
            stream,
            session,
            info,
            recv_buf: Vec::new(),
            plaintext_buf: Vec::new(),
            raw_mode: false,
        })
    }

    /// Establish a V9-FS telescopic circuit and return the live tunnel.
    ///
    /// `hops` and per-hop preferences are taken from `chain`. The chosen suite
    /// for each hop is the first client-offered suite that appears in the hop's
    /// server preference list (identical intersection logic to the V8 path).
    ///
    /// `credential` — optional anonymous credential to embed in `FsInitFrame`.
    /// When `None`, `credential_scheme=0x00` / `credential=vec![]` are sent
    /// (legacy/tolerant-mode behaviour).  Pass a fresh per-dial token from
    /// `mint_epoch_hmac_credential` for untrusted-peer enforce mode.
    pub async fn connect(
        chain: &ChainConfig,
        _destination: NextHop,
        initial_user_data: &[u8],
        mesh_id: &[u8],
        client_offered_suites: Vec<AeadSuite>,
        peer_suite_prefs: &[PeerSuitePreference],
        peer_table_generation: u64,
        credential: Option<ClientCredential>,
    ) -> Result<Self, MirageError> {
        chain.validate().map_err(|e| {
            let me = MirageError::Config(e.to_string());
            warn!(chain_id = %chain.chain_id, error = %me, "onion-fs connect: chain.validate() failed");
            me
        })?;

        if chain.hops.is_empty() {
            return Err(MirageError::Config(format!(
                "v9-fs: chain {} hops is empty",
                chain.chain_id
            )));
        }
        if client_offered_suites.is_empty() {
            return Err(MirageError::Config(
                "v9-fs: client_offered_suites is empty".into(),
            ));
        }

        let hop0 = &chain.hops[0];
        let hop0_addr = resolve_hop_addr_fs(hop0).await.map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                hop0_addr = %hop0.addr,
                error = %e,
                "onion-fs connect: resolve_hop_addr failed"
            );
            e
        })?;
        debug!(
            hop0 = %hop0_addr,
            hops = chain.hops.len(),
            chain_id = %chain.chain_id,
            "onion-fs v9: connecting to entry hop"
        );

        // ── Open TCP to entry hop (identical to OnionTunnel) ──────────────────
        let mut stream: Box<dyn BidiStream> = if let Some(cam) = &hop0.camouflage {
            let pubkey = decode_hex_pubkey_fs(
                hop0.camo_server_pubkey
                    .as_deref()
                    .or(hop0.public_key.as_deref())
                    .unwrap_or(""),
            )
            .map_err(|e| {
                warn!(
                    chain_id = %chain.chain_id,
                    hop0_addr = %hop0_addr,
                    error = %e,
                    "onion-fs connect: decode_hex_pubkey_fs failed for camouflage hop"
                );
                e
            })?;
            let sni = hop0.sni.as_deref().unwrap_or("");
            tokio::time::timeout(
                Duration::from_secs(10),
                wrap_tcp_client(hop0_addr, cam, &pubkey, sni),
            )
            .await
            .map_err(|_| {
                let e = MirageError::NodeUnreachable(format!(
                    "v9-fs: camouflage-wrapped connect to {hop0_addr} timed out"
                ));
                warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, "onion-fs connect: wrap_tcp_client timed out");
                e
            })
            .and_then(|r| {
                r.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, error = %e, "onion-fs connect: wrap_tcp_client failed");
                    e
                })
            })?
        } else {
            let tcp = tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect(hop0_addr),
            )
            .await
            .map_err(|_| {
                warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, "onion-fs connect: TcpStream::connect timed out");
                MirageError::NodeUnreachable(format!(
                    "v9-fs: connect to {hop0_addr} timed out"
                ))
            })?
            .map_err(|e| {
                warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, error = %e, "onion-fs connect: TcpStream::connect failed");
                MirageError::Io(e)
            })?;
            Box::new(tcp)
        };

        // ── byte_cipher skin prefix (identical to OnionTunnel) ───────────────
        if let Some(bc) = chain.hops.first().and_then(|h| h.byte_cipher.as_ref()) {
            if let Some(prefix) = mirage_protocol::byte_cipher::byte_cipher_skin_prefix(bc) {
                stream.write_all(&prefix).await.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, error = %e, "onion-fs connect: write byte_cipher skin prefix failed");
                    MirageError::Io(e)
                })?;
                stream.flush().await.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, error = %e, "onion-fs connect: flush after byte_cipher skin prefix failed");
                    MirageError::Io(e)
                })?;
            }
        }

        // ── The face hello the entry's perimeter is waiting for ──────────────
        //
        // The entry hop is reached at its published CHAIN FACE, and a face is
        // fronted by the perimeter: its classifier will not call this
        // connection wire until 97 bytes that parse as a V9 ClientHello have
        // arrived, and `chain_splice` below it skips exactly that many before
        // reading the envelope. Writing the envelope straight after the
        // camouflage therefore never reached the node at all — the perimeter
        // waited, its peek timed out, and it HELD the connection, which is
        // silent to us and indistinguishable from an unreachable box.
        //
        // A relay dialing the next hop's face already wrote this hello. The
        // client dialing the entry's face did not, and that asymmetry is the
        // whole defect: a face exists so that a client's opening and a relay's
        // are not separable, and one of the two was not sending the opening.
        // Same function for both, so they cannot drift into two
        // distributions.
        mirage_protocol::auth::v9::write_face_hello(&mut stream)
            .await
            .map_err(|e| {
                warn!(
                    chain_id = %chain.chain_id,
                    hop0_addr = %hop0_addr,
                    error = %e,
                    "onion-fs connect: writing the face hello failed"
                );
                e
            })?;

        // ── Compute per-hop chosen suites (same intersection as V8) ──────────
        let chosen_suites = compute_chosen_suites_fs(&chain.hops, &client_offered_suites, peer_suite_prefs, &chain.chain_id)?;

        // ── Telescopic setup loop ─────────────────────────────────────────────
        // State accumulated across iterations.
        let mut layer_keys: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut layer_aead_suites: Vec<AeadSuite> = Vec::with_capacity(chain.hops.len());
        let mut client_eph_pubs: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut server_eph_pubs: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut transcripts: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());

        // transcript starts at the base (pre-hop) value.
        let mut prev_transcript = compute_fs_transcript_base(mesh_id, chain.chain_id.as_bytes());

        for i in 0..chain.hops.len() {
            let hop = &chain.hops[i];
            let suite = chosen_suites[i];

            // Resolve hop's certified static pubkey — required for ntor authentication.
            let hop_static_pub = hop.public_key.as_deref()
                .ok_or_else(|| {
                    warn!(chain_id = %chain.chain_id, hop = i, "onion-fs: hop missing certified static pubkey");
                    MirageError::Protocol(format!(
                        "v9-fs: hop[{i}] missing certified node static pubkey (FS onion requires authenticated hops)"
                    ))
                })
                .and_then(|hex| decode_hex_pubkey_fs(hex))?;

            // Use StaticSecret (throwaway per-dial) so we can do two DHs from the same key.
            let client_eph = StaticSecret::random_from_rng(OsRng);
            let client_eph_pub = x25519_dalek::PublicKey::from(&client_eph).to_bytes();

            // Build and encrypt the setup message for hop i.
            let wire_bytes = if i == 0 {
                // Hop 0: plain FsInitFrame, no encryption yet.
                let node_id = hop
                    .node_id
                    .as_deref()
                    .or(hop.display_name.as_deref())
                    .ok_or_else(|| {
                        MirageError::Config(format!(
                            "v9-fs: chain {} hop[0] requires node_id",
                            chain.chain_id
                        ))
                    })?;
                let _ = node_id; // used for error context; actual node_id binding happens in transcript
                let (cred_scheme, cred_bytes) = match &credential {
                    Some(c) => (c.scheme, c.token.clone()),
                    None    => (0x00, vec![]),
                };
                let frame = FsInitFrame {
                    mesh_id: mesh_id.to_vec(),
                    chain_id: chain.chain_id.as_bytes().to_vec(),
                    chain_length: chain.hops.len() as u8,
                    chain_position: 0,
                    client_suites: client_offered_suites.clone(),
                    client_eph_pub,
                    expected_peer_table_generation: peer_table_generation,
                    credential_scheme: cred_scheme,
                    credential: cred_bytes,
                    selector_token: hop_selector_token(
                        &chain.chain_id,
                        i,
                        hop.selector_token_hex.as_deref(),
                    )?,
                };
                frame.encode().map_err(|e| {
                    warn!(chain_id = %chain.chain_id, error = %e, "onion-fs: FsInitFrame encode failed");
                    e
                })?
            } else {
                // Hop i (i > 0): FsExtendFrame, then encrypted through layers 0..i-1.
                let next_hop_addr = hop.addr.clone();
                let extend = FsExtendFrame {
                    chain_position: i as u8,
                    next_hop_addr,
                    client_eph_pub,
                    expected_peer_table_generation: peer_table_generation,
                    client_suites: client_offered_suites.clone(),
                    prev_transcript,
                    selector_token: hop_selector_token(
                        &chain.chain_id,
                        i,
                        hop.selector_token_hex.as_deref(),
                    )?,
                };
                let extend_bytes = extend.encode().map_err(|e| {
                    warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs: FsExtendFrame encode failed");
                    e
                })?;
                // Encrypt through layers i-1 down to 0.
                // Layer i-1 is innermost (applied first); layer 0 is outermost (applied last).
                // When peeling: entry hop (layer 0) peels first, forwarding to layer 1, etc.
                encrypt_extend_through_layers(&extend_bytes, &layer_keys[..i], &layer_aead_suites[..i])?
            };

            // Send [4B BE len][wire_bytes].
            let len_be = (wire_bytes.len() as u32).to_be_bytes();
            stream.write_all(&len_be).await.map_err(|e| {
                warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs: write frame length failed");
                MirageError::Io(e)
            })?;
            stream.write_all(&wire_bytes).await.map_err(|e| {
                warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs: write frame body failed");
                MirageError::Io(e)
            })?;
            stream.flush().await.map_err(|e| {
                warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs: flush after frame write failed");
                MirageError::Io(e)
            })?;
            debug!(chain_id = %chain.chain_id, hop = i, frame_len = wire_bytes.len(), "onion-fs: frame sent, awaiting FsCreatedFrame");

            // Read FsCreatedFrame (exactly ENCODED_LEN bytes, 15 s timeout).
            let mut created_buf = [0u8; FsCreatedFrame::ENCODED_LEN];
            tokio::time::timeout(
                Duration::from_secs(15),
                read_exact_fs(&mut stream, &mut created_buf),
            )
            .await
            .map_err(|_| {
                // A hop that refuses us holds the connection and says nothing
                // — deliberately, so a prober cannot tell a selector miss from
                // a refused credential. That leaves this side with a bare
                // timeout, which is the same shape as an unreachable box or a
                // slow one. The hop's own journal already names the cause,
                // keyed by this digest; printing it here is what lets the two
                // be joined. See `selector_digest`.
                let token = hop_selector_token(
                    &chain.chain_id,
                    i,
                    hop.selector_token_hex.as_deref(),
                )
                .unwrap_or_default();
                let digest =
                    selector_digest(&selector_for_hop(chain.chain_id.as_str(), i, &token));
                let node = hop
                    .node_id
                    .as_deref()
                    .or(hop.display_name.as_deref())
                    .unwrap_or("<unnamed>");
                warn!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    node_id = %node,
                    selector_hash = %digest,
                    "onion-fs: FsCreatedFrame read timed out (15s) — the hop wrote no                      reply; grep its journal for this selector_hash to read the cause                      it recorded"
                );
                MirageError::Protocol(format!(
                    "v9-fs hop[{i}] ({node}): no FsCreated in 15s — the hop held the                      connection and named no cause on the wire, by design; its own log                      has the cause under selector_hash={digest}"
                ))
            })
            .and_then(|r| {
                r.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs: FsCreatedFrame read failed");
                    e
                })
            })?;

            let created = FsCreatedFrame::decode(&created_buf).map_err(|e| {
                warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs: FsCreatedFrame decode failed");
                e
            })?;

            // Validate status.
            if !created.status.is_ok() {
                warn!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    status = created.status.name(),
                    code = created.status.as_u32(),
                    "onion-fs: hop rejected FS handshake"
                );
                return Err(MirageError::Protocol(format!(
                    "v9-fs hop[{i}]: {} (code {})",
                    created.status.name(),
                    created.status.as_u32()
                )));
            }

            // Validate chain_position.
            if created.chain_position as usize != i {
                return Err(MirageError::Protocol(format!(
                    "v9-fs hop[{i}]: FsCreatedFrame.chain_position={} (expected {i})",
                    created.chain_position
                )));
            }

            // Validate suite match.
            if created.suite != suite {
                return Err(MirageError::Protocol(format!(
                    "v9-fs hop[{i}]: server suite {:?} does not match expected {:?}",
                    created.suite, suite
                )));
            }

            // Compute transcript_i binding both ephemerals AND certified static pub.
            let node_id = hop
                .node_id
                .as_deref()
                .or(hop.display_name.as_deref())
                .unwrap_or("");
            let transcript_i = extend_fs_transcript(
                &prev_transcript,
                i as u8,
                node_id,
                &client_eph_pub,
                &created.server_eph_pub,
                &hop_static_pub,
                suite,
            );

            // Verify transcript_hash from server matches our computation.
            if created.transcript_hash != transcript_i {
                warn!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    client_hex = %hex_short_fs(&transcript_i),
                    server_hex = %hex_short_fs(&created.transcript_hash),
                    "onion-fs: transcript hash mismatch"
                );
                return Err(MirageError::Protocol(format!(
                    "v9-fs hop[{i}]: transcript hash mismatch"
                )));
            }

            // ntor: two DHs — ee (forward secrecy) + es (node authentication).
            let ee = Zeroizing::new(
                client_eph.diffie_hellman(&PublicKey::from(created.server_eph_pub)).to_bytes(),
            );
            let es = Zeroizing::new(
                client_eph.diffie_hellman(&PublicKey::from(hop_static_pub)).to_bytes(),
            );
            let key_i = derive_layer_key_v9_fs(&ee, &es, i as u8, &transcript_i, suite);

            // Verify key-confirmation auth_tag — proves node holds certified static secret.
            let expected_auth = compute_fs_auth_tag(&key_i, &transcript_i, &created.server_eph_pub);
            if created.auth_tag != expected_auth {
                warn!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    "onion-fs: auth_tag mismatch — possible on-path party or wrong node identity"
                );
                return Err(MirageError::Protocol(format!(
                    "v9-fs hop[{i}]: key-confirmation auth_tag mismatch (possible on-path party / wrong node identity)"
                )));
            }

            debug!(
                chain_id = %chain.chain_id,
                hop = i,
                suite = ?suite,
                "onion-fs: hop established, key derived"
            );

            // Accumulate state.
            layer_keys.push(key_i);
            layer_aead_suites.push(suite);
            client_eph_pubs.push(client_eph_pub);
            server_eph_pubs.push(created.server_eph_pub);
            transcripts.push(transcript_i);
            prev_transcript = transcript_i;
        }

        debug!(
            chain_id = %chain.chain_id,
            hops = chain.hops.len(),
            "onion-fs: all hops established"
        );

        // ── Send initial user_data wrapped in all N layer keys ────────────────
        // Innermost layer = exit key (layer N-1), outermost = entry key (layer 0).
        // Apply from exit inward: wrap with layer[N-1], then layer[N-2], ..., layer[0].
        if !initial_user_data.is_empty() {
            // Single exit-layer wrap (same forward convention as send()).
            let n = layer_keys.len();
            let wrapped = mirage_protocol::onion::layer::wrap_reply_layer_v7(
                layer_aead_suites[n - 1],
                &layer_keys[n - 1],
                initial_user_data,
            )?;
            let len_be = (wrapped.len() as u32).to_be_bytes();
            stream.write_all(&len_be).await.map_err(MirageError::Io)?;
            stream.write_all(&wrapped).await.map_err(MirageError::Io)?;
            stream.flush().await.map_err(MirageError::Io)?;
        }

        let info = TransportInfo::tcp_raw(hop0_addr);
        let session = OnionFsSession {
            layer_keys,
            layer_aead_suites,
            client_eph_pubs,
            server_eph_pubs,
            transcripts,
        };

        Ok(OnionFsTunnel {
            stream,
            session,
            info,
            recv_buf: Vec::new(),
            plaintext_buf: Vec::new(),
            raw_mode: false,
        })
    }
}

// ── AEAD layering helpers ─────────────────────────────────────────────────────

/// Encrypt `extend_bytes` through layers `0..n` where `layer_keys[0]` is the
/// entry hop (outermost) and `layer_keys[n-1]` is the innermost established hop.
///
/// Wrapping order: apply layer `n-1` first (innermost), then `n-2`, …, then
/// layer `0` last (outermost). This means entry hop peels layer 0 first, then
/// forwards to layer 1, etc. — identical to the forward-direction onion wrapping
/// in `build_onion_ephemeral_v8`.
///
/// Uses `wrap_layer_v7` with `NextHop::Terminal` as the AAD next-hop address —
/// the relay already knows where to forward based on circuit state; the extend
/// payload is what carries the actual next-hop address.
///
/// `pub(crate)`: this is the ONE function the datagram twin
/// (`onion_tunnel_fs_udp::OnionFsUdpTunnel::connect`) reuses unmodified per
/// the U5 design doc — the telescopic extend exchange is transport-neutral,
/// only the carriage (stream framing vs. one-datagram-per-frame) differs.
pub(crate) fn encrypt_extend_through_layers(
    extend_bytes: &[u8],
    layer_keys: &[[u8; 32]],
    layer_suites: &[AeadSuite],
) -> Result<Vec<u8>, MirageError> {
    use mirage_protocol::onion::layer::wrap_layer_v7;

    let n = layer_keys.len();
    let mut current = extend_bytes.to_vec();
    // Apply innermost layer first, outermost last.
    for i in (0..n).rev() {
        current = wrap_layer_v7(layer_suites[i], &NextHop::Terminal, &layer_keys[i], &current)?;
    }
    Ok(current)
}

// ── Suite negotiation ─────────────────────────────────────────────────────────

/// Default suite preference when a peer has not published one.
const FS_DEFAULT_SUITE_PREF: [AeadSuite; 3] = [
    AeadSuite::ChaCha20Poly1305,
    AeadSuite::Aes256Gcm,
    AeadSuite::Aes128Gcm,
];

pub(crate) fn compute_chosen_suites_fs(
    hops: &[HopConfig],
    client_offered: &[AeadSuite],
    peer_suite_prefs: &[PeerSuitePreference],
    chain_id: &str,
) -> Result<Vec<AeadSuite>, MirageError> {
    let mut chosen = Vec::with_capacity(hops.len());
    for (i, hop) in hops.iter().enumerate() {
        let node_id = hop
            .node_id
            .as_deref()
            .or(hop.display_name.as_deref())
            .unwrap_or("");
        let server_pref = peer_suite_prefs
            .iter()
            .find(|p| p.node_id == node_id)
            .map(|p| p.aead_suite_preference.as_slice())
            .unwrap_or(&[]);
        let effective: &[AeadSuite] = if server_pref.is_empty() {
            &FS_DEFAULT_SUITE_PREF
        } else {
            server_pref
        };
        let suite = client_offered
            .iter()
            .find(|s| effective.contains(s))
            .copied()
            .ok_or_else(|| {
                MirageError::Protocol(format!(
                    "v9-fs: chain {chain_id} hop[{i}] node_id='{node_id}': no common AEAD suite"
                ))
            })?;
        chosen.push(suite);
    }
    Ok(chosen)
}

// ── I/O helpers ──────────────────────────────────────────────────────────────

async fn read_exact_fs(
    stream: &mut Box<dyn BidiStream>,
    buf: &mut [u8],
) -> Result<(), MirageError> {
    let mut off = 0;
    while off < buf.len() {
        let n = stream.read(&mut buf[off..]).await.map_err(MirageError::Io)?;
        if n == 0 {
            return Err(MirageError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "v9-fs: EOF mid-read",
            )));
        }
        off += n;
    }
    Ok(())
}

pub(crate) async fn resolve_hop_addr_fs(hop: &HopConfig) -> Result<SocketAddr, MirageError> {
    if let Ok(sa) = hop.addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let mut iter = tokio::net::lookup_host(&hop.addr)
        .await
        .map_err(MirageError::Io)?;
    iter.next().ok_or_else(|| {
        MirageError::Config(format!(
            "v9-fs: no DNS result for hop.addr={}",
            hop.addr
        ))
    })
}

pub(crate) fn decode_hex_pubkey_fs(hex: &str) -> Result<[u8; 32], MirageError> {
    if hex.len() != 64 {
        return Err(MirageError::Config(format!(
            "v9-fs: hop public_key must be 64 hex chars, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| MirageError::Config(format!("v9-fs: invalid hex: {e}")))?;
    }
    Ok(out)
}

fn hex_short_fs(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for x in &b[..8] {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// ── Tunnel trait implementation ───────────────────────────────────────────────

/// Identical to `OnionTunnel` — raw send, N-layer AEAD reply unwrap.
#[async_trait]
impl Tunnel for OnionFsTunnel {
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        // Forward data is encrypted with the EXIT layer key ONLY (single layer,
        // wrap_reply_layer_v7) and length-prefixed `[4B len][wrapped]`. Intermediate
        // hops forward the bytes transparently (they cannot read exit-bound data);
        // the exit peels this one layer with peel_reply_layer_v7. The reply path is
        // multi-layer (each hop wraps) — see recv()/unwrap_reply. The exit treats the
        // FIRST such frame as `[2B tlen][target][payload]`, subsequent frames as raw
        // forward bytes to the destination.
        let n = self.session.layer_keys.len();
        if n == 0 {
            return self.stream.write_all(data).await.map_err(MirageError::Io);
        }
        let exit_key = self.session.layer_keys[n - 1];
        let exit_suite = self.session.layer_aead_suites[n - 1];
        let wrapped = mirage_protocol::onion::layer::wrap_reply_layer_v7(exit_suite, &exit_key, data)?;
        let len_be = (wrapped.len() as u32).to_be_bytes();
        self.stream.write_all(&len_be).await.map_err(MirageError::Io)?;
        self.stream.write_all(&wrapped).await.map_err(MirageError::Io)?;
        self.stream.flush().await.map_err(MirageError::Io)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        if self.raw_mode {
            return self.stream.read(buf).await.map_err(MirageError::Io);
        }

        if !self.plaintext_buf.is_empty() {
            let copy_len = self.plaintext_buf.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&self.plaintext_buf[..copy_len]);
            self.plaintext_buf.drain(..copy_len);
            return Ok(copy_len);
        }

        let mut tmp = [0u8; 8192];

        while self.recv_buf.len() < 4 {
            let n = self.stream.read(&mut tmp).await.map_err(MirageError::Io)?;
            if n == 0 {
                return Ok(0);
            }
            self.recv_buf.extend_from_slice(&tmp[..n]);
        }

        let len = u32::from_be_bytes([
            self.recv_buf[0],
            self.recv_buf[1],
            self.recv_buf[2],
            self.recv_buf[3],
        ]) as usize;
        if len > 65536 {
            return Err(MirageError::Protocol(format!(
                "v9-fs: reply chunk too large: {} bytes",
                len
            )));
        }

        let total = 4 + len;
        while self.recv_buf.len() < total {
            let n = self.stream.read(&mut tmp).await.map_err(MirageError::Io)?;
            if n == 0 {
                return Err(MirageError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "v9-fs: tunnel closed mid-frame",
                )));
            }
            self.recv_buf.extend_from_slice(&tmp[..n]);
        }

        match self.session.unwrap_reply(&self.recv_buf[4..total]) {
            Ok(plaintext) => {
                let copy_len = plaintext.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&plaintext[..copy_len]);
                if plaintext.len() > buf.len() {
                    self.plaintext_buf
                        .extend_from_slice(&plaintext[copy_len..]);
                }
                self.recv_buf.drain(..total);
                Ok(copy_len)
            }
            Err(e) => {
                let wire = &self.recv_buf[4..total];
                let preview_len = wire.len().min(16);
                let preview: Vec<String> = wire[..preview_len]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                warn!(
                    error = %e,
                    frame_len = len,
                    wire_preview = %preview.join(" "),
                    "v9-fs: unwrap_reply failed"
                );
                Err(e)
            }
        }
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}

// ── In-memory unit test ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::crypto::KeyPair;
    use mirage_protocol::onion::builder::{
        compute_fs_auth_tag, compute_fs_transcript_base, derive_layer_key_v9_fs,
        extend_fs_transcript, peel_onion_fs_layer, OnionFsSession,
    };
    use mirage_protocol::onion::layer::wrap_reply_layer_v7;

    fn hex_encode_pub(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Simulate a 3-hop ntor FS telescopic setup entirely in memory (no sockets).
    ///
    /// For each hop i:
    /// - Client generates `client_eph_i` (StaticSecret for two DHs).
    /// - Server generates `server_eph_i`, calls `peel_onion_fs_layer` with node static keypair.
    /// - Client receives `server_eph_pub_i`, derives `key_i` + `transcript_i`, verifies `auth_tag`.
    ///
    /// Verifies:
    /// 1. `client_key_i == server_key_i` for all i.
    /// 2. All three keys are distinct.
    /// 3. auth_tags match at every hop.
    /// 4. Reply path roundtrip works via `OnionFsSession::unwrap_reply`.
    #[test]
    fn onion_fs_tunnel_key_agreement_3hop() {
        use x25519_dalek::{EphemeralSecret, StaticSecret};
        let suite = AeadSuite::ChaCha20Poly1305;
        let mesh_id = b"staging-v2";
        let chain_id = b"c-fs-tunnel-3hop";
        let node_ids = ["node-0", "node-1", "node-2"];

        // Each node has a certified static keypair.
        let node_kps: Vec<KeyPair> = (0..3).map(|_| KeyPair::generate()).collect();

        let base = compute_fs_transcript_base(mesh_id, chain_id);
        let mut prev = base;

        let mut client_layer_keys = Vec::new();
        let mut client_layer_suites = Vec::new();
        let mut client_eph_pubs_vec = Vec::new();
        let mut server_eph_pubs_vec = Vec::new();
        let mut transcripts_vec = Vec::new();

        for i in 0..3usize {
            let node_static_pub = node_kps[i].public.to_bytes();

            // Client side: StaticSecret for two DHs.
            let c = StaticSecret::random_from_rng(OsRng);
            let c_pub = x25519_dalek::PublicKey::from(&c).to_bytes();

            // Server side: peel derives t_i + auth_tag using node static keypair.
            let s = EphemeralSecret::random_from_rng(OsRng);
            let s_pub_bytes = PublicKey::from(&s).to_bytes();
            let (server_key, srv_pub_returned, server_t_i, auth_tag_server) =
                peel_onion_fs_layer(s, &node_kps[i], &c_pub, i as u8, &prev, node_ids[i], suite);

            assert_eq!(srv_pub_returned, s_pub_bytes, "peel_onion_fs_layer must return server eph pub");

            // Client derives transcript and key.
            let t_i = extend_fs_transcript(
                &prev, i as u8, node_ids[i], &c_pub, &srv_pub_returned, &node_static_pub, suite,
            );
            let ee = Zeroizing::new(c.diffie_hellman(&PublicKey::from(srv_pub_returned)).to_bytes());
            let es = Zeroizing::new(c.diffie_hellman(&PublicKey::from(node_static_pub)).to_bytes());
            let client_key = derive_layer_key_v9_fs(&ee, &es, i as u8, &t_i, suite);
            let auth_tag_client = compute_fs_auth_tag(&client_key, &t_i, &srv_pub_returned);

            assert_eq!(client_key, server_key, "hop {i}: client and server keys must agree");
            assert_eq!(t_i, server_t_i, "hop {i}: client and server transcript must agree");
            assert_eq!(auth_tag_client, auth_tag_server, "hop {i}: auth_tags must match");

            client_layer_keys.push(client_key);
            client_layer_suites.push(suite);
            client_eph_pubs_vec.push(c_pub);
            server_eph_pubs_vec.push(srv_pub_returned);
            transcripts_vec.push(t_i);
            prev = t_i;
        }

        // All keys must be distinct.
        assert_ne!(client_layer_keys[0], client_layer_keys[1]);
        assert_ne!(client_layer_keys[1], client_layer_keys[2]);
        assert_ne!(client_layer_keys[0], client_layer_keys[2]);

        // Reply path roundtrip.
        let session = OnionFsSession {
            layer_keys: client_layer_keys.clone(),
            layer_aead_suites: client_layer_suites,
            client_eph_pubs: client_eph_pubs_vec,
            server_eph_pubs: server_eph_pubs_vec,
            transcripts: transcripts_vec,
        };

        let plaintext = b"v9-fs hello from exit";
        let r2 = wrap_reply_layer_v7(suite, &client_layer_keys[2], plaintext).unwrap();
        let mut r2_framed = (r2.len() as u32).to_be_bytes().to_vec();
        r2_framed.extend_from_slice(&r2);
        let r1 = wrap_reply_layer_v7(suite, &client_layer_keys[1], &r2_framed).unwrap();
        let mut r1_framed = (r1.len() as u32).to_be_bytes().to_vec();
        r1_framed.extend_from_slice(&r1);
        let r0 = wrap_reply_layer_v7(suite, &client_layer_keys[0], &r1_framed).unwrap();

        let unwrapped = session.unwrap_reply(&r0).unwrap();
        assert_eq!(unwrapped, plaintext, "reply path must roundtrip correctly");
    }

    /// Verify `encrypt_extend_through_layers` produces ciphertext that cannot
    /// be decrypted with the wrong key.
    #[test]
    fn encrypt_extend_wrong_key_fails() {
        use mirage_protocol::onion::layer::peel_layer_v7;

        let suite = AeadSuite::ChaCha20Poly1305;
        let key0 = [0x11u8; 32];
        let extend_bytes = b"fake extend payload";

        let ciphertext =
            encrypt_extend_through_layers(extend_bytes, &[key0], &[suite]).unwrap();

        // Peel with correct key must succeed.
        let (_, inner) = peel_layer_v7(suite, &ciphertext, &key0).unwrap();
        assert_eq!(inner, extend_bytes);

        // Peel with wrong key must fail.
        let wrong_key = [0x22u8; 32];
        let res = peel_layer_v7(suite, &ciphertext, &wrong_key);
        assert!(res.is_err(), "wrong key must not decrypt extend frame");
    }

    // ── Phase 6: 2-hop in-memory duplex integration test ─────────────────────

    /// Drive `OnionFsTunnel::connect_with_stream` against a hand-rolled in-memory
    /// node simulator over `tokio::io::duplex`.
    ///
    /// The simulator plays both hops (entry=hop0, exit=hop1) sequentially on
    /// `node_end`.  All telescopic frames — FsInitFrame, FsExtend, FsCreated,
    /// and the initial user-data frame — flow over a single duplex byte stream.
    ///
    /// Asserts:
    /// (a) Handshake completes without error.
    /// (b) Initial user-data sent by the client is correctly recovered by the
    ///     simulator after peeling both AEAD layers (proves the data-path wrapping).
    /// (c) A reply wrapped by the simulator (exit→entry order) round-trips back
    ///     through `OnionFsSession::unwrap_reply`.
    ///
    /// Each node uses a real certified static KeyPair; the client passes their
    /// public keys in `public_key` HopConfig fields. The simulator calls
    /// `peel_onion_fs_layer` with the full KeyPair so both DHs are computed.
    #[tokio::test]
    async fn onion_fs_2hop_duplex_e2e() {
        use mirage_core::config::{
            CamouflageMode, ChainConfig, CoverTrafficConfig, HandshakeStrategy, HopConfig,
            HopRole, ProtocolId, ReplyMode, ShapingPreset, TcpProtocolId,
        };
        use mirage_core::mirage::wire::RelayMode;
        use mirage_protocol::onion::builder::{
            compute_fs_transcript_base, peel_onion_fs_layer,
        };
        use mirage_protocol::onion::fs_frame::{
            FsCreatedFrame, FsCreatedStatus, FsExtendFrame, FsInitFrame,
        };
        use mirage_protocol::onion::layer::{peel_layer_v7, peel_reply_layer_v7, wrap_reply_layer_v7};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use x25519_dalek::EphemeralSecret;

        let suite = AeadSuite::ChaCha20Poly1305;
        let mesh_id = b"staging-v2";
        let chain_id_str = "c-fs-e2e-2hop";
        let node_id_0 = "test-node-0";
        let node_id_1 = "test-node-1";
        let initial_data = b"hello from client";
        let reply_payload = b"reply from exit";

        // Generate certified static keypairs for both nodes.
        let node_kp_0 = KeyPair::generate();
        let node_kp_1 = KeyPair::generate();
        let node_pub_0 = node_kp_0.public.to_bytes();
        let node_pub_1 = node_kp_1.public.to_bytes();

        // Build a minimal 2-hop ChainConfig with certified static pubkeys.
        let chain = ChainConfig {
            chain_id: chain_id_str.into(),
            hops: vec![
                HopConfig {
                    addr: "127.0.0.1:19000".into(),
                    public_key: Some(hex_encode_pub(&node_pub_0)),
                    node_id: Some(node_id_0.into()),
                    sni: None,
                    role: HopRole::Entry,
                    display_name: None,
                    camouflage: None,
                    byte_cipher: None,
                    relay_mode: RelayMode::OnionPeel,
                    camo_server_pubkey: None,
                    selector_token_hex: None,
                },
                HopConfig {
                    addr: "127.0.0.1:19001".into(),
                    public_key: Some(hex_encode_pub(&node_pub_1)),
                    node_id: Some(node_id_1.into()),
                    sni: None,
                    role: HopRole::Exit,
                    display_name: None,
                    camouflage: None,
                    byte_cipher: None,
                    relay_mode: RelayMode::OnionPeel,
                    camo_server_pubkey: None,
                    selector_token_hex: None,
                },
            ],
            handshake: HandshakeStrategy::Telescopic,
            reply: ReplyMode::Onion,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: ShapingPreset::default(),
            camouflage: CamouflageMode::default(),
            cover_traffic: CoverTrafficConfig::default(),
            socks5_bind: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        };

        // duplex: 64 KiB buffer — plenty for all FS frames.
        let (client_end, node_end) = tokio::io::duplex(64 * 1024);

        // ── Simulator task: plays both hops on node_end ───────────────────────
        let sim_handle = tokio::spawn(async move {
            let mut node = node_end;

            // Helper: read a length-prefixed frame [4B BE len][body].
            async fn read_lv(
                s: &mut tokio::io::DuplexStream,
            ) -> Vec<u8> {
                let mut len_buf = [0u8; 4];
                s.read_exact(&mut len_buf).await.expect("sim: read len");
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                s.read_exact(&mut body).await.expect("sim: read body");
                body
            }

            // === HOP 0 HANDSHAKE ===
            let init_bytes = read_lv(&mut node).await;
            let (init, _) = FsInitFrame::decode(&init_bytes)
                .expect("sim: FsInitFrame decode");
            assert_eq!(init.chain_position, 0);

            let chosen_suite0 = *init.client_suites.first().expect("sim: no suites");

            let base = compute_fs_transcript_base(&init.mesh_id, &init.chain_id);

            let s0 = EphemeralSecret::random_from_rng(OsRng);
            let (key0, s0_pub, t0, auth_tag0) = peel_onion_fs_layer(
                s0,
                &node_kp_0,
                &init.client_eph_pub,
                0,
                &base,
                node_id_0,
                chosen_suite0,
            );

            let created0 = FsCreatedFrame {
                chain_position: 0,
                suite: chosen_suite0,
                status: FsCreatedStatus::Ok,
                server_eph_pub: s0_pub,
                transcript_hash: t0,
                auth_tag: auth_tag0,
            };
            node.write_all(&created0.encode())
                .await
                .expect("sim: write created0");
            node.flush().await.expect("sim: flush created0");

            // === HOP 1 HANDSHAKE ===
            let extend_encrypted = read_lv(&mut node).await;

            let (_next_hop, extend_inner) =
                peel_layer_v7(chosen_suite0, &extend_encrypted, &key0)
                    .expect("sim: peel extend layer 0");

            let (extend, _) = FsExtendFrame::decode(&extend_inner)
                .expect("sim: FsExtendFrame decode");
            assert_eq!(extend.chain_position, 1, "extend must target position 1");

            let chosen_suite1 = *extend.client_suites.first().expect("sim: extend no suites");

            let s1 = EphemeralSecret::random_from_rng(OsRng);
            let (key1, s1_pub, t1, auth_tag1) = peel_onion_fs_layer(
                s1,
                &node_kp_1,
                &extend.client_eph_pub,
                1,
                &extend.prev_transcript,
                node_id_1,
                chosen_suite1,
            );

            let created1 = FsCreatedFrame {
                chain_position: 1,
                suite: chosen_suite1,
                status: FsCreatedStatus::Ok,
                server_eph_pub: s1_pub,
                transcript_hash: t1,
                auth_tag: auth_tag1,
            };
            node.write_all(&created1.encode())
                .await
                .expect("sim: write created1");
            node.flush().await.expect("sim: flush created1");

            // === DATA PHASE ===
            // Forward data = single EXIT-layer wrap (exit-terminal encryption,
            // NOT a multi-layer onion). The entry hop pipes transparently; only
            // the exit peels its one layer, with `peel_reply_layer_v7` (the
            // inverse of the client's `wrap_reply_layer_v7`). This sim collapses
            // both hops into one stream, so peel ONCE with the exit key (key1) —
            // mirrors the real exit (exit/onion_fs.rs::peel_reply_layer_v7).
            let data_frame = read_lv(&mut node).await;

            let plaintext = peel_reply_layer_v7(chosen_suite1, &key1, &data_frame)
                .expect("sim: peel user-data (single exit layer)");
            let _ = chosen_suite0; // entry hop is transparent for forward data
            let _ = &key0;

            assert_eq!(
                plaintext.as_slice(),
                initial_data,
                "sim: recovered user-data must match what client sent"
            );

            // === REPLY ===
            let r1 = wrap_reply_layer_v7(chosen_suite1, &key1, reply_payload)
                .expect("sim: wrap reply layer 1");
            let r1_framed = {
                let mut v = (r1.len() as u32).to_be_bytes().to_vec();
                v.extend_from_slice(&r1);
                v
            };
            let r0 = wrap_reply_layer_v7(chosen_suite0, &key0, &r1_framed)
                .expect("sim: wrap reply layer 0");

            let len_be = (r0.len() as u32).to_be_bytes();
            node.write_all(&len_be).await.expect("sim: write reply len");
            node.write_all(&r0).await.expect("sim: write reply body");
            node.flush().await.expect("sim: flush reply");

            // Verify auth tags are non-zero (sanity check — real keys were used).
            assert_ne!(auth_tag0, [0u8; 32], "auth_tag0 must be non-zero");
            assert_ne!(auth_tag1, [0u8; 32], "auth_tag1 must be non-zero");
            assert_ne!(auth_tag0, auth_tag1, "auth tags must differ per hop");

            (key0, key1)
        });

        // ── Client side ───────────────────────────────────────────────────────
        let fake_addr: std::net::SocketAddr = "127.0.0.1:19000".parse().unwrap();

        let mut tunnel = OnionFsTunnel::connect_with_stream(
            Box::new(client_end),
            fake_addr,
            &chain,
            initial_data,
            mesh_id,
            vec![suite],
            &[], // no peer suite prefs → defaults to [ChaCha, Aes256, Aes128]
            0,
        )
        .await
        .expect("connect_with_stream must succeed — full 2-hop FS handshake with ntor auth");

        // (a) Handshake completed → we have an established OnionFsTunnel.
        assert_eq!(
            tunnel.session.layer_keys.len(),
            2,
            "session must hold 2 layer keys after 2-hop setup"
        );

        // (c) Read the reply the simulator sent.
        let mut recv_buf = [0u8; 256];
        let n = tunnel.recv(&mut recv_buf).await.expect("recv must succeed");
        assert_eq!(
            &recv_buf[..n],
            reply_payload,
            "reply round-trip: unwrapped payload must match simulator's reply"
        );

        // Await the simulator task to surface any assertion failures from its side.
        let (_k0, _k1) = sim_handle.await.expect("simulator task must not panic");
    }
}

#[cfg(test)]
mod selector_digest_tests {
    use super::*;

    /// The digest the client prints and the one the HOP prints must be the
    /// same eight characters, or the two log lines stop joining and the
    /// diagnosis this exists for quietly goes away — with both sides still
    /// looking correct on their own.
    ///
    /// `mirage2node`'s `chain_splice::selector_hash` pins this same vector.
    /// If either spelling drifts, one of the two tests fails; a shared
    /// constant in a shared crate would be better and is worth doing when
    /// something else needs to move.
    const JOIN_VECTOR_SELECTOR: &[u8] = b"auto-deadbeef-h1";
    const JOIN_VECTOR_DIGEST: &str = "40cb86a3";

    #[test]
    fn the_join_digest_matches_the_hop_side_spelling() {
        assert_eq!(selector_digest(JOIN_VECTOR_SELECTOR), JOIN_VECTOR_DIGEST);
    }

    /// A hop with a minted token is addressed by the token; one without falls
    /// back to the derived name. The digest follows whichever was used, so an
    /// operator joining on it sees the same hop either way.
    #[test]
    fn the_selector_follows_the_token_when_there_is_one() {
        let derived = selector_for_hop("auto-deadbeef", 1, &[]);
        assert_eq!(derived, b"auto-deadbeef-h1".to_vec());

        let token = vec![0xABu8; 16];
        let with_token = selector_for_hop("auto-deadbeef", 1, &token);
        assert_eq!(with_token, token);
        assert_ne!(selector_digest(&with_token), selector_digest(&derived));
    }
}
