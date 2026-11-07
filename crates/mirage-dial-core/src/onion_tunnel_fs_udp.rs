//! Client-side V9-FS forward-secret onion tunnel — DATAGRAM carriage.
//!
//! U5 design doc: `docs/mirage/plans/u5-datagram-telescopic-design-2026-09-09.md`,
//! Slice 3. Builds on Slice 1 (`FS_CHAIN_HELLO_FLAG`, `is_fs_chain_hello`,
//! `build_face_hello_bytes` — `mirage-protocol`). The node-side handlers
//! (Slice 4) do not exist yet; nothing here dials past `hops[0]`.
//!
//! The telescopic exchange itself — ntor key agreement per hop, transcript
//! chaining, key-confirmation auth tag, suite negotiation — is IDENTICAL to
//! the stream twin ([`crate::onion_tunnel_fs::OnionFsTunnel`]): the exchange
//! is transport-neutral (design decision (A)). This module reuses
//! [`crate::onion_tunnel_fs::encrypt_extend_through_layers`] UNMODIFIED (the
//! ONE function the design names for reuse — visibility bumped from private
//! to `pub(crate)`, nothing else about it changed) and adapts the stream
//! twin's suite-negotiation, address-resolution, pubkey-decode and
//! selector-digest helpers, which needed the same visibility bump but no
//! behavioural change since they were already transport-neutral (none of
//! them touch a stream or a socket). Only the CARRIAGE differs, in three
//! ways:
//!
//! 1. **One frame per datagram, no `[4B len]` wrapper.** A UDP datagram IS
//!    the frame boundary — `FsInitFrame` / `FsExtendFrame` / `FsCreatedFrame`
//!    decode from a whole received datagram directly, with no incremental
//!    reader needed (unlike the stream twin, which must first read a length
//!    prefix to know how much more to read).
//! 2. **The classifier-token hello rides its own datagram, sent once, before
//!    the telescopic loop.** The entry hop's perimeter fronts every chain
//!    face with a shape classifier that will not admit a `(face_port, peer)`
//!    flow until it has seen [`CLIENT_HELLO_LEN`] bytes that parse as a
//!    `V9ClientHello` — the same reason the stream twin writes
//!    `write_face_hello` before its own telescopic loop. Here the hello is a
//!    THROWAWAY classifier token: [`FS_CHAIN_HELLO_FLAG`] is set and its
//!    content is never parsed, because the datagram plane runs no real V9
//!    handshake for a chain session (design decision (A)) — a raw
//!    `FsInitFrame` follows as a SEPARATE datagram right after it.
//! 3. **The retransmit unit is the (hello, frame) pair — but only at step
//!    0.** Nothing acknowledges the classifier hello on its own, so a lost
//!    hello is indistinguishable, from this side, from a lost `FsInitFrame`:
//!    either one means the flow was never admitted and no `FsCreatedFrame`
//!    will ever arrive, so step 0's retry resends both (mirroring the
//!    design doc's Q1: "the client's retry unit is therefore the pair, not
//!    the frame"). Steps `1..N` do NOT resend the hello: by then the
//!    `(face_port, peer)` flow is already admitted — every setup frame for a
//!    session travels over the SAME bound [`UdpPeerSocket`], because the
//!    client never dials hop `i > 0` directly (the relay chain does that on
//!    the client's behalf; see the design doc's Q2/Q3) — and a stray extra
//!    hello datagram arriving mid-session would not be recognised as one:
//!    the far side is past admission and reading its NEXT expected frame,
//!    not re-running its shape classifier, so a redundant hello there risks
//!    being read as garbage in place of the real retry rather than being
//!    silently ignored.
//!
//! # Reply path
//!
//! [`Tunnel::recv`] reads one datagram and peels it with
//! [`OnionFsSession::unwrap_reply`] directly — no `[4B len]` read loop first
//! (unlike the stream twin's `recv`, which needs one because TCP has no
//! message boundary of its own). [`Tunnel::send`] wraps outbound data with
//! the exit-layer key only (`wrap_reply_layer_v7`, single layer — forward
//! data is never onion-wrapped, only the reply path is) and sends it as one
//! datagram, again with no length prefix.
//!
//! # The size guard — why it has to run at every hop, not once
//!
//! Above [`SAFE_UDP_HANDSHAKE_PAYLOAD_LEN`], IP fragmentation becomes
//! possible and a lost fragment degrades the datagram to silently absent,
//! not corrupted — "torn" reduces to "lost" (design doc Q1). Each already-
//! established layer adds one AEAD nonce+tag to every frame sent to a hop
//! further out (`encrypt_extend_through_layers` wraps hop `i`'s
//! `FsExtendFrame` through `i` layers), so the wrapped size is a runtime
//! function of `chain_position`, which has no compile-time ceiling in this
//! workspace. [`guard_step_frame_size`] is therefore evaluated fresh on the
//! actual encoded bytes at every hop of the extend loop, not once at the
//! top — see its own doc for the alternative this rules out.
//!
//! # What this module does NOT do
//!
//! It never dials a hop past `hops[0]`. The client's [`UdpPeerSocket`] is
//! bound once, to the entry hop's face, for the tunnel's entire life —
//! exactly the stream twin's "one TCP connection to hop0" shape, translated
//! to "one UDP 4-tuple to hop0's face". Reaching hop `i > 0` is the relay
//! chain's job (design doc Slice 4, node-side — not this crate, and not yet
//! built).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use mirage_core::{config::ChainConfig, crypto::AeadSuite, error::MirageError};
use mirage_protocol::auth::v9::build_face_hello_bytes;
use mirage_protocol::core::udp_handshake::{FS_CHAIN_HELLO_FLAG, SAFE_UDP_HANDSHAKE_PAYLOAD_LEN};
use mirage_protocol::driver::ClientCredential;
use mirage_protocol::onion::{
    builder::{
        compute_fs_auth_tag, compute_fs_transcript_base, derive_layer_key_v9_fs,
        extend_fs_transcript, OnionFsSession, PeerSuitePreference,
    },
    fs_frame::{FsCreatedFrame, FsExtendFrame, FsInitFrame},
    layer::wrap_reply_layer_v7,
};
use mirage_protocol::traits::{TransportInfo, Tunnel};
use mirage_protocol::transport::udp::UdpPeerSocket;
use rand::rngs::OsRng;
use tracing::{debug, warn};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::onion_tunnel_fs::{
    compute_chosen_suites_fs, decode_hex_pubkey_fs, encrypt_extend_through_layers,
    hop_selector_token, resolve_hop_addr_fs, selector_digest, selector_for_hop,
};

// ─────────────────────────────────────────────────────────────────────────────
// Retransmit bounds — named siblings of udp_handshake's own constants
// ─────────────────────────────────────────────────────────────────────────────

/// Base per-step wait for a `FsCreatedFrame` before retransmitting this
/// step's (hello, frame) pair (step 0) or frame alone (steps `1..N`). The
/// actual wait is this multiplied by the hop's distance — see the call site.
///
/// # Why this is not `CLIENT_HELLO_RETRANSMIT_TIMEOUT`'s 500ms
///
/// It started as a named sibling of that constant, on the reasoning that one
/// datagram round trip is one datagram round trip. That is true for the
/// single-hop handshake it was borrowed from, and false here: a step's answer
/// crosses every relay in between, and each of those relays does its own
/// bounded retransmit of its own next-hop dial. A relay leg is budgeted at
/// three attempts on a 500ms cadence (`dial_next_hop`, mirage2node), so one
/// leg can legitimately take 1.5s before it either answers or gives up.
///
/// Sized off the relay leg it contains, not guessed. A relay leg is three
/// attempts on a 1300ms cadence (`dial_next_hop`, mirage2node) because the
/// receiving perimeter drains a refused session for a full second and a
/// faster retry spends every attempt inside that window — so one leg costs
/// up to 3.9s. 4200ms leaves that plus a real round trip, and a step's wait
/// is `4200ms * (hop_index + 1)` so it covers every leg its answer crosses.
///
/// Measured 2026-09-09, twice, in the same afternoon: at 500ms the client
/// abandoned a 3-hop step in 1.5s while the middle relay was still resending,
/// and at 1500ms it still gave up before a leg that had to wait out a drain
/// window could finish. An outer bound below the inner one it contains does
/// not detect failure, it manufactures it — and I wrote that sentence once
/// already before making the same mistake with a different number.
///
/// `pub(crate)`: `tunnel.rs`'s multi-hop dispatch (`establish_udp_datagram_tunnel`,
/// U5 Slice 7) reads this to size its own outer per-chain timeout off the
/// SAME bound this loop actually retries against, rather than duplicating an
/// unrelated guess.
pub(crate) const FS_STEP_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(4200);

/// Named sibling of `CLIENT_HELLO_MAX_RETRANSMITS` — identical value and
/// Bounds ONE hop's worst-case wall-clock cost to
/// `FS_STEP_RETRANSMIT_TIMEOUT * (FS_STEP_MAX_RETRANSMITS + 1)` against an
/// unreachable or silently dropping hop, instead of retrying forever.
///
/// # Why two and not five
///
/// It was five, copied from the single-hop handshake where the client is the
/// only thing retransmitting anything. On a chain it is not: every relay
/// retries its own next-hop dial, so client retries multiply against relay
/// retries instead of adding to them. With the current leg budget, five
/// client attempts at the deepest step of a 4-hop chain came to about a
/// hundred seconds of worst case — a bound nobody waits out, which makes it
/// a bound that never gets tested and therefore never gets trusted.
///
/// Two keeps a genuine second chance for a loss on the FIRST leg, which is
/// the only one no relay is retrying on the client's behalf, and lets the
/// per-leg retries own everything deeper.
///
/// `pub(crate)`: see `FS_STEP_RETRANSMIT_TIMEOUT`'s doc for why `tunnel.rs`
/// reads this too.
pub(crate) const FS_STEP_MAX_RETRANSMITS: u32 = 2;

/// Refuse a per-hop FS setup frame that would not fit inside one
/// unfragmented UDP datagram, by name, instead of sending it and losing it
/// to IP fragmentation.
///
/// Why this can't be a compile-time check: the encoded size is a function of
/// `chain_position` (each already-established layer adds one AEAD
/// nonce+tag), and `chain_position` has no compile-time ceiling in this
/// workspace. Why it can't be skipped: above the safe ceiling, "torn"
/// reduces to "lost" (design doc Q1) — this call's own bounded retransmit
/// loop would then spend its whole budget resending a frame that could
/// never fit no matter how many times it is sent.
fn guard_step_frame_size(hop_index: usize, wire_bytes: &[u8]) -> Result<(), MirageError> {
    if wire_bytes.len() > SAFE_UDP_HANDSHAKE_PAYLOAD_LEN {
        return Err(MirageError::Protocol(format!(
            "v9-fs udp: FS frame for hop {hop_index} is {} bytes, over the \
             {SAFE_UDP_HANDSHAKE_PAYLOAD_LEN}-byte datagram-safe ceiling",
            wire_bytes.len()
        )));
    }
    Ok(())
}

/// Client-side V9-FS forward-secret onion tunnel, datagram carriage.
///
/// Established by [`OnionFsUdpTunnel::connect`] via the same telescopic
/// N-round key agreement as the stream twin, one datagram per round instead
/// of one `[4B len][body]` write. See the module doc for exactly what
/// differs.
pub struct OnionFsUdpTunnel {
    socket: UdpPeerSocket,
    session: OnionFsSession,
    info: TransportInfo,
}

impl OnionFsUdpTunnel {
    /// Establish a V9-FS telescopic circuit over UDP and return the live
    /// tunnel.
    ///
    /// `hops` and per-hop preferences are taken from `chain`, identically to
    /// the stream twin. The client dials only `chain.hops[0]`'s face — see
    /// the module doc for why nothing here ever reaches a deeper hop
    /// directly.
    ///
    /// `credential` — optional anonymous credential embedded in `FsInitFrame`
    /// exactly as the stream twin embeds it. `None` sends
    /// `credential_scheme=0x00` / `credential=vec![]`.
    pub async fn connect(
        chain: &ChainConfig,
        initial_user_data: &[u8],
        mesh_id: &[u8],
        client_offered_suites: Vec<AeadSuite>,
        peer_suite_prefs: &[PeerSuitePreference],
        peer_table_generation: u64,
        credential: Option<ClientCredential>,
    ) -> Result<Self, MirageError> {
        chain.validate().map_err(|e| {
            let me = MirageError::Config(e.to_string());
            warn!(chain_id = %chain.chain_id, error = %me, "onion-fs udp connect: chain.validate() failed");
            me
        })?;

        if chain.hops.is_empty() {
            return Err(MirageError::Config(format!(
                "v9-fs udp: chain {} hops is empty",
                chain.chain_id
            )));
        }
        if client_offered_suites.is_empty() {
            return Err(MirageError::Config(
                "v9-fs udp: client_offered_suites is empty".into(),
            ));
        }

        let hop0 = &chain.hops[0];
        let hop0_addr = resolve_hop_addr_fs(hop0).await.map_err(|e| {
            warn!(
                chain_id = %chain.chain_id,
                hop0_addr = %hop0.addr,
                error = %e,
                "onion-fs udp connect: resolve_hop_addr_fs failed"
            );
            e
        })?;
        debug!(
            hop0 = %hop0_addr,
            hops = chain.hops.len(),
            chain_id = %chain.chain_id,
            "onion-fs udp v9: connecting to entry hop face"
        );

        // ── Bind the ONE UDP flow this whole session ever uses ───────────
        //
        // No camouflage wrap and no byte_cipher skin here (unlike the stream
        // twin's TCP connect): the UDP camouflage variants' `connect_client`
        // wiring for the relay's OUTBOUND leg is design doc Slice 6, deferred
        // and independent of this slice; the client's own leg to hop0's face
        // rides raw UDP for now.
        let socket = UdpPeerSocket::bind_client(hop0_addr).await.map_err(|e| {
            warn!(chain_id = %chain.chain_id, hop0_addr = %hop0_addr, error = %e, "onion-fs udp connect: bind_client failed");
            e
        })?;

        // ── The classifier-token hello — built once, sent at step 0 only ──
        //
        // See the module doc, point 2. `build_face_hello_bytes` is the exact
        // same construction the stream twin's `write_face_hello` writes;
        // here the bytes are handed to `UdpPeerSocket::send` directly rather
        // than to `AsyncWrite::write_all`, and bit 6 of byte 92 is set so
        // the entry's classifier recognises this as a throwaway token rather
        // than attempting the real V9 handshake.
        let mut hello = build_face_hello_bytes();
        hello[92] |= FS_CHAIN_HELLO_FLAG;

        let chosen_suites = compute_chosen_suites_fs(
            &chain.hops,
            &client_offered_suites,
            peer_suite_prefs,
            &chain.chain_id,
        )?;

        let mut layer_keys: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut layer_aead_suites: Vec<AeadSuite> = Vec::with_capacity(chain.hops.len());
        let mut client_eph_pubs: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut server_eph_pubs: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());
        let mut transcripts: Vec<[u8; 32]> = Vec::with_capacity(chain.hops.len());

        let mut prev_transcript = compute_fs_transcript_base(mesh_id, chain.chain_id.as_bytes());

        for i in 0..chain.hops.len() {
            let hop = &chain.hops[i];
            let suite = chosen_suites[i];

            let hop_static_pub = hop
                .public_key
                .as_deref()
                .ok_or_else(|| {
                    warn!(chain_id = %chain.chain_id, hop = i, "onion-fs udp: hop missing certified static pubkey");
                    MirageError::Protocol(format!(
                        "v9-fs udp: hop[{i}] missing certified node static pubkey (FS onion requires authenticated hops)"
                    ))
                })
                .and_then(decode_hex_pubkey_fs)?;

            // Throwaway per-dial StaticSecret so we can do two DHs from the
            // same key (ee + es), identical to the stream twin.
            let client_eph = StaticSecret::random_from_rng(OsRng);
            let client_eph_pub = PublicKey::from(&client_eph).to_bytes();

            let wire_bytes = if i == 0 {
                if hop.node_id.as_deref().or(hop.display_name.as_deref()).is_none() {
                    return Err(MirageError::Config(format!(
                        "v9-fs udp: chain {} hop[0] requires node_id",
                        chain.chain_id
                    )));
                }
                let (cred_scheme, cred_bytes) = match &credential {
                    Some(c) => (c.scheme, c.token.clone()),
                    None => (0x00, vec![]),
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
                    warn!(chain_id = %chain.chain_id, error = %e, "onion-fs udp: FsInitFrame encode failed");
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
                    warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs udp: FsExtendFrame encode failed");
                    e
                })?;
                encrypt_extend_through_layers(&extend_bytes, &layer_keys[..i], &layer_aead_suites[..i])?
            };

            guard_step_frame_size(i, &wire_bytes)?;

            // ── Bounded retransmit of the (hello, frame) pair ────────────
            //
            // See the module doc, point 3: the hello is only meaningful (and
            // only resent) at step 0, since that is the one step admitting
            // the (face_port, peer) flow at all.
            let mut retransmits = 0u32;
            let created: FsCreatedFrame = loop {
                if i == 0 {
                    socket.send(&hello).await.map_err(|e| {
                        warn!(chain_id = %chain.chain_id, error = %e, "onion-fs udp: send classifier hello failed");
                        e
                    })?;
                }
                socket.send(&wire_bytes).await.map_err(|e| {
                    warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs udp: send FS frame failed");
                    e
                })?;
                debug!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    frame_len = wire_bytes.len(),
                    retransmits,
                    "onion-fs udp: frame sent, awaiting FsCreatedFrame"
                );

                // Sized to the safe ceiling rather than exactly
                // FsCreatedFrame::ENCODED_LEN: reading into an exactly-sized
                // buffer would silently truncate a larger, malformed reply to
                // the expected length and let it pass the length check below
                // by accident.
                let mut reply_buf = [0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
                // The wait scales with how far away the answering hop is.
                //
                // A flat 500ms is right for hop 0, which is one round trip
                // away, and wrong for every hop after it: hop `i`'s
                // `FsCreated` travels back through `i` intermediate relays,
                // so the client is waiting on `i + 1` round trips plus each
                // relay's own forwarding. Measured on a lab mesh: a 3-hop chain
                // completes in 1.8-2.0s end to end, which already exceeds a
                // flat per-step 500ms at the deepest step — and a 4-hop dial
                // failed at hop[1] on one attempt and hop[2] on the next,
                // the signature of a bound that is racing distance rather
                // than detecting loss.
                //
                // `i + 1` multiples of the base, so hop 0 keeps exactly the
                // bound it always had and each further hop gets one more
                // round trip's worth. Depth is not named anywhere: the
                // factor comes from the hop's own index, so this scales to
                // whatever N the caller asked for.
                let step_timeout = FS_STEP_RETRANSMIT_TIMEOUT * (i as u32 + 1);
                let recv_result =
                    tokio::time::timeout(step_timeout, socket.recv(&mut reply_buf)).await;

                match recv_result {
                    Ok(Ok(n)) if n == FsCreatedFrame::ENCODED_LEN => {
                        break FsCreatedFrame::decode(&reply_buf[..n]).map_err(|e| {
                            warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs udp: FsCreatedFrame decode failed");
                            e
                        })?;
                    }
                    Ok(Ok(n)) => {
                        return Err(MirageError::Protocol(format!(
                            "v9-fs udp hop[{i}]: FsCreatedFrame datagram had unexpected length {n} \
                             (expected {})",
                            FsCreatedFrame::ENCODED_LEN
                        )));
                    }
                    Ok(Err(e)) => {
                        warn!(chain_id = %chain.chain_id, hop = i, error = %e, "onion-fs udp: recv failed");
                        return Err(e);
                    }
                    Err(_elapsed) => {
                        retransmits += 1;
                        if retransmits > FS_STEP_MAX_RETRANSMITS {
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
                                "onion-fs udp: FsCreatedFrame not received after \
                                 {FS_STEP_MAX_RETRANSMITS} retransmits — the hop wrote no reply; grep \
                                 its journal for this selector_hash to read the cause it recorded"
                            );
                            return Err(MirageError::HandshakeTimedOut(format!(
                                "v9-fs udp hop[{i}] ({node}): no FsCreated after {FS_STEP_MAX_RETRANSMITS} \
                                 retransmits ({step_timeout:?} each, scaled by this hop's distance) — the hop wrote no \
                                 reply, by design; its own log has the cause under selector_hash={digest}"
                            )));
                        }
                        continue;
                    }
                }
            };

            if !created.status.is_ok() {
                warn!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    status = created.status.name(),
                    code = created.status.as_u32(),
                    "onion-fs udp: hop rejected FS handshake"
                );
                return Err(MirageError::Protocol(format!(
                    "v9-fs udp hop[{i}]: {} (code {})",
                    created.status.name(),
                    created.status.as_u32()
                )));
            }
            if created.chain_position as usize != i {
                return Err(MirageError::Protocol(format!(
                    "v9-fs udp hop[{i}]: FsCreatedFrame.chain_position={} (expected {i})",
                    created.chain_position
                )));
            }
            if created.suite != suite {
                return Err(MirageError::Protocol(format!(
                    "v9-fs udp hop[{i}]: server suite {:?} does not match expected {:?}",
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
                warn!(chain_id = %chain.chain_id, hop = i, "onion-fs udp: transcript hash mismatch");
                return Err(MirageError::Protocol(format!(
                    "v9-fs udp hop[{i}]: transcript hash mismatch"
                )));
            }

            let ee = Zeroizing::new(
                client_eph.diffie_hellman(&PublicKey::from(created.server_eph_pub)).to_bytes(),
            );
            let es = Zeroizing::new(
                client_eph.diffie_hellman(&PublicKey::from(hop_static_pub)).to_bytes(),
            );
            let key_i = derive_layer_key_v9_fs(&ee, &es, i as u8, &transcript_i, suite);

            let expected_auth = compute_fs_auth_tag(&key_i, &transcript_i, &created.server_eph_pub);
            if created.auth_tag != expected_auth {
                warn!(
                    chain_id = %chain.chain_id,
                    hop = i,
                    "onion-fs udp: auth_tag mismatch — possible on-path party or wrong node identity"
                );
                return Err(MirageError::Protocol(format!(
                    "v9-fs udp hop[{i}]: key-confirmation auth_tag mismatch (possible on-path party / wrong node identity)"
                )));
            }

            debug!(chain_id = %chain.chain_id, hop = i, suite = ?suite, "onion-fs udp: hop established, key derived");

            layer_keys.push(key_i);
            layer_aead_suites.push(suite);
            client_eph_pubs.push(client_eph_pub);
            server_eph_pubs.push(created.server_eph_pub);
            transcripts.push(transcript_i);
            prev_transcript = transcript_i;
        }

        debug!(chain_id = %chain.chain_id, hops = chain.hops.len(), "onion-fs udp: all hops established");

        // ── Initial user_data — single exit-layer wrap, one raw datagram ──
        //
        // Same forward convention as `send()` below: forward data is
        // exit-terminal encryption, never a multi-layer onion. No length
        // prefix, unlike the stream twin — the datagram is the boundary.
        if !initial_user_data.is_empty() {
            let n = layer_keys.len();
            let wrapped = wrap_reply_layer_v7(layer_aead_suites[n - 1], &layer_keys[n - 1], initial_user_data)?;
            socket.send(&wrapped).await.map_err(|e| {
                warn!(chain_id = %chain.chain_id, error = %e, "onion-fs udp: send initial user_data failed");
                e
            })?;
        }

        let info = TransportInfo::udp_raw(hop0_addr);
        let session = OnionFsSession {
            layer_keys,
            layer_aead_suites,
            client_eph_pubs,
            server_eph_pubs,
            transcripts,
        };

        Ok(OnionFsUdpTunnel { socket, session, info })
    }

    /// Split this tunnel into an owned send half and an owned receive half.
    ///
    /// Same motivation as `MirageCoreUdpTunnel::into_split`
    /// (`mirage-protocol/src/core/udp_tunnel.rs`) — this crate's own
    /// `socks5.rs::run_datagram_udp_session` needs to write from its main
    /// loop while a spawned task reads concurrently, and `send`/`recv` both
    /// take `&mut self`, so a single un-split tunnel cannot do both at once
    /// without a `Mutex` around the whole thing. This avoids that lock
    /// entirely, following the same pattern:
    ///
    /// - `socket` moves behind an `Arc` shared by both halves — safe to call
    ///   concurrently because [`UdpPeerSocket::send`]/[`UdpPeerSocket::recv`]
    ///   take `&self`, not `&mut self`.
    /// - Forward data (`send`, see its own doc) only ever reads the EXIT
    ///   layer — `session.layer_keys[n-1]` / `layer_aead_suites[n-1]` — so
    ///   the send half copies out just that one key and suite rather than
    ///   the whole `OnionFsSession`.
    /// - Reply data (`recv`) has to peel every layer in order
    ///   (`OnionFsSession::unwrap_reply` walks `layer_keys[0..n]`), so the
    ///   receive half keeps the entire session, plus `info` (nothing else
    ///   has an ongoing reason to report who the tunnel talks to).
    ///
    /// `OnionFsSession::unwrap_reply` takes `&self`, not `&mut self` — the
    /// reply-side state (all N layer keys) is read-only after `connect`
    /// returns, with no counter or window that the two directions could
    /// race on. That is what makes this split sound: there is no field
    /// either half would need to mutate that the OTHER half also reads, so
    /// nothing here stands in for the `Mutex` this method exists to avoid.
    pub fn into_split(self) -> (OnionFsUdpTunnelSender, OnionFsUdpTunnelReceiver) {
        let socket = Arc::new(self.socket);
        let n = self.session.layer_keys.len();
        // `n == 0` cannot happen from a tunnel `connect` actually built —
        // `connect` refuses an empty `chain.hops` before the loop that
        // pushes exactly one layer key per hop — but `Tunnel::send` above
        // guards the identical case explicitly rather than assume the
        // invariant, and an `n - 1` index here without the same guard would
        // be exactly the underflow that discipline exists to rule out.
        let exit_layer = if n == 0 {
            None
        } else {
            Some((self.session.layer_keys[n - 1], self.session.layer_aead_suites[n - 1]))
        };
        let sender = OnionFsUdpTunnelSender { socket: Arc::clone(&socket), exit_layer };
        let receiver = OnionFsUdpTunnelReceiver {
            socket,
            session: self.session,
            info: self.info,
        };
        (sender, receiver)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OnionFsUdpTunnelSender / OnionFsUdpTunnelReceiver — owned halves from
// `into_split`
// ─────────────────────────────────────────────────────────────────────────────

/// Owned send half of an [`OnionFsUdpTunnel`], produced by
/// [`OnionFsUdpTunnel::into_split`].
///
/// Carries only the exit-layer key and suite — see `into_split`'s own doc
/// for why forward data never needs the rest of the session.
pub struct OnionFsUdpTunnelSender {
    socket: Arc<UdpPeerSocket>,
    /// `None` only for a zero-hop tunnel, which `OnionFsUdpTunnel::connect`
    /// never actually produces (see `into_split`'s own doc) — kept as an
    /// `Option` rather than indexed unconditionally so this mirrors
    /// `Tunnel::send`'s own `n == 0` guard instead of assuming the
    /// invariant a second time.
    exit_layer: Option<([u8; 32], AeadSuite)>,
}

impl OnionFsUdpTunnelSender {
    /// Send one whole UDP datagram. Identical wire behaviour to
    /// [`Tunnel::send`] on the un-split tunnel — same single exit-layer
    /// wrap, same "no length prefix, the datagram is the boundary" framing,
    /// same raw fallback when there is no exit layer.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        match self.exit_layer {
            Some((key, suite)) => {
                let wrapped = wrap_reply_layer_v7(suite, &key, data)?;
                self.socket.send(&wrapped).await?;
            }
            None => {
                self.socket.send(data).await?;
            }
        }
        Ok(())
    }
}

/// Owned receive half of an [`OnionFsUdpTunnel`], produced by
/// [`OnionFsUdpTunnel::into_split`].
///
/// Carries the entire [`OnionFsSession`] (every layer key is needed to peel
/// a reply in order) plus the tunnel's [`TransportInfo`] — see
/// `into_split`'s own doc for why the receive half, not the send half,
/// keeps `info`.
pub struct OnionFsUdpTunnelReceiver {
    socket: Arc<UdpPeerSocket>,
    session: OnionFsSession,
    info: TransportInfo,
}

impl OnionFsUdpTunnelReceiver {
    /// Receive one whole, decrypted, authenticated reply datagram. Identical
    /// framing and layer-peeling to [`Tunnel::recv`] on the un-split tunnel
    /// — same [`OnionFsSession::unwrap_reply`] call, same "no `[4B len]`
    /// read loop first" reasoning (the datagram already is the message
    /// boundary).
    ///
    /// Returns the decrypted payload as an owned `Vec<u8>` rather than
    /// filling a caller-supplied buffer — the truncation-proof shape
    /// [`MirageCoreUdpTunnel::recv_datagram`] uses, and the shape
    /// `run_datagram_udp_session`'s read loop already drives against that
    /// type's own [`UdpTunnelReceiver::recv_datagram`]; giving this half the
    /// identical method name and signature lets one dispatch enum wrap both.
    ///
    /// A zero-length datagram (`n == 0`) is returned as `Ok(Vec::new())`
    /// rather than attempted as an AEAD-framed reply — mirrors
    /// [`MirageCoreUdpTunnel::recv_datagram`]'s own "no closed state" rule:
    /// this tunnel type has nothing that end-of-stream could mean.
    ///
    /// [`MirageCoreUdpTunnel::recv_datagram`]: mirage_protocol::core::MirageCoreUdpTunnel::recv_datagram
    /// [`UdpTunnelReceiver::recv_datagram`]: mirage_protocol::core::UdpTunnelReceiver::recv_datagram
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        let mut tmp = vec![0u8; crate::udp_framing::MAX_UDP_DATAGRAM];
        let n = self.socket.recv(&mut tmp).await?;
        if n == 0 {
            return Ok(Vec::new());
        }
        match self.session.unwrap_reply(&tmp[..n]) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => {
                let preview_len = n.min(16);
                let preview: Vec<String> =
                    tmp[..preview_len].iter().map(|b| format!("{b:02x}")).collect();
                warn!(
                    error = %e,
                    frame_len = n,
                    wire_preview = %preview.join(" "),
                    "v9-fs udp (split receiver): unwrap_reply failed"
                );
                Err(e)
            }
        }
    }

    /// The tunnel's transport metadata (remote address, protocol ids,
    /// established-at instant) — see [`TransportInfo`].
    pub fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}

impl OnionFsUdpTunnel {
    /// Receive one whole, decrypted, authenticated reply datagram, WITHOUT
    /// splitting first.
    ///
    /// Same peeling as [`OnionFsUdpTunnelReceiver::recv_datagram`] — one
    /// `unwrap_reply`, no `[4B len]` loop, a zero-length datagram returned as
    /// an empty payload rather than attempted as an AEAD frame.
    ///
    /// Why it exists: `MirageCoreUdpTunnel` carries `recv_datagram` on the
    /// tunnel ITSELF as well as on its split half, and this type only had it
    /// on the half. A dispatch enum over the two therefore could not offer
    /// the method at all, so a caller that never splits — a probe doing one
    /// send and one receive — was forced to split just to read a datagram,
    /// or to fall back to `Tunnel::recv`, which fills a caller's buffer and
    /// can report a partial read on a plane where one datagram is one whole
    /// message. The asymmetry was the defect; this removes it.
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        let mut tmp = vec![0u8; crate::udp_framing::MAX_UDP_DATAGRAM];
        let n = self.socket.recv(&mut tmp).await?;
        if n == 0 {
            return Ok(Vec::new());
        }
        match self.session.unwrap_reply(&tmp[..n]) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => {
                let preview_len = n.min(16);
                let preview: Vec<String> =
                    tmp[..preview_len].iter().map(|b| format!("{b:02x}")).collect();
                warn!(
                    error = %e,
                    frame_len = n,
                    wire_preview = %preview.join(" "),
                    "v9-fs udp: unwrap_reply failed"
                );
                Err(e)
            }
        }
    }
}

// ── Tunnel trait implementation ───────────────────────────────────────────────

#[async_trait]
impl Tunnel for OnionFsUdpTunnel {
    /// Forward data is wrapped with the EXIT layer key ONLY (single layer,
    /// `wrap_reply_layer_v7`) and sent as one raw datagram — no length
    /// prefix, unlike the stream twin, because the datagram already marks
    /// where this frame ends. Intermediate hops forward the bytes
    /// transparently; only the exit peels this one layer.
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        let n = self.session.layer_keys.len();
        if n == 0 {
            self.socket.send(data).await?;
            return Ok(());
        }
        let exit_key = self.session.layer_keys[n - 1];
        let exit_suite = self.session.layer_aead_suites[n - 1];
        let wrapped = wrap_reply_layer_v7(exit_suite, &exit_key, data)?;
        self.socket.send(&wrapped).await?;
        Ok(())
    }

    /// Reads exactly one reply datagram and peels all N reply layers with
    /// [`OnionFsSession::unwrap_reply`] directly — no `[4B len]` read loop
    /// first (the datagram already is the message boundary; see the module
    /// doc).
    ///
    /// If `buf` is smaller than the recovered plaintext, the excess bytes
    /// are discarded rather than queued for a later call — matching
    /// `UdpPeerSocket::recv`'s own truncation contract. A UDP datagram's
    /// reply is exactly one caller-sized read; there is no continuous
    /// stream to queue against, unlike the stream twin's `recv`, which keeps
    /// a `plaintext_buf` because more than one reply chunk can already be
    /// sitting in its length-framed byte stream.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        let mut tmp = vec![0u8; crate::udp_framing::MAX_UDP_DATAGRAM];
        let n = self.socket.recv(&mut tmp).await?;
        if n == 0 {
            return Ok(0);
        }
        match self.session.unwrap_reply(&tmp[..n]) {
            Ok(plaintext) => {
                let copy_len = plaintext.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&plaintext[..copy_len]);
                Ok(copy_len)
            }
            Err(e) => {
                let preview_len = n.min(16);
                let preview: Vec<String> =
                    tmp[..preview_len].iter().map(|b| format!("{b:02x}")).collect();
                warn!(
                    error = %e,
                    frame_len = n,
                    wire_preview = %preview.join(" "),
                    "v9-fs udp: unwrap_reply failed"
                );
                Err(e)
            }
        }
    }

    /// A UDP socket has no shutdown handshake — nothing to flush or close
    /// beyond dropping the bound socket, which happens when this tunnel is
    /// dropped.
    async fn close(&mut self) -> Result<(), MirageError> {
        Ok(())
    }

    fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}

// ── In-memory unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_core::config::{
        CamouflageMode, ChainConfig, CoverTrafficConfig, HandshakeStrategy, HopConfig, HopRole,
        ProtocolId, ReplyMode, ShapingPreset, UdpProtocolId,
    };
    use mirage_core::crypto::KeyPair;
    use mirage_core::mirage::wire::RelayMode;
    use mirage_protocol::core::udp_handshake::is_fs_chain_hello;
    use mirage_protocol::onion::builder::peel_onion_fs_layer;
    use mirage_protocol::onion::fs_frame::FsCreatedStatus;
    use mirage_protocol::onion::layer::{peel_layer_v7, peel_reply_layer_v7};
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use x25519_dalek::EphemeralSecret;

    fn hex_encode_pub(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// Build an N-hop `ChainConfig` addressed at `entry_addr` for hop 0.
    /// Hops past 0 carry a placeholder `addr` — under design decision (A)
    /// the client never dials them directly, so the value is inert for this
    /// slice (it only matters to the relay chain's own outbound dial,
    /// Slice 4, not under test here).
    fn build_chain(chain_id: &str, entry_addr: SocketAddr, pubkeys_hex: &[String], node_ids: &[String]) -> ChainConfig {
        let n = pubkeys_hex.len();
        let hops = (0..n)
            .map(|i| {
                let role = if n == 1 {
                    HopRole::Exit
                } else if i == 0 {
                    HopRole::Entry
                } else if i == n - 1 {
                    HopRole::Exit
                } else {
                    HopRole::Middle
                };
                HopConfig {
                    addr: if i == 0 { entry_addr.to_string() } else { "127.0.0.1:1".into() },
                    public_key: Some(pubkeys_hex[i].clone()),
                    node_id: Some(node_ids[i].clone()),
                    sni: None,
                    role,
                    display_name: None,
                    camouflage: None,
                    byte_cipher: None,
                    relay_mode: RelayMode::OnionPeel,
                    camo_server_pubkey: None,
                    selector_token_hex: None,
                }
            })
            .collect();
        ChainConfig {
            chain_id: chain_id.into(),
            hops,
            handshake: HandshakeStrategy::Telescopic,
            reply: ReplyMode::Onion,
            protocol: ProtocolId::Udp(UdpProtocolId::MirageUdp),
            priority: 0,
            shaping: ShapingPreset::default(),
            camouflage: CamouflageMode::default(),
            cover_traffic: CoverTrafficConfig::default(),
            socks5_bind: None,
            aead_suite: AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        }
    }

    /// Play every hop of an N-hop FS-chain session on ONE bound UDP socket,
    /// collapsing the whole chain onto one process — the same simplification
    /// the stream twin's own `onion_fs_2hop_duplex_e2e` makes (see its doc),
    /// valid here for the identical reason: from the CLIENT's point of view
    /// there is only ever ONE peer address (hop0's face) for the whole
    /// session (design doc Q2/Q3 — the relay chain dials hop `i > 0` on the
    /// client's behalf; that dial and hop `i > 0`'s own admission handshake
    /// are Slice 4, not under test here).
    ///
    /// Returns the per-hop keys THIS side derived, so the caller can assert
    /// they equal the client's own — the actual key-agreement proof.
    ///
    /// `post_split_send_expected`, when `Some`, reads and decodes ONE more
    /// datagram after sending the reply and asserts it decodes to the given
    /// bytes under the exit layer — the same `peel_reply_layer_v7` this
    /// function already uses to decode `initial_data_expected`. This is how
    /// the `..._into_split_...` tests below prove
    /// [`super::OnionFsUdpTunnelSender::send`] wraps with the correct
    /// exit-layer key after the tunnel has been split, not merely that the
    /// call returns `Ok`.
    async fn run_fs_udp_simulator(
        sock: UdpSocket,
        node_kps: &[KeyPair],
        node_ids: &[String],
        initial_data_expected: &[u8],
        reply_payload: &[u8],
        post_split_send_expected: Option<&[u8]>,
    ) -> Vec<[u8; 32]> {
        let n = node_kps.len();
        let mut buf = vec![0u8; 4096];

        // Datagram 1: the classifier-token hello. Shape-checked only, per
        // design decision (A) — its content is never parsed.
        let (hn, client_addr) = sock.recv_from(&mut buf).await.expect("sim: recv hello");
        assert!(
            is_fs_chain_hello(&buf[..hn]),
            "sim: datagram 1 must be a shaped FS-chain classifier hello"
        );

        // Datagram 2: FsInitFrame, step 0.
        let (n0, from0) = sock.recv_from(&mut buf).await.expect("sim: recv FsInitFrame");
        assert_eq!(from0, client_addr, "sim: step 0 frame must come from the hello's own peer");
        let (init, _) = FsInitFrame::decode(&buf[..n0]).expect("sim: FsInitFrame decode");
        assert_eq!(init.chain_position, 0);

        let mut layer_keys: Vec<[u8; 32]> = Vec::with_capacity(n);
        let mut layer_suites: Vec<AeadSuite> = Vec::with_capacity(n);
        let mut prev_transcript = compute_fs_transcript_base(&init.mesh_id, &init.chain_id);
        let mut client_eph_pub = init.client_eph_pub;
        let mut suite = *init.client_suites.first().expect("sim: no suites offered");

        for i in 0..n {
            if i > 0 {
                let (nx, fromx) = sock.recv_from(&mut buf).await.expect("sim: recv extend frame");
                assert_eq!(fromx, client_addr, "sim: extend frame must come from the same peer");
                let mut current = buf[..nx].to_vec();
                for (j, key) in layer_keys.iter().enumerate().take(i) {
                    let (_next_hop, inner) =
                        peel_layer_v7(layer_suites[j], &current, key).expect("sim: peel extend layer");
                    current = inner;
                }
                let (extend, _) = FsExtendFrame::decode(&current).expect("sim: FsExtendFrame decode");
                assert_eq!(extend.chain_position as usize, i);
                client_eph_pub = extend.client_eph_pub;
                suite = *extend.client_suites.first().expect("sim: extend no suites");
                prev_transcript = extend.prev_transcript;
            }

            let s = EphemeralSecret::random_from_rng(OsRng);
            let (key, s_pub, t, auth_tag) = peel_onion_fs_layer(
                s,
                &node_kps[i],
                &client_eph_pub,
                i as u8,
                &prev_transcript,
                &node_ids[i],
                suite,
            );
            let created = FsCreatedFrame {
                chain_position: i as u8,
                suite,
                status: FsCreatedStatus::Ok,
                server_eph_pub: s_pub,
                transcript_hash: t,
                auth_tag,
            };
            sock.send_to(&created.encode(), client_addr).await.expect("sim: send FsCreatedFrame");

            layer_keys.push(key);
            layer_suites.push(suite);
            prev_transcript = t;
        }

        if !initial_data_expected.is_empty() {
            let (dn, fromd) = sock.recv_from(&mut buf).await.expect("sim: recv initial user data");
            assert_eq!(fromd, client_addr);
            let plaintext = peel_reply_layer_v7(layer_suites[n - 1], &layer_keys[n - 1], &buf[..dn])
                .expect("sim: peel initial user data (single exit layer)");
            assert_eq!(
                plaintext, initial_data_expected,
                "sim: recovered user-data must match what the client sent"
            );

            // Reply: innermost (exit) wrap first, then each outer layer wraps
            // `[4B len][inner]` around the previous result — the exact
            // convention `OnionFsSession::unwrap_reply` expects at every
            // layer boundary except the last one it peels.
            let mut current = wrap_reply_layer_v7(layer_suites[n - 1], &layer_keys[n - 1], reply_payload)
                .expect("sim: wrap reply innermost layer");
            for j in (0..n - 1).rev() {
                let mut framed = (current.len() as u32).to_be_bytes().to_vec();
                framed.extend_from_slice(&current);
                current = wrap_reply_layer_v7(layer_suites[j], &layer_keys[j], &framed)
                    .expect("sim: wrap reply outer layer");
            }
            sock.send_to(&current, client_addr).await.expect("sim: send reply");

            if let Some(expected) = post_split_send_expected {
                let (pn, fromp) = sock
                    .recv_from(&mut buf)
                    .await
                    .expect("sim: recv post-split forward datagram");
                assert_eq!(fromp, client_addr, "sim: post-split datagram must come from the same peer");
                let plaintext = peel_reply_layer_v7(layer_suites[n - 1], &layer_keys[n - 1], &buf[..pn])
                    .expect("sim: peel post-split forward datagram (exit layer)");
                assert_eq!(
                    plaintext, expected,
                    "sim: post-split forward datagram must decode to exactly what the split sender sent"
                );
            }
        }

        layer_keys
    }

    /// Drive `OnionFsUdpTunnel::connect` against a hand-rolled UDP simulator
    /// playing `n_hops` hops on one socket, and assert:
    /// (a) the handshake completes with one layer key per hop;
    /// (b) the client's and the simulator's independently-derived per-hop
    ///     keys agree — the actual key-agreement proof;
    /// (c) a reply the simulator wraps through every layer round-trips back
    ///     through `Tunnel::recv`.
    async fn assert_key_agreement_and_reply_round_trip(n_hops: usize) {
        let mesh_id = b"staging-v2";
        let chain_id = format!("c-fs-udp-{n_hops}hop");
        let node_kps: Vec<KeyPair> = (0..n_hops).map(|_| KeyPair::generate()).collect();
        let node_ids: Vec<String> = (0..n_hops).map(|i| format!("test-node-udp-{i}")).collect();
        let pubkeys_hex: Vec<String> =
            node_kps.iter().map(|kp| hex_encode_pub(&kp.public.to_bytes())).collect();
        let initial_data = b"hello from udp client";
        let reply_payload = b"reply from udp exit";

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind sim socket");
        let entry_addr = sock.local_addr().expect("sim local addr");

        let chain = build_chain(&chain_id, entry_addr, &pubkeys_hex, &node_ids);

        let sim_node_ids = node_ids.clone();
        let sim_handle = tokio::spawn(async move {
            run_fs_udp_simulator(sock, &node_kps, &sim_node_ids, initial_data, reply_payload, None).await
        });

        let mut tunnel = OnionFsUdpTunnel::connect(
            &chain,
            initial_data,
            mesh_id,
            vec![AeadSuite::ChaCha20Poly1305],
            &[], // no peer suite prefs → defaults inside compute_chosen_suites_fs
            0,
            None,
        )
        .await
        .expect("connect must succeed — full N-hop FS UDP handshake with ntor auth");

        assert_eq!(
            tunnel.session.layer_keys.len(),
            n_hops,
            "session must hold one layer key per hop"
        );

        let mut recv_buf = [0u8; 256];
        let n = tunnel.recv(&mut recv_buf).await.expect("recv must succeed");
        assert_eq!(
            &recv_buf[..n],
            reply_payload,
            "reply round-trip: unwrapped payload must match simulator's reply"
        );

        let server_keys = sim_handle.await.expect("simulator task must not panic");
        assert_eq!(
            server_keys, tunnel.session.layer_keys,
            "client and server derived keys must agree at every hop"
        );
    }

    #[tokio::test]
    async fn onion_fs_udp_tunnel_establishes_key_agreement_and_a_reply_round_trip_at_one_hop() {
        assert_key_agreement_and_reply_round_trip(1).await;
    }

    #[tokio::test]
    async fn onion_fs_udp_tunnel_establishes_key_agreement_and_a_reply_round_trip_at_two_hops() {
        assert_key_agreement_and_reply_round_trip(2).await;
    }

    /// Same proof as [`assert_key_agreement_and_reply_round_trip`] above, but
    /// driven entirely through [`OnionFsUdpTunnel::into_split`]'s sender and
    /// receiver halves instead of the un-split tunnel: a reply the simulator
    /// wraps through every layer round-trips back through
    /// [`super::OnionFsUdpTunnelReceiver::recv_datagram`] byte for byte, a
    /// forward datagram sent through
    /// [`super::OnionFsUdpTunnelSender::send`] AFTER the split decodes on
    /// the simulator's side under the same exit-layer key the un-split
    /// tunnel would have used, and the per-hop keys the client derived
    /// before splitting still equal the simulator's independently-derived
    /// keys. This is the property `run_datagram_udp_session` actually
    /// depends on — it never touches the un-split tunnel at all.
    async fn assert_split_key_agreement_and_reply_round_trip(n_hops: usize) {
        let mesh_id = b"staging-v2";
        let chain_id = format!("c-fs-udp-split-{n_hops}hop");
        let node_kps: Vec<KeyPair> = (0..n_hops).map(|_| KeyPair::generate()).collect();
        let node_ids: Vec<String> =
            (0..n_hops).map(|i| format!("test-node-udp-split-{i}")).collect();
        let pubkeys_hex: Vec<String> =
            node_kps.iter().map(|kp| hex_encode_pub(&kp.public.to_bytes())).collect();
        let initial_data = b"hello from udp client (split)";
        let reply_payload = b"reply from udp exit (split)";
        let post_split_payload = b"outbound over the split sender half";

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind sim socket");
        let entry_addr = sock.local_addr().expect("sim local addr");

        let chain = build_chain(&chain_id, entry_addr, &pubkeys_hex, &node_ids);

        let sim_node_ids = node_ids.clone();
        let sim_handle = tokio::spawn(async move {
            run_fs_udp_simulator(
                sock,
                &node_kps,
                &sim_node_ids,
                initial_data,
                reply_payload,
                Some(post_split_payload),
            )
            .await
        });

        let tunnel = OnionFsUdpTunnel::connect(
            &chain,
            initial_data,
            mesh_id,
            vec![AeadSuite::ChaCha20Poly1305],
            &[], // no peer suite prefs → defaults inside compute_chosen_suites_fs
            0,
            None,
        )
        .await
        .expect("connect must succeed — full N-hop FS UDP handshake with ntor auth");

        let client_keys = tunnel.session.layer_keys.clone();
        assert_eq!(client_keys.len(), n_hops, "session must hold one layer key per hop");

        let (mut sender, mut receiver) = tunnel.into_split();

        let got = receiver
            .recv_datagram()
            .await
            .expect("split receiver recv_datagram must succeed");
        assert_eq!(
            got, reply_payload,
            "split receiver: reply round-trip must match simulator's reply exactly"
        );

        sender
            .send(post_split_payload)
            .await
            .expect("split sender send must succeed after the split");

        let server_keys = sim_handle.await.expect("simulator task must not panic");
        assert_eq!(
            server_keys, client_keys,
            "client and server derived keys must agree at every hop, through the split too"
        );
    }

    #[tokio::test]
    async fn onion_fs_udp_tunnel_into_split_halves_carry_a_key_agreement_and_reply_round_trip_at_one_hop() {
        assert_split_key_agreement_and_reply_round_trip(1).await;
    }

    #[tokio::test]
    async fn onion_fs_udp_tunnel_into_split_halves_carry_a_key_agreement_and_reply_round_trip_at_two_hops() {
        assert_split_key_agreement_and_reply_round_trip(2).await;
    }

    /// [`guard_step_frame_size`] must refuse, by name, a frame over the
    /// datagram-safe ceiling — and accept one exactly at it. Tested directly
    /// against synthetic bytes rather than through a real deep chain: the
    /// guard's own logic is a pure length comparison, and manufacturing a
    /// chain long enough (~26+ hops) to organically grow a frame past 1200
    /// bytes through real AEAD wrapping would prove nothing the direct check
    /// does not already prove, at a large fixture cost.
    #[test]
    fn a_frame_that_would_exceed_the_datagram_safe_ceiling_is_refused_by_name() {
        let oversized = vec![0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN + 1];
        let err = guard_step_frame_size(3, &oversized).expect_err("an oversized frame must be refused");
        let msg = err.to_string();
        assert!(msg.contains("hop 3"), "the refusal must name which hop's frame overflowed: {msg}");
        assert!(
            msg.contains(&SAFE_UDP_HANDSHAKE_PAYLOAD_LEN.to_string()),
            "the refusal must name the ceiling it checked against: {msg}"
        );

        let at_ceiling = vec![0u8; SAFE_UDP_HANDSHAKE_PAYLOAD_LEN];
        assert!(
            guard_step_frame_size(3, &at_ceiling).is_ok(),
            "a frame exactly at the ceiling must be accepted, not refused"
        );
    }

    /// A hop that reads every datagram but never answers must make `connect`
    /// fail — after retrying, not immediately — and the failure must name
    /// the retransmit bound it gave up after, not surface a bare timeout.
    #[tokio::test]
    async fn a_lost_reply_is_retransmitted_and_then_gives_up_by_name_after_the_bound() {
        let node_kp = KeyPair::generate();
        let node_id = "test-node-silent".to_string();
        let pubkey_hex = hex_encode_pub(&node_kp.public.to_bytes());

        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind silent sim socket");
        let entry_addr = sock.local_addr().expect("sim local addr");
        // Reads every datagram (so the client's sends never see an ICMP
        // port-unreachable) but answers none — indistinguishable, from the
        // client's side, from a hop that lost every reply.
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while sock.recv_from(&mut buf).await.is_ok() {}
        });

        let chain = build_chain(
            "c-fs-udp-silent",
            entry_addr,
            &[pubkey_hex],
            &[node_id],
        );

        let started = std::time::Instant::now();
        let result = OnionFsUdpTunnel::connect(
            &chain,
            b"",
            b"staging-v2",
            vec![AeadSuite::ChaCha20Poly1305],
            &[],
            0,
            None,
        )
        .await;
        let elapsed = started.elapsed();

        let err = match result {
            Ok(_) => panic!("connect must fail against a hop that never replies"),
            Err(e) => e,
        };
        assert!(
            matches!(err, MirageError::HandshakeTimedOut(_)),
            "giving up after the retransmit bound must surface as HandshakeTimedOut: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains(&FS_STEP_MAX_RETRANSMITS.to_string()) && msg.contains("retransmits"),
            "the refusal must name the retransmit bound it gave up after: {msg}"
        );
        assert!(
            elapsed >= FS_STEP_RETRANSMIT_TIMEOUT * FS_STEP_MAX_RETRANSMITS,
            "must actually have retried up to the bound, not given up early: {elapsed:?}"
        );
    }
}
